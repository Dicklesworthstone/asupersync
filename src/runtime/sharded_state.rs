//! Sharded runtime state for reduced contention.
//!
//! `ShardedState` replaces the single-lock `Arc<Mutex<RuntimeState>>` with
//! independently locked shards, enabling hot-path operations (task polling)
//! to proceed without blocking region/obligation mutations.
//!
//! # Lock Order
//!
//! When multiple shard locks must be held simultaneously, acquire in this
//! fixed order to prevent deadlocks:
//!
//! ```text
//! E (Config) → D (Instrumentation) → B (Regions) → A (Tasks) → C (Obligations)
//! ```
//!
//! **Mnemonic:** Every Day Brings Another Challenge.
//!
//! # Shard Responsibilities
//!
//! - **Shard A (Tasks)**: Hot-path task records, stored futures, intrusive queue links
//! - **Shard B (Regions)**: Region ownership tree, child counts, state transitions
//! - **Shard C (Obligations)**: Resource tracking, commit/abort/leak handling
//! - **Shard D (Instrumentation)**: Trace buffer, metrics provider (lock-free)
//! - **Shard E (Config)**: Read-only configuration (no lock needed)
//!
//! # RuntimeState Method → ShardGuard Mapping
//!
//! Any method that calls `advance_region_state` needs all three locks (B→A→C)
//! because the `Finalizing` branch checks task terminal status (A) and handles
//! obligation leaks (C).
//!
//! | RuntimeState method              | Guard                    | Shards  | Reason                    |
//! |----------------------------------|--------------------------|---------|---------------------------|
//! | poll / push / pop / steal        | `tasks_only`             | A       | Hot-path task access only |
//! | region tree queries              | `regions_only`           | B       | Read-only region checks   |
//! | obligation queries               | `obligations_only`       | C       | Read-only obligation data |
//! | `create_obligation`              | `for_obligation`         | B→C     | Region validate + insert  |
//! | `commit_obligation`              | `for_obligation_resolve` | B→A→C   | Calls advance_region_state|
//! | `abort_obligation`               | `for_obligation_resolve` | B→A→C   | Calls advance_region_state|
//! | `mark_obligation_leaked`         | `for_obligation_resolve` | B→A→C   | Calls advance_region_state|
//! | `spawn` / `create_task`          | `for_spawn`              | B→A     | Region + task insert      |
//! | `cancel_request`                 | `for_cancel`             | B→A→C   | Calls advance_region_state|
//! | `cancel_sibling_tasks`           | `for_cancel`             | B→A→C   | May propagate cancel      |
//! | `task_completed`                 | `for_task_completed`     | B→A→C   | Task remove + region adv. |
//! | snapshot / quiescence check      | `all`                    | B→A→C   | Full-state read           |
//!
//! See `docs/runtime_state_contention_inventory.md` for the full spec.

use crate::cx::cx::ObservabilityState;
use crate::observability::metrics::MetricsProvider;
use crate::observability::{LogCollector, ObservabilityConfig};
use crate::runtime::config::{LeakEscalation, ObligationLeakResponse};
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::{BlockingPoolHandle, ObligationTable, RegionTable, TaskTable};
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::trace::TraceBufferHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{CancelAttributionConfig, RegionId, TaskId, Time};
use crate::util::{ArenaIndex, EntropySource};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Observability configuration wrapper for sharded state.
///
/// Stores the observability config and a pre-created log collector
/// for efficient per-task observability state creation.
#[derive(Debug, Clone)]
pub struct ShardedObservability {
    config: ObservabilityConfig,
    collector: LogCollector,
}

impl ShardedObservability {
    /// Creates a new observability wrapper from the given config.
    #[must_use]
    pub fn new(config: ObservabilityConfig) -> Self {
        let collector = config.create_collector();
        Self { config, collector }
    }

    /// Creates an `ObservabilityState` for a specific task.
    #[must_use]
    pub fn for_task(&self, region: RegionId, task: TaskId) -> ObservabilityState {
        ObservabilityState::new_with_config(
            region,
            task,
            &self.config,
            Some(self.collector.clone()),
        )
    }

    /// Returns a reference to the underlying config.
    #[must_use]
    pub fn config(&self) -> &ObservabilityConfig {
        &self.config
    }

    /// Returns a clone of the log collector.
    #[must_use]
    pub fn collector(&self) -> LogCollector {
        self.collector.clone()
    }
}

/// Read-only runtime configuration for sharded state (Shard E).
///
/// These fields are set at runtime initialization and never mutated.
/// Stored as `Arc<ShardedConfig>` for zero-cost shared access.
#[derive(Debug)]
pub struct ShardedConfig {
    /// I/O driver for reactor integration.
    pub io_driver: Option<IoDriverHandle>,
    /// Timer driver for sleep/timeout operations.
    pub timer_driver: Option<TimerDriverHandle>,
    /// Logical clock mode used for task contexts.
    pub logical_clock_mode: LogicalClockMode,
    /// Cancel attribution configuration.
    pub cancel_attribution: CancelAttributionConfig,
    /// Entropy source for capability-based randomness.
    pub entropy_source: Arc<dyn EntropySource>,
    /// Blocking pool handle for synchronous work offloading.
    pub blocking_pool: Option<BlockingPoolHandle>,
    /// Response policy when obligation leaks are detected.
    pub obligation_leak_response: ObligationLeakResponse,
    /// Optional escalation policy for obligation leaks.
    pub leak_escalation: Option<LeakEscalation>,
    /// Optional observability configuration for runtime contexts.
    pub observability: Option<ShardedObservability>,
}

/// Sharded runtime state with independent locks per shard.
///
/// This structure enables fine-grained locking: hot-path task operations
/// can proceed concurrently with region/obligation mutations, significantly
/// reducing contention in multi-worker schedulers.
pub struct ShardedState {
    // ── Shard A: Tasks (HOT) ───────────────────────────────────────────
    /// Task table: arena + stored futures.
    /// Locked for every poll cycle; keep lock hold time minimal.
    ///
    /// Arc-shared (E1.2 subsystem 3c,
    /// br-asupersync-sched-hot-path-perf-bt4y5f.2.2): the scheduler's
    /// external-table seam takes `Arc<ContendedMutex<TaskTable>>`, so shard A
    /// lives behind an `Arc` and [`Self::task_shard_handle`] hands the
    /// scheduler an alias of this exact shard instead of a second table.
    /// `ShardGuard` acquisition is unchanged — the guard locks through the
    /// `Arc` deref, so scheduler dispatch and guard-ordered lifecycle work
    /// contend on the same mutex.
    pub tasks: Arc<ContendedMutex<TaskTable>>,

    // ── Shard B: Regions (WARM) ────────────────────────────────────────
    /// Region table: ownership tree, child counts, state transitions.
    /// Locked for spawn, region create/close, advance_region_state.
    ///
    /// Arc-shared (E2 subsystem 1, br-asupersync-m9wsza, mirroring the
    /// 3c shard-A precedent): the B/C lifecycle conversion routes
    /// region operations through external-table seams the same way E1.2
    /// routed task operations, so shard B lives behind an `Arc` and
    /// [`Self::region_shard_handle`] hands lifecycle seams an alias of
    /// this exact shard. `ShardGuard` acquisition is unchanged — guards
    /// lock through the `Arc` deref, so seam-routed region work and
    /// guard-ordered multi-shard work contend on the same mutex.
    pub regions: Arc<ContendedMutex<RegionTable>>,

    /// The root region ID (set once at initialization).
    root_region: AtomicU64,

    // ── Shard C: Obligations (WARM) ────────────────────────────────────
    /// Obligation table: resource tracking and commit/abort.
    /// Locked for obligation create/commit/abort/leak.
    ///
    /// Arc-shared (E2 subsystem 1, br-asupersync-m9wsza): same alias
    /// seam as shard B above; [`Self::obligation_shard_handle`] is the
    /// accessor.
    pub obligations: Arc<ContendedMutex<ObligationTable>>,

    /// Cumulative count of obligation leaks (for escalation threshold).
    /// Using AtomicU64 for lock-free increment.
    pub leak_count: AtomicU64,

    // ── Shard D: Instrumentation (internal mutex + atomics) ────────────
    //
    // Shard D is not *lock-free* — `TraceBufferHandle` holds an internal
    // `Mutex<TraceBuffer>` (see `src/trace/buffer.rs`). The shard is not
    // represented in [`LockShard`] because its mutex is short-held, never
    // taken across shard mutations, and always acquired AFTER any shard
    // lock in the canonical E→D→B→A→C order. Concretely: every current
    // call site takes the trace mutex last, inside a shard-guarded
    // critical section. Any future refactor that inverts this — e.g. a
    // trace-emit callback that re-enters shard mutation — would break
    // the ordering without tripping `before_lock`'s debug_assert, so the
    // rule is enforced by convention plus this invariant comment.
    /// Trace buffer for events.
    /// Internally synchronized via Arc + internal Mutex; acquired after
    /// shard locks by convention (see note above).
    pub trace: TraceBufferHandle,

    /// Metrics provider for runtime instrumentation.
    /// Internally thread-safe via atomics; no shard lock needed.
    pub metrics: Arc<dyn MetricsProvider>,

    /// Current logical time.
    /// Read-only in production; Lab mode may write (single-threaded).
    pub now: AtomicU64,

    // ── Shard E: Config (read-only) ────────────────────────────────────
    /// Read-only runtime configuration.
    /// No lock needed; immutable after initialization.
    pub config: Arc<ShardedConfig>,
}

impl std::fmt::Debug for ShardedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedState")
            .field("tasks", &"<ContendedMutex<TaskTable>>")
            .field("regions", &"<ContendedMutex<RegionTable>>")
            .field("root_region", &self.root_region())
            .field("obligations", &"<ContendedMutex<ObligationTable>>")
            .field("leak_count", &self.leak_count.load(Ordering::Relaxed))
            .field("trace", &self.trace)
            .field("metrics", &"<dyn MetricsProvider>")
            .field("now", &self.now.load(Ordering::Relaxed))
            .field("config", &self.config)
            .finish()
    }
}

impl ShardedState {
    /// Creates a new sharded state with the provided configuration.
    #[must_use]
    pub fn new(
        trace: TraceBufferHandle,
        metrics: Arc<dyn MetricsProvider>,
        config: ShardedConfig,
    ) -> Self {
        Self {
            tasks: Arc::new(ContendedMutex::new("tasks", TaskTable::new())),
            regions: Arc::new(ContendedMutex::new("regions", RegionTable::new())),
            root_region: AtomicU64::new(ROOT_REGION_NONE),
            obligations: Arc::new(ContendedMutex::new("obligations", ObligationTable::new())),
            leak_count: AtomicU64::new(0),
            trace,
            metrics,
            now: AtomicU64::new(0),
            config: Arc::new(config),
        }
    }

    /// Returns the current logical time.
    #[inline]
    #[must_use]
    pub fn current_time(&self) -> Time {
        Time::from_nanos(self.now.load(Ordering::Acquire))
    }

    /// Sets the logical time (Lab mode only).
    #[inline]
    pub fn set_time(&self, time: Time) {
        self.now.store(time.as_nanos(), Ordering::Release);
    }

    /// Increments the leak count and returns the new value.
    #[inline]
    pub fn increment_leak_count(&self) -> u64 {
        self.leak_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the current leak count.
    #[inline]
    #[must_use]
    pub fn leak_count(&self) -> u64 {
        self.leak_count.load(Ordering::Relaxed)
    }

    /// Returns the root region ID, if set.
    #[inline]
    #[must_use]
    pub fn root_region(&self) -> Option<RegionId> {
        decode_root_region(self.root_region.load(Ordering::Acquire))
    }

    /// Sets the root region ID.
    ///
    /// Returns `true` if the root region was set, `false` if it was already set.
    pub fn set_root_region(&self, region: RegionId) -> bool {
        let encoded = encode_root_region(region);
        let result = self.root_region.compare_exchange(
            ROOT_REGION_NONE,
            encoded,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        result.is_ok()
    }

    /// Returns the shard-A task-table handle for scheduler aliasing
    /// (E1.2 subsystem 3c, br-asupersync-sched-hot-path-perf-bt4y5f.2.2).
    ///
    /// The returned `Arc` is the SAME shard the [`ShardGuard`] builders
    /// lock, so a scheduler constructed with it dispatches against shard A
    /// directly: records minted through the scheduler's admission/finalizer
    /// seams are visible to guard-ordered lifecycle work and vice versa.
    #[inline]
    #[must_use]
    pub fn task_shard_handle(&self) -> Arc<ContendedMutex<TaskTable>> {
        Arc::clone(&self.tasks)
    }

    /// Returns an alias of shard B — the region table — for external-seam
    /// routing (E2 subsystem 1, br-asupersync-m9wsza).
    ///
    /// The returned `Arc` is the SAME shard the [`ShardGuard`] builders
    /// lock: region lifecycle work routed through a seam holding this
    /// handle and guard-ordered multi-shard work contend on one mutex,
    /// exactly as [`Self::task_shard_handle`] established for shard A.
    #[inline]
    #[must_use]
    pub fn region_shard_handle(&self) -> Arc<ContendedMutex<RegionTable>> {
        Arc::clone(&self.regions)
    }

    /// Returns an alias of shard C — the obligation table — for
    /// external-seam routing (E2 subsystem 1, br-asupersync-m9wsza).
    ///
    /// Same contract as [`Self::region_shard_handle`], for the
    /// obligation shard.
    #[inline]
    #[must_use]
    pub fn obligation_shard_handle(&self) -> Arc<ContendedMutex<ObligationTable>> {
        Arc::clone(&self.obligations)
    }

    /// Returns a clone of the trace handle.
    #[inline]
    #[must_use]
    pub fn trace_handle(&self) -> TraceBufferHandle {
        self.trace.clone()
    }

    /// Returns a clone of the metrics provider.
    #[inline]
    #[must_use]
    pub fn metrics_provider(&self) -> Arc<dyn MetricsProvider> {
        Arc::clone(&self.metrics)
    }

    /// Returns a reference to the configuration.
    #[inline]
    #[must_use]
    pub fn config(&self) -> &Arc<ShardedConfig> {
        &self.config
    }

    /// Returns the I/O driver handle if available.
    #[inline]
    #[must_use]
    pub fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.config.io_driver.clone()
    }

    /// Returns the timer driver handle if available.
    #[inline]
    #[must_use]
    pub fn timer_driver_handle(&self) -> Option<TimerDriverHandle> {
        self.config.timer_driver.clone()
    }
}

const ROOT_REGION_NONE: u64 = 0;

#[inline]
fn encode_root_region(region: RegionId) -> u64 {
    let arena = region.arena_index();
    let index = u64::from(arena.index());
    let generation = u64::from(arena.generation());
    let packed = (generation << 32) | index;
    // Reserve 0 for NONE.
    // If packed == u64::MAX, packed + 1 is 0, which would be confused with NONE.
    assert!(packed != u64::MAX, "region ID too large for atomic storage");
    packed + 1
}

#[inline]
fn decode_root_region(encoded: u64) -> Option<RegionId> {
    if encoded == ROOT_REGION_NONE {
        return None;
    }
    let packed = encoded - 1;
    let index = (packed & 0xFFFF_FFFF) as u32;
    let generation = (packed >> 32) as u32;
    Some(RegionId::from_arena(ArenaIndex::new(index, generation)))
}

/// Guard for multi-shard operations that enforces canonical lock ordering.
///
/// When operations require multiple shards, use `ShardGuard` to ensure
/// locks are acquired in the correct order (E→D→B→A→C) and prevent deadlocks.
///
/// # Example
///
/// ```ignore
/// // For task_completed: needs D→B→A→C
/// let guard = ShardGuard::for_task_completed(&shards);
/// // Now safe to access guard.regions, guard.tasks, guard.obligations
/// ```
pub struct ShardGuard<'a> {
    /// Reference to config (Shard E, no lock needed).
    pub config: &'a Arc<ShardedConfig>,
    /// Region shard guard (Shard B), if acquired.
    pub regions: Option<crate::sync::ContendedMutexGuard<'a, RegionTable>>,
    /// Task shard guard (Shard A), if acquired.
    pub tasks: Option<crate::sync::ContendedMutexGuard<'a, TaskTable>>,
    /// Obligation shard guard (Shard C), if acquired.
    pub obligations: Option<crate::sync::ContendedMutexGuard<'a, ObligationTable>>,
    /// Number of debug lock entries recorded for this guard.
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    debug_locks: usize,
}

impl<'a> ShardGuard<'a> {
    /// Lock only the task shard (hot path).
    ///
    /// Use for: poll, push/pop/steal, wake_state operations.
    #[must_use]
    pub fn tasks_only(shards: &'a ShardedState) -> Self {
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);
        Self {
            config: &shards.config,
            regions: None,
            tasks: Some(tasks),
            obligations: None,
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 1,
        }
    }

    /// Lock only the region shard.
    ///
    /// Use for: read-only region tree queries, region count checks.
    #[must_use]
    pub fn regions_only(shards: &'a ShardedState) -> Self {
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: None,
            obligations: None,
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 1,
        }
    }

    /// Lock only the obligation shard.
    ///
    /// Use for: read-only obligation queries, obligation count checks.
    #[must_use]
    pub fn obligations_only(shards: &'a ShardedState) -> Self {
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);
        Self {
            config: &shards.config,
            regions: None,
            tasks: None,
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 1,
        }
    }

    /// Lock for task_completed: D→B→A→C.
    ///
    /// Use for: completing a task, orphan obligation scan, region state advance.
    #[must_use]
    pub fn for_task_completed(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C (D is lock-free)
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 3,
        }
    }

    /// Lock for cancel_request: D→B→A→C.
    ///
    /// Use for: initiating cancellation, propagating to descendant tasks.
    ///
    /// # Why B→A→C (not just B→A)
    ///
    /// `cancel_request` calls `advance_region_state`, which in the
    /// `Finalizing` branch can call `handle_obligation_leaks` →
    /// `abort_obligation` → obligation table access. Any cancel path
    /// that triggers region state advancement needs obligation access.
    #[must_use]
    pub fn for_cancel(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C (D is lock-free)
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 3,
        }
    }

    /// Lock for obligation creation: D→B→C.
    ///
    /// Use for: `create_obligation` only. This guard does NOT cover
    /// resolve operations (commit/abort/mark_leaked) — use
    /// [`for_obligation_resolve`](Self::for_obligation_resolve) for those.
    #[must_use]
    pub fn for_obligation(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→C (D is lock-free, A not needed for creation)
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: None,
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 2,
        }
    }

    /// Lock for obligation resolve operations: D→B→A→C.
    ///
    /// Use for: `commit_obligation`, `abort_obligation`, `mark_obligation_leaked`.
    ///
    /// # Why B→A→C (not just B→C)
    ///
    /// Obligation resolve operations call `advance_region_state`, which
    /// in the `Finalizing` branch checks task terminal status (needs A)
    /// and handles obligation leaks (needs C). The task shard is required
    /// because `can_region_complete_close` iterates task IDs to verify
    /// all tasks are terminal before allowing region closure.
    #[must_use]
    pub fn for_obligation_resolve(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C (D is lock-free)
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 3,
        }
    }

    /// Lock for spawn: E→D→B→A.
    ///
    /// Use for: creating a new task.
    #[must_use]
    pub fn for_spawn(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A (E read-only, D lock-free, C not needed)
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: None,
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 2,
        }
    }

    /// Lock all shards for full-state operations (snapshot, quiescence check).
    ///
    /// Use sparingly; prefer narrow guards when possible.
    #[must_use]
    pub fn all(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards
            .regions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(any(debug_assertions, feature = "lock-metrics"))]
            debug_locks: 3,
        }
    }
}

impl Drop for ShardGuard<'_> {
    fn drop(&mut self) {
        let obligations = self.obligations.take();
        let tasks = self.tasks.take();
        let regions = self.regions.take();
        drop(obligations);
        drop(tasks);
        drop(regions);
        #[cfg(any(debug_assertions, feature = "lock-metrics"))]
        {
            lock_order::unlock_n(self.debug_locks);
        }
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockShard {
    Regions,
    Tasks,
    Obligations,
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl LockShard {
    /// Returns the canonical acquisition order index.
    ///
    /// Lock order: Regions(0) < Tasks(1) < Obligations(2).
    /// This matches the documented E→D→B→A→C order where
    /// B=Regions, A=Tasks, C=Obligations (E and D are lock-free).
    const fn order(self) -> u8 {
        match self {
            Self::Regions => 0,
            Self::Tasks => 1,
            Self::Obligations => 2,
        }
    }

    /// Returns a human-readable label for diagnostics.
    const fn label(self) -> &'static str {
        match self {
            Self::Regions => "B:Regions",
            Self::Tasks => "A:Tasks",
            Self::Obligations => "C:Obligations",
        }
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl std::fmt::Display for LockShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Debug-only lock ordering enforcement via thread-local state.
///
/// Tracks which shard locks the current thread holds and asserts
/// that new acquisitions follow the canonical order:
///   Regions (0) → Tasks (1) → Obligations (2)
///
/// Violations trigger a `debug_assert!` panic with a diagnostic
/// message naming both the held lock and the violating acquisition.
///
/// # Thread Safety
///
/// State is per-thread (thread-local). No cross-thread coordination
/// is needed because lock ordering is a per-thread property.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
pub(crate) mod lock_order {
    use super::LockShard;
    use std::cell::RefCell;

    thread_local! {
        static HELD: RefCell<Vec<LockShard>> = const { RefCell::new(Vec::new()) };
    }

    /// Asserts that acquiring `next` does not violate lock ordering.
    ///
    /// Panics (debug_assert) if the thread already holds a lock with
    /// equal or higher order than `next`.
    pub fn before_lock(next: LockShard) {
        HELD.with(|held| {
            let held = held.borrow();
            if let Some(last) = held.last() {
                debug_assert!(
                    last.order() < next.order(),
                    "lock order violation: holding {} (order {}) then acquiring {} (order {}); \
                     canonical order is B:Regions(0) → A:Tasks(1) → C:Obligations(2)",
                    last.label(),
                    last.order(),
                    next.label(),
                    next.order(),
                );
            }
        });
    }

    /// Records that `locked` has been acquired by this thread.
    pub fn after_lock(locked: LockShard) {
        HELD.with(|held| {
            held.borrow_mut().push(locked);
        });
    }

    /// Releases the most recent `count` lock records (LIFO).
    pub fn unlock_n(count: usize) {
        let _ = HELD.try_with(|held| {
            let mut held = held.borrow_mut();
            for _ in 0..count {
                held.pop();
            }
        });
    }

    /// Returns the number of shard locks currently held by this thread.
    ///
    /// Useful in tests to verify guards properly track acquisitions.
    #[cfg(test)]
    pub fn held_count() -> usize {
        HELD.with(|held| held.borrow().len())
    }

    /// Returns a snapshot of the shard locks currently held by this thread.
    ///
    /// Returns labels in acquisition order (earliest first).
    #[cfg(test)]
    pub fn held_labels() -> Vec<&'static str> {
        HELD.with(|held| held.borrow().iter().map(|s| s.label()).collect())
    }
}

#[cfg(test)]
#[path = "sharded_state_inline_tests.rs"]
mod tests;
