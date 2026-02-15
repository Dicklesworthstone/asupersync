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
use crate::trace::distributed::LogicalClockMode;
use crate::trace::TraceBufferHandle;
use crate::types::{CancelAttributionConfig, RegionId, TaskId, Time};
use crate::util::{ArenaIndex, EntropySource};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    pub tasks: ContendedMutex<TaskTable>,

    // ── Shard B: Regions (WARM) ────────────────────────────────────────
    /// Region table: ownership tree, child counts, state transitions.
    /// Locked for spawn, region create/close, advance_region_state.
    pub regions: ContendedMutex<RegionTable>,

    /// The root region ID (set once at initialization).
    root_region: AtomicU64,

    // ── Shard C: Obligations (WARM) ────────────────────────────────────
    /// Obligation table: resource tracking and commit/abort.
    /// Locked for obligation create/commit/abort/leak.
    pub obligations: ContendedMutex<ObligationTable>,

    /// Cumulative count of obligation leaks (for escalation threshold).
    /// Using AtomicU64 for lock-free increment.
    pub leak_count: AtomicU64,

    // ── Shard D: Instrumentation (lock-free) ───────────────────────────
    /// Trace buffer for events.
    /// Internally synchronized via Arc + internal Mutex; no shard lock needed.
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
            tasks: ContendedMutex::new("tasks", TaskTable::new()),
            regions: ContendedMutex::new("regions", RegionTable::new()),
            root_region: AtomicU64::new(ROOT_REGION_NONE),
            obligations: ContendedMutex::new("obligations", ObligationTable::new()),
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
    #[cfg(debug_assertions)]
    debug_locks: usize,
}

impl<'a> ShardGuard<'a> {
    /// Lock only the task shard (hot path).
    ///
    /// Use for: poll, push/pop/steal, wake_state operations.
    #[must_use]
    pub fn tasks_only(shards: &'a ShardedState) -> Self {
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);
        Self {
            config: &shards.config,
            regions: None,
            tasks: Some(tasks),
            obligations: None,
            #[cfg(debug_assertions)]
            debug_locks: 1,
        }
    }

    /// Lock only the region shard.
    ///
    /// Use for: read-only region tree queries, region count checks.
    #[must_use]
    pub fn regions_only(shards: &'a ShardedState) -> Self {
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: None,
            obligations: None,
            #[cfg(debug_assertions)]
            debug_locks: 1,
        }
    }

    /// Lock only the obligation shard.
    ///
    /// Use for: read-only obligation queries, obligation count checks.
    #[must_use]
    pub fn obligations_only(shards: &'a ShardedState) -> Self {
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);
        Self {
            config: &shards.config,
            regions: None,
            tasks: None,
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
            debug_locks: 1,
        }
    }

    /// Lock for task_completed: D→B→A→C.
    ///
    /// Use for: completing a task, orphan obligation scan, region state advance.
    #[must_use]
    pub fn for_task_completed(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C (D is lock-free)
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
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
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
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
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: None,
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
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
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
            debug_locks: 3,
        }
    }

    /// Lock for spawn: E→D→B→A.
    ///
    /// Use for: creating a new task.
    #[must_use]
    pub fn for_spawn(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A (E read-only, D lock-free, C not needed)
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: None,
            #[cfg(debug_assertions)]
            debug_locks: 2,
        }
    }

    /// Lock all shards for full-state operations (snapshot, quiescence check).
    ///
    /// Use sparingly; prefer narrow guards when possible.
    #[must_use]
    pub fn all(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A→C
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Regions);
        let regions = shards.regions.lock().expect("regions lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Regions);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Tasks);
        let tasks = shards.tasks.lock().expect("tasks lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Tasks);
        #[cfg(debug_assertions)]
        lock_order::before_lock(LockShard::Obligations);
        let obligations = shards
            .obligations
            .lock()
            .expect("obligations lock poisoned");
        #[cfg(debug_assertions)]
        lock_order::after_lock(LockShard::Obligations);

        Self {
            config: &shards.config,
            regions: Some(regions),
            tasks: Some(tasks),
            obligations: Some(obligations),
            #[cfg(debug_assertions)]
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
        #[cfg(debug_assertions)]
        {
            lock_order::unlock_n(self.debug_locks);
        }
    }
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockShard {
    Regions,
    Tasks,
    Obligations,
}

#[cfg(debug_assertions)]
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

#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
mod lock_order {
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
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            for _ in 0..count {
                held.pop();
            }
        });
    }

    /// Returns the number of shard locks currently held by this thread.
    ///
    /// Useful in tests to verify guards properly track acquisitions.
    pub fn held_count() -> usize {
        HELD.with(|held| held.borrow().len())
    }

    /// Returns a snapshot of the shard locks currently held by this thread.
    ///
    /// Returns labels in acquisition order (earliest first).
    pub fn held_labels() -> Vec<&'static str> {
        HELD.with(|held| held.borrow().iter().map(|s| s.label()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metrics::NoOpMetrics;
    use crate::trace::TraceBufferHandle;
    use crate::util::OsEntropy;

    fn test_config() -> ShardedConfig {
        ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            observability: None,
        }
    }

    #[test]
    fn sharded_state_creation() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert!(state.root_region().is_none());
        assert_eq!(state.current_time(), Time::ZERO);
        assert_eq!(state.leak_count(), 0);
    }

    #[test]
    fn root_region_set_once() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let first = RegionId::from_arena(ArenaIndex::new(1, 0));
        let second = RegionId::from_arena(ArenaIndex::new(2, 0));

        assert!(state.set_root_region(first));
        assert_eq!(state.root_region(), Some(first));
        assert!(!state.set_root_region(second));
        assert_eq!(state.root_region(), Some(first));
    }

    #[test]
    fn time_operations() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        state.set_time(Time::from_nanos(12345));
        assert_eq!(state.current_time(), Time::from_nanos(12345));
    }

    #[test]
    fn leak_count_increment() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert_eq!(state.increment_leak_count(), 1);
        assert_eq!(state.increment_leak_count(), 2);
        assert_eq!(state.leak_count(), 2);
    }

    #[test]
    fn tasks_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::tasks_only(&state);
        assert!(guard.tasks.is_some());
        assert!(guard.regions.is_none());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn for_task_completed_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_task_completed(&state);
        assert!(guard.tasks.is_some());
        assert!(guard.regions.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn regions_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::regions_only(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_none());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn obligations_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::obligations_only(&state);
        assert!(guard.obligations.is_some());
        assert!(guard.regions.is_none());
        assert!(guard.tasks.is_none());
    }

    #[test]
    fn for_cancel_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_cancel(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_obligation_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_obligation(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_none());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_obligation_resolve_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_obligation_resolve(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_spawn_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_spawn(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn all_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::all(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    // ── Lock ordering enforcement tests ──────────────────────────────────

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_held_count_tracks_acquisitions() {
        // Verify held_count is 0 at start, increments on acquire, decrements on drop.
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_task_completed(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_single_shard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::tasks_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["A:Tasks"]);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _guard = ShardGuard::regions_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["B:Regions"]);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _guard = ShardGuard::obligations_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["C:Obligations"]);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_spawn_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_spawn(&state);
            assert_eq!(lock_order::held_count(), 2);
            assert_eq!(lock_order::held_labels(), vec!["B:Regions", "A:Tasks"]);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_cancel_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_cancel(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_obligation_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_obligation(&state);
            assert_eq!(lock_order::held_count(), 2);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_obligation_resolve_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_obligation_resolve(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    // ── Lock ordering violation tests (should_panic) ─────────────────────
    //
    // These tests verify that debug assertions catch out-of-order
    // lock acquisitions. Each test directly manipulates the lock_order
    // module to simulate a violation without needing two ShardedState
    // instances (which would introduce real deadlock risk).

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_tasks_before_regions() {
        // Holding Tasks (order 1) then acquiring Regions (order 0) is illegal.
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Regions); // ← panic
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_obligations_before_tasks() {
        // Holding Obligations (order 2) then acquiring Tasks (order 1) is illegal.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        lock_order::before_lock(LockShard::Tasks); // ← panic
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_obligations_before_regions() {
        // Holding Obligations (order 2) then acquiring Regions (order 0) is illegal.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        lock_order::before_lock(LockShard::Regions); // ← panic
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_duplicate_shard() {
        // Acquiring the same shard twice is also a violation (order not strictly increasing).
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Tasks); // ← panic (1 not < 1)
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_valid_full_sequence() {
        // Canonical order: Regions → Tasks → Obligations should succeed.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 3);
        assert_eq!(
            lock_order::held_labels(),
            vec!["B:Regions", "A:Tasks", "C:Obligations"]
        );

        // Clean up
        lock_order::unlock_n(3);
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_unlock_then_reacquire() {
        // After releasing all locks, any shard can be acquired again.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        assert_eq!(lock_order::held_count(), 1);

        lock_order::unlock_n(1);
        assert_eq!(lock_order::held_count(), 0);

        // Now Regions (lower order) is fine because nothing is held.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        assert_eq!(lock_order::held_count(), 1);
        assert_eq!(lock_order::held_labels(), vec!["B:Regions"]);

        lock_order::unlock_n(1);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_partial_sequence_regions_tasks() {
        // Regions → Tasks is a valid subsequence.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_partial_sequence_regions_obligations() {
        // Regions → Obligations (skipping Tasks) is valid.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn lock_order_partial_sequence_tasks_obligations() {
        // Tasks → Obligations is valid.
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    // ── Concurrent guard tests ───────────────────────────────────────────

    #[test]
    fn concurrent_guard_access_no_deadlock() {
        // Multiple threads acquire ShardGuards simultaneously.
        // This verifies no deadlock occurs when using the guard API correctly.
        use std::sync::Barrier;
        use std::thread;

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = Arc::new(ShardedState::new(trace, metrics, test_config()));
        let barrier = Arc::new(Barrier::new(4));
        let iterations = 100;

        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..iterations {
                        // Each thread cycles through different guard types.
                        match thread_id % 4 {
                            0 => {
                                let _g = ShardGuard::tasks_only(&state);
                            }
                            1 => {
                                let _g = ShardGuard::for_spawn(&state);
                            }
                            2 => {
                                let _g = ShardGuard::for_obligation(&state);
                            }
                            3 => {
                                let _g = ShardGuard::for_task_completed(&state);
                            }
                            _ => unreachable!(),
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    #[test]
    fn concurrent_mixed_guards_no_deadlock() {
        // All threads use ALL guard types in rotation.
        // This is a stronger test than the above because each thread
        // exercises all ordering patterns.
        use std::sync::Barrier;
        use std::thread;

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = Arc::new(ShardedState::new(trace, metrics, test_config()));
        let barrier = Arc::new(Barrier::new(4));
        let iterations = 50;

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for i in 0..iterations {
                        match i % 8 {
                            0 => {
                                let _g = ShardGuard::tasks_only(&state);
                            }
                            1 => {
                                let _g = ShardGuard::regions_only(&state);
                            }
                            2 => {
                                let _g = ShardGuard::obligations_only(&state);
                            }
                            3 => {
                                let _g = ShardGuard::for_spawn(&state);
                            }
                            4 => {
                                let _g = ShardGuard::for_cancel(&state);
                            }
                            5 => {
                                let _g = ShardGuard::for_obligation(&state);
                            }
                            6 => {
                                let _g = ShardGuard::for_obligation_resolve(&state);
                            }
                            7 => {
                                let _g = ShardGuard::all(&state);
                            }
                            _ => unreachable!(),
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn guard_drop_cleans_up_lock_order_state() {
        // Verify that dropping a guard properly cleans up thread-local state
        // so subsequent guards don't see stale entries.
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert_eq!(lock_order::held_count(), 0);

        {
            let _g = ShardGuard::all(&state);
            assert_eq!(lock_order::held_count(), 3);
        }
        assert_eq!(lock_order::held_count(), 0);

        // After drop, we can acquire in any order (starting fresh).
        {
            let _g = ShardGuard::obligations_only(&state);
            assert_eq!(lock_order::held_count(), 1);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _g = ShardGuard::regions_only(&state);
            assert_eq!(lock_order::held_count(), 1);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    // ── Audit regression tests ───────────────────────────────────────────

    #[test]
    fn root_region_encoding_roundtrip_zero() {
        // (0, 0) is a valid ArenaIndex and must roundtrip correctly.
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        let encoded = encode_root_region(region);
        assert_ne!(encoded, ROOT_REGION_NONE, "encoded must differ from NONE");
        let decoded = decode_root_region(encoded);
        assert_eq!(decoded, Some(region));
    }

    #[test]
    fn root_region_encoding_roundtrip_large() {
        // Large but valid (index, generation) must roundtrip.
        let region = RegionId::from_arena(ArenaIndex::new(u32::MAX, u32::MAX - 1));
        let encoded = encode_root_region(region);
        let decoded = decode_root_region(encoded);
        assert_eq!(decoded, Some(region));
    }

    #[test]
    #[should_panic(expected = "region ID too large")]
    fn root_region_encoding_max_panics() {
        // (u32::MAX, u32::MAX) encodes to u64::MAX and must be rejected.
        let region = RegionId::from_arena(ArenaIndex::new(u32::MAX, u32::MAX));
        let _ = encode_root_region(region);
    }

    #[test]
    fn guard_drop_releases_in_reverse_order() {
        // Verify that after dropping a full guard, we can immediately
        // acquire any single shard (obligations first, which is the
        // "last" in lock order and would fail if drop leaked state).
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _g = ShardGuard::all(&state);
        }

        // If drop didn't properly release, this would deadlock.
        let g = ShardGuard::obligations_only(&state);
        assert!(g.obligations.is_some());
    }
}
