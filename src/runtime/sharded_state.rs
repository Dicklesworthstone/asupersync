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
    let index = u64::from(arena.index()).saturating_add(1);
    let generation = u64::from(arena.generation()).saturating_add(1);
    (generation << 32) | index
}

#[inline]
fn decode_root_region(encoded: u64) -> Option<RegionId> {
    if encoded == ROOT_REGION_NONE {
        return None;
    }
    let index = ((encoded & 0xFFFF_FFFF) as u32).saturating_sub(1);
    let generation = ((encoded >> 32) as u32).saturating_sub(1);
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

    /// Lock for cancel_request: D→B→A.
    ///
    /// Use for: initiating cancellation, propagating to descendant tasks.
    #[must_use]
    pub fn for_cancel(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→A (D is lock-free, C not needed)
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

    /// Lock for obligation lifecycle: D→B→C.
    ///
    /// Use for: create/commit/abort obligation.
    #[must_use]
    pub fn for_obligation(shards: &'a ShardedState) -> Self {
        // Acquire in order: B→C (D is lock-free, A not needed)
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
    const fn order(self) -> u8 {
        match self {
            Self::Regions => 0,
            Self::Tasks => 1,
            Self::Obligations => 2,
        }
    }
}

#[cfg(debug_assertions)]
mod lock_order {
    use super::LockShard;
    use std::cell::RefCell;

    thread_local! {
        static HELD: RefCell<Vec<LockShard>> = const { RefCell::new(Vec::new()) };
    }

    pub fn before_lock(next: LockShard) {
        HELD.with(|held| {
            let held = held.borrow();
            if let Some(last) = held.last() {
                debug_assert!(
                    last.order() < next.order(),
                    "lock order violation: {last:?} before {next:?}"
                );
            }
        });
    }

    pub fn after_lock(locked: LockShard) {
        HELD.with(|held| {
            held.borrow_mut().push(locked);
        });
    }

    pub fn unlock_n(count: usize) {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            for _ in 0..count {
                held.pop();
            }
        });
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
}
