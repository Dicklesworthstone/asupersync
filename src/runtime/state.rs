//! Global runtime state.
//!
//! The runtime state Σ contains all live entities:
//! - Regions (ownership tree)
//! - Tasks (units of execution)
//! - Obligations (resources to be resolved)
//! - Current time

use super::region_table::RegionCreateError;
use crate::cx::cx::ObservabilityState;
use crate::error::{Error, ErrorKind};
use crate::observability::metrics::{MetricsProvider, NoOpMetrics, OutcomeKind};
use crate::observability::{LogCollector, ObservabilityConfig};
use crate::record::{
    AdmissionError, ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState,
    RegionLimits, RegionRecord, SourceLocation, TaskRecord,
    finalizer::{FINALIZER_TIME_BUDGET_NANOS, Finalizer, finalizer_budget},
    region::RegionState,
    task::TaskState,
};
use crate::runtime::config::{LeakEscalation, ObligationLeakResponse};
use crate::runtime::io_driver::{IoDriver, IoDriverHandle};
use crate::runtime::reactor::Reactor;
use crate::runtime::stored_task::StoredTask;
use crate::runtime::task_handle::JoinError;
use crate::runtime::{BlockingPoolHandle, ObligationTable, RegionTable, TaskTable};
use crate::time::TimerDriverHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::trace::event::{TraceData, TraceEventKind};
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{debug, debug_span, trace, trace_span};
use crate::types::policy::PolicyAction;
use crate::types::task_context::{CxInner, MAX_MASK_DEPTH};
use crate::types::{
    Budget, CancelAttributionConfig, CancelKind, CancelReason, ObligationId, Outcome, Policy,
    RegionId, TaskId, Time,
};
use crate::util::{Arena, ArenaIndex, EntropySource, OsEntropy};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Errors that can occur when spawning a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    /// The target region does not exist.
    RegionNotFound(RegionId),
    /// The target region is closed or draining and cannot accept new tasks.
    RegionClosed(RegionId),
    /// Local spawn attempted without an active worker-local scheduler.
    LocalSchedulerUnavailable,
    /// Named service registration failed during spawn.
    NameRegistrationFailed {
        /// The attempted service name.
        name: String,
        /// Deterministic failure reason.
        reason: String,
    },
    /// The target region has reached its admission limit.
    RegionAtCapacity {
        /// The region that rejected the spawn.
        region: RegionId,
        /// The configured admission limit.
        limit: usize,
        /// The number of live tasks at the time of rejection.
        live: usize,
    },
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "region not found: {id:?}"),
            Self::RegionClosed(id) => write!(f, "region closed: {id:?}"),
            Self::LocalSchedulerUnavailable => {
                write!(f, "local spawn requires an active worker scheduler")
            }
            Self::NameRegistrationFailed { name, reason } => {
                write!(f, "name registration failed: name={name} reason={reason}")
            }
            Self::RegionAtCapacity {
                region,
                limit,
                live,
            } => write!(
                f,
                "region admission limit reached: region={region:?} limit={limit} live={live}"
            ),
        }
    }
}

impl std::error::Error for SpawnError {}

#[derive(Debug, Clone, Copy)]
enum TaskCompletionKind {
    Ok,
    Err,
    Cancelled,
    Panicked,
    Unknown,
}

impl TaskCompletionKind {
    fn from_state(state: &TaskState) -> Self {
        match state {
            TaskState::Completed(Outcome::Ok(())) => Self::Ok,
            TaskState::Completed(Outcome::Err(_)) => Self::Err,
            TaskState::Completed(Outcome::Cancelled(_)) => Self::Cancelled,
            TaskState::Completed(Outcome::Panicked(_)) => Self::Panicked,
            _ => Self::Unknown,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Err => "err",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
            Self::Unknown => "unknown",
        }
    }
}

struct MaskedFinalizer {
    inner: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    cx_inner: Arc<parking_lot::RwLock<CxInner>>,
    entered: bool,
}

impl MaskedFinalizer {
    fn new(
        inner: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
        cx_inner: Arc<parking_lot::RwLock<CxInner>>,
    ) -> Self {
        Self {
            inner,
            cx_inner,
            entered: false,
        }
    }

    fn enter_mask(&mut self) {
        if self.entered {
            return;
        }
        let mut guard = self.cx_inner.write();
        debug_assert!(
            guard.mask_depth < MAX_MASK_DEPTH,
            "mask depth exceeded MAX_MASK_DEPTH ({MAX_MASK_DEPTH}): this violates INV-MASK-BOUNDED \
             and prevents cancellation from ever being observed. \
             Reduce nesting of masked sections.",
        );
        if guard.mask_depth >= MAX_MASK_DEPTH {
            crate::tracing_compat::error!(
                depth = guard.mask_depth,
                max = MAX_MASK_DEPTH,
                "INV-MASK-BOUNDED violated: mask depth saturated, cancellation may be unobservable"
            );
            return;
        }
        guard.mask_depth += 1;
        drop(guard);
        self.entered = true;
    }

    fn exit_mask(&mut self) {
        if !self.entered {
            return;
        }
        let mut guard = self.cx_inner.write();
        guard.mask_depth = guard.mask_depth.saturating_sub(1);
        drop(guard);
        self.entered = false;
    }
}

impl Future for MaskedFinalizer {
    type Output = ();

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        self.enter_mask();
        let poll = self.inner.as_mut().poll(cx);
        if poll.is_ready() {
            self.exit_mask();
        }
        poll
    }
}

impl Drop for MaskedFinalizer {
    fn drop(&mut self) {
        self.exit_mask();
    }
}

impl Unpin for MaskedFinalizer {}

#[derive(Debug, Clone)]
struct LeakedObligationInfo {
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    acquired_at: SourceLocation,
    held_duration_ns: u64,
    description: Option<String>,
    acquire_backtrace: Option<Arc<Backtrace>>,
}

impl fmt::Display for LeakedObligationInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:?} holder={:?} region={:?} acquired_at={} held_ns={}",
            self.id, self.kind, self.holder, self.region, self.acquired_at, self.held_duration_ns
        )?;
        if let Some(desc) = &self.description {
            write!(f, " desc={desc}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ObligationLeakError {
    task_id: Option<TaskId>,
    region_id: RegionId,
    completion: Option<TaskCompletionKind>,
    leaks: Vec<LeakedObligationInfo>,
}

impl fmt::Display for ObligationLeakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let completion = self
            .completion
            .map_or("unknown", TaskCompletionKind::as_str);
        write!(
            f,
            "obligation leak: task={:?} region={:?} completion={} leaked={}",
            self.task_id,
            self.region_id,
            completion,
            self.leaks.len()
        )?;
        for leak in &self.leaks {
            write!(f, "\n  - {leak}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct CancelRegionNode {
    id: RegionId,
    parent: Option<RegionId>,
    depth: usize,
}

#[derive(Debug, Clone)]
struct RuntimeObservability {
    config: ObservabilityConfig,
    collector: LogCollector,
}

impl RuntimeObservability {
    fn new(config: ObservabilityConfig) -> Self {
        let collector = config.create_collector();
        Self { config, collector }
    }

    fn for_task(&self, region: RegionId, task: TaskId) -> ObservabilityState {
        ObservabilityState::new_with_config(
            region,
            task,
            &self.config,
            Some(self.collector.clone()),
        )
    }
}

/// The global runtime state.
///
/// This is the "Σ" from the formal semantics:
/// `Σ = ⟨R, T, O, τ_now⟩`
pub struct RuntimeState {
    /// All region records.
    pub regions: RegionTable,
    /// Task table for hot-path task state + stored futures.
    pub tasks: TaskTable,
    /// All obligation records.
    pub obligations: ObligationTable,
    /// Current logical time.
    pub now: Time,
    /// The root region.
    pub root_region: Option<RegionId>,
    /// Trace buffer for events.
    pub trace: TraceBufferHandle,
    /// Metrics provider for runtime instrumentation.
    pub metrics: Arc<dyn MetricsProvider>,
    /// I/O driver for reactor integration.
    ///
    /// When present, the runtime can wait on I/O events via the reactor.
    /// When `None`, the runtime operates in pure Lab mode without real I/O.
    io_driver: Option<IoDriverHandle>,
    /// Timer driver for sleep/timeout operations.
    ///
    /// When present, timers use the driver's timing wheel for efficient
    /// multiplexed wakeups. When `None`, timers fall back to thread-based sleeps.
    timer_driver: Option<TimerDriverHandle>,
    /// Logical clock mode used for task contexts.
    logical_clock_mode: LogicalClockMode,
    /// Cancel attribution configuration (cause-chain limits, memory caps).
    cancel_attribution: CancelAttributionConfig,
    /// Entropy source for capability-based randomness.
    entropy_source: Arc<dyn EntropySource>,
    /// Optional observability configuration for runtime contexts.
    observability: Option<RuntimeObservability>,
    /// Blocking pool handle for offloading synchronous work.
    blocking_pool: Option<BlockingPoolHandle>,
    /// Response policy when obligation leaks are detected.
    obligation_leak_response: ObligationLeakResponse,
    /// Optional escalation policy for obligation leaks.
    leak_escalation: Option<LeakEscalation>,
    /// Cumulative count of obligation leaks (for escalation threshold).
    leak_count: u64,
    /// Reentrance guard for `handle_obligation_leaks`.
    ///
    /// Prevents reentrant calls from inflating `leak_count` when
    /// `mark_obligation_leaked → advance_region_state → collect_obligation_leaks`
    /// discovers obligations already being processed by the outer caller.
    handling_leaks: bool,
    /// Count of regions currently in `Finalizing` state.
    ///
    /// Incremented when `begin_finalize()` succeeds, decremented when
    /// `complete_close()` succeeds.  Allows `drain_ready_async_finalizers`
    /// to skip a full region-arena scan on every poll (the common case has
    /// zero finalizing regions).
    finalizing_region_count: usize,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("regions", &self.regions)
            .field("tasks", &self.tasks)
            .field("obligations", &self.obligations)
            .field("now", &self.now)
            .field("root_region", &self.root_region)
            .field("trace", &self.trace)
            .field("metrics", &"<dyn MetricsProvider>")
            .field("io_driver", &self.io_driver)
            .field("timer_driver", &self.timer_driver)
            .field("logical_clock_mode", &self.logical_clock_mode)
            .field("cancel_attribution", &self.cancel_attribution)
            .field("entropy_source", &"<dyn EntropySource>")
            .field("observability", &self.observability.is_some())
            .field("blocking_pool", &self.blocking_pool.is_some())
            .field("obligation_leak_response", &self.obligation_leak_response)
            .field("leak_escalation", &self.leak_escalation)
            .field("leak_count", &self.leak_count)
            .field("handling_leaks", &self.handling_leaks)
            .field("finalizing_region_count", &self.finalizing_region_count)
            .finish()
    }
}

impl RuntimeState {
    /// Creates a new empty runtime state without a reactor.
    ///
    /// This is equivalent to [`without_reactor()`](Self::without_reactor) and creates
    /// a runtime suitable for Lab mode or pure computation without I/O.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_metrics(Arc::new(NoOpMetrics))
    }

    /// Creates a new runtime state with an explicit metrics provider.
    #[must_use]
    pub fn new_with_metrics(metrics: Arc<dyn MetricsProvider>) -> Self {
        Self {
            regions: RegionTable::new(),
            tasks: TaskTable::new(),
            obligations: ObligationTable::new(),
            now: Time::ZERO,
            root_region: None,
            trace: TraceBufferHandle::new(4096),
            metrics,
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            observability: None,
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            leak_count: 0,
            handling_leaks: false,
            finalizing_region_count: 0,
        }
    }

    /// Creates a runtime state with a real reactor and metrics provider.
    ///
    /// The provided reactor will be wrapped in an [`IoDriver`] to handle
    /// waker dispatch. Use this constructor when you need real I/O support
    /// and want to preserve the runtime's metrics configuration.
    ///
    /// # Arguments
    ///
    /// * `reactor` - The platform-specific reactor (e.g., `EpollReactor` on Linux)
    /// * `metrics` - Metrics provider to attach to the runtime state
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::{RuntimeState, EpollReactor};
    /// use std::sync::Arc;
    ///
    /// let reactor = Arc::new(EpollReactor::new()?);
    /// let state = RuntimeState::with_reactor_and_metrics(reactor, Arc::new(NoOpMetrics));
    /// ```
    #[must_use]
    pub fn with_reactor_and_metrics(
        reactor: Arc<dyn Reactor>,
        metrics: Arc<dyn MetricsProvider>,
    ) -> Self {
        let mut state = Self::new_with_metrics(metrics);
        state.io_driver = Some(IoDriverHandle::new(reactor));
        state.timer_driver = Some(TimerDriverHandle::with_wall_clock());
        state.logical_clock_mode = LogicalClockMode::Hybrid;
        state
    }

    /// Creates a runtime state with a real reactor for production use.
    ///
    /// This uses a [`NoOpMetrics`] provider by default. Prefer
    /// [`with_reactor_and_metrics`](Self::with_reactor_and_metrics) if you
    /// need custom metrics.
    #[must_use]
    pub fn with_reactor(reactor: Arc<dyn Reactor>) -> Self {
        Self::with_reactor_and_metrics(reactor, Arc::new(NoOpMetrics))
    }

    /// Creates a runtime state without a reactor (Lab mode).
    ///
    /// Use this for deterministic testing or pure computation without I/O.
    /// This is equivalent to [`new()`](Self::new).
    #[must_use]
    pub fn without_reactor() -> Self {
        Self::new()
    }

    /// Returns a reference to the I/O driver handle, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    #[inline]
    #[must_use]
    pub fn io_driver(&self) -> Option<&IoDriverHandle> {
        self.io_driver.as_ref()
    }

    /// Returns a locked guard to the I/O driver, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    pub fn io_driver_mut(&self) -> Option<parking_lot::MutexGuard<'_, IoDriver>> {
        self.io_driver.as_ref().map(IoDriverHandle::lock)
    }

    /// Returns a cloned handle to the I/O driver, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    #[inline]
    #[must_use]
    pub fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.io_driver.clone()
    }

    /// Returns a reference to the timer driver handle, if present.
    ///
    /// Returns `None` if the runtime was created without a timer driver.
    #[inline]
    #[must_use]
    pub fn timer_driver(&self) -> Option<&TimerDriverHandle> {
        self.timer_driver.as_ref()
    }

    /// Returns a cloned handle to the timer driver, if present.
    ///
    /// Returns `None` if the runtime was created without a timer driver.
    #[inline]
    #[must_use]
    pub fn timer_driver_handle(&self) -> Option<TimerDriverHandle> {
        self.timer_driver.clone()
    }

    /// Returns a cloned handle to the blocking pool, if present.
    #[inline]
    #[must_use]
    pub fn blocking_pool_handle(&self) -> Option<BlockingPoolHandle> {
        self.blocking_pool.clone()
    }

    /// Sets the blocking pool handle for this runtime.
    pub fn set_blocking_pool(&mut self, handle: BlockingPoolHandle) {
        self.blocking_pool = Some(handle);
    }

    /// Sets the timer driver for this runtime.
    pub fn set_timer_driver(&mut self, driver: TimerDriverHandle) {
        self.timer_driver = Some(driver);
    }

    /// Returns the logical clock mode for new task contexts.
    #[must_use]
    pub fn logical_clock_mode(&self) -> &LogicalClockMode {
        &self.logical_clock_mode
    }

    /// Sets the logical clock mode for new task contexts.
    pub fn set_logical_clock_mode(&mut self, mode: LogicalClockMode) {
        self.logical_clock_mode = mode;
    }

    /// Returns the cancel attribution configuration for this runtime.
    #[must_use]
    pub fn cancel_attribution_config(&self) -> CancelAttributionConfig {
        self.cancel_attribution
    }

    /// Sets the cancel attribution configuration for this runtime.
    pub fn set_cancel_attribution_config(&mut self, config: CancelAttributionConfig) {
        self.cancel_attribution = config;
    }

    /// Returns the entropy source for this runtime.
    #[inline]
    #[must_use]
    pub fn entropy_source(&self) -> Arc<dyn EntropySource> {
        self.entropy_source.clone()
    }

    /// Sets the entropy source for this runtime.
    pub fn set_entropy_source(&mut self, source: Arc<dyn EntropySource>) {
        self.entropy_source = source;
    }

    /// Configures runtime observability for new tasks.
    pub fn set_observability_config(&mut self, config: ObservabilityConfig) {
        self.observability = Some(RuntimeObservability::new(config));
    }

    /// Clears runtime observability configuration.
    pub fn clear_observability_config(&mut self) {
        self.observability = None;
    }

    /// Sets the response policy when obligation leaks are detected.
    pub fn set_obligation_leak_response(&mut self, response: ObligationLeakResponse) {
        self.obligation_leak_response = response;
    }

    /// Sets the escalation policy for obligation leaks.
    pub fn set_leak_escalation(&mut self, escalation: Option<LeakEscalation>) {
        self.leak_escalation = escalation;
    }

    /// Returns the cumulative count of obligation leaks.
    #[must_use]
    pub fn leak_count(&self) -> u64 {
        self.leak_count
    }

    /// Returns a handle to the trace buffer.
    #[inline]
    #[must_use]
    pub fn trace_handle(&self) -> TraceBufferHandle {
        self.trace.clone()
    }

    /// Returns the metrics provider for this runtime.
    #[inline]
    #[must_use]
    pub fn metrics_provider(&self) -> Arc<dyn MetricsProvider> {
        self.metrics.clone()
    }

    /// Sets the metrics provider for this runtime.
    pub fn set_metrics_provider(&mut self, provider: Arc<dyn MetricsProvider>) {
        self.metrics = provider;
    }

    /// Returns a shared reference to a task record by ID.
    #[inline]
    #[must_use]
    pub fn task(&self, task_id: TaskId) -> Option<&TaskRecord> {
        self.tasks.task(task_id)
    }

    /// Returns a mutable reference to a task record by ID.
    #[inline]
    pub fn task_mut(&mut self, task_id: TaskId) -> Option<&mut TaskRecord> {
        self.tasks.task_mut(task_id)
    }

    /// Inserts a new task record into the arena.
    ///
    /// Returns the assigned arena index.
    #[inline]
    pub fn insert_task(&mut self, record: TaskRecord) -> ArenaIndex {
        self.tasks.insert_task(record)
    }

    /// Inserts a new task record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    #[inline]
    pub fn insert_task_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> TaskRecord,
    {
        self.tasks.insert_task_with(f)
    }

    /// Removes a task record from the arena.
    ///
    /// Returns the removed record if it existed.
    #[inline]
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        self.tasks.remove_task(task_id)
    }

    /// Returns an iterator over all task records.
    pub fn tasks_iter(&self) -> impl Iterator<Item = (ArenaIndex, &TaskRecord)> {
        self.tasks.tasks_arena().iter()
    }

    /// Returns `true` if the task arena is empty.
    #[must_use]
    pub fn tasks_is_empty(&self) -> bool {
        self.tasks.tasks_arena().is_empty()
    }

    /// Provides direct access to the tasks arena.
    ///
    /// Used by intrusive data structures (LocalQueue) that operate on the arena.
    #[inline]
    #[must_use]
    pub fn tasks_arena(&self) -> &Arena<TaskRecord> {
        self.tasks.tasks_arena()
    }

    /// Provides mutable access to the tasks arena.
    ///
    /// Used by intrusive data structures (LocalQueue) that operate on the arena.
    #[inline]
    pub fn tasks_arena_mut(&mut self) -> &mut Arena<TaskRecord> {
        self.tasks.tasks_arena_mut()
    }

    /// Returns a shared reference to a region record by ID.
    #[inline]
    #[must_use]
    pub fn region(&self, region_id: RegionId) -> Option<&RegionRecord> {
        self.regions.get(region_id.arena_index())
    }

    /// Returns a mutable reference to a region record by ID.
    #[inline]
    pub fn region_mut(&mut self, region_id: RegionId) -> Option<&mut RegionRecord> {
        self.regions.get_mut(region_id.arena_index())
    }

    /// Returns an iterator over all region records.
    pub fn regions_iter(&self) -> impl Iterator<Item = (ArenaIndex, &RegionRecord)> {
        self.regions.iter()
    }

    /// Returns the number of regions in the table.
    #[must_use]
    pub fn regions_len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` if there are no regions.
    #[must_use]
    pub fn regions_is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Returns a shared reference to an obligation record by ID.
    #[must_use]
    pub fn obligation(&self, obligation_id: ObligationId) -> Option<&ObligationRecord> {
        self.obligations.get(obligation_id.arena_index())
    }

    /// Returns a mutable reference to an obligation record by ID.
    #[inline]
    pub fn obligation_mut(&mut self, obligation_id: ObligationId) -> Option<&mut ObligationRecord> {
        self.obligations.get_mut(obligation_id.arena_index())
    }

    /// Returns an iterator over all obligation records.
    pub fn obligations_iter(&self) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations.iter()
    }

    /// Returns the number of obligations in the table.
    #[must_use]
    pub fn obligations_len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns `true` if there are no obligations.
    #[must_use]
    pub fn obligations_is_empty(&self) -> bool {
        self.obligations.is_empty()
    }

    /// Returns `true` if this runtime has an I/O driver.
    #[inline]
    #[must_use]
    pub fn has_io_driver(&self) -> bool {
        self.io_driver.is_some()
    }

    /// Takes a point-in-time snapshot of the runtime state for debugging or visualization.
    ///
    /// The snapshot captures a consistent view of regions, tasks, obligations, and
    /// recent trace events. It is designed to be lightweight and serializable.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let mut obligations_by_task: HashMap<TaskId, Vec<ObligationId>> =
            HashMap::with_capacity(self.obligations_len());
        let obligations: Vec<ObligationSnapshot> = self
            .obligations_iter()
            .map(|(_, record)| {
                obligations_by_task
                    .entry(record.holder)
                    .or_default()
                    .push(record.id);
                ObligationSnapshot::from_record(record)
            })
            .collect();

        let regions: Vec<RegionSnapshot> = self
            .regions_iter()
            .map(|(_, record)| RegionSnapshot::from_record(record))
            .collect();

        let tasks: Vec<TaskSnapshot> = self
            .tasks_iter()
            .map(|(_, record)| {
                let task_obligations = obligations_by_task
                    .get(&record.id)
                    .cloned()
                    .unwrap_or_default();
                TaskSnapshot::from_record(record, task_obligations)
            })
            .collect();

        let recent_events: Vec<EventSnapshot> = self
            .trace
            .snapshot()
            .iter()
            .map(EventSnapshot::from_event)
            .collect();

        RuntimeSnapshot {
            timestamp: self.now.as_nanos(),
            regions,
            tasks,
            obligations,
            recent_events,
        }
    }

    /// Creates a root region and returns its ID.
    pub fn create_root_region(&mut self, budget: Budget) -> RegionId {
        let id = self.regions.create_root(budget, self.now);

        self.root_region = Some(id);
        let seq = self.next_trace_seq();
        self.trace
            .push_event(TraceEvent::region_created(seq, self.now, id, None));
        self.metrics.region_created(id, None);
        id
    }

    /// Creates a child region under the given parent and returns its ID.
    ///
    /// The child's effective budget is the meet (tightest constraints) of the
    /// parent budget and the provided budget.
    pub fn create_child_region(
        &mut self,
        parent: RegionId,
        budget: Budget,
    ) -> Result<RegionId, RegionCreateError> {
        let id = self.regions.create_child(parent, budget, self.now)?;

        let seq = self.next_trace_seq();
        self.trace
            .push_event(TraceEvent::region_created(seq, self.now, id, Some(parent)));
        self.metrics.region_created(id, Some(parent));
        Ok(id)
    }

    /// Updates admission limits for a region.
    ///
    /// Returns `false` if the region does not exist.
    pub fn set_region_limits(&mut self, region: RegionId, limits: RegionLimits) -> bool {
        self.regions.set_limits(region, limits)
    }

    /// Returns the current admission limits for a region.
    #[must_use]
    pub fn region_limits(&self, region: RegionId) -> Option<RegionLimits> {
        self.regions.limits(region)
    }

    /// Creates the infrastructure for a task (record, context, channel) without storing the future.
    ///
    /// This helper allows `create_task` and `spawn_local` to share the same setup logic
    /// while storing the future in different places (global vs thread-local).
    #[allow(clippy::type_complexity)]
    pub(crate) fn create_task_infrastructure<T>(
        &mut self,
        region: RegionId,
        budget: Budget,
    ) -> Result<
        (
            TaskId,
            crate::runtime::TaskHandle<T>,
            crate::cx::Cx,
            crate::channel::oneshot::Sender<Result<T, crate::runtime::task_handle::JoinError>>,
        ),
        SpawnError,
    >
    where
        T: Send + 'static,
    {
        use crate::channel::oneshot;

        // Create oneshot channel for the result
        let (result_tx, result_rx) =
            oneshot::channel::<Result<T, crate::runtime::task_handle::JoinError>>();

        // Create the TaskRecord
        let now = self.now;
        let idx = self.tasks.insert_task_with(|idx| {
            TaskRecord::new_with_time(TaskId::from_arena(idx), region, budget, now)
        });
        let task_id = TaskId::from_arena(idx);

        // Add task to the region's task list
        if let Some(region_record) = self.regions.get(region.arena_index()) {
            if let Err(err) = region_record.add_task(task_id) {
                // Rollback task creation
                let _ = self.remove_task(task_id);
                return Err(match err {
                    AdmissionError::Closed => SpawnError::RegionClosed(region),
                    AdmissionError::LimitReached { limit, live, .. } => {
                        SpawnError::RegionAtCapacity {
                            region,
                            limit,
                            live,
                        }
                    }
                });
            }
        } else {
            // Rollback task creation
            let _ = self.remove_task(task_id);
            return Err(SpawnError::RegionNotFound(region));
        }

        // Create the task's capability context
        let entropy = self.entropy_source.fork(task_id);
        let observability = self
            .observability
            .as_ref()
            .map(|obs| obs.for_task(region, task_id));
        let logical_clock = self
            .logical_clock_mode
            .build_handle(self.timer_driver_handle());
        let cx = crate::cx::Cx::new_with_drivers(
            region,
            task_id,
            budget,
            observability,
            self.io_driver_handle(),
            None,
            self.timer_driver_handle(),
            Some(entropy),
        )
        .with_blocking_pool_handle(self.blocking_pool_handle())
        .with_logical_clock(logical_clock);
        cx.set_trace_buffer(self.trace_handle());
        let cx_weak = std::sync::Arc::downgrade(&cx.inner);

        // Link the shared state to the TaskRecord
        if let Some(record) = self.task_mut(task_id) {
            record.set_cx_inner(cx.inner.clone());
            record.set_cx(cx.clone());
        }

        self.record_task_spawn(task_id, region);

        // Trace task creation
        debug!(
            task_id = ?task_id,
            region_id = ?region,
            initial_state = "Created",
            poll_quota = budget.poll_quota,
            "task created via RuntimeState"
        );

        // Create the TaskHandle
        let handle = crate::runtime::TaskHandle::new(task_id, result_rx, cx_weak);

        Ok((task_id, handle, cx, result_tx))
    }

    /// Creates a task and stores its future for polling.
    ///
    /// This is the core spawn primitive. It:
    /// 1. Creates a TaskRecord in the specified region
    /// 2. Wraps the future to send its result through a oneshot channel
    /// 3. Stores the wrapped future for the executor to poll
    /// 4. Returns a TaskHandle for awaiting the result
    ///
    /// # Arguments
    /// * `region` - The region that will own this task
    /// * `budget` - The budget for this task
    /// * `future` - The future to execute
    ///
    /// # Returns
    /// A Result containing `(TaskId, TaskHandle)` on success, or `SpawnError` on failure.
    ///
    /// # Example
    /// ```ignore
    /// let (task_id, handle) = state.create_task(region, budget, async { 42 })?;
    /// // Later: scheduler.schedule(task_id);
    /// // Even later: let result = handle.join(cx)?;
    /// ```
    pub fn create_task<F, T>(
        &mut self,
        region: RegionId,
        budget: Budget,
        future: F,
    ) -> Result<(TaskId, crate::runtime::TaskHandle<T>), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use crate::runtime::task_handle::JoinError;

        let (task_id, handle, cx, result_tx) = self.create_task_infrastructure(region, budget)?;

        // Wrap the future to send the result through the channel
        let wrapped_future = async move {
            let result = future.await;
            // Send the result - ignore error if TaskHandle was dropped
            let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
            crate::types::Outcome::Ok(())
        };

        // Store the wrapped future with task_id for poll tracing
        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        Ok((task_id, handle))
    }

    fn attach_logical_time_for_task(&self, task_id: TaskId, event: TraceEvent) -> TraceEvent {
        let Some(record) = self.task(task_id) else {
            return event;
        };
        let Some(cx) = record.cx.as_ref() else {
            return event;
        };
        event.with_logical_time(cx.logical_tick())
    }

    pub(crate) fn record_task_spawn(&self, task_id: TaskId, region: RegionId) {
        let seq = self.next_trace_seq();
        let event = TraceEvent::spawn(seq, self.now, task_id, region);
        self.trace
            .push_event(self.attach_logical_time_for_task(task_id, event));
        self.metrics.task_spawned(region, task_id);
    }

    fn record_task_complete(&self, task: &TaskRecord) {
        let seq = self.next_trace_seq();
        let event = TraceEvent::complete(seq, self.now, task.id, task.owner);
        self.trace
            .push_event(self.attach_logical_time_for_task(task.id, event));

        let duration = Duration::from_nanos(self.now.duration_since(task.created_at()));
        let outcome_kind = match &task.state {
            TaskState::Completed(outcome) => OutcomeKind::from(outcome),
            _ => OutcomeKind::Err,
        };
        self.metrics.task_completed(task.id, outcome_kind, duration);
    }

    fn capture_obligation_backtrace() -> Option<Arc<Backtrace>> {
        if cfg!(debug_assertions) {
            Some(Arc::new(Backtrace::capture()))
        } else {
            None
        }
    }

    fn collect_obligation_leaks<F>(&self, mut predicate: F) -> Vec<LeakedObligationInfo>
    where
        F: FnMut(&ObligationRecord) -> bool,
    {
        self.obligations
            .iter()
            .filter_map(|(_, record)| {
                if !record.is_pending() || !predicate(record) {
                    return None;
                }

                let held_duration_ns = self.now.duration_since(record.reserved_at);
                Some(LeakedObligationInfo {
                    id: record.id,
                    kind: record.kind,
                    holder: record.holder,
                    region: record.region,
                    acquired_at: record.acquired_at,
                    held_duration_ns,
                    description: record.description.clone(),
                    acquire_backtrace: record.acquire_backtrace.clone(),
                })
            })
            .collect()
    }

    /// Collect obligation leaks for a specific task holder using the secondary index.
    fn collect_obligation_leaks_for_holder(&self, task_id: TaskId) -> Vec<LeakedObligationInfo> {
        self.obligations
            .ids_for_holder(task_id)
            .iter()
            .filter_map(|id| {
                let record = self.obligations.get(id.arena_index())?;
                if !record.is_pending() {
                    return None;
                }
                let held_duration_ns = self.now.duration_since(record.reserved_at);
                Some(LeakedObligationInfo {
                    id: record.id,
                    kind: record.kind,
                    holder: record.holder,
                    region: record.region,
                    acquired_at: record.acquired_at,
                    held_duration_ns,
                    description: record.description.clone(),
                    acquire_backtrace: record.acquire_backtrace.clone(),
                })
            })
            .collect()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn handle_obligation_leaks(&mut self, error: ObligationLeakError) {
        if error.leaks.is_empty() || self.handling_leaks {
            return;
        }

        self.handling_leaks = true;

        // Track cumulative leaks for escalation.
        self.leak_count = self.leak_count.saturating_add(error.leaks.len() as u64);

        // Determine the effective response: check escalation threshold first.
        let mut response = if let Some(ref esc) = self.leak_escalation {
            if self.leak_count >= esc.threshold {
                esc.escalate_to
            } else {
                self.obligation_leak_response
            }
        } else {
            self.obligation_leak_response
        };

        // PREVENT DOUBLE PANIC: If we are already panicking, we must not panic again.
        if matches!(response, ObligationLeakResponse::Panic) && std::thread::panicking() {
            crate::tracing_compat::error!(
                task_id = ?error.task_id,
                "obligation leaks detected during panic; downgrading Panic policy to Log to prevent double-panic abort"
            );
            response = ObligationLeakResponse::Log;
        }

        let leak_ids: Vec<ObligationId> = error.leaks.iter().map(|leak| leak.id).collect();
        match response {
            ObligationLeakResponse::Panic => {
                // Mark leaked first so trace/metrics capture the event before panicking.
                for id in leak_ids {
                    let _ = self.mark_obligation_leaked(id);
                }
                let msg = error.to_string();
                // This is a runtime invariant violation. We fail-fast to surface the bug, but we
                // avoid the `panic!` macro so UBS doesn't treat this as a library panic surface.
                crate::tracing_compat::error!(
                    task_id = ?error.task_id,
                    region_id = ?error.region_id,
                    completion = %error
                        .completion
                        .map_or("unknown", TaskCompletionKind::as_str),
                    leak_count = error.leaks.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks detected (fail-fast)"
                );
                std::panic::panic_any(msg);
            }
            ObligationLeakResponse::Log => {
                for id in leak_ids {
                    let _ = self.mark_obligation_leaked(id);
                }
                crate::tracing_compat::error!(
                    task_id = ?error.task_id,
                    region_id = ?error.region_id,
                    completion = %error
                        .completion
                        .map_or("unknown", TaskCompletionKind::as_str),
                    leak_count = error.leaks.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks detected"
                );
            }
            ObligationLeakResponse::Silent => {
                for id in leak_ids {
                    let _ = self.mark_obligation_leaked(id);
                }
            }
            ObligationLeakResponse::Recover => {
                for id in leak_ids {
                    // Abort instead of marking leaked — performs resource cleanup.
                    let _ = self.abort_obligation(id, ObligationAbortReason::Error);
                }
                crate::tracing_compat::warn!(
                    task_id = ?error.task_id,
                    region_id = ?error.region_id,
                    completion = %error
                        .completion
                        .map_or("unknown", TaskCompletionKind::as_str),
                    leak_count = error.leaks.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks recovered via auto-abort"
                );
            }
        }

        self.handling_leaks = false;
    }

    /// Creates and registers an obligation for the given task and region.
    ///
    /// This records the obligation in the registry and emits a trace event.
    /// Returns an error if the region is closed or admission limits are reached.
    #[allow(clippy::result_large_err)]
    #[track_caller]
    pub fn create_obligation(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        description: Option<String>,
    ) -> Result<ObligationId, Error> {
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return Err(Error::new(ErrorKind::RegionClosed).with_message("region not found"));
        };

        if let Err(err) = region_record.try_reserve_obligation() {
            return Err(match err {
                AdmissionError::Closed => {
                    Error::new(ErrorKind::RegionClosed).with_message("region closed")
                }
                AdmissionError::LimitReached { limit, live, .. } => {
                    Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                        "region {region:?} obligation limit {limit} reached (live {live})"
                    ))
                }
            });
        }

        let acquired_at = SourceLocation::from_panic_location(std::panic::Location::caller());
        let acquire_backtrace = Self::capture_obligation_backtrace();
        let obligation_id =
            self.obligations
                .create(super::obligation_table::ObligationCreateArgs {
                    kind,
                    holder,
                    region,
                    now: self.now,
                    description,
                    acquired_at,
                    acquire_backtrace,
                });

        let _guard = crate::tracing_compat::debug_span!(
            "obligation_reserve",
            obligation_id = ?obligation_id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region
        )
        .entered();
        crate::tracing_compat::debug!(
            obligation_id = ?obligation_id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            "obligation reserved"
        );

        let seq = self.next_trace_seq();
        let event =
            TraceEvent::obligation_reserve(seq, self.now, obligation_id, holder, region, kind);
        self.trace
            .push_event(self.attach_logical_time_for_task(holder, event));
        self.metrics.obligation_created(region);

        Ok(obligation_id)
    }

    /// Marks an obligation as committed and emits a trace event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    #[allow(clippy::result_large_err)]
    pub fn commit_obligation(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        let info = self.obligations.commit(obligation, self.now)?;

        let span = crate::tracing_compat::debug_span!(
            "obligation_commit",
            obligation_id = ?info.id,
            kind = ?info.kind,
            holder_task = ?info.holder,
            region_id = ?info.region,
            duration_ns = info.duration
        );
        let _span_guard = span.enter();
        crate::tracing_compat::debug!(
            obligation_id = ?info.id,
            kind = ?info.kind,
            holder_task = ?info.holder,
            region_id = ?info.region,
            duration_ns = info.duration,
            "obligation committed"
        );

        let seq = self.next_trace_seq();
        let event = TraceEvent::obligation_commit(
            seq,
            self.now,
            info.id,
            info.holder,
            info.region,
            info.kind,
            info.duration,
        );
        self.trace
            .push_event(self.attach_logical_time_for_task(info.holder, event));
        self.metrics.obligation_discharged(info.region);

        if let Some(region_record) = self.regions.get(info.region.arena_index()) {
            region_record.resolve_obligation();
        }

        self.advance_region_state(info.region);

        Ok(info.duration)
    }

    /// Marks an obligation as aborted and emits a trace event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    #[allow(clippy::result_large_err)]
    pub fn abort_obligation(
        &mut self,
        obligation: ObligationId,
        reason: ObligationAbortReason,
    ) -> Result<u64, Error> {
        let info = self.obligations.abort(obligation, self.now, reason)?;

        let span = crate::tracing_compat::debug_span!(
            "obligation_abort",
            obligation_id = ?info.id,
            kind = ?info.kind,
            holder_task = ?info.holder,
            region_id = ?info.region,
            duration_ns = info.duration,
            abort_reason = %info.reason
        );
        let _span_guard = span.enter();
        crate::tracing_compat::debug!(
            obligation_id = ?info.id,
            kind = ?info.kind,
            holder_task = ?info.holder,
            region_id = ?info.region,
            duration_ns = info.duration,
            abort_reason = %info.reason,
            "obligation aborted"
        );

        let seq = self.next_trace_seq();
        let event = TraceEvent::obligation_abort(
            seq,
            self.now,
            info.id,
            info.holder,
            info.region,
            info.kind,
            info.duration,
            info.reason,
        );
        self.trace
            .push_event(self.attach_logical_time_for_task(info.holder, event));
        self.metrics.obligation_discharged(info.region);

        if let Some(region_record) = self.regions.get(info.region.arena_index()) {
            region_record.resolve_obligation();
        }

        self.advance_region_state(info.region);

        Ok(info.duration)
    }

    /// Marks an obligation as leaked and emits a trace + error event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    #[allow(clippy::result_large_err)]
    pub fn mark_obligation_leaked(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        let info = self.obligations.mark_leaked(obligation, self.now)?;

        let seq = self.next_trace_seq();
        let event = TraceEvent::obligation_leak(
            seq,
            self.now,
            info.id,
            info.holder,
            info.region,
            info.kind,
            info.duration,
        );
        self.trace
            .push_event(self.attach_logical_time_for_task(info.holder, event));
        self.metrics.obligation_leaked(info.region);
        if self.obligation_leak_response != ObligationLeakResponse::Silent {
            let span = crate::tracing_compat::error_span!(
                "obligation_leak",
                obligation_id = ?info.id,
                kind = ?info.kind,
                holder_task = ?info.holder,
                region_id = ?info.region,
                duration_ns = info.duration,
                acquired_at = %info.acquired_at
            );
            let _span_guard = span.enter();
            #[allow(clippy::single_match, unused_variables)]
            match info.acquire_backtrace.as_ref() {
                Some(backtrace) => {
                    crate::tracing_compat::error!(
                        obligation_id = ?info.id,
                        kind = ?info.kind,
                        holder_task = ?info.holder,
                        region_id = ?info.region,
                        duration_ns = info.duration,
                        acquired_at = %info.acquired_at,
                        acquire_backtrace = ?backtrace,
                        "obligation leaked"
                    );
                }
                None => {
                    crate::tracing_compat::error!(
                        obligation_id = ?info.id,
                        kind = ?info.kind,
                        holder_task = ?info.holder,
                        region_id = ?info.region,
                        duration_ns = info.duration,
                        acquired_at = %info.acquired_at,
                        "obligation leaked"
                    );
                }
            }
        }

        if let Some(region_record) = self.regions.get(info.region.arena_index()) {
            region_record.resolve_obligation();
        }

        self.advance_region_state(info.region);

        Ok(info.duration)
    }

    /// Gets a mutable reference to a stored future for polling.
    ///
    /// Returns `None` if no future is stored for this task.
    #[inline]
    pub fn get_stored_future(&mut self, task_id: TaskId) -> Option<&mut StoredTask> {
        self.tasks.get_stored_future(task_id)
    }

    /// Removes and returns a stored future.
    ///
    /// Called when a task completes to clean up the future storage.
    #[inline]
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        self.tasks.remove_stored_future(task_id)
    }

    /// Stores a spawned task's future for execution.
    ///
    /// This is called after `Scope::spawn` to register the `StoredTask` with
    /// the runtime. The task must already have a `TaskRecord` created via spawn.
    ///
    /// # Arguments
    /// * `task_id` - The ID of the task (from the TaskHandle)
    /// * `stored` - The StoredTask containing the wrapped future
    ///
    /// # Example
    /// ```ignore
    /// let (handle, stored) = scope.spawn(&mut state, &cx, |_| async { 42 })?;
    /// state.store_spawned_task(handle.task_id(), stored);
    /// // Now the executor can poll the task
    /// ```
    #[inline]
    pub fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        self.tasks.store_spawned_task(task_id, stored);
    }

    /// Returns the next trace sequence number and increments it.
    #[must_use]
    pub fn next_trace_seq(&self) -> u64 {
        self.trace.next_seq()
    }

    /// Counts live tasks.
    #[must_use]
    pub fn live_task_count(&self) -> usize {
        self.tasks_iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    /// Counts live regions.
    #[must_use]
    pub fn live_region_count(&self) -> usize {
        self.regions_iter()
            .filter(|(_, r)| !r.state().is_terminal())
            .count()
    }

    /// Counts pending obligations.
    #[must_use]
    pub fn pending_obligation_count(&self) -> usize {
        self.obligations_iter()
            .filter(|(_, o)| o.is_pending())
            .count()
    }

    /// Returns true if the runtime is quiescent (no live work).
    ///
    /// A runtime is quiescent when:
    /// - No live tasks are running
    /// - No pending obligations exist
    /// - No I/O sources are registered (if I/O driver is present)
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let no_tasks = self.live_task_count() == 0;
        let no_obligations = self.pending_obligation_count() == 0;
        let no_io = self.io_driver.as_ref().is_none_or(IoDriverHandle::is_empty);
        let no_finalizers = self.regions.iter().all(|(_, r)| r.finalizers_empty());
        no_tasks && no_obligations && no_io && no_finalizers
    }

    /// Applies the region policy when a child reaches a terminal outcome.
    ///
    /// This is the core hook for fail-fast behavior: the policy decides whether
    /// siblings should be cancelled.
    ///
    /// Returns the policy action taken and a list of tasks that need to be
    /// moved to the cancel lane in the scheduler.
    pub fn apply_policy_on_child_outcome<P: Policy<Error = crate::error::Error>>(
        &mut self,
        region: RegionId,
        child: TaskId,
        outcome: &Outcome<(), crate::error::Error>,
        policy: &P,
    ) -> (PolicyAction, SmallVec<[(TaskId, u8); 4]>) {
        let action = policy.on_child_outcome(child, outcome);
        let tasks_to_schedule = if let PolicyAction::CancelSiblings(reason) = &action {
            self.cancel_sibling_tasks(region, child, reason)
        } else {
            SmallVec::new()
        };
        (action, tasks_to_schedule)
    }

    fn cancel_sibling_tasks(
        &mut self,
        region: RegionId,
        child: TaskId,
        reason: &CancelReason,
    ) -> SmallVec<[(TaskId, u8); 4]> {
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return SmallVec::new();
        };
        let sibling_candidates = region_record.task_ids_small();
        let mut tasks_to_cancel =
            SmallVec::with_capacity(sibling_candidates.len().saturating_sub(1));

        for &task_id in &sibling_candidates {
            if task_id == child {
                continue;
            }
            let budget = reason.cleanup_budget();
            let (newly_cancelled, is_cancelling) = {
                let Some(task_record) = self.task_mut(task_id) else {
                    continue;
                };
                let newly_cancelled =
                    task_record.request_cancel_with_budget(reason.clone(), budget);
                let is_cancelling = task_record.state.is_cancelling();
                (newly_cancelled, is_cancelling)
            };
            if newly_cancelled {
                let seq = self.trace.next_seq();
                let event =
                    TraceEvent::cancel_request(seq, self.now, task_id, region, reason.clone());
                self.trace
                    .push_event(self.attach_logical_time_for_task(task_id, event));
            }
            if newly_cancelled || is_cancelling {
                tasks_to_cancel.push((task_id, budget.priority));
            }
        }
        tasks_to_cancel
    }

    /// Requests cancellation for a region and all its descendants.
    ///
    /// This implements the CANCEL-REQUEST transition from the formal semantics.
    /// Cancellation propagates down the region tree:
    /// - The target region's cancel_reason is set/strengthened
    /// - All descendant regions are marked with `ParentCancelled`
    /// - All tasks in affected regions are moved to `CancelRequested` state
    ///
    /// Returns a list of (TaskId, priority) pairs for tasks that should be
    /// moved to the cancel lane. The caller is responsible for updating the
    /// scheduler.
    ///
    /// # Arguments
    /// * `region_id` - The region to cancel
    /// * `reason` - The reason for cancellation
    /// * `source_task` - The task that initiated cancellation, if known
    ///
    /// # Example
    /// ```ignore
    /// let tasks_to_schedule = state.cancel_request(region, &CancelReason::timeout(), None);
    /// for (task_id, priority) in tasks_to_schedule {
    ///     scheduler.move_to_cancel_lane(task_id, priority);
    /// }
    /// ```
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::used_underscore_binding)]
    pub fn cancel_request(
        &mut self,
        region_id: RegionId,
        reason: &CancelReason,
        _source_task: Option<TaskId>,
    ) -> Vec<(TaskId, u8)> {
        let mut tasks_to_cancel = Vec::with_capacity(self.live_task_count());
        let _cleanup_budget = reason.cleanup_budget();
        let root_span = debug_span!(
            "cancel_request",
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = _cleanup_budget.poll_quota,
            cleanup_priority = _cleanup_budget.priority,
            source_task = ?_source_task
        );
        let _root_guard = root_span.enter();

        debug!(
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = _cleanup_budget.poll_quota,
            cleanup_priority = _cleanup_budget.priority,
            source_task = ?_source_task,
            "cancel request initiated"
        );

        // Collect all regions to cancel (target + descendants) with depth information
        let mut regions_to_cancel = self.collect_region_and_descendants_with_depth(region_id);

        // Sort by depth (ascending) to ensure parents are processed before children.
        // This is required for building proper cause chains.
        regions_to_cancel.sort_by_key(|node| node.depth);

        // Build a map of region -> cancel reason for cause chain construction.
        // Each child region's reason chains to its parent's reason.
        let mut region_reasons: HashMap<RegionId, CancelReason> =
            HashMap::with_capacity(regions_to_cancel.len());

        // First pass: mark regions with cancellation reason and transition to Closing
        for node in &regions_to_cancel {
            let rid = node.id;

            // Build the cancel reason with proper cause chain:
            // - Root region gets the original reason
            // - Descendants get ParentCancelled chained to their parent's reason
            let region_reason = if rid == region_id {
                reason.clone()
            } else if let Some(parent_id) = node.parent {
                // Look up parent's reason from the map (guaranteed to exist since we process by depth)
                let parent_reason = region_reasons
                    .get(&parent_id)
                    .cloned()
                    .unwrap_or_else(|| reason.clone());

                CancelReason::parent_cancelled()
                    .with_region(parent_id)
                    .with_timestamp(reason.timestamp)
                    .with_cause_limited(parent_reason, &self.cancel_attribution)
            } else {
                // Fallback: no parent but not root (shouldn't happen)
                CancelReason::parent_cancelled()
                    .with_timestamp(reason.timestamp)
                    .with_cause_limited(reason.clone(), &self.cancel_attribution)
            };

            // Store this region's reason for child chain building
            region_reasons.insert(rid, region_reason.clone());

            let seq = self.next_trace_seq();
            self.trace.push_event(TraceEvent::region_cancelled(
                seq,
                self.now,
                rid,
                region_reason.clone(),
            ));
            self.metrics.cancellation_requested(rid, region_reason.kind);

            if let Some(_parent) = node.parent {
                let span = trace_span!(
                    "cancel_propagate_region",
                    from_region = ?_parent,
                    to_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    chain_depth = region_reason.chain_depth()
                );
                span.follows_from(&root_span);
                let _guard = span.enter();
                trace!(
                    from_region = ?_parent,
                    to_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    chain_depth = region_reason.chain_depth(),
                    root_cause = ?region_reason.root_cause().kind,
                    "cancel propagated to region with cause chain"
                );
            } else {
                trace!(
                    target_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    "cancel target region"
                );
            }

            if let Some(region) = self.regions.get(rid.arena_index()) {
                // Use the properly chained reason.
                // Try to transition to Closing with the reason.
                // If already Closing/Draining/etc., strengthen the reason instead.
                if region.begin_close(Some(region_reason.clone())) {
                    let seq = self.next_trace_seq();
                    self.trace.push_event(TraceEvent::new(
                        seq,
                        self.now,
                        TraceEventKind::RegionCloseBegin,
                        TraceData::Region {
                            region: rid,
                            parent: node.parent,
                        },
                    ));
                } else {
                    region.strengthen_cancel_reason(region_reason);
                }
            }
        }

        // Second pass: mark tasks for cancellation.
        // Reuse a single buffer across iterations to avoid per-region allocation.
        let mut task_id_buf = Vec::new();
        for node in &regions_to_cancel {
            let rid = node.id;
            // Need to get tasks list first to avoid borrow conflict
            task_id_buf.clear();
            if let Some(region) = self.regions.get(rid.arena_index()) {
                region.copy_task_ids_into(&mut task_id_buf);
            }

            // Get the region's cancel reason with proper cause chain
            let task_reason = region_reasons
                .get(&rid)
                .cloned()
                .unwrap_or_else(|| reason.clone());

            for &task_id in &task_id_buf {
                if let Some(task) = self.task_mut(task_id) {
                    let task_budget = task_reason.cleanup_budget();
                    let newly_cancelled =
                        task.request_cancel_with_budget(task_reason.clone(), task_budget);
                    let already_cancelling = task.state.is_cancelling();
                    let _cancel_kind = task.cancel_reason().map(|r| r.kind);
                    if newly_cancelled {
                        let seq = self.trace.next_seq();
                        let event = TraceEvent::cancel_request(
                            seq,
                            self.now,
                            task_id,
                            rid,
                            task_reason.clone(),
                        );
                        self.trace
                            .push_event(self.attach_logical_time_for_task(task_id, event));
                    }
                    let span = trace_span!(
                        "cancel_propagate_task",
                        from_region = ?rid,
                        to_task = ?task_id,
                        depth = node.depth,
                        cancel_kind = ?_cancel_kind,
                        chain_depth = task_reason.chain_depth()
                    );
                    span.follows_from(&root_span);
                    let _guard = span.enter();
                    trace!(
                        from_region = ?rid,
                        to_task = ?task_id,
                        depth = node.depth,
                        newly_cancelled,
                        already_cancelling,
                        cleanup_poll_quota = task_budget.poll_quota,
                        cleanup_priority = task_budget.priority,
                        chain_depth = task_reason.chain_depth(),
                        root_cause = ?task_reason.root_cause().kind,
                        "cancel propagated to task with cause chain"
                    );

                    if newly_cancelled {
                        // Task was newly cancelled, add to list
                        tasks_to_cancel.push((task_id, task_budget.priority));
                    } else if already_cancelling {
                        // Task already cancelling, but still needs scheduling priority
                        tasks_to_cancel.push((task_id, task_budget.priority));
                    }
                }
            }
        }

        // Ensure regions with pending finalizers and no live work can advance into
        // Finalizing immediately so finalizers are scheduled without waiting for
        // task completion.
        for node in &regions_to_cancel {
            let Some(region) = self.regions.get(node.id.arena_index()) else {
                continue;
            };
            let no_children = region.child_count() == 0;
            let no_tasks = region.task_count() == 0;
            let has_finalizers = !region.finalizers_empty();
            if no_children && no_tasks && has_finalizers {
                self.advance_region_state(node.id);
            }
        }

        tasks_to_cancel
    }

    /// Collects a region and all its descendants (recursive).
    ///
    /// Returns a Vec containing the region and all nested child regions.
    fn collect_region_and_descendants_with_depth(
        &self,
        region_id: RegionId,
    ) -> Vec<CancelRegionNode> {
        let mut result = Vec::new();
        let mut stack = Vec::new();
        let mut child_buf = Vec::new();
        stack.push((region_id, None, 0usize));

        while let Some((rid, parent, depth)) = stack.pop() {
            result.push(CancelRegionNode {
                id: rid,
                parent,
                depth,
            });

            if let Some(region) = self.regions.get(rid.arena_index()) {
                child_buf.clear();
                region.copy_child_ids_into(&mut child_buf);
                for &child_id in &child_buf {
                    stack.push((child_id, Some(rid), depth + 1));
                }
            }
        }

        result
    }

    /// Checks if a region can transition to finalization.
    ///
    /// A region can finalize when all its tasks and child regions have completed.
    /// Returns `true` if the region has no live work remaining.
    #[must_use]
    pub fn can_region_finalize(&self, region_id: RegionId) -> bool {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Check all tasks are terminal
        let all_tasks_done = region
            .task_ids()
            .iter()
            .all(|&task_id| self.task(task_id).is_none_or(|t| t.state.is_terminal()));

        // Check all child regions are closed
        let all_children_closed = region.child_ids().iter().all(|&child_id| {
            self.regions
                .get(child_id.arena_index())
                .is_none_or(|r| r.state().is_terminal())
        });

        all_tasks_done && all_children_closed
    }

    /// Notifies that a task has completed.
    ///
    /// This checks if the owning region can advance its state.
    /// Returns the task's waiters that should be woken.
    #[allow(clippy::used_underscore_binding)]
    pub fn task_completed(&mut self, task_id: TaskId) -> SmallVec<[TaskId; 4]> {
        let (owner, completion, _outcome_kind) = {
            let Some(task) = self.task(task_id) else {
                trace!(
                    task_id = ?task_id,
                    "task_completed called for unknown task"
                );
                return SmallVec::new();
            };
            if let Some(inner) = task.cx_inner.as_ref() {
                // Read-first: skip the write lock when cancel_waker is already
                // None (the common case — waker was cached back into the record).
                if inner.read().cancel_waker.is_some() {
                    inner.write().cancel_waker = None;
                }
            }

            self.record_task_complete(task);

            let outcome_kind = match &task.state {
                crate::record::task::TaskState::Completed(outcome) => match outcome {
                    Outcome::Ok(()) => "Ok",
                    Outcome::Err(_) => "Err",
                    Outcome::Cancelled(_) => "Cancelled",
                    Outcome::Panicked(_) => "Panicked",
                },
                _ => "Unknown",
            };
            let owner = task.owner;
            let completion = TaskCompletionKind::from_state(&task.state);
            (owner, completion, outcome_kind)
        };
        // Take waiters by value (avoiding clone) since the task is about to be removed.
        let waiters = self
            .task_mut(task_id)
            .map(|task| std::mem::take(&mut task.waiters))
            .unwrap_or_default();
        let _waiter_count = waiters.len();

        if !matches!(completion, TaskCompletionKind::Cancelled) {
            let leaks = self.collect_obligation_leaks_for_holder(task_id);
            if !leaks.is_empty() {
                self.handle_obligation_leaks(ObligationLeakError {
                    task_id: Some(task_id),
                    region_id: owner,
                    completion: Some(completion),
                    leaks,
                });
            }
        }

        // Trace task completion
        debug!(
            task_id = ?task_id,
            region_id = ?owner,
            outcome_kind = _outcome_kind,
            waiter_count = _waiter_count,
            "task cleanup from runtime state"
        );

        // Abort any pending obligations held by this task to prevent
        // orphaned obligations from blocking region close (deadlock).
        // Uses the holder secondary index for O(obligations_per_task) instead of O(arena_capacity).
        let orphaned = self.obligations.sorted_pending_ids_for_holder(task_id);
        for ob_id in orphaned {
            let _ = self.abort_obligation(ob_id, ObligationAbortReason::Cancel);
        }

        // Remove the task record to prevent memory leaks
        let _ = self.remove_task(task_id);

        // Remove task from owning region to prevent memory leak
        if let Some(region) = self.regions.get(owner.arena_index()) {
            region.remove_task(task_id);
        }

        // Advance region state if possible (e.g. if this was the last task)
        self.advance_region_state(owner);

        // Return the waiters for the completed task
        waiters
    }

    // =========================================================================
    // Async Finalizer Scheduling
    // =========================================================================

    /// Drains async finalizers for regions that are ready to run them.
    ///
    /// This runs sync finalizers inline and schedules at most one async
    /// finalizer per region (respecting the async barrier).
    pub fn drain_ready_async_finalizers(&mut self) -> SmallVec<[(TaskId, u8); 2]> {
        if self.finalizing_region_count == 0 {
            return SmallVec::new();
        }
        let mut scheduled = SmallVec::new();
        let regions: SmallVec<[RegionId; 8]> = self
            .regions
            .iter()
            .filter(|(_, region)| {
                region.state() == RegionState::Finalizing && !region.finalizers_empty()
            })
            .map(|(idx, _)| RegionId::from_arena(idx))
            .collect();

        for region_id in regions {
            let Some(finalizer) = self.run_sync_finalizers(region_id) else {
                continue;
            };
            let Finalizer::Async(future) = finalizer else {
                continue;
            };
            if let Some((task_id, priority)) = self.spawn_finalizer_task(region_id, future) {
                scheduled.push((task_id, priority));
            }
        }

        scheduled
    }

    fn spawn_finalizer_task(
        &mut self,
        region_id: RegionId,
        future: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Option<(TaskId, u8)> {
        let deadline = self.now.saturating_add_nanos(FINALIZER_TIME_BUDGET_NANOS);
        let budget = finalizer_budget().with_deadline(deadline);

        let (task_id, _handle, cx, result_tx) = self
            .create_task_infrastructure::<()>(region_id, budget)
            .ok()?;
        let cx_inner = Arc::clone(&cx.inner);
        let masked = MaskedFinalizer::new(future, cx_inner);

        let wrapped_future = async move {
            masked.await;
            let _ = result_tx.send(&cx, Ok::<_, JoinError>(()));
            Outcome::Ok(())
        };

        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        // Mark the task as notified since it will be immediately injected into
        // the ready queue by the caller (drain_ready_async_finalizers).
        if let Some(record) = self.task(task_id) {
            record.wake_state.notify();
        }

        Some((task_id, budget.priority))
    }

    // =========================================================================
    // Finalizer Registration
    // =========================================================================

    /// Registers a synchronous finalizer for a region.
    ///
    /// Finalizers are stored in LIFO order and run when the region transitions
    /// to the Finalizing state, after all children have completed.
    ///
    /// # Arguments
    /// * `region_id` - The region to register the finalizer with
    /// * `f` - The synchronous cleanup function
    ///
    /// # Returns
    /// `true` if the finalizer was registered, `false` if the region doesn't exist
    /// or is not in a state that accepts finalizers.
    pub fn register_sync_finalizer<F>(&mut self, region_id: RegionId, f: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Reject registration once the region has begun closing or is terminal
        if region.state().is_closing() || region.state().is_terminal() {
            return false;
        }

        region.add_finalizer(Finalizer::Sync(Box::new(f)));
        true
    }

    /// Registers an asynchronous finalizer for a region.
    ///
    /// Async finalizers run under a cancel mask to prevent interruption.
    /// They are driven to completion with a bounded budget.
    ///
    /// # Arguments
    /// * `region_id` - The region to register the finalizer with
    /// * `future` - The async cleanup future
    ///
    /// # Returns
    /// `true` if the finalizer was registered, `false` if the region doesn't exist
    /// or is not in a state that accepts finalizers.
    pub fn register_async_finalizer<F>(&mut self, region_id: RegionId, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Reject registration once the region has begun closing or is terminal
        if region.state().is_closing() || region.state().is_terminal() {
            return false;
        }

        region.add_finalizer(Finalizer::Async(Box::pin(future)));
        true
    }

    /// Pops the next finalizer from a region's finalizer stack.
    ///
    /// This is called during the Finalizing phase to get the next cleanup
    /// handler to run. Finalizers are returned in LIFO order.
    ///
    /// # Returns
    /// The next finalizer to run, or `None` if all finalizers have been executed.
    pub fn pop_region_finalizer(&mut self, region_id: RegionId) -> Option<Finalizer> {
        let region = self.regions.get(region_id.arena_index())?;
        region.pop_finalizer()
    }

    /// Returns the number of pending finalizers for a region.
    #[must_use]
    pub fn region_finalizer_count(&self, region_id: RegionId) -> usize {
        self.regions
            .get(region_id.arena_index())
            .map_or(0, RegionRecord::finalizer_count)
    }

    /// Returns true if a region has no pending finalizers.
    #[must_use]
    pub fn region_finalizers_empty(&self, region_id: RegionId) -> bool {
        self.regions
            .get(region_id.arena_index())
            .is_none_or(RegionRecord::finalizers_empty)
    }

    /// Runs synchronous finalizers for a region until an async finalizer is encountered or the stack is empty.
    ///
    /// This method pops and executes sync finalizers in LIFO order.
    /// If an async finalizer is encountered, it is returned immediately (and not executed).
    /// The caller must schedule/await the async finalizer before calling this method again
    /// to process remaining finalizers.
    ///
    /// # Returns
    /// An async finalizer that needs to be scheduled, or `None` if the stack is empty.
    pub fn run_sync_finalizers(&mut self, region_id: RegionId) -> Option<Finalizer> {
        loop {
            let finalizer = self.pop_region_finalizer(region_id)?;

            match finalizer {
                Finalizer::Sync(f) => {
                    // Run synchronously
                    f();
                    // Trace event would be recorded here in full implementation
                }
                Finalizer::Async(_) => {
                    // Stop and return the async barrier
                    return Some(finalizer);
                }
            }
        }
    }

    /// Checks if a region can complete its close sequence.
    ///
    /// A region can complete close when:
    /// 1. It's in the Finalizing state
    /// 2. All finalizers have been executed
    /// 3. All tasks (including those spawned by finalizers) are terminal
    /// 4. All obligations are resolved
    ///
    /// # Returns
    /// `true` if the region can transition to Closed state.
    #[must_use]
    pub fn can_region_complete_close(&self, region_id: RegionId) -> bool {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        if region.state() == crate::record::region::RegionState::Closed {
            return true;
        }

        // Must be in Finalizing state
        if region.state() != crate::record::region::RegionState::Finalizing {
            return false;
        }

        // All finalizers must be done
        if !region.finalizers_empty() {
            return false;
        }

        // All tasks must be terminal (including any spawned by finalizers).
        // Use map_or(false, ...) instead of is_none_or: a task that was removed
        // from the arena but still appears in the region's task list (ghost task
        // during mid-cleanup in task_completed) must NOT be treated as terminal,
        // otherwise re-entrant advance_region_state calls can prematurely close
        // the region while task_completed is still processing obligations.
        let all_tasks_done = region
            .task_ids_small()
            .iter()
            .all(|&task_id| self.task(task_id).is_some_and(|t| t.state.is_terminal()));

        if !all_tasks_done {
            return false;
        }

        // All obligations must be resolved
        if region.pending_obligations() > 0 {
            return false;
        }

        true
    }

    /// Advances the region state machine if possible.
    ///
    /// This method checks if the region can transition to the next state in its
    /// lifecycle (Closing -> Draining -> Finalizing -> Closed). It drives the
    /// transitions automatically when prerequisites (no children, no tasks, etc.)
    /// are met.
    ///
    /// This should be called whenever a task completes, a child region closes,
    /// or an obligation is resolved.
    ///
    /// Uses an iterative loop instead of recursion to bound stack depth and
    /// enable future migration to `ShardGuard`-based locking (where recursive
    /// self-calls would deadlock on non-reentrant mutexes).
    pub fn advance_region_state(&mut self, initial_region: RegionId) {
        let mut current = Some(initial_region);

        while let Some(region_id) = current.take() {
            // Get state and parent without holding a long borrow on self.regions
            let (state, parent) = {
                let Some(region) = self.regions.get(region_id.arena_index()) else {
                    break;
                };
                (region.state(), region.parent)
            };

            match state {
                crate::record::region::RegionState::Closing
                | crate::record::region::RegionState::Draining => {
                    // Transition to Finalizing only once child regions and tasks are gone.
                    let transition_to_finalizing = {
                        let Some(region) = self.regions.get(region_id.arena_index()) else {
                            break;
                        };
                        let no_children = region.child_count() == 0;
                        let no_tasks = region.task_count() == 0;
                        if no_children && no_tasks {
                            region.begin_finalize()
                        } else {
                            if !no_children
                                && region.state() == crate::record::region::RegionState::Closing
                            {
                                region.begin_drain();
                            }
                            false
                        }
                    };

                    if transition_to_finalizing {
                        self.finalizing_region_count += 1;
                        // Re-process same region as Finalizing in next iteration
                        current = Some(region_id);
                    }
                }
                crate::record::region::RegionState::Finalizing => {
                    // Run sync finalizers (requires mut self).
                    // If we hit an async finalizer, reinsert it and wait for a scheduler.
                    if let Some(async_finalizer) = self.run_sync_finalizers(region_id) {
                        if let Some(region) = self.regions.get(region_id.arena_index()) {
                            region.add_finalizer(async_finalizer);
                        }
                        break; // Async finalizer pending; stop advancing
                    }

                    // If finalizing and obligations remain with no live tasks, mark leaks.
                    // Use map_or(false, ...) to prevent ghost tasks (removed from arena
                    // but still in region list during task_completed mid-cleanup) from
                    // triggering premature leak detection.
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        if region.pending_obligations() > 0 {
                            let tasks_done = region.task_ids_small().iter().all(|&task_id| {
                                self.task(task_id).is_some_and(|t| t.state.is_terminal())
                            });
                            if tasks_done {
                                let leaks = self
                                    .collect_obligation_leaks(|record| record.region == region_id);
                                if !leaks.is_empty() {
                                    self.handle_obligation_leaks(ObligationLeakError {
                                        task_id: None,
                                        region_id,
                                        completion: None,
                                        leaks,
                                    });
                                }
                            }
                        }
                    }

                    // Check if we can complete close
                    if self.can_region_complete_close(region_id) {
                        let closed = {
                            let Some(region) = self.regions.get(region_id.arena_index()) else {
                                break;
                            };
                            region.complete_close()
                        };

                        if closed {
                            self.finalizing_region_count =
                                self.finalizing_region_count.saturating_sub(1);
                            // Emit RegionCloseComplete trace event (pairs
                            // with RegionCloseBegin emitted in cancel_request).
                            let seq = self.next_trace_seq();
                            self.trace.push_event(TraceEvent::new(
                                seq,
                                self.now,
                                TraceEventKind::RegionCloseComplete,
                                TraceData::Region {
                                    region: region_id,
                                    parent,
                                },
                            ));

                            // Emit region_closed metric with lifetime.
                            if let Some(region) = self.regions.get(region_id.arena_index()) {
                                let lifetime = Duration::from_nanos(
                                    self.now.duration_since(region.created_at()),
                                );
                                self.metrics.region_closed(region_id, lifetime);
                            }

                            if let Some(parent_id) = parent {
                                // Remove from parent
                                if let Some(parent_record) =
                                    self.regions.get(parent_id.arena_index())
                                {
                                    parent_record.remove_child(region_id);
                                }
                                // Advance parent in next iteration
                                current = Some(parent_id);
                            }

                            // Cleanup: Remove the closed region from the arena to prevent memory leaks
                            self.regions.remove(region_id.arena_index());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable identifier snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdSnapshot {
    /// Arena index for the entity.
    pub index: u32,
    /// Generation counter for ABA safety.
    pub generation: u32,
}

impl From<RegionId> for IdSnapshot {
    fn from(id: RegionId) -> Self {
        let arena = id.arena_index();
        Self {
            index: arena.index(),
            generation: arena.generation(),
        }
    }
}

impl From<TaskId> for IdSnapshot {
    fn from(id: TaskId) -> Self {
        let arena = id.arena_index();
        Self {
            index: arena.index(),
            generation: arena.generation(),
        }
    }
}

impl From<ObligationId> for IdSnapshot {
    fn from(id: ObligationId) -> Self {
        let arena = id.arena_index();
        Self {
            index: arena.index(),
            generation: arena.generation(),
        }
    }
}

/// Serializable budget snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Deadline in nanoseconds, if any.
    pub deadline: Option<u64>,
    /// Poll quota for the budget.
    pub poll_quota: u32,
    /// Optional cost quota.
    pub cost_quota: Option<u64>,
    /// Scheduling priority (0-255).
    pub priority: u8,
}

impl From<Budget> for BudgetSnapshot {
    fn from(budget: Budget) -> Self {
        Self {
            deadline: budget.deadline.map(Time::as_nanos),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

/// Snapshot of the runtime state for debugging or visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    /// Snapshot timestamp in nanoseconds.
    pub timestamp: u64,
    /// Region snapshots.
    pub regions: Vec<RegionSnapshot>,
    /// Task snapshots.
    pub tasks: Vec<TaskSnapshot>,
    /// Obligation snapshots.
    pub obligations: Vec<ObligationSnapshot>,
    /// Recent trace events (if tracing is enabled).
    pub recent_events: Vec<EventSnapshot>,
}

/// Serializable region snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionSnapshot {
    /// Region identifier.
    pub id: IdSnapshot,
    /// Parent region identifier, if any.
    pub parent_id: Option<IdSnapshot>,
    /// Current region state.
    pub state: RegionStateSnapshot,
    /// Effective budget for the region.
    pub budget: BudgetSnapshot,
    /// Number of child regions.
    pub child_count: usize,
    /// Number of tasks owned by the region.
    pub task_count: usize,
    /// Optional human-friendly name.
    pub name: Option<String>,
}

impl RegionSnapshot {
    fn from_record(record: &RegionRecord) -> Self {
        let child_count = record.child_count();
        let task_count = record.task_count();
        Self {
            id: record.id.into(),
            parent_id: record.parent.map(IdSnapshot::from),
            state: RegionStateSnapshot::from(record.state()),
            budget: BudgetSnapshot::from(record.budget()),
            child_count,
            task_count,
            name: None,
        }
    }
}

/// Serializable region lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegionStateSnapshot {
    /// Region is open and accepting work.
    Open,
    /// Region has begun closing.
    Closing,
    /// Region is draining children.
    Draining,
    /// Region is running finalizers.
    Finalizing,
    /// Region is fully closed.
    Closed,
}

impl From<RegionState> for RegionStateSnapshot {
    fn from(state: RegionState) -> Self {
        match state {
            RegionState::Open => Self::Open,
            RegionState::Closing => Self::Closing,
            RegionState::Draining => Self::Draining,
            RegionState::Finalizing => Self::Finalizing,
            RegionState::Closed => Self::Closed,
        }
    }
}

/// Serializable task snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSnapshot {
    /// Task identifier.
    pub id: IdSnapshot,
    /// Owning region identifier.
    pub region_id: IdSnapshot,
    /// Current task state.
    pub state: TaskStateSnapshot,
    /// Optional human-friendly name.
    pub name: Option<String>,
    /// Estimated poll count since creation.
    pub poll_count: u64,
    /// Task creation time in nanoseconds.
    pub created_at: u64,
    /// Obligations currently held by the task.
    pub obligations: Vec<IdSnapshot>,
}

impl TaskSnapshot {
    fn from_record(record: &TaskRecord, obligations: Vec<ObligationId>) -> Self {
        let poll_count = record
            .cx_inner
            .as_ref()
            .map(|inner| inner.read())
            .map(|inner| inner.budget_baseline.poll_quota)
            .map_or(0, |baseline| {
                u64::from(baseline.saturating_sub(record.polls_remaining))
            });

        let obligations = obligations.into_iter().map(IdSnapshot::from).collect();

        Self {
            id: record.id.into(),
            region_id: record.owner.into(),
            state: TaskStateSnapshot::from_state(&record.state),
            name: None,
            poll_count,
            created_at: record.created_at().as_nanos(),
            obligations,
        }
    }
}

/// Serializable task lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStateSnapshot {
    /// Task created but not yet running.
    Created,
    /// Task is running normally.
    Running,
    /// Cancellation requested.
    CancelRequested {
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Task acknowledged cancellation and is cleaning up.
    Cancelling {
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Task is running finalizers.
    Finalizing {
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Task completed with an outcome.
    Completed {
        /// Completion outcome.
        outcome: OutcomeSnapshot,
    },
}

impl TaskStateSnapshot {
    fn from_state(state: &TaskState) -> Self {
        match state {
            TaskState::Created => Self::Created,
            TaskState::Running => Self::Running,
            TaskState::CancelRequested { reason, .. } => Self::CancelRequested {
                reason: CancelReasonSnapshot::from(reason),
            },
            TaskState::Cancelling { reason, .. } => Self::Cancelling {
                reason: CancelReasonSnapshot::from(reason),
            },
            TaskState::Finalizing { reason, .. } => Self::Finalizing {
                reason: CancelReasonSnapshot::from(reason),
            },
            TaskState::Completed(outcome) => Self::Completed {
                outcome: OutcomeSnapshot::from_outcome(outcome),
            },
        }
    }
}

/// Serializable cancellation kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CancelKindSnapshot {
    /// Explicit user cancellation.
    User,
    /// Deadline or timeout cancellation.
    Timeout,
    /// Deadline budget exhaustion.
    Deadline,
    /// Poll quota exhaustion.
    PollQuota,
    /// Cost budget exhaustion.
    CostBudget,
    /// Fail-fast cancellation.
    FailFast,
    /// Race-loser cancellation.
    RaceLost,
    /// Parent region cancelled.
    ParentCancelled,
    /// Resource unavailability cancellation.
    ResourceUnavailable,
    /// Runtime shutdown cancellation.
    Shutdown,
    /// Linked task exit propagation (Spork).
    LinkedExit,
}

impl From<CancelKind> for CancelKindSnapshot {
    fn from(kind: CancelKind) -> Self {
        match kind {
            CancelKind::User => Self::User,
            CancelKind::Timeout => Self::Timeout,
            CancelKind::Deadline => Self::Deadline,
            CancelKind::PollQuota => Self::PollQuota,
            CancelKind::CostBudget => Self::CostBudget,
            CancelKind::FailFast => Self::FailFast,
            CancelKind::RaceLost => Self::RaceLost,
            CancelKind::ParentCancelled => Self::ParentCancelled,
            CancelKind::ResourceUnavailable => Self::ResourceUnavailable,
            CancelKind::Shutdown => Self::Shutdown,
            CancelKind::LinkedExit => Self::LinkedExit,
        }
    }
}

/// Serializable cancellation reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelReasonSnapshot {
    /// Cancellation kind.
    pub kind: CancelKindSnapshot,
    /// Originating region identifier.
    pub origin_region: IdSnapshot,
    /// Originating task identifier, if any.
    pub origin_task: Option<IdSnapshot>,
    /// Timestamp when cancellation was requested (nanoseconds).
    pub timestamp: u64,
    /// Optional static message.
    pub message: Option<String>,
    /// Optional parent cause.
    pub cause: Option<Box<Self>>,
}

impl From<&CancelReason> for CancelReasonSnapshot {
    fn from(reason: &CancelReason) -> Self {
        Self {
            kind: CancelKindSnapshot::from(reason.kind()),
            origin_region: reason.origin_region.into(),
            origin_task: reason.origin_task.map(IdSnapshot::from),
            timestamp: reason.timestamp.as_nanos(),
            message: reason.message.map(str::to_string),
            cause: reason
                .cause
                .as_deref()
                .map(|cause| Box::new(Self::from(cause))),
        }
    }
}

/// Serializable task outcome summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutcomeSnapshot {
    /// Task completed successfully.
    Ok,
    /// Task completed with an application error.
    Err {
        /// Optional error message.
        message: Option<String>,
    },
    /// Task completed due to cancellation.
    Cancelled {
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Task panicked.
    Panicked {
        /// Optional panic message.
        message: Option<String>,
    },
}

impl OutcomeSnapshot {
    fn from_outcome(outcome: &Outcome<(), crate::error::Error>) -> Self {
        match outcome {
            Outcome::Ok(()) => Self::Ok,
            Outcome::Err(err) => Self::Err {
                message: Some(err.to_string()),
            },
            Outcome::Cancelled(reason) => Self::Cancelled {
                reason: CancelReasonSnapshot::from(reason),
            },
            Outcome::Panicked(payload) => Self::Panicked {
                message: Some(payload.message().to_string()),
            },
        }
    }
}

/// Serializable down/exit reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DownReasonSnapshot {
    /// Process completed successfully.
    Normal,
    /// Process terminated with an application error.
    Error {
        /// Error message.
        message: String,
    },
    /// Process was cancelled.
    Cancelled {
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Process panicked.
    Panicked {
        /// Panic message.
        message: String,
    },
}

impl From<&crate::monitor::DownReason> for DownReasonSnapshot {
    fn from(reason: &crate::monitor::DownReason) -> Self {
        match reason {
            crate::monitor::DownReason::Normal => Self::Normal,
            crate::monitor::DownReason::Error(message) => Self::Error {
                message: message.clone(),
            },
            crate::monitor::DownReason::Cancelled(reason) => Self::Cancelled {
                reason: CancelReasonSnapshot::from(reason),
            },
            crate::monitor::DownReason::Panicked(payload) => Self::Panicked {
                message: payload.message().to_string(),
            },
        }
    }
}

/// Serializable obligation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationSnapshot {
    /// Obligation identifier.
    pub id: IdSnapshot,
    /// Obligation kind.
    pub kind: ObligationKindSnapshot,
    /// Obligation state.
    pub state: ObligationStateSnapshot,
    /// Task holding the obligation.
    pub holder_task: IdSnapshot,
    /// Region owning the obligation.
    pub owning_region: IdSnapshot,
    /// Time when the obligation was created.
    pub created_at: u64,
}

impl ObligationSnapshot {
    fn from_record(record: &ObligationRecord) -> Self {
        Self {
            id: record.id.into(),
            kind: ObligationKindSnapshot::from(record.kind),
            state: ObligationStateSnapshot::from(record.state),
            holder_task: record.holder.into(),
            owning_region: record.region.into(),
            created_at: record.reserved_at.as_nanos(),
        }
    }
}

/// Serializable obligation kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObligationKindSnapshot {
    /// Send permit.
    SendPermit,
    /// Acknowledgement.
    Ack,
    /// Lease.
    Lease,
    /// I/O operation.
    IoOp,
}

impl From<ObligationKind> for ObligationKindSnapshot {
    fn from(kind: ObligationKind) -> Self {
        match kind {
            ObligationKind::SendPermit => Self::SendPermit,
            ObligationKind::Ack => Self::Ack,
            ObligationKind::Lease => Self::Lease,
            ObligationKind::IoOp => Self::IoOp,
        }
    }
}

/// Serializable obligation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObligationStateSnapshot {
    /// Reserved but not yet resolved.
    Reserved,
    /// Committed successfully.
    Committed,
    /// Aborted cleanly.
    Aborted,
    /// Leaked (error).
    Leaked,
}

impl From<ObligationState> for ObligationStateSnapshot {
    fn from(state: ObligationState) -> Self {
        match state {
            ObligationState::Reserved => Self::Reserved,
            ObligationState::Committed => Self::Committed,
            ObligationState::Aborted => Self::Aborted,
            ObligationState::Leaked => Self::Leaked,
        }
    }
}

/// Serializable obligation abort reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObligationAbortReasonSnapshot {
    /// Aborted due to cancellation.
    Cancel,
    /// Aborted due to error.
    Error,
    /// Explicitly aborted.
    Explicit,
}

impl From<ObligationAbortReason> for ObligationAbortReasonSnapshot {
    fn from(reason: ObligationAbortReason) -> Self {
        match reason {
            ObligationAbortReason::Cancel => Self::Cancel,
            ObligationAbortReason::Error => Self::Error,
            ObligationAbortReason::Explicit => Self::Explicit,
        }
    }
}

/// Serializable trace event snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSnapshot {
    /// Event schema version.
    pub version: u32,
    /// Sequence number.
    pub seq: u64,
    /// Event timestamp in nanoseconds.
    pub time: u64,
    /// Event kind.
    pub kind: EventKindSnapshot,
    /// Event data payload.
    pub data: EventDataSnapshot,
}

impl EventSnapshot {
    fn from_event(event: &TraceEvent) -> Self {
        Self {
            version: event.version,
            seq: event.seq,
            time: event.time.as_nanos(),
            kind: EventKindSnapshot::from(event.kind),
            data: EventDataSnapshot::from_trace_data(&event.data),
        }
    }
}

/// Serializable trace event kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKindSnapshot {
    /// Task was spawned.
    Spawn,
    /// Task was scheduled.
    Schedule,
    /// Task yielded.
    Yield,
    /// Task was woken.
    Wake,
    /// Task was polled.
    Poll,
    /// Task completed.
    Complete,
    /// Cancellation requested.
    CancelRequest,
    /// Cancellation acknowledged.
    CancelAck,
    /// Region close started.
    RegionCloseBegin,
    /// Region close completed.
    RegionCloseComplete,
    /// Region created.
    RegionCreated,
    /// Region cancelled.
    RegionCancelled,
    /// Obligation reserved.
    ObligationReserve,
    /// Obligation committed.
    ObligationCommit,
    /// Obligation aborted.
    ObligationAbort,
    /// Obligation leaked.
    ObligationLeak,
    /// Time advanced.
    TimeAdvance,
    /// Timer scheduled.
    TimerScheduled,
    /// Timer fired.
    TimerFired,
    /// Timer cancelled.
    TimerCancelled,
    /// I/O interest requested.
    IoRequested,
    /// I/O ready.
    IoReady,
    /// I/O result.
    IoResult,
    /// I/O error.
    IoError,
    /// RNG seed.
    RngSeed,
    /// RNG value.
    RngValue,
    /// Replay checkpoint.
    Checkpoint,
    /// Futurelock detected.
    FuturelockDetected,
    /// Chaos injection occurred.
    ChaosInjection,
    /// User trace point.
    UserTrace,
    /// A monitor was established.
    MonitorCreated,
    /// A monitor was removed.
    MonitorDropped,
    /// A Down notification was delivered.
    DownDelivered,
    /// A link was established.
    LinkCreated,
    /// A link was removed.
    LinkDropped,
    /// An exit signal was delivered to a linked task.
    ExitDelivered,
}

impl From<TraceEventKind> for EventKindSnapshot {
    fn from(kind: TraceEventKind) -> Self {
        match kind {
            TraceEventKind::Spawn => Self::Spawn,
            TraceEventKind::Schedule => Self::Schedule,
            TraceEventKind::Yield => Self::Yield,
            TraceEventKind::Wake => Self::Wake,
            TraceEventKind::Poll => Self::Poll,
            TraceEventKind::Complete => Self::Complete,
            TraceEventKind::CancelRequest => Self::CancelRequest,
            TraceEventKind::CancelAck => Self::CancelAck,
            TraceEventKind::RegionCloseBegin => Self::RegionCloseBegin,
            TraceEventKind::RegionCloseComplete => Self::RegionCloseComplete,
            TraceEventKind::RegionCreated => Self::RegionCreated,
            TraceEventKind::RegionCancelled => Self::RegionCancelled,
            TraceEventKind::ObligationReserve => Self::ObligationReserve,
            TraceEventKind::ObligationCommit => Self::ObligationCommit,
            TraceEventKind::ObligationAbort => Self::ObligationAbort,
            TraceEventKind::ObligationLeak => Self::ObligationLeak,
            TraceEventKind::TimeAdvance => Self::TimeAdvance,
            TraceEventKind::TimerScheduled => Self::TimerScheduled,
            TraceEventKind::TimerFired => Self::TimerFired,
            TraceEventKind::TimerCancelled => Self::TimerCancelled,
            TraceEventKind::IoRequested => Self::IoRequested,
            TraceEventKind::IoReady => Self::IoReady,
            TraceEventKind::IoResult => Self::IoResult,
            TraceEventKind::IoError => Self::IoError,
            TraceEventKind::RngSeed => Self::RngSeed,
            TraceEventKind::RngValue => Self::RngValue,
            TraceEventKind::Checkpoint => Self::Checkpoint,
            TraceEventKind::FuturelockDetected => Self::FuturelockDetected,
            TraceEventKind::ChaosInjection => Self::ChaosInjection,
            TraceEventKind::UserTrace => Self::UserTrace,
            TraceEventKind::MonitorCreated => Self::MonitorCreated,
            TraceEventKind::MonitorDropped => Self::MonitorDropped,
            TraceEventKind::DownDelivered => Self::DownDelivered,
            TraceEventKind::LinkCreated => Self::LinkCreated,
            TraceEventKind::LinkDropped => Self::LinkDropped,
            TraceEventKind::ExitDelivered => Self::ExitDelivered,
        }
    }
}

/// Serializable trace event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventDataSnapshot {
    /// No additional data.
    None,
    /// Task-related event.
    Task {
        /// Task identifier.
        task: IdSnapshot,
        /// Region identifier.
        region: IdSnapshot,
    },
    /// Region-related event.
    Region {
        /// Region identifier.
        region: IdSnapshot,
        /// Parent region identifier.
        parent: Option<IdSnapshot>,
    },
    /// Obligation-related event.
    Obligation {
        /// Obligation identifier.
        obligation: IdSnapshot,
        /// Task holding the obligation.
        task: IdSnapshot,
        /// Owning region.
        region: IdSnapshot,
        /// Obligation kind.
        kind: ObligationKindSnapshot,
        /// Obligation state.
        state: ObligationStateSnapshot,
        /// Duration held in nanoseconds, if resolved.
        duration_ns: Option<u64>,
        /// Abort reason, if applicable.
        abort_reason: Option<ObligationAbortReasonSnapshot>,
    },
    /// Cancellation-related event.
    Cancel {
        /// Task identifier.
        task: IdSnapshot,
        /// Region identifier.
        region: IdSnapshot,
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Region cancellation event.
    RegionCancel {
        /// Region identifier.
        region: IdSnapshot,
        /// Cancellation reason.
        reason: CancelReasonSnapshot,
    },
    /// Time-related event.
    Time {
        /// Previous time in nanoseconds.
        old: u64,
        /// New time in nanoseconds.
        new: u64,
    },
    /// Timer event.
    Timer {
        /// Timer identifier.
        timer_id: u64,
        /// Deadline in nanoseconds, if applicable.
        deadline: Option<u64>,
    },
    /// I/O request event.
    IoRequested {
        /// I/O token.
        token: u64,
        /// Interest bitflags.
        interest: u8,
    },
    /// I/O ready event.
    IoReady {
        /// I/O token.
        token: u64,
        /// Readiness bitflags.
        readiness: u8,
    },
    /// I/O result event.
    IoResult {
        /// I/O token.
        token: u64,
        /// Bytes transferred.
        bytes: i64,
    },
    /// I/O error event.
    IoError {
        /// I/O token.
        token: u64,
        /// Error kind.
        kind: u8,
    },
    /// RNG seed event.
    RngSeed {
        /// Seed value.
        seed: u64,
    },
    /// RNG value event.
    RngValue {
        /// Generated value.
        value: u64,
    },
    /// Checkpoint event.
    Checkpoint {
        /// Monotonic sequence number.
        sequence: u64,
        /// Active task count.
        active_tasks: u32,
        /// Active region count.
        active_regions: u32,
    },
    /// Futurelock event data.
    Futurelock {
        /// Task identifier.
        task: IdSnapshot,
        /// Region identifier.
        region: IdSnapshot,
        /// Idle steps since last poll.
        idle_steps: u64,
        /// Obligations held at detection time.
        held: Vec<HeldObligationSnapshot>,
    },
    /// Monitor lifecycle event.
    Monitor {
        /// Monitor reference id.
        monitor_ref: u64,
        /// Watcher task id.
        watcher: IdSnapshot,
        /// Watcher region id.
        watcher_region: IdSnapshot,
        /// Monitored task id.
        monitored: IdSnapshot,
    },
    /// Down notification delivery.
    Down {
        /// Monitor reference id.
        monitor_ref: u64,
        /// Watcher task id.
        watcher: IdSnapshot,
        /// Monitored task id.
        monitored: IdSnapshot,
        /// Completion virtual time (nanoseconds).
        completion_vt: u64,
        /// Reason for termination.
        reason: DownReasonSnapshot,
    },
    /// Link lifecycle event.
    Link {
        /// Link reference id.
        link_ref: u64,
        /// One side task id.
        task_a: IdSnapshot,
        /// One side region id.
        region_a: IdSnapshot,
        /// Other side task id.
        task_b: IdSnapshot,
        /// Other side region id.
        region_b: IdSnapshot,
    },
    /// Exit signal delivery.
    Exit {
        /// Link reference id.
        link_ref: u64,
        /// Source task id.
        from: IdSnapshot,
        /// Target task id.
        to: IdSnapshot,
        /// Failure virtual time (nanoseconds).
        failure_vt: u64,
        /// Reason for termination.
        reason: DownReasonSnapshot,
    },
    /// User-defined message.
    Message(String),
    /// Chaos injection details.
    Chaos {
        /// Chaos kind.
        kind: String,
        /// Optional task identifier.
        task: Option<IdSnapshot>,
        /// Additional detail.
        detail: String,
    },
}

impl EventDataSnapshot {
    #[allow(clippy::too_many_lines)]
    fn from_trace_data(data: &TraceData) -> Self {
        match data {
            TraceData::None => Self::None,
            TraceData::Task { task, region } => Self::Task {
                task: (*task).into(),
                region: (*region).into(),
            },
            TraceData::Region { region, parent } => Self::Region {
                region: (*region).into(),
                parent: parent.map(IdSnapshot::from),
            },
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => Self::Obligation {
                obligation: (*obligation).into(),
                task: (*task).into(),
                region: (*region).into(),
                kind: ObligationKindSnapshot::from(*kind),
                state: ObligationStateSnapshot::from(*state),
                duration_ns: *duration_ns,
                abort_reason: abort_reason.map(ObligationAbortReasonSnapshot::from),
            },
            TraceData::Cancel {
                task,
                region,
                reason,
            } => Self::Cancel {
                task: (*task).into(),
                region: (*region).into(),
                reason: CancelReasonSnapshot::from(reason),
            },
            TraceData::RegionCancel { region, reason } => Self::RegionCancel {
                region: (*region).into(),
                reason: CancelReasonSnapshot::from(reason),
            },
            TraceData::Time { old, new } => Self::Time {
                old: old.as_nanos(),
                new: new.as_nanos(),
            },
            TraceData::Timer { timer_id, deadline } => Self::Timer {
                timer_id: *timer_id,
                deadline: deadline.map(Time::as_nanos),
            },
            TraceData::IoRequested { token, interest } => Self::IoRequested {
                token: *token,
                interest: *interest,
            },
            TraceData::IoReady { token, readiness } => Self::IoReady {
                token: *token,
                readiness: *readiness,
            },
            TraceData::IoResult { token, bytes } => Self::IoResult {
                token: *token,
                bytes: *bytes,
            },
            TraceData::IoError { token, kind } => Self::IoError {
                token: *token,
                kind: *kind,
            },
            TraceData::RngSeed { seed } => Self::RngSeed { seed: *seed },
            TraceData::RngValue { value } => Self::RngValue { value: *value },
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            } => Self::Checkpoint {
                sequence: *sequence,
                active_tasks: *active_tasks,
                active_regions: *active_regions,
            },
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => Self::Futurelock {
                task: (*task).into(),
                region: (*region).into(),
                idle_steps: *idle_steps,
                held: held
                    .iter()
                    .map(|(obligation, kind)| HeldObligationSnapshot {
                        obligation: (*obligation).into(),
                        kind: ObligationKindSnapshot::from(*kind),
                    })
                    .collect(),
            },
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            } => Self::Monitor {
                monitor_ref: *monitor_ref,
                watcher: (*watcher).into(),
                watcher_region: (*watcher_region).into(),
                monitored: (*monitored).into(),
            },
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            } => Self::Down {
                monitor_ref: *monitor_ref,
                watcher: (*watcher).into(),
                monitored: (*monitored).into(),
                completion_vt: completion_vt.as_nanos(),
                reason: DownReasonSnapshot::from(reason),
            },
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            } => Self::Link {
                link_ref: *link_ref,
                task_a: (*task_a).into(),
                region_a: (*region_a).into(),
                task_b: (*task_b).into(),
                region_b: (*region_b).into(),
            },
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            } => Self::Exit {
                link_ref: *link_ref,
                from: (*from).into(),
                to: (*to).into(),
                failure_vt: failure_vt.as_nanos(),
                reason: DownReasonSnapshot::from(reason),
            },
            TraceData::Message(message) => Self::Message(message.clone()),
            TraceData::Chaos { kind, task, detail } => Self::Chaos {
                kind: kind.clone(),
                task: task.map(IdSnapshot::from),
                detail: detail.clone(),
            },
        }
    }
}

/// Serializable representation of a held obligation at futurelock detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldObligationSnapshot {
    /// Obligation identifier.
    pub obligation: IdSnapshot,
    /// Obligation kind.
    pub kind: ObligationKindSnapshot,
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::observability::{LogEntry, ObservabilityConfig};
    use crate::record::task::TaskState;
    use crate::record::{ObligationKind, ObligationRecord, RegionLimits};
    use crate::runtime::reactor::LabReactor;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::trace::event::TRACE_EVENT_SCHEMA_VERSION;
    use crate::types::{CancelAttributionConfig, CancelKind};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct TestMetrics {
        cancellations: AtomicUsize,
        completions: Mutex<Vec<OutcomeKind>>,
        spawns: AtomicUsize,
    }

    impl MetricsProvider for TestMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {
            self.spawns.fetch_add(1, Ordering::Relaxed);
        }

        fn task_completed(&self, _: TaskId, outcome: OutcomeKind, _: Duration) {
            self.completions.lock().push(outcome);
        }

        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

        fn region_closed(&self, _: RegionId, _: Duration) {}

        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {
            self.cancellations.fetch_add(1, Ordering::Relaxed);
        }

        fn drain_completed(&self, _: RegionId, _: Duration) {}

        fn deadline_set(&self, _: RegionId, _: Duration) {}

        fn deadline_exceeded(&self, _: RegionId) {}

        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}

        fn deadline_violation(&self, _: &str, _: Duration) {}

        fn deadline_remaining(&self, _: &str, _: Duration) {}

        fn checkpoint_interval(&self, _: &str, _: Duration) {}

        fn task_stuck_detected(&self, _: &str) {}

        fn obligation_created(&self, _: RegionId) {}

        fn obligation_discharged(&self, _: RegionId) {}

        fn obligation_leaked(&self, _: RegionId) {}

        fn scheduler_tick(&self, _: usize, _: Duration) {}
    }

    struct TestWaker(AtomicBool);

    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn insert_task(state: &mut RuntimeState, region: RegionId) -> TaskId {
        let idx = state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        state.task_mut(id).expect("task missing").id = id;
        let added = state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .add_task(id);
        crate::assert_with_log!(added.is_ok(), "task added to region", true, added.is_ok());
        id
    }

    #[test]
    fn cx_trace_emits_user_trace_event() {
        init_test("cx_trace_emits_user_trace_event");
        let metrics = Arc::new(TestMetrics::default());
        let mut state = RuntimeState::new_with_metrics(metrics);
        let root = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");
        let cx = state
            .task(task_id)
            .and_then(|record| record.cx.clone())
            .expect("cx missing");

        cx.trace("user trace");

        let saw_user_trace = state
            .trace
            .snapshot()
            .iter()
            .any(|event| event.kind == TraceEventKind::UserTrace);
        crate::assert_with_log!(saw_user_trace, "user trace recorded", true, saw_user_trace);
        crate::test_complete!("cx_trace_emits_user_trace_event");
    }

    #[test]
    fn cx_log_attaches_collector_and_timestamp() {
        init_test("cx_log_attaches_collector_and_timestamp");
        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        state.set_observability_config(ObservabilityConfig::testing().with_max_log_entries(8));
        let root = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");
        let cx = state
            .task(task_id)
            .and_then(|record| record.cx.clone())
            .expect("cx missing");

        cx.log(LogEntry::info("hello"));

        let collector = cx.log_collector().expect("collector missing");
        let entries = collector.peek();
        crate::assert_with_log!(entries.len() == 1, "log entry count", 1, entries.len());
        let entry = &entries[0];
        crate::assert_with_log!(
            entry.message() == "hello",
            "log entry message",
            "hello",
            entry.message()
        );
        crate::assert_with_log!(
            entry.timestamp() == Time::from_millis(5),
            "log entry timestamp",
            Time::from_millis(5),
            entry.timestamp()
        );
        let task_str = task_id.to_string();
        let region_str = root.to_string();
        crate::assert_with_log!(
            entry.get_field("task_id") == Some(task_str.as_str()),
            "log entry task id",
            task_str.as_str(),
            entry.get_field("task_id")
        );
        crate::assert_with_log!(
            entry.get_field("region_id") == Some(region_str.as_str()),
            "log entry region id",
            region_str.as_str(),
            entry.get_field("region_id")
        );
        crate::test_complete!("cx_log_attaches_collector_and_timestamp");
    }

    #[test]
    fn cx_log_respects_timestamp_toggle() {
        init_test("cx_log_respects_timestamp_toggle");
        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(9)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let config = ObservabilityConfig::testing().with_include_timestamps(false);
        state.set_observability_config(config);
        let root = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");
        let cx = state
            .task(task_id)
            .and_then(|record| record.cx.clone())
            .expect("cx missing");

        cx.log(LogEntry::info("no timestamps"));

        let collector = cx.log_collector().expect("collector missing");
        let entries = collector.peek();
        crate::assert_with_log!(entries.len() == 1, "log entry count", 1, entries.len());
        let entry = &entries[0];
        crate::assert_with_log!(
            entry.timestamp() == Time::ZERO,
            "timestamps disabled",
            Time::ZERO,
            entry.timestamp()
        );
        crate::test_complete!("cx_log_respects_timestamp_toggle");
    }

    #[test]
    fn cancel_request_emits_trace_and_metrics() {
        init_test("cancel_request_emits_trace_and_metrics");
        let metrics = Arc::new(TestMetrics::default());
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);

        let _ = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");
        let reason = CancelReason::timeout();
        let _ = state.cancel_request(root, &reason, None);

        let events = state.trace.snapshot();
        let saw_cancel = events
            .iter()
            .any(|event| event.kind == TraceEventKind::CancelRequest);
        crate::assert_with_log!(saw_cancel, "cancel trace recorded", true, saw_cancel);

        let cancellations = metrics.cancellations.load(Ordering::Relaxed);
        crate::assert_with_log!(
            cancellations == 1,
            "cancellation metrics",
            1usize,
            cancellations
        );
        crate::test_complete!("cancel_request_emits_trace_and_metrics");
    }

    #[test]
    fn spawn_trace_attaches_logical_time() {
        init_test("spawn_trace_attaches_logical_time");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        let _ = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");

        let events = state.trace.snapshot();
        let spawn_event = events
            .iter()
            .find(|event| event.kind == TraceEventKind::Spawn)
            .expect("spawn event");
        crate::assert_with_log!(
            spawn_event.logical_time.is_some(),
            "spawn logical time present",
            true,
            spawn_event.logical_time.is_some()
        );
        crate::test_complete!("spawn_trace_attaches_logical_time");
    }

    #[test]
    fn cancellation_outcome_metric_emitted() {
        init_test("cancellation_outcome_metric_emitted");
        let metrics = Arc::new(TestMetrics::default());
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async { 1_u8 })
            .expect("task spawn");

        if let Some(record) = state.task_mut(task_id) {
            record.complete(Outcome::Cancelled(CancelReason::timeout()));
        }
        let _ = state.task_completed(task_id);

        let saw_cancelled = metrics.completions.lock().contains(&OutcomeKind::Cancelled);
        crate::assert_with_log!(
            saw_cancelled,
            "cancelled outcome metric",
            true,
            saw_cancelled
        );
        crate::test_complete!("cancellation_outcome_metric_emitted");
    }

    #[test]
    fn snapshot_captures_entities() {
        init_test("snapshot_captures_entities");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(region, Budget::INFINITE, async { 42 })
            .expect("task create");

        let obl_idx = state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::SendPermit,
            task_id,
            region,
            state.now,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        state
            .obligations
            .get_mut(obl_idx)
            .expect("obligation missing")
            .id = obl_id;

        let snapshot = state.snapshot();
        crate::assert_with_log!(
            snapshot.regions.len() == 1,
            "region count",
            1,
            snapshot.regions.len()
        );
        crate::assert_with_log!(
            snapshot.tasks.len() == 1,
            "task count",
            1,
            snapshot.tasks.len()
        );
        crate::assert_with_log!(
            snapshot.obligations.len() == 1,
            "obligation count",
            1,
            snapshot.obligations.len()
        );

        let task_snapshot = snapshot
            .tasks
            .iter()
            .find(|t| t.id == IdSnapshot::from(task_id))
            .expect("task snapshot missing");
        let has_obligation = task_snapshot
            .obligations
            .contains(&IdSnapshot::from(obl_id));
        crate::assert_with_log!(has_obligation, "task has obligation", true, has_obligation);
        crate::test_complete!("snapshot_captures_entities");
    }

    #[test]
    fn snapshot_preserves_event_version() {
        init_test("snapshot_preserves_event_version");
        let state = RuntimeState::new();
        let event = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        state.trace.push_event(event);

        let snapshot = state.snapshot();
        let event_snapshot = snapshot
            .recent_events
            .first()
            .expect("event snapshot missing");
        crate::assert_with_log!(
            event_snapshot.version == TRACE_EVENT_SCHEMA_VERSION,
            "event version",
            TRACE_EVENT_SCHEMA_VERSION,
            event_snapshot.version
        );
        crate::test_complete!("snapshot_preserves_event_version");
    }

    #[test]
    fn can_region_complete_close_checks_running_finalizer_tasks() {
        init_test("can_region_complete_close_checks_running_finalizer_tasks");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Manually transition to Finalizing (simulating finalizer execution)
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Add a running task (representing an async finalizer)
        let task = insert_task(&mut state, region);
        state.task_mut(task).expect("task").start_running();

        // Should NOT be able to close because a task is running
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close with running task",
            false,
            can_close
        );

        // Complete the task
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));

        // Now should be able to close
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close after task completes", true, can_close);
        crate::test_complete!("can_region_complete_close_checks_running_finalizer_tasks");
    }

    #[test]
    fn empty_state_is_quiescent() {
        init_test("empty_state_is_quiescent");
        let state = RuntimeState::new();
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "state quiescent", true, quiescent);
        crate::test_complete!("empty_state_is_quiescent");
    }

    #[test]
    fn create_root_region() {
        init_test("create_root_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        crate::assert_with_log!(
            state.root_region.is_some(),
            "root region set",
            true,
            state.root_region.is_some()
        );
        crate::assert_with_log!(
            state.root_region == Some(root),
            "root id matches",
            Some(root),
            state.root_region
        );
        crate::assert_with_log!(
            state.live_region_count() == 1,
            "live region count",
            1usize,
            state.live_region_count()
        );
        crate::test_complete!("create_root_region");
    }

    #[test]
    fn policy_can_cancel_siblings() {
        init_test("policy_can_cancel_siblings");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib1 = insert_task(&mut state, region);
        let sib2 = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let (action, tasks) = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        let expected_action = PolicyAction::CancelSiblings(CancelReason::sibling_failed());
        crate::assert_with_log!(
            action == expected_action,
            "cancel siblings action",
            expected_action,
            action
        );
        crate::assert_with_log!(tasks.len() == 2, "tasks len", 2usize, tasks.len());

        for sib in [sib1, sib2] {
            let record = state.task(sib).expect("sib missing");
            let is_cancel_requested = matches!(&record.state, TaskState::CancelRequested { .. });
            assert!(
                is_cancel_requested,
                "expected CancelRequested, got {:?}",
                record.state
            );

            if let TaskState::CancelRequested { reason, .. } = &record.state {
                crate::assert_with_log!(
                    reason.kind == CancelKind::FailFast,
                    "cancel reason kind",
                    CancelKind::FailFast,
                    reason.kind
                );
            }
        }
        let child_record = state.task(child).expect("child missing");
        let is_created = matches!(child_record.state, TaskState::Created);
        crate::assert_with_log!(is_created, "child remains created", true, is_created);
        crate::test_complete!("policy_can_cancel_siblings");
    }

    #[test]
    fn policy_does_not_cancel_siblings_on_cancelled_child() {
        init_test("policy_does_not_cancel_siblings_on_cancelled_child");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let (action, _) = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        crate::assert_with_log!(
            action == PolicyAction::Continue,
            "action continue",
            PolicyAction::Continue,
            action
        );
        let sib_record = state.task(sib).expect("sib missing");
        let is_created = matches!(sib_record.state, TaskState::Created);
        crate::assert_with_log!(is_created, "sibling remains created", true, is_created);
        crate::test_complete!("policy_does_not_cancel_siblings_on_cancelled_child");
    }

    fn create_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
        let idx = state.regions.insert(RegionRecord::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            Some(parent),
            Budget::INFINITE,
        ));
        let id = RegionId::from_arena(idx);
        state.regions.get_mut(idx).expect("region missing").id = id;
        let added = state
            .regions
            .get_mut(parent.arena_index())
            .expect("parent missing")
            .add_child(id);
        crate::assert_with_log!(added.is_ok(), "child added to parent", true, added.is_ok());
        id
    }

    #[test]
    fn cancel_request_marks_region() {
        init_test("cancel_request_marks_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let _tasks = state.cancel_request(region, &CancelReason::timeout(), None);

        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        let cancel_reason = region_record.cancel_reason();
        crate::assert_with_log!(
            cancel_reason.is_some(),
            "cancel reason set",
            true,
            cancel_reason.is_some()
        );
        let kind = cancel_reason.as_ref().unwrap().kind;
        crate::assert_with_log!(
            kind == CancelKind::Timeout,
            "cancel kind timeout",
            CancelKind::Timeout,
            kind
        );
        crate::test_complete!("cancel_request_marks_region");
    }

    #[test]
    fn cancel_request_marks_tasks() {
        init_test("cancel_request_marks_tasks");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task1 = insert_task(&mut state, region);
        let task2 = insert_task(&mut state, region);

        let tasks_to_schedule = state.cancel_request(region, &CancelReason::timeout(), None);

        // Both tasks should be returned for scheduling
        crate::assert_with_log!(
            tasks_to_schedule.len() == 2,
            "tasks scheduled",
            2usize,
            tasks_to_schedule.len()
        );
        let task_ids: Vec<_> = tasks_to_schedule.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            task_ids.contains(&task2),
            "contains task2",
            true,
            task_ids.contains(&task2)
        );

        // Tasks should be in CancelRequested state
        for (task_id, _) in tasks_to_schedule {
            let task = state.task(task_id).expect("task missing");
            let is_cancel_requested = matches!(task.state, TaskState::CancelRequested { .. });
            crate::assert_with_log!(
                is_cancel_requested,
                "task cancel requested",
                true,
                is_cancel_requested
            );
        }
        crate::test_complete!("cancel_request_marks_tasks");
    }

    #[test]
    fn cancel_request_propagates_to_descendants() {
        init_test("cancel_request_propagates_to_descendants");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);
        let grandchild_task = insert_task(&mut state, grandchild);

        let tasks_to_schedule = state.cancel_request(root, &CancelReason::user("stop"), None);

        // All 3 tasks should be scheduled
        crate::assert_with_log!(
            tasks_to_schedule.len() == 3,
            "tasks scheduled",
            3usize,
            tasks_to_schedule.len()
        );

        // Root region gets original reason
        let root_record = state.regions.get(root.arena_index()).expect("root missing");
        let root_kind = root_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            root_kind == CancelKind::User,
            "root cancel kind",
            CancelKind::User,
            root_kind
        );

        // Descendants get ParentCancelled
        let child_record = state
            .regions
            .get(child.arena_index())
            .expect("child missing");
        let child_kind = child_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            child_kind == CancelKind::ParentCancelled,
            "child cancel kind",
            CancelKind::ParentCancelled,
            child_kind
        );

        let grandchild_record = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild missing");
        let grandchild_kind = grandchild_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            grandchild_kind == CancelKind::ParentCancelled,
            "grandchild cancel kind",
            CancelKind::ParentCancelled,
            grandchild_kind
        );

        // Root task gets User reason, descendants get ParentCancelled
        let root_task_record = state.task(root_task).expect("task missing");
        let is_cancel_requested =
            matches!(&root_task_record.state, TaskState::CancelRequested { .. });
        assert!(
            is_cancel_requested,
            "expected CancelRequested, got {:?}",
            root_task_record.state
        );

        if let TaskState::CancelRequested { reason, .. } = &root_task_record.state {
            crate::assert_with_log!(
                reason.kind == CancelKind::User,
                "root task cancel kind",
                CancelKind::User,
                reason.kind
            );
        }

        let child_task_record = state.task(child_task).expect("task missing");
        let is_cancel_requested =
            matches!(&child_task_record.state, TaskState::CancelRequested { .. });
        assert!(
            is_cancel_requested,
            "expected CancelRequested, got {:?}",
            child_task_record.state
        );

        if let TaskState::CancelRequested { reason, .. } = &child_task_record.state {
            crate::assert_with_log!(
                reason.kind == CancelKind::ParentCancelled,
                "child task cancel kind",
                CancelKind::ParentCancelled,
                reason.kind
            );
        }

        let grandchild_task_record = state.task(grandchild_task).expect("task missing");
        let is_cancel_requested = matches!(
            &grandchild_task_record.state,
            TaskState::CancelRequested { .. }
        );
        assert!(
            is_cancel_requested,
            "expected CancelRequested, got {:?}",
            grandchild_task_record.state
        );

        if let TaskState::CancelRequested { reason, .. } = &grandchild_task_record.state {
            crate::assert_with_log!(
                reason.kind == CancelKind::ParentCancelled,
                "grandchild task cancel kind",
                CancelKind::ParentCancelled,
                reason.kind
            );
        }
        crate::test_complete!("cancel_request_propagates_to_descendants");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn cancel_request_builds_cause_chains() {
        init_test("cancel_request_builds_cause_chains");
        let mut state = RuntimeState::new();

        // Create a region tree: root -> child -> grandchild
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        // Create tasks in each region
        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);
        let grandchild_task = insert_task(&mut state, grandchild);

        // Cancel the root with a Deadline reason
        let original_reason = CancelReason::deadline().with_message("budget exhausted");
        let _ = state.cancel_request(root, &original_reason, None);

        // Verify root region has original reason (no cause chain)
        let root_record = state.regions.get(root.arena_index()).expect("root missing");
        let root_reason_opt = root_record.cancel_reason();
        let root_reason = root_reason_opt.as_ref().unwrap();
        crate::assert_with_log!(
            root_reason.kind == CancelKind::Deadline,
            "root reason kind",
            CancelKind::Deadline,
            root_reason.kind
        );
        crate::assert_with_log!(
            root_reason.chain_depth() == 1,
            "root chain depth",
            1,
            root_reason.chain_depth()
        );
        crate::assert_with_log!(
            root_reason.cause.is_none(),
            "root has no cause",
            true,
            root_reason.cause.is_none()
        );

        // Verify child region has ParentCancelled with cause chain to root's reason
        let child_record = state
            .regions
            .get(child.arena_index())
            .expect("child missing");
        let child_reason_opt = child_record.cancel_reason();
        let child_reason = child_reason_opt.as_ref().unwrap();
        crate::assert_with_log!(
            child_reason.kind == CancelKind::ParentCancelled,
            "child reason kind",
            CancelKind::ParentCancelled,
            child_reason.kind
        );
        crate::assert_with_log!(
            child_reason.chain_depth() == 2,
            "child chain depth",
            2,
            child_reason.chain_depth()
        );
        // Root cause should be the original Deadline
        let child_root_cause = child_reason.root_cause();
        crate::assert_with_log!(
            child_root_cause.kind == CancelKind::Deadline,
            "child root cause kind",
            CancelKind::Deadline,
            child_root_cause.kind
        );
        // Origin region should be the root (where cancellation originated)
        crate::assert_with_log!(
            child_reason.origin_region == root,
            "child origin region",
            root,
            child_reason.origin_region
        );

        // Verify grandchild region has ParentCancelled with chain depth of 3
        let grandchild_record = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild missing");
        let grandchild_reason_opt = grandchild_record.cancel_reason();
        let grandchild_reason = grandchild_reason_opt.as_ref().unwrap();
        crate::assert_with_log!(
            grandchild_reason.kind == CancelKind::ParentCancelled,
            "grandchild reason kind",
            CancelKind::ParentCancelled,
            grandchild_reason.kind
        );
        crate::assert_with_log!(
            grandchild_reason.chain_depth() == 3,
            "grandchild chain depth",
            3,
            grandchild_reason.chain_depth()
        );
        // Root cause should still be the original Deadline
        let grandchild_root_cause = grandchild_reason.root_cause();
        crate::assert_with_log!(
            grandchild_root_cause.kind == CancelKind::Deadline,
            "grandchild root cause kind",
            CancelKind::Deadline,
            grandchild_root_cause.kind
        );
        // Origin region should be the child (immediate parent)
        crate::assert_with_log!(
            grandchild_reason.origin_region == child,
            "grandchild origin region",
            child,
            grandchild_reason.origin_region
        );

        // Verify tasks also have properly chained reasons
        let grandchild_task_record = state.task(grandchild_task).expect("task missing");
        let is_cancel_requested = matches!(
            &grandchild_task_record.state,
            TaskState::CancelRequested { .. }
        );
        assert!(
            is_cancel_requested,
            "expected CancelRequested, got {:?}",
            grandchild_task_record.state
        );

        if let TaskState::CancelRequested { reason, .. } = &grandchild_task_record.state {
            crate::assert_with_log!(
                reason.chain_depth() == 3,
                "grandchild task chain depth",
                3,
                reason.chain_depth()
            );
            crate::assert_with_log!(
                reason.root_cause().kind == CancelKind::Deadline,
                "grandchild task root cause",
                CancelKind::Deadline,
                reason.root_cause().kind
            );
        }

        // Verify we can traverse the full cause chain
        let chain: Vec<_> = grandchild_reason.chain().collect();
        crate::assert_with_log!(chain.len() == 3, "chain length", 3, chain.len());
        crate::assert_with_log!(
            chain[0].kind == CancelKind::ParentCancelled,
            "chain[0] kind",
            CancelKind::ParentCancelled,
            chain[0].kind
        );
        crate::assert_with_log!(
            chain[1].kind == CancelKind::ParentCancelled,
            "chain[1] kind",
            CancelKind::ParentCancelled,
            chain[1].kind
        );
        crate::assert_with_log!(
            chain[2].kind == CancelKind::Deadline,
            "chain[2] kind",
            CancelKind::Deadline,
            chain[2].kind
        );

        // Suppress unused variable warnings
        let _ = root_task;
        let _ = child_task;

        crate::test_complete!("cancel_request_builds_cause_chains");
    }

    #[test]
    fn cancel_request_respects_attribution_limits() {
        init_test("cancel_request_respects_attribution_limits");
        let mut state = RuntimeState::new();
        state.set_cancel_attribution_config(CancelAttributionConfig::new(2, 256));

        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        let reason = CancelReason::deadline().with_message("root deadline");
        let _ = state.cancel_request(root, &reason, None);

        let child_reason = state
            .regions
            .get(child.arena_index())
            .and_then(RegionRecord::cancel_reason)
            .expect("child cancel reason missing");
        crate::assert_with_log!(
            child_reason.chain_depth() == 2,
            "child chain depth",
            2,
            child_reason.chain_depth()
        );
        crate::assert_with_log!(
            !child_reason.truncated,
            "child chain not truncated",
            false,
            child_reason.truncated
        );

        let grandchild_reason = state
            .regions
            .get(grandchild.arena_index())
            .and_then(RegionRecord::cancel_reason)
            .expect("grandchild cancel reason missing");
        crate::assert_with_log!(
            grandchild_reason.chain_depth() == 2,
            "grandchild chain depth",
            2,
            grandchild_reason.chain_depth()
        );
        crate::assert_with_log!(
            grandchild_reason.truncated,
            "grandchild chain truncated",
            true,
            grandchild_reason.truncated
        );
        crate::assert_with_log!(
            grandchild_reason.truncated_at_depth == Some(2),
            "grandchild truncation depth",
            Some(2),
            grandchild_reason.truncated_at_depth
        );

        crate::test_complete!("cancel_request_respects_attribution_limits");
    }

    #[test]
    fn cancel_request_respects_chain_depth_limit() {
        init_test("cancel_request_respects_chain_depth_limit");
        let mut state = RuntimeState::new();
        state.set_cancel_attribution_config(CancelAttributionConfig::new(2, usize::MAX));

        let root = state.create_root_region(Budget::INFINITE);
        let mut current = root;
        for _ in 0..4 {
            current = create_child_region(&mut state, current);
        }
        let leaf_task = insert_task(&mut state, current);

        let _ = state.cancel_request(root, &CancelReason::timeout(), None);

        let leaf_record = state
            .regions
            .get(current.arena_index())
            .expect("leaf missing");
        let binding = leaf_record.cancel_reason();
        let leaf_reason = binding.as_ref().expect("reason missing");
        crate::assert_with_log!(
            leaf_reason.chain_depth() <= 2,
            "leaf chain depth bounded",
            2,
            leaf_reason.chain_depth()
        );
        crate::assert_with_log!(
            leaf_reason.any_truncated(),
            "leaf reason truncated",
            true,
            leaf_reason.any_truncated()
        );

        let leaf_task_record = state
            .tasks
            .get(leaf_task.arena_index())
            .expect("task missing");
        match &leaf_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.chain_depth() <= 2,
                    "leaf task chain depth bounded",
                    2,
                    reason.chain_depth()
                );
                crate::assert_with_log!(
                    reason.any_truncated(),
                    "leaf task reason truncated",
                    true,
                    reason.any_truncated()
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        crate::test_complete!("cancel_request_respects_chain_depth_limit");
    }

    #[test]
    fn cancel_request_truncates_large_tree() {
        init_test("cancel_request_truncates_large_tree");
        let mut state = RuntimeState::new();
        state.set_cancel_attribution_config(CancelAttributionConfig::new(4, 256));

        let root = state.create_root_region(Budget::INFINITE);
        let mut current = root;
        for _ in 0..64 {
            current = create_child_region(&mut state, current);
        }
        let leaf_task = insert_task(&mut state, current);

        let _ = state.cancel_request(root, &CancelReason::shutdown(), None);

        let leaf_record = state
            .regions
            .get(current.arena_index())
            .expect("leaf missing");
        let binding = leaf_record.cancel_reason();
        let leaf_reason = binding.as_ref().expect("reason missing");
        crate::assert_with_log!(
            leaf_reason.chain_depth() <= 4,
            "large tree chain depth bounded",
            4,
            leaf_reason.chain_depth()
        );
        crate::assert_with_log!(
            leaf_reason.any_truncated(),
            "large tree reason truncated",
            true,
            leaf_reason.any_truncated()
        );

        let leaf_task_record = state
            .tasks
            .get(leaf_task.arena_index())
            .expect("task missing");
        match &leaf_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.chain_depth() <= 4,
                    "large tree task chain depth bounded",
                    4,
                    reason.chain_depth()
                );
                crate::assert_with_log!(
                    reason.any_truncated(),
                    "large tree task reason truncated",
                    true,
                    reason.any_truncated()
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        crate::test_complete!("cancel_request_truncates_large_tree");
    }

    #[test]
    fn cancel_request_strengthens_existing_reason() {
        init_test("cancel_request_strengthens_existing_reason");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // First cancel with User
        let _ = state.cancel_request(region, &CancelReason::user("stop"), None);

        // Second cancel with Shutdown (higher severity)
        let _ = state.cancel_request(region, &CancelReason::shutdown(), None);

        // Region should have Shutdown reason
        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        let region_kind = region_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            region_kind == CancelKind::Shutdown,
            "region cancel kind",
            CancelKind::Shutdown,
            region_kind
        );

        // Task should have Shutdown reason
        let task_record = state.task(task).expect("task missing");
        let is_cancel_requested = matches!(&task_record.state, TaskState::CancelRequested { .. });
        assert!(
            is_cancel_requested,
            "expected CancelRequested, got {:?}",
            task_record.state
        );

        if let TaskState::CancelRequested { reason, .. } = &task_record.state {
            crate::assert_with_log!(
                reason.kind == CancelKind::Shutdown,
                "task cancel kind",
                CancelKind::Shutdown,
                reason.kind
            );
        }
        crate::test_complete!("cancel_request_strengthens_existing_reason");
    }

    #[test]
    fn can_region_finalize_with_all_tasks_done() {
        init_test("can_region_finalize_with_all_tasks_done");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Not finalizable while task is live
        let can_finalize = state.can_region_finalize(region);
        crate::assert_with_log!(
            !can_finalize,
            "cannot finalize with live task",
            false,
            can_finalize
        );

        // Complete the task
        state
            .task_mut(task)
            .expect("task missing")
            .complete(Outcome::Ok(()));

        // Now region can finalize
        let can_finalize = state.can_region_finalize(region);
        crate::assert_with_log!(can_finalize, "can finalize", true, can_finalize);
        crate::test_complete!("can_region_finalize_with_all_tasks_done");
    }

    #[test]
    fn can_region_finalize_requires_child_regions_closed() {
        init_test("can_region_finalize_requires_child_regions_closed");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);

        // Child region is Open, so root cannot finalize
        let can_finalize = state.can_region_finalize(root);
        crate::assert_with_log!(
            !can_finalize,
            "cannot finalize with open child",
            false,
            can_finalize
        );

        // Close the child region
        let child_record = state
            .regions
            .get_mut(child.arena_index())
            .expect("child missing");
        child_record.begin_close(None);
        child_record.begin_finalize();
        child_record.complete_close();

        // Now root can finalize
        let can_finalize = state.can_region_finalize(root);
        crate::assert_with_log!(can_finalize, "can finalize", true, can_finalize);
        crate::test_complete!("can_region_finalize_requires_child_regions_closed");
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn register_sync_finalizer() {
        init_test("register_sync_finalizer");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        crate::assert_with_log!(
            state.region_finalizers_empty(region),
            "finalizers empty",
            true,
            state.region_finalizers_empty(region)
        );
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 0,
            "finalizer count",
            0usize,
            state.region_finalizer_count(region)
        );

        // Register a sync finalizer
        let registered = state.register_sync_finalizer(region, || {});
        crate::assert_with_log!(registered, "register sync finalizer", true, registered);

        crate::assert_with_log!(
            !state.region_finalizers_empty(region),
            "finalizers not empty",
            false,
            state.region_finalizers_empty(region)
        );
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 1,
            "finalizer count",
            1usize,
            state.region_finalizer_count(region)
        );
        crate::test_complete!("register_sync_finalizer");
    }

    #[test]
    fn register_async_finalizer() {
        init_test("register_async_finalizer");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let registered = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "register async finalizer", true, registered);
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 1,
            "finalizer count",
            1usize,
            state.region_finalizer_count(region)
        );
        crate::test_complete!("register_async_finalizer");
    }

    #[test]
    fn register_finalizer_fails_when_region_not_open() {
        init_test("register_finalizer_fails_when_region_not_open");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Close the region
        state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .begin_close(None);

        // Registration should fail
        let sync_ok = state.register_sync_finalizer(region, || {});
        let async_ok = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(!sync_ok, "sync finalizer rejected", false, sync_ok);
        crate::assert_with_log!(!async_ok, "async finalizer rejected", false, async_ok);
        crate::test_complete!("register_finalizer_fails_when_region_not_open");
    }

    #[test]
    fn register_finalizer_fails_for_nonexistent_region() {
        init_test("register_finalizer_fails_for_nonexistent_region");
        let mut state = RuntimeState::new();
        let fake_region = RegionId::from_arena(ArenaIndex::new(999, 0));

        let sync_ok = state.register_sync_finalizer(fake_region, || {});
        let async_ok = state.register_async_finalizer(fake_region, async {});
        crate::assert_with_log!(!sync_ok, "sync finalizer rejected", false, sync_ok);
        crate::assert_with_log!(!async_ok, "async finalizer rejected", false, async_ok);
        crate::test_complete!("register_finalizer_fails_for_nonexistent_region");
    }

    #[test]
    fn pop_region_finalizer_lifo() {
        init_test("pop_region_finalizer_lifo");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let order = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        // Register finalizers: 1, 2, 3
        state.register_sync_finalizer(region, move || o1.lock().push(1));
        state.register_sync_finalizer(region, move || o2.lock().push(2));
        state.register_sync_finalizer(region, move || o3.lock().push(3));

        // Pop and execute in LIFO order
        while let Some(finalizer) = state.pop_region_finalizer(region) {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        let observed = order.lock().clone();
        crate::assert_with_log!(
            observed == vec![3, 2, 1],
            "finalizer order",
            vec![3, 2, 1],
            observed
        );
        crate::test_complete!("pop_region_finalizer_lifo");
    }

    #[test]
    fn run_sync_finalizers_executes_and_returns_async() {
        init_test("run_sync_finalizers_executes_and_returns_async");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let sync_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sync_called_clone = sync_called.clone();

        // Register mix of sync and async finalizers
        // Execution Order (LIFO): Sync(empty), Async, Sync(flag=true)
        state.register_sync_finalizer(region, move || {
            sync_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        state.register_async_finalizer(region, async {});
        state.register_sync_finalizer(region, || {}); // Another sync

        // First pass: runs the top Sync(empty), stops at Async
        let async_finalizer = state.run_sync_finalizers(region);

        // The first sync finalizer (bottom of stack) should NOT have run yet due to async barrier
        let sync_flag = sync_called.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(
            !sync_flag,
            "first sync finalizer NOT called yet",
            false,
            sync_flag
        );

        // One async finalizer should be returned
        crate::assert_with_log!(
            async_finalizer.is_some(),
            "async finalizer returned",
            true,
            async_finalizer.is_some()
        );
        let is_async = matches!(async_finalizer, Some(Finalizer::Async(_)));
        crate::assert_with_log!(is_async, "is async", true, is_async);

        // Second pass: runs the remaining Sync(flag=true)
        let remaining = state.run_sync_finalizers(region);
        crate::assert_with_log!(
            remaining.is_none(),
            "no more async",
            true,
            remaining.is_none()
        );

        // Now the first sync finalizer should have run
        let sync_flag = sync_called.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(sync_flag, "first sync finalizer called", true, sync_flag);

        // All finalizers should be cleared from region
        let empty = state.region_finalizers_empty(region);
        crate::assert_with_log!(empty, "finalizers cleared", true, empty);
        crate::test_complete!("run_sync_finalizers_executes_and_returns_async");
    }

    #[test]
    fn can_region_complete_close_requires_finalizing_state() {
        init_test("can_region_complete_close_requires_finalizing_state");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Must be in Finalizing state
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close when not finalizing",
            false,
            can_close
        );

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Now it can complete (no finalizers)
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close", true, can_close);
        crate::test_complete!("can_region_complete_close_requires_finalizing_state");
    }

    #[test]
    fn can_region_complete_close_checks_finalizers() {
        init_test("can_region_complete_close_checks_finalizers");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Add finalizer while open
        state.register_sync_finalizer(region, || {});

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Can't complete while finalizers pending
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close with pending finalizers",
            false,
            can_close
        );

        // Run the finalizers
        let _ = state.run_sync_finalizers(region);

        // Now can complete
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close", true, can_close);
        crate::test_complete!("can_region_complete_close_checks_finalizers");
    }

    #[test]
    fn task_completed_removes_task_from_region() {
        init_test("task_completed_removes_task_from_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Insert some tasks
        let task1 = insert_task(&mut state, region);
        let task2 = insert_task(&mut state, region);
        let task3 = insert_task(&mut state, region);

        // Verify all tasks are in the region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let task_ids = region_record.task_ids();
        crate::assert_with_log!(task_ids.len() == 3, "task count", 3usize, task_ids.len());
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            task_ids.contains(&task2),
            "contains task2",
            true,
            task_ids.contains(&task2)
        );
        crate::assert_with_log!(
            task_ids.contains(&task3),
            "contains task3",
            true,
            task_ids.contains(&task3)
        );

        // Complete task2 (transition to Completed state first)
        state
            .task_mut(task2)
            .expect("task2")
            .complete(Outcome::Ok(()));

        // Call task_completed to notify the runtime
        let waiters = state.task_completed(task2);
        crate::assert_with_log!(waiters.is_empty(), "no waiters", true, waiters.is_empty()); // No waiters registered

        // Verify task2 is removed from the region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let task_ids = region_record.task_ids();
        crate::assert_with_log!(task_ids.len() == 2, "task count", 2usize, task_ids.len());
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            !task_ids.contains(&task2),
            "task2 removed",
            false,
            task_ids.contains(&task2)
        );
        crate::assert_with_log!(
            task_ids.contains(&task3),
            "contains task3",
            true,
            task_ids.contains(&task3)
        );

        // Verify task2 is removed from the state
        let removed = state.task(task2).is_none();
        crate::assert_with_log!(removed, "task2 removed from state", true, removed);

        // Complete remaining tasks
        state
            .task_mut(task1)
            .expect("task1")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task1);

        state
            .task_mut(task3)
            .expect("task3")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task3);

        // Verify all tasks removed from region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let empty = region_record.task_ids().is_empty();
        crate::assert_with_log!(empty, "region tasks empty", true, empty);
        crate::test_complete!("task_completed_removes_task_from_region");
    }

    #[test]
    fn spawn_rejected_when_task_limit_reached() {
        init_test("spawn_rejected_when_task_limit_reached");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let limits = RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        };
        let set = state.set_region_limits(region, limits);
        crate::assert_with_log!(set, "limits set", true, set);

        let (task_id, _handle) = state
            .create_task(region, Budget::INFINITE, async { 1_u8 })
            .expect("first task");
        let result = state.create_task(region, Budget::INFINITE, async { 2_u8 });
        let rejected = matches!(result, Err(SpawnError::RegionAtCapacity { .. }));
        crate::assert_with_log!(rejected, "spawn rejected", true, rejected);
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let tasks = region_record.task_ids();
        crate::assert_with_log!(tasks.len() == 1, "one task live", 1, tasks.len());
        crate::assert_with_log!(
            tasks.contains(&task_id),
            "task id preserved",
            true,
            tasks.contains(&task_id)
        );
        crate::assert_with_log!(
            state.tasks_arena().len() == 1,
            "arena len stable",
            1,
            state.tasks_arena().len()
        );
        crate::test_complete!("spawn_rejected_when_task_limit_reached");
    }

    #[test]
    fn obligation_rejected_when_limit_reached() {
        init_test("obligation_rejected_when_limit_reached");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let limits = RegionLimits {
            max_obligations: Some(0),
            ..RegionLimits::unlimited()
        };
        let set = state.set_region_limits(region, limits);
        crate::assert_with_log!(set, "limits set", true, set);

        let holder = insert_task(&mut state, region);
        let err = state
            .create_obligation(ObligationKind::IoOp, holder, region, None)
            .expect_err("obligation limit enforced");
        crate::assert_with_log!(
            err.kind() == ErrorKind::AdmissionDenied,
            "admission denied",
            ErrorKind::AdmissionDenied,
            err.kind()
        );
        let pending = state.pending_obligation_count();
        crate::assert_with_log!(pending == 0, "no obligations recorded", 0, pending);
        crate::test_complete!("obligation_rejected_when_limit_reached");
    }

    #[test]
    fn cancel_request_should_prevent_new_spawns() {
        init_test("cancel_request_should_prevent_new_spawns");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Request cancellation
        let _ = state.cancel_request(region, &CancelReason::user("stop"), None);

        // Verify state transition
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let region_state = region_record.state();
        let can_spawn = region_state.can_spawn();
        crate::assert_with_log!(
            !can_spawn,
            "region no longer accepts spawns",
            false,
            can_spawn
        );

        // Verify spawning is rejected with error (not panic)
        let result = state.create_task(region, Budget::INFINITE, async { 42 });
        let rejected = matches!(result, Err(SpawnError::RegionClosed(_)));
        crate::assert_with_log!(rejected, "spawn rejected", true, rejected);
        crate::test_complete!("cancel_request_should_prevent_new_spawns");
    }

    // =========================================================================
    // IoDriver Integration Tests
    // =========================================================================

    #[test]
    fn new_creates_state_without_io_driver() {
        init_test("new_creates_state_without_io_driver");
        let state = RuntimeState::new();
        crate::assert_with_log!(
            !state.has_io_driver(),
            "no io driver",
            false,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_none(),
            "io driver none",
            true,
            state.io_driver().is_none()
        );
        crate::test_complete!("new_creates_state_without_io_driver");
    }

    #[test]
    fn without_reactor_creates_state_without_io_driver() {
        init_test("without_reactor_creates_state_without_io_driver");
        let state = RuntimeState::without_reactor();
        crate::assert_with_log!(
            !state.has_io_driver(),
            "no io driver",
            false,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_none(),
            "io driver none",
            true,
            state.io_driver().is_none()
        );
        crate::test_complete!("without_reactor_creates_state_without_io_driver");
    }

    #[test]
    fn with_reactor_creates_state_with_io_driver() {
        init_test("with_reactor_creates_state_with_io_driver");
        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        crate::assert_with_log!(
            state.has_io_driver(),
            "has io driver",
            true,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_some(),
            "io driver some",
            true,
            state.io_driver().is_some()
        );

        // Verify the driver is functional
        let driver = state.io_driver().unwrap();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.waker_count() == 0,
            "waker count",
            0usize,
            driver.waker_count()
        );
        crate::test_complete!("with_reactor_creates_state_with_io_driver");
    }

    #[test]
    fn io_driver_mut_allows_modification() {
        init_test("io_driver_mut_allows_modification");

        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        // Mutably access driver to register a waker
        let waker_state = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_state);
        {
            let mut driver = state.io_driver_mut().unwrap();
            let _key = driver.register_waker(waker);
        }

        // Verify registration
        let waker_count = state.io_driver().unwrap().waker_count();
        crate::assert_with_log!(waker_count == 1, "waker count", 1usize, waker_count);
        let empty = state.io_driver().unwrap().is_empty();
        crate::assert_with_log!(!empty, "driver not empty", false, empty);
        crate::test_complete!("io_driver_mut_allows_modification");
    }

    #[test]
    fn is_quiescent_considers_io_driver() {
        init_test("is_quiescent_considers_io_driver");

        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        // Initially quiescent (no tasks, no I/O registrations)
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "initial quiescent", true, quiescent);

        // Register a waker
        let waker_state = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_state);
        let key = {
            let mut driver = state.io_driver_mut().unwrap();
            driver.register_waker(waker)
        };

        // No longer quiescent due to I/O registration
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(!quiescent, "not quiescent", false, quiescent);

        // Deregister
        {
            let mut driver = state.io_driver_mut().unwrap();
            driver.deregister_waker(key);
        }

        // Quiescent again
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent again", true, quiescent);
        crate::test_complete!("is_quiescent_considers_io_driver");
    }

    #[test]
    fn is_quiescent_without_io_driver_ignores_io() {
        init_test("is_quiescent_without_io_driver_ignores_io");
        let state = RuntimeState::new();

        // Quiescent without I/O driver
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
        crate::test_complete!("is_quiescent_without_io_driver_ignores_io");
    }

    // =========================================================================
    // Cancellation + Obligations Lifecycle Tests (bd-38kk)
    // =========================================================================

    #[test]
    #[allow(clippy::too_many_lines)]
    fn cancel_drain_finalize_full_lifecycle() {
        init_test("cancel_drain_finalize_full_lifecycle");
        let metrics = Arc::new(TestMetrics::default());
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);

        // Spawn tasks in the region
        let task1 = insert_task(&mut state, root);
        let task2 = insert_task(&mut state, root);

        // Register a sync finalizer while region is open
        let finalizer_called = Arc::new(AtomicBool::new(false));
        let finalizer_flag = finalizer_called.clone();
        state.register_sync_finalizer(root, move || {
            finalizer_flag.store(true, Ordering::SeqCst);
        });

        // Phase 1: Cancel request → region enters Closing
        let tasks_to_schedule = state.cancel_request(root, &CancelReason::timeout(), None);
        crate::assert_with_log!(
            tasks_to_schedule.len() == 2,
            "both tasks scheduled for cancel",
            2usize,
            tasks_to_schedule.len()
        );
        let region_state = state
            .regions
            .get(root.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closing,
            "region closing after cancel request",
            crate::record::region::RegionState::Closing,
            region_state
        );

        // Phase 2: First task completes with Cancelled outcome → still draining
        state
            .task_mut(task1)
            .expect("task1")
            .complete(Outcome::Cancelled(CancelReason::timeout()));
        let _ = state.task_completed(task1);
        let region_state = state
            .regions
            .get(root.arena_index())
            .expect("region")
            .state();
        // Region should still be Closing (one task remains)
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closing,
            "region still closing with live task",
            crate::record::region::RegionState::Closing,
            region_state
        );
        let finalizer_ran = finalizer_called.load(Ordering::SeqCst);
        crate::assert_with_log!(
            !finalizer_ran,
            "finalizer not yet called",
            false,
            finalizer_ran
        );

        // Phase 3: Second task completes → triggers advance_region_state
        // → Finalizing (no children, no tasks) → runs sync finalizers → Closed
        state
            .task_mut(task2)
            .expect("task2")
            .complete(Outcome::Cancelled(CancelReason::timeout()));
        let _ = state.task_completed(task2);

        // Region should transition through Finalizing → Closed
        // (sync finalizers are run inline by advance_region_state)
        let region_state = state
            .regions
            .get(root.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closed,
            "region closed after all tasks complete",
            crate::record::region::RegionState::Closed,
            region_state
        );
        let finalizer_ran = finalizer_called.load(Ordering::SeqCst);
        crate::assert_with_log!(
            finalizer_ran,
            "finalizer was called during finalization",
            true,
            finalizer_ran
        );

        // Verify metrics recorded both cancelled completions
        let cancelled_count = metrics
            .completions
            .lock()
            .iter()
            .filter(|o| **o == OutcomeKind::Cancelled)
            .count();
        crate::assert_with_log!(
            cancelled_count == 2,
            "cancelled completions count",
            2usize,
            cancelled_count
        );

        // Verify trace contains both CancelRequest and task completion events
        let events = state.trace.snapshot();
        let cancel_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::CancelRequest)
            .count();
        crate::assert_with_log!(
            cancel_events >= 1,
            "cancel request trace events",
            true,
            cancel_events >= 1
        );
        crate::test_complete!("cancel_drain_finalize_full_lifecycle");
    }

    #[test]
    fn cancel_drain_finalize_nested_regions() {
        init_test("cancel_drain_finalize_nested_regions");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);

        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);

        // Cancel the root region (propagates to child)
        let _ = state.cancel_request(root, &CancelReason::user("stop"), None);

        // Complete child task first
        state
            .task_mut(child_task)
            .expect("child_task")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(child_task);

        // Child region should close since it has no tasks and no children
        let child_state = state
            .regions
            .get(child.arena_index())
            .expect("child region")
            .state();
        crate::assert_with_log!(
            child_state == crate::record::region::RegionState::Closed,
            "child closed after its task completes",
            crate::record::region::RegionState::Closed,
            child_state
        );

        // Root should still be open (has root_task)
        let root_state = state
            .regions
            .get(root.arena_index())
            .expect("root region")
            .state();
        let root_closing = matches!(
            root_state,
            crate::record::region::RegionState::Closing
                | crate::record::region::RegionState::Draining
        );
        crate::assert_with_log!(
            root_closing,
            "root still closing/draining with live task",
            true,
            root_closing
        );

        // Complete root task → root should close
        state
            .task_mut(root_task)
            .expect("root_task")
            .complete(Outcome::Cancelled(CancelReason::user("stop")));
        let _ = state.task_completed(root_task);

        let root_state = state
            .regions
            .get(root.arena_index())
            .expect("root region")
            .state();
        crate::assert_with_log!(
            root_state == crate::record::region::RegionState::Closed,
            "root closed after all tasks and children done",
            crate::record::region::RegionState::Closed,
            root_state
        );
        crate::test_complete!("cancel_drain_finalize_nested_regions");
    }

    #[test]
    fn obligations_auto_aborted_on_cancelled_task_completion() {
        init_test("obligations_auto_aborted_on_cancelled_task_completion");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Silent;
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create obligations of different kinds
        let obl_send = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create send permit");
        let obl_ack = state
            .create_obligation(ObligationKind::Ack, task, region, None)
            .expect("create ack");
        let obl_io = state
            .create_obligation(ObligationKind::IoOp, task, region, None)
            .expect("create io op");

        crate::assert_with_log!(
            state.pending_obligation_count() == 3,
            "three pending obligations",
            3usize,
            state.pending_obligation_count()
        );

        // Cancel region → task gets cancel-requested
        let _ = state.cancel_request(region, &CancelReason::timeout(), None);

        // Complete task with Cancelled outcome
        // task_completed() should auto-abort orphaned obligations
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::timeout()));
        let _ = state.task_completed(task);

        // All obligations should be resolved (aborted by task_completed)
        for obl_id in [obl_send, obl_ack, obl_io] {
            let record = state
                .obligations
                .get(obl_id.arena_index())
                .expect("obligation still in arena");
            crate::assert_with_log!(
                !record.is_pending(),
                "obligation resolved after task cancel",
                false,
                record.is_pending()
            );
        }

        // No pending obligations remain
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "zero pending obligations",
            0usize,
            state.pending_obligation_count()
        );

        // Verify trace has obligation events
        let events = state.trace.snapshot();
        let abort_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationAbort)
            .count();
        crate::assert_with_log!(
            abort_events == 3,
            "three obligation abort trace events",
            3usize,
            abort_events
        );
        crate::test_complete!("obligations_auto_aborted_on_cancelled_task_completion");
    }

    #[test]
    fn obligation_commit_before_cancel_then_drain() {
        init_test("obligation_commit_before_cancel_then_drain");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create obligation and commit it before cancellation
        let obl = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create obligation");
        let _ = state.commit_obligation(obl).expect("commit before cancel");

        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "no pending after commit",
            0usize,
            state.pending_obligation_count()
        );

        // Cancel and complete the task
        let _ = state.cancel_request(region, &CancelReason::timeout(), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::timeout()));
        let _ = state.task_completed(task);

        // Region should close cleanly (no leaks, obligation was already committed)
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closed,
            "region closed cleanly",
            crate::record::region::RegionState::Closed,
            region_state
        );

        // Verify trace has commit event
        let events = state.trace.snapshot();
        let commit_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationCommit)
            .count();
        crate::assert_with_log!(
            commit_events == 1,
            "one obligation commit event",
            1usize,
            commit_events
        );
        crate::test_complete!("obligation_commit_before_cancel_then_drain");
    }

    #[test]
    fn region_close_blocked_by_pending_obligations() {
        init_test("region_close_blocked_by_pending_obligations");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Silent;
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create an obligation
        let obl = state
            .create_obligation(ObligationKind::Lease, task, region, None)
            .expect("create obligation");

        // Transition region to Finalizing manually
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Complete the task to make it terminal
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));

        // can_region_complete_close should return false (pending obligation)
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close with pending obligation",
            false,
            can_close
        );

        // Commit the obligation
        let _ = state.commit_obligation(obl).expect("commit obligation");

        // Now it should be closable (task is terminal, obligation resolved)
        // Remove the task from the region to simulate full completion
        if let Some(region_rec) = state.regions.get(region.arena_index()) {
            region_rec.remove_task(task);
        }
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            can_close,
            "can close after obligation committed",
            true,
            can_close
        );
        crate::test_complete!("region_close_blocked_by_pending_obligations");
    }

    #[test]
    fn cancel_with_obligations_full_trace_lifecycle() {
        init_test("cancel_with_obligations_full_trace_lifecycle");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);
        state.record_task_spawn(task, region);

        // Create obligation
        let _obl = state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("test-permit".to_string()),
            )
            .expect("create obligation");

        // Cancel and complete
        let _ = state.cancel_request(region, &CancelReason::deadline(), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::deadline()));
        let _ = state.task_completed(task);

        // Verify full trace event sequence
        let events = state.trace.snapshot();
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();

        // Should contain: Spawn, ObligationReserve, CancelRequest, ObligationAbort
        let has_spawn = kinds.contains(&TraceEventKind::Spawn);
        let has_reserve = kinds.contains(&TraceEventKind::ObligationReserve);
        let has_cancel = kinds.contains(&TraceEventKind::CancelRequest);
        let has_abort = kinds.contains(&TraceEventKind::ObligationAbort);

        crate::assert_with_log!(has_spawn, "trace has spawn", true, has_spawn);
        crate::assert_with_log!(
            has_reserve,
            "trace has obligation reserve",
            true,
            has_reserve
        );
        crate::assert_with_log!(has_cancel, "trace has cancel request", true, has_cancel);
        crate::assert_with_log!(has_abort, "trace has obligation abort", true, has_abort);

        // Verify ordering: reserve < cancel < abort
        let reserve_seq = events
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationReserve)
            .map(|e| e.seq)
            .expect("reserve event");
        let cancel_seq = events
            .iter()
            .find(|e| e.kind == TraceEventKind::CancelRequest)
            .map(|e| e.seq)
            .expect("cancel event");
        let abort_seq = events
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .map(|e| e.seq)
            .expect("abort event");
        crate::assert_with_log!(
            reserve_seq < cancel_seq,
            "reserve before cancel",
            true,
            reserve_seq < cancel_seq
        );
        crate::assert_with_log!(
            cancel_seq < abort_seq,
            "cancel before abort",
            true,
            cancel_seq < abort_seq
        );

        // Region should be fully closed
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closed,
            "region closed",
            crate::record::region::RegionState::Closed,
            region_state
        );
        crate::test_complete!("cancel_with_obligations_full_trace_lifecycle");
    }

    #[test]
    fn mixed_obligation_resolution_during_cancel() {
        init_test("mixed_obligation_resolution_during_cancel");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create three obligations
        let obl_committed = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create send");
        let obl_aborted = state
            .create_obligation(ObligationKind::Ack, task, region, None)
            .expect("create ack");
        let obl_orphaned = state
            .create_obligation(ObligationKind::IoOp, task, region, None)
            .expect("create io");

        // Commit one before cancellation
        let _ = state.commit_obligation(obl_committed).expect("commit send");

        // Explicitly abort another before cancellation
        let _ = state
            .abort_obligation(obl_aborted, ObligationAbortReason::Explicit)
            .expect("abort ack");

        crate::assert_with_log!(
            state.pending_obligation_count() == 1,
            "one obligation still pending",
            1usize,
            state.pending_obligation_count()
        );

        // Cancel and complete task (obl_orphaned should be auto-aborted)
        let _ = state.cancel_request(region, &CancelReason::shutdown(), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::shutdown()));
        let _ = state.task_completed(task);

        // All obligations resolved
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "zero pending obligations",
            0usize,
            state.pending_obligation_count()
        );

        // Verify the orphaned one was aborted
        let orphaned_record = state
            .obligations
            .get(obl_orphaned.arena_index())
            .expect("orphaned obligation");
        crate::assert_with_log!(
            !orphaned_record.is_pending(),
            "orphaned obligation resolved",
            false,
            orphaned_record.is_pending()
        );

        // Region should be closed
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closed,
            "region closed",
            crate::record::region::RegionState::Closed,
            region_state
        );
        crate::test_complete!("mixed_obligation_resolution_during_cancel");
    }

    #[test]
    fn region_quiescence_requires_no_live_children_or_tasks() {
        init_test("region_quiescence_requires_no_live_children_or_tasks");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let task = insert_task(&mut state, child);

        // Root cannot finalize: has open child with live task
        let can_finalize_root = state.can_region_finalize(root);
        crate::assert_with_log!(
            !can_finalize_root,
            "root cannot finalize with open child",
            false,
            can_finalize_root
        );

        // Child cannot finalize: has live task
        let can_finalize_child = state.can_region_finalize(child);
        crate::assert_with_log!(
            !can_finalize_child,
            "child cannot finalize with live task",
            false,
            can_finalize_child
        );

        // Cancel and complete everything
        let _ = state.cancel_request(root, &CancelReason::user("done"), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(task);

        // Both should now be closed (advance_region_state drives the cascade)
        let child_state = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        crate::assert_with_log!(
            child_state == crate::record::region::RegionState::Closed,
            "child closed",
            crate::record::region::RegionState::Closed,
            child_state
        );
        let root_state = state.regions.get(root.arena_index()).expect("root").state();
        crate::assert_with_log!(
            root_state == crate::record::region::RegionState::Closed,
            "root closed",
            crate::record::region::RegionState::Closed,
            root_state
        );
        crate::test_complete!("region_quiescence_requires_no_live_children_or_tasks");
    }

    #[test]
    fn cancel_prevents_new_obligation_creation() {
        init_test("cancel_prevents_new_obligation_creation");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Cancel the region
        let _ = state.cancel_request(region, &CancelReason::timeout(), None);

        // Attempt to create an obligation in a cancelled region should fail
        let result = state.create_obligation(ObligationKind::SendPermit, task, region, None);
        let rejected = result.is_err();
        crate::assert_with_log!(
            rejected,
            "obligation creation rejected in cancelled region",
            true,
            rejected
        );
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "no obligations created",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!("cancel_prevents_new_obligation_creation");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn multiple_tasks_obligations_cancel_drain_finalize() {
        init_test("multiple_tasks_obligations_cancel_drain_finalize");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task_a = insert_task(&mut state, region);
        let task_b = insert_task(&mut state, region);

        // Each task holds obligations
        let obl_a = state
            .create_obligation(ObligationKind::SendPermit, task_a, region, None)
            .expect("obl_a");
        let obl_b1 = state
            .create_obligation(ObligationKind::Ack, task_b, region, None)
            .expect("obl_b1");
        let obl_b2 = state
            .create_obligation(ObligationKind::Lease, task_b, region, None)
            .expect("obl_b2");

        crate::assert_with_log!(
            state.pending_obligation_count() == 3,
            "three pending",
            3usize,
            state.pending_obligation_count()
        );

        // Cancel the region
        let _ = state.cancel_request(region, &CancelReason::deadline(), None);

        // task_a commits its obligation during cleanup, then completes
        let _ = state.commit_obligation(obl_a).expect("commit obl_a");
        state
            .task_mut(task_a)
            .expect("task_a")
            .complete(Outcome::Cancelled(CancelReason::deadline()));
        let _ = state.task_completed(task_a);

        // Region still open: task_b still alive with obligations
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closing,
            "region still closing",
            crate::record::region::RegionState::Closing,
            region_state
        );
        crate::assert_with_log!(
            state.pending_obligation_count() == 2,
            "two pending (task_b's)",
            2usize,
            state.pending_obligation_count()
        );

        // task_b completes → its orphaned obligations auto-aborted
        state
            .task_mut(task_b)
            .expect("task_b")
            .complete(Outcome::Cancelled(CancelReason::deadline()));
        let _ = state.task_completed(task_b);

        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "all obligations resolved",
            0usize,
            state.pending_obligation_count()
        );

        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closed,
            "region closed",
            crate::record::region::RegionState::Closed,
            region_state
        );

        // Verify trace events
        let events = state.trace.snapshot();
        let reserve_count = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationReserve)
            .count();
        let commit_count = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationCommit)
            .count();
        let abort_count = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationAbort)
            .count();
        crate::assert_with_log!(
            reserve_count == 3,
            "three reserve events",
            3usize,
            reserve_count
        );
        crate::assert_with_log!(
            commit_count == 1,
            "one commit event (obl_a)",
            1usize,
            commit_count
        );
        crate::assert_with_log!(
            abort_count == 2,
            "two abort events (obl_b1 + obl_b2)",
            2usize,
            abort_count
        );
        // Suppress unused variable warnings
        let _ = obl_b1;
        let _ = obl_b2;
        crate::test_complete!("multiple_tasks_obligations_cancel_drain_finalize");
    }

    /// Integration test with real epoll reactor.
    #[cfg(target_os = "linux")]
    mod epoll_integration {
        use super::*;
        use crate::runtime::reactor::{EpollReactor, Interest};
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Wake, Waker};
        use std::time::Duration;

        struct FlagWaker(AtomicBool);
        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        #[test]
        fn runtime_state_with_epoll_reactor() {
            super::init_test("runtime_state_with_epoll_reactor");
            let reactor = Arc::new(EpollReactor::new().expect("create reactor"));
            let state = RuntimeState::with_reactor(reactor);

            crate::assert_with_log!(
                state.has_io_driver(),
                "has io driver",
                true,
                state.has_io_driver()
            );
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(quiescent, "quiescent", true, quiescent);

            // Create a socket pair
            let (sock_read, mut sock_write) = UnixStream::pair().expect("socket pair");

            // Register with the driver
            let waker_state = Arc::new(FlagWaker(AtomicBool::new(false)));
            let waker = Waker::from(waker_state.clone());

            let registration = {
                let mut driver = state.io_driver_mut().unwrap();
                driver
                    .register(&sock_read, Interest::READABLE, waker)
                    .expect("register")
            };

            // Not quiescent due to I/O registration
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(!quiescent, "not quiescent", false, quiescent);

            // Make socket readable
            sock_write.write_all(b"hello").expect("write");

            // Turn the driver to dispatch waker
            let count = {
                let mut driver = state.io_driver_mut().unwrap();
                driver.turn(Some(Duration::from_millis(100))).expect("turn")
            };

            crate::assert_with_log!(count >= 1, "event count", true, count >= 1);
            let flag = waker_state.0.load(Ordering::SeqCst);
            crate::assert_with_log!(flag, "waker fired", true, flag);

            // Deregister and verify quiescence
            {
                let mut driver = state.io_driver_mut().unwrap();
                driver.deregister(registration).expect("deregister");
            }
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
            crate::test_complete!("runtime_state_with_epoll_reactor");
        }
    }

    // =========================================================================
    // OBLIGATION LEAK ESCALATION POLICY TESTS (bd-n6xm4)
    // =========================================================================

    /// Helper: create a state with an obligation that will leak on task completion.
    /// Returns (state, region, task, obligation_id).
    fn setup_leakable_obligation(
        response: ObligationLeakResponse,
    ) -> (RuntimeState, RegionId, TaskId, ObligationId) {
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(response);
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);
        let obl = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create obligation");
        (state, region, task, obl)
    }

    /// Helper: complete a task with Ok outcome (triggers leak detection for
    /// pending obligations, unlike Cancelled which auto-aborts them).
    fn complete_task_ok(state: &mut RuntimeState, task: TaskId) {
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task);
    }

    #[test]
    fn leak_response_silent_marks_leaked_no_log() {
        init_test("leak_response_silent_marks_leaked_no_log");
        let (mut state, _region, task, obl) =
            setup_leakable_obligation(ObligationLeakResponse::Silent);

        complete_task_ok(&mut state, task);

        // Obligation should be in Leaked state
        let record = state.obligations.get(obl.arena_index()).expect("obl");
        crate::assert_with_log!(
            record.state == ObligationState::Leaked,
            "obligation leaked",
            ObligationState::Leaked,
            record.state
        );
        crate::assert_with_log!(
            state.leak_count() == 1,
            "leak count incremented",
            1u64,
            state.leak_count()
        );
        crate::test_complete!("leak_response_silent_marks_leaked_no_log");
    }

    #[test]
    fn leak_response_log_marks_leaked() {
        init_test("leak_response_log_marks_leaked");
        let (mut state, _region, task, obl) =
            setup_leakable_obligation(ObligationLeakResponse::Log);

        complete_task_ok(&mut state, task);

        let record = state.obligations.get(obl.arena_index()).expect("obl");
        crate::assert_with_log!(
            record.state == ObligationState::Leaked,
            "obligation leaked via Log mode",
            ObligationState::Leaked,
            record.state
        );

        // Trace should contain ObligationLeak event
        let events = state.trace.snapshot();
        let leak_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationLeak)
            .count();
        crate::assert_with_log!(
            leak_events == 1,
            "one leak trace event",
            1usize,
            leak_events
        );
        crate::assert_with_log!(
            state.leak_count() == 1,
            "leak count",
            1u64,
            state.leak_count()
        );
        crate::test_complete!("leak_response_log_marks_leaked");
    }

    #[test]
    fn leak_response_recover_aborts_instead_of_leaking() {
        init_test("leak_response_recover_aborts_instead_of_leaking");
        let (mut state, _region, task, obl) =
            setup_leakable_obligation(ObligationLeakResponse::Recover);

        complete_task_ok(&mut state, task);

        // With Recover, the obligation is aborted (not leaked)
        let record = state.obligations.get(obl.arena_index()).expect("obl");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "obligation aborted by recovery",
            ObligationState::Aborted,
            record.state
        );

        // Trace should contain ObligationAbort (not ObligationLeak)
        let events = state.trace.snapshot();
        let abort_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationAbort)
            .count();
        let leak_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationLeak)
            .count();
        crate::assert_with_log!(
            abort_events >= 1,
            "abort trace event from recovery",
            true,
            abort_events >= 1
        );
        crate::assert_with_log!(
            leak_events == 0,
            "no leak trace event in recover mode",
            0usize,
            leak_events
        );
        crate::assert_with_log!(
            state.leak_count() == 1,
            "leak count still incremented",
            1u64,
            state.leak_count()
        );
        crate::test_complete!("leak_response_recover_aborts_instead_of_leaking");
    }

    #[test]
    #[should_panic(expected = "obligation leak")]
    fn leak_response_panic_panics() {
        init_test("leak_response_panic_panics");
        let (mut state, _region, task, _obl) =
            setup_leakable_obligation(ObligationLeakResponse::Panic);

        complete_task_ok(&mut state, task);
        // Should panic before reaching here
    }

    #[test]
    fn leak_escalation_from_log_to_panic() {
        init_test("leak_escalation_from_log_to_panic");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Log);
        state.set_leak_escalation(Some(LeakEscalation::new(3, ObligationLeakResponse::Panic)));
        let region = state.create_root_region(Budget::INFINITE);

        // First two leaks should be logged (not panic)
        for i in 0u64..2 {
            let task = insert_task(&mut state, region);
            state
                .create_obligation(ObligationKind::SendPermit, task, region, None)
                .expect("create obligation");
            complete_task_ok(&mut state, task);
            let expected = i + 1;
            crate::assert_with_log!(
                state.leak_count() == expected,
                &format!("leak count after batch {expected}"),
                expected,
                state.leak_count()
            );
        }

        // Third leak should escalate to Panic
        let task = insert_task(&mut state, region);
        state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create obligation");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            complete_task_ok(&mut state, task);
        }));
        crate::assert_with_log!(
            result.is_err(),
            "escalated to panic at threshold",
            true,
            result.is_err()
        );
        crate::test_complete!("leak_escalation_from_log_to_panic");
    }

    #[test]
    fn leak_escalation_from_silent_to_recover() {
        init_test("leak_escalation_from_silent_to_recover");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);
        state.set_leak_escalation(Some(LeakEscalation::new(
            2,
            ObligationLeakResponse::Recover,
        )));
        let region = state.create_root_region(Budget::INFINITE);

        // First leak: Silent mode — obligation gets Leaked state
        let task1 = insert_task(&mut state, region);
        let obl1 = state
            .create_obligation(ObligationKind::Ack, task1, region, None)
            .expect("create");
        complete_task_ok(&mut state, task1);
        let record1 = state.obligations.get(obl1.arena_index()).expect("obl1");
        crate::assert_with_log!(
            record1.state == ObligationState::Leaked,
            "first leak: Leaked state (silent)",
            ObligationState::Leaked,
            record1.state
        );

        // Second leak: escalates to Recover — obligation gets Aborted state
        let task2 = insert_task(&mut state, region);
        let obl2 = state
            .create_obligation(ObligationKind::Lease, task2, region, None)
            .expect("create");
        complete_task_ok(&mut state, task2);
        let record2 = state.obligations.get(obl2.arena_index()).expect("obl2");
        crate::assert_with_log!(
            record2.state == ObligationState::Aborted,
            "second leak: Aborted (recovered)",
            ObligationState::Aborted,
            record2.state
        );
        crate::assert_with_log!(
            state.leak_count() == 2,
            "total leak count",
            2u64,
            state.leak_count()
        );
        crate::test_complete!("leak_escalation_from_silent_to_recover");
    }

    #[test]
    fn leak_count_accumulates_across_tasks() {
        init_test("leak_count_accumulates_across_tasks");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);
        let region = state.create_root_region(Budget::INFINITE);

        // Create 5 tasks, each with 2 obligations — 10 total leaks
        for _ in 0..5 {
            let task = insert_task(&mut state, region);
            state
                .create_obligation(ObligationKind::SendPermit, task, region, None)
                .expect("create");
            state
                .create_obligation(ObligationKind::IoOp, task, region, None)
                .expect("create");
            complete_task_ok(&mut state, task);
        }

        crate::assert_with_log!(
            state.leak_count() == 10,
            "10 cumulative leaks",
            10u64,
            state.leak_count()
        );
        crate::test_complete!("leak_count_accumulates_across_tasks");
    }

    #[test]
    fn no_escalation_when_not_configured() {
        init_test("no_escalation_when_not_configured");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);
        // No escalation configured
        let region = state.create_root_region(Budget::INFINITE);

        // Even after 100 leaks, response stays Silent (no escalation)
        for _ in 0..100 {
            let task = insert_task(&mut state, region);
            state
                .create_obligation(ObligationKind::SendPermit, task, region, None)
                .expect("create");
            complete_task_ok(&mut state, task);
        }

        crate::assert_with_log!(
            state.leak_count() == 100,
            "100 leaks, no panic",
            100u64,
            state.leak_count()
        );
        crate::test_complete!("no_escalation_when_not_configured");
    }

    // ── bd-2wfti: Cross-entity lock ordering regression tests ──────────
    //
    // These tests exercise multi-entity state machine transitions that will
    // need to hold multiple shard locks (B→A→C) once RuntimeState is migrated
    // to ShardedState. They serve as safety nets for that migration.

    #[test]
    #[allow(clippy::too_many_lines)]
    fn three_level_cascade_with_obligations() {
        // Verifies: cancel propagation through 3-level region tree with
        // obligations at each level. Tests the B→A→C lock ordering path
        // through advance_region_state's cascading parent advancement.
        init_test("three_level_cascade_with_obligations");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Silent;
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        // Insert tasks at each level
        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);
        let gc_task = insert_task(&mut state, grandchild);

        // Create obligations at each level
        let _root_obl = state
            .create_obligation(ObligationKind::SendPermit, root_task, root, None)
            .expect("root obl");
        let child_obl = state
            .create_obligation(ObligationKind::Ack, child_task, child, None)
            .expect("child obl");
        let _gc_obl = state
            .create_obligation(ObligationKind::IoOp, gc_task, grandchild, None)
            .expect("gc obl");

        crate::assert_with_log!(
            state.pending_obligation_count() == 3,
            "three pending obligations across tree",
            3usize,
            state.pending_obligation_count()
        );

        // Cancel root (propagates to child and grandchild)
        let tasks_to_schedule = state.cancel_request(root, &CancelReason::user("shutdown"), None);
        crate::assert_with_log!(
            tasks_to_schedule.len() == 3,
            "all three tasks scheduled for cancel",
            3usize,
            tasks_to_schedule.len()
        );

        // Complete leaf-first: grandchild task (gc_obl auto-aborted)
        state
            .task_mut(gc_task)
            .expect("gc_task")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(gc_task);

        // Grandchild region should close (no tasks, no children, no pending obligations)
        let gc_state = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild")
            .state();
        crate::assert_with_log!(
            gc_state == RegionState::Closed,
            "grandchild closed",
            RegionState::Closed,
            gc_state
        );

        // Child still open (child_task alive with child_obl)
        let child_state_now = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        let child_still_active = !matches!(child_state_now, RegionState::Closed);
        crate::assert_with_log!(
            child_still_active,
            "child not yet closed",
            true,
            child_still_active
        );

        // Commit child obligation explicitly, then complete child task
        let _ = state
            .commit_obligation(child_obl)
            .expect("commit child obl");
        state
            .task_mut(child_task)
            .expect("child_task")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(child_task);

        // Child region should close (no tasks, no children, obligation committed)
        let child_state_final = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        crate::assert_with_log!(
            child_state_final == RegionState::Closed,
            "child closed after task + obligation resolved",
            RegionState::Closed,
            child_state_final
        );

        // Root still open (root_task alive with root_obl)
        let root_state_mid = state.regions.get(root.arena_index()).expect("root").state();
        let root_not_closed = !matches!(root_state_mid, RegionState::Closed);
        crate::assert_with_log!(
            root_not_closed,
            "root not yet closed",
            true,
            root_not_closed
        );

        // Complete root task (root_obl orphaned, auto-aborted via leak detection)
        state
            .task_mut(root_task)
            .expect("root_task")
            .complete(Outcome::Cancelled(CancelReason::user("shutdown")));
        let _ = state.task_completed(root_task);

        // Root should close (all children closed, all tasks done, obligations resolved)
        let root_state_final = state.regions.get(root.arena_index()).expect("root").state();
        crate::assert_with_log!(
            root_state_final == RegionState::Closed,
            "root closed after full cascade",
            RegionState::Closed,
            root_state_final
        );

        // All obligations resolved
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "zero pending obligations after cascade",
            0usize,
            state.pending_obligation_count()
        );

        // Verify trace has events for all three levels
        let events = state.trace.snapshot();
        let cancel_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::CancelRequest)
            .count();
        crate::assert_with_log!(
            cancel_events >= 1,
            "cancel trace events emitted",
            true,
            cancel_events >= 1
        );

        let abort_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationAbort)
            .count();
        // gc_obl and root_obl were auto-aborted (child_obl was committed)
        crate::assert_with_log!(
            abort_events >= 2,
            "at least two obligation aborts (gc + root)",
            true,
            abort_events >= 2
        );
        crate::test_complete!("three_level_cascade_with_obligations");
    }

    #[test]
    fn obligation_resolve_advances_draining_region() {
        // Verifies: resolving the last obligation in a draining region
        // triggers advance_region_state through the Finalizing path.
        // This exercises the B→A→C path in for_obligation_resolve.
        init_test("obligation_resolve_advances_draining_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create two obligations
        let obl1 = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("obl1");
        let obl2 = state
            .create_obligation(ObligationKind::Ack, task, region, None)
            .expect("obl2");

        // Cancel region → Closing
        let _ = state.cancel_request(region, &CancelReason::timeout(), None);

        // Complete task (obligations become orphans → auto-aborted only if
        // task_completed detects them). Let's commit one before completing.
        let _ = state.commit_obligation(obl1).expect("commit obl1");

        // Abort the second explicitly
        let _ = state
            .abort_obligation(obl2, ObligationAbortReason::Cancel)
            .expect("abort obl2");

        // Now complete the task
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::timeout()));
        let _ = state.task_completed(task);

        // Region should advance through Finalizing → Closed
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == RegionState::Closed,
            "region closed after obligation resolve + task complete",
            RegionState::Closed,
            region_state
        );

        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "zero pending",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!("obligation_resolve_advances_draining_region");
    }

    #[test]
    fn shardguard_locking_patterns_exercised() {
        use crate::runtime::ShardGuard;
        use crate::runtime::ShardedState;
        use crate::runtime::sharded_state::ShardedConfig;

        // Verifies: ShardGuard factory methods correctly acquire locks
        // for each cross-entity operation pattern.
        // This test validates the ShardGuard infrastructure that will be
        // used when RuntimeState methods are migrated to work with shards.
        init_test("shardguard_locking_patterns_exercised");

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(TestMetrics::default());
        let config = ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            observability: None,
        };
        let shards = ShardedState::new(trace, metrics, config);

        // Verify each guard pattern acquires the correct shards
        {
            let guard = ShardGuard::for_spawn(&shards);
            let has_regions = guard.regions.is_some();
            let has_tasks = guard.tasks.is_some();
            let no_obligations = guard.obligations.is_none();
            drop(guard);
            crate::assert_with_log!(
                has_regions && has_tasks && no_obligations,
                "for_spawn: B+A only",
                true,
                has_regions && has_tasks && no_obligations
            );
        }

        {
            let guard = ShardGuard::for_obligation(&shards);
            let has_regions = guard.regions.is_some();
            let no_tasks = guard.tasks.is_none();
            let has_obligations = guard.obligations.is_some();
            drop(guard);
            crate::assert_with_log!(
                has_regions && no_tasks && has_obligations,
                "for_obligation: B+C only",
                true,
                has_regions && no_tasks && has_obligations
            );
        }

        {
            let guard = ShardGuard::for_task_completed(&shards);
            let all_present =
                guard.regions.is_some() && guard.tasks.is_some() && guard.obligations.is_some();
            drop(guard);
            crate::assert_with_log!(all_present, "for_task_completed: B+A+C", true, all_present);
        }

        {
            let guard = ShardGuard::for_cancel(&shards);
            let all_present =
                guard.regions.is_some() && guard.tasks.is_some() && guard.obligations.is_some();
            drop(guard);
            crate::assert_with_log!(all_present, "for_cancel: B+A+C", true, all_present);
        }

        {
            let guard = ShardGuard::for_obligation_resolve(&shards);
            let all_present =
                guard.regions.is_some() && guard.tasks.is_some() && guard.obligations.is_some();
            drop(guard);
            crate::assert_with_log!(
                all_present,
                "for_obligation_resolve: B+A+C",
                true,
                all_present
            );
        }

        crate::test_complete!("shardguard_locking_patterns_exercised");
    }

    #[test]
    fn task_completed_ok_with_leaked_obligations_closes_region() {
        // Verifies: non-cancelled task completing with pending obligations
        // triggers the leak handling path (not the auto-abort path).
        // mark_obligation_leaked must call resolve_obligation() so the
        // region's pending_obligations counter is decremented. Without this,
        // the region would be stuck in Finalizing with a desynchronized counter.
        // This exercises the B→A→C path through handle_obligation_leaks.
        init_test("task_completed_ok_with_leaked_obligations_closes_region");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Silent;
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create obligations but DO NOT commit/abort them
        let _obl1 = state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("obl1");
        let _obl2 = state
            .create_obligation(ObligationKind::Ack, task, region, None)
            .expect("obl2");

        // Request close on the region so advance_region_state is allowed to
        // drive it through Closing -> Finalizing -> Closed.
        {
            let region_record = state.regions.get(region.arena_index()).expect("region");
            region_record.begin_close(None);
        }

        crate::assert_with_log!(
            state.pending_obligation_count() == 2,
            "two pending obligations",
            2usize,
            state.pending_obligation_count()
        );

        // Complete the task with Ok (NOT Cancelled) — this triggers the leak
        // handling path at task_completed:1831-1841 instead of the auto-abort.
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task);

        // Region should still close because mark_obligation_leaked resolves
        // the obligation from the region's perspective.
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == RegionState::Closed,
            "region closed despite leaked obligations (Silent mode)",
            RegionState::Closed,
            region_state
        );

        // Verify leak trace events were emitted
        let events = state.trace.snapshot();
        let leak_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationLeak)
            .count();
        crate::assert_with_log!(
            leak_events == 2,
            "two obligation leak trace events",
            2usize,
            leak_events
        );
        crate::test_complete!("task_completed_ok_with_leaked_obligations_closes_region");
    }

    #[test]
    fn cancel_sibling_tasks_preserves_triggering_child() {
        // Verifies: cancel_sibling_tasks cancels all siblings in a region
        // EXCEPT the triggering child. This exercises the B→A path through
        // the sibling cancellation flow.
        init_test("cancel_sibling_tasks_preserves_triggering_child");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Insert 4 tasks in the same region
        let task_a = insert_task(&mut state, region);
        let task_b = insert_task(&mut state, region);
        let task_c = insert_task(&mut state, region);
        let task_d = insert_task(&mut state, region);

        // Cancel siblings of task_b (should cancel a, c, d but not b)
        let reason = CancelReason::fail_fast().with_message("sibling failed");
        let to_cancel = state.cancel_sibling_tasks(region, task_b, &reason);

        // task_b should NOT appear in the cancellation list
        let cancelled_ids: Vec<TaskId> = to_cancel.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(
            !cancelled_ids.contains(&task_b),
            "triggering child not cancelled",
            false,
            cancelled_ids.contains(&task_b)
        );

        // All other tasks should be cancelled
        crate::assert_with_log!(
            cancelled_ids.len() == 3,
            "three siblings cancelled",
            3usize,
            cancelled_ids.len()
        );
        for &expected in &[task_a, task_c, task_d] {
            crate::assert_with_log!(
                cancelled_ids.contains(&expected),
                "sibling in cancel list",
                true,
                cancelled_ids.contains(&expected)
            );
        }

        // Verify task_b's state is unchanged (still Created)
        let b_record = state.task(task_b).expect("task_b");
        crate::assert_with_log!(
            matches!(b_record.state, TaskState::Created),
            "triggering child state unchanged",
            true,
            matches!(b_record.state, TaskState::Created)
        );

        // Verify cancelled siblings have CancelRequested state
        for &sib in &[task_a, task_c, task_d] {
            let record = state.task(sib).expect("sibling");
            let is_cancel_requested = record.state.is_cancelling();
            crate::assert_with_log!(
                is_cancel_requested,
                "sibling is cancelling",
                true,
                is_cancel_requested
            );
        }
        crate::test_complete!("cancel_sibling_tasks_preserves_triggering_child");
    }

    #[test]
    fn bottom_up_cascade_without_cancel() {
        // Verifies: regions close bottom-up via advance_region_state when
        // tasks complete naturally (no cancellation involved). This tests
        // the iterative parent advancement in advance_region_state.
        init_test("bottom_up_cascade_without_cancel");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        // One task in each region
        let gc_task = insert_task(&mut state, grandchild);
        let child_task = insert_task(&mut state, child);
        let root_task = insert_task(&mut state, root);

        // Request close on root (sets Closing, but doesn't cancel tasks)
        {
            let region = state.regions.get(root.arena_index()).expect("root");
            region.begin_close(None);
        }
        {
            let region = state.regions.get(child.arena_index()).expect("child");
            region.begin_close(None);
        }
        {
            let region = state
                .regions
                .get(grandchild.arena_index())
                .expect("grandchild");
            region.begin_close(None);
        }

        // Complete grandchild task → grandchild region should cascade to Closed
        state
            .task_mut(gc_task)
            .expect("gc_task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(gc_task);

        let gc_state = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild")
            .state();
        crate::assert_with_log!(
            gc_state == RegionState::Closed,
            "grandchild closed after task done",
            RegionState::Closed,
            gc_state
        );

        // Child should NOT be closed yet (child_task still alive)
        let child_state = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        let child_not_closed = !matches!(child_state, RegionState::Closed);
        crate::assert_with_log!(
            child_not_closed,
            "child not closed (task alive)",
            true,
            child_not_closed
        );

        // Complete child task → child region should cascade to Closed
        state
            .task_mut(child_task)
            .expect("child_task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(child_task);

        let child_state_final = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        crate::assert_with_log!(
            child_state_final == RegionState::Closed,
            "child closed after task done + grandchild closed",
            RegionState::Closed,
            child_state_final
        );

        // Root should NOT be closed yet (root_task still alive)
        let root_state = state.regions.get(root.arena_index()).expect("root").state();
        let root_not_closed = !matches!(root_state, RegionState::Closed);
        crate::assert_with_log!(
            root_not_closed,
            "root not closed (task alive)",
            true,
            root_not_closed
        );

        // Complete root task → root should cascade to Closed
        state
            .task_mut(root_task)
            .expect("root_task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(root_task);

        let root_state_final = state.regions.get(root.arena_index()).expect("root").state();
        crate::assert_with_log!(
            root_state_final == RegionState::Closed,
            "root closed after full cascade",
            RegionState::Closed,
            root_state_final
        );
        crate::test_complete!("bottom_up_cascade_without_cancel");
    }

    #[test]
    fn obligation_leak_recover_mode_allows_region_close() {
        // Verifies: Recover mode aborts leaked obligations (via abort_obligation)
        // so the region's pending_obligations counter is decremented and the
        // region can complete close. This exercises the B→A→C path through
        // handle_obligation_leaks → abort_obligation → resolve_obligation →
        // advance_region_state.
        init_test("obligation_leak_recover_mode_allows_region_close");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Recover;
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create obligations that will be leaked
        let _obl1 = state
            .create_obligation(ObligationKind::Lease, task, region, None)
            .expect("lease");
        let _obl2 = state
            .create_obligation(ObligationKind::IoOp, task, region, None)
            .expect("io_op");

        // Request close on the region so advance_region_state can complete close
        // once leaked obligations are recovered (auto-aborted).
        {
            let region_record = state.regions.get(region.arena_index()).expect("region");
            region_record.begin_close(None);
        }

        crate::assert_with_log!(
            state.pending_obligation_count() == 2,
            "two pending obligations",
            2usize,
            state.pending_obligation_count()
        );

        // Complete task with Err (non-cancelled) → triggers leak handler
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Err(Error::new(ErrorKind::Internal)));
        let _ = state.task_completed(task);

        // In Recover mode, leaked obligations are aborted, so region should close
        let region_state = state
            .regions
            .get(region.arena_index())
            .expect("region")
            .state();
        crate::assert_with_log!(
            region_state == RegionState::Closed,
            "region closed in Recover mode",
            RegionState::Closed,
            region_state
        );

        // Verify abort events (Recover mode aborts, doesn't just mark leaked)
        let events = state.trace.snapshot();
        let abort_events = events
            .iter()
            .filter(|e| e.kind == TraceEventKind::ObligationAbort)
            .count();
        crate::assert_with_log!(
            abort_events == 2,
            "two obligation aborts in recover mode",
            2usize,
            abort_events
        );
        crate::test_complete!("obligation_leak_recover_mode_allows_region_close");
    }

    #[test]
    fn mixed_obligation_resolution_during_cancel_cascade() {
        // Verifies: a mix of committed, aborted, and orphaned obligations
        // during a cancel cascade all resolve correctly, allowing the region
        // tree to close. Exercises the full B→A→C cross-entity path with
        // interleaved obligation state changes.
        init_test("mixed_obligation_resolution_during_cancel_cascade");
        let mut state = RuntimeState::new();
        state.obligation_leak_response = ObligationLeakResponse::Silent;
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);

        let root_task = insert_task(&mut state, root);
        let child_task1 = insert_task(&mut state, child);
        let child_task2 = insert_task(&mut state, child);

        // Create obligations on different tasks
        let root_obl = state
            .create_obligation(ObligationKind::SendPermit, root_task, root, None)
            .expect("root obl");
        let child_obl1 = state
            .create_obligation(ObligationKind::Ack, child_task1, child, None)
            .expect("child obl1");
        let _child_obl2 = state
            .create_obligation(ObligationKind::IoOp, child_task2, child, None)
            .expect("child obl2");

        // Commit root obligation BEFORE cancel
        let _ = state.commit_obligation(root_obl).expect("commit root obl");

        // Cancel the root (cascades to child)
        let _ = state.cancel_request(root, &CancelReason::user("test"), None);

        // Abort child_obl1 explicitly during cancellation
        let _ = state
            .abort_obligation(child_obl1, ObligationAbortReason::Cancel)
            .expect("abort child obl1");

        // Complete child tasks (child_obl2 will be orphaned → auto-aborted)
        state
            .task_mut(child_task1)
            .expect("child_task1")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(child_task1);

        state
            .task_mut(child_task2)
            .expect("child_task2")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(child_task2);

        // Child should be closed
        let child_state = state
            .regions
            .get(child.arena_index())
            .expect("child")
            .state();
        crate::assert_with_log!(
            child_state == RegionState::Closed,
            "child closed",
            RegionState::Closed,
            child_state
        );

        // Complete root task
        state
            .task_mut(root_task)
            .expect("root_task")
            .complete(Outcome::Cancelled(CancelReason::user("test")));
        let _ = state.task_completed(root_task);

        // Root should close (all children closed, tasks done, obligations resolved)
        let root_state = state.regions.get(root.arena_index()).expect("root").state();
        crate::assert_with_log!(
            root_state == RegionState::Closed,
            "root closed after mixed resolution",
            RegionState::Closed,
            root_state
        );

        // No pending obligations
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "zero pending",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!("mixed_obligation_resolution_during_cancel_cascade");
    }

    // ── asupersync-sipro: Regression tests for audit findings ────────────

    /// Test metrics that tracks region_closed calls.
    #[derive(Default)]
    struct RegionCloseMetrics {
        closed: Mutex<Vec<(RegionId, Duration)>>,
    }

    impl MetricsProvider for RegionCloseMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}
        fn task_completed(&self, _: TaskId, _: OutcomeKind, _: Duration) {}
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, id: RegionId, lifetime: Duration) {
            self.closed.lock().push((id, lifetime));
        }
        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {}
        fn drain_completed(&self, _: RegionId, _: Duration) {}
        fn deadline_set(&self, _: RegionId, _: Duration) {}
        fn deadline_exceeded(&self, _: RegionId) {}
        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}
        fn deadline_violation(&self, _: &str, _: Duration) {}
        fn deadline_remaining(&self, _: &str, _: Duration) {}
        fn checkpoint_interval(&self, _: &str, _: Duration) {}
        fn task_stuck_detected(&self, _: &str) {}
        fn obligation_created(&self, _: RegionId) {}
        fn obligation_discharged(&self, _: RegionId) {}
        fn obligation_leaked(&self, _: RegionId) {}
        fn scheduler_tick(&self, _: usize, _: Duration) {}
    }

    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn region_closed_metric_fires_on_close() {
        // Regression: advance_region_state did not call metrics.region_closed()
        // after complete_close(), causing active region gauge to grow monotonically.
        init_test("region_closed_metric_fires_on_close");
        let metrics = Arc::new(RegionCloseMetrics::default());
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, root);

        // Close region: begin_close, complete task, advance
        {
            let region = state.regions.get(root.arena_index()).expect("root");
            region.begin_close(None);
        }
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task);

        {
            let closed = metrics.closed.lock();
            crate::assert_with_log!(
                closed.len() == 1,
                "region_closed metric fired exactly once",
                1usize,
                closed.len()
            );
            crate::assert_with_log!(
                closed[0].0 == root,
                "correct region ID in metric",
                root,
                closed[0].0
            );
        }
        crate::test_complete!("region_closed_metric_fires_on_close");
    }

    #[test]
    fn leak_count_exact_for_multiple_obligations() {
        // Regression: handle_obligation_leaks was reentrant via
        // mark_obligation_leaked → advance_region_state → collect_obligation_leaks,
        // causing leak_count to inflate to N*(N+1)/2 instead of N.
        init_test("leak_count_exact_for_multiple_obligations");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Create 5 obligations on the same task — all will leak on completion
        for _ in 0..5 {
            state
                .create_obligation(ObligationKind::SendPermit, task, region, None)
                .expect("create obligation");
        }

        complete_task_ok(&mut state, task);

        // Without the reentrance guard, leak_count would be 5+4+3+2+1 = 15
        crate::assert_with_log!(
            state.leak_count() == 5,
            "leak_count is exactly N, not inflated by reentrance",
            5u64,
            state.leak_count()
        );
        crate::test_complete!("leak_count_exact_for_multiple_obligations");
    }

    // =========================================================================
    // Wave 58 – pure data-type trait coverage (snapshot types)
    // =========================================================================

    #[test]
    fn budget_snapshot_debug_clone_copy() {
        let s = BudgetSnapshot {
            deadline: Some(1_000_000),
            poll_quota: 128,
            cost_quota: None,
            priority: 5,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("BudgetSnapshot"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied.priority, cloned.priority);
    }

    #[test]
    fn cancel_kind_snapshot_debug_clone() {
        let k = CancelKindSnapshot::User;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("User"), "{dbg}");
        let cloned = k;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn region_state_snapshot_debug_clone() {
        let s = RegionStateSnapshot::Open;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Open"), "{dbg}");
        let cloned = s;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }
}
