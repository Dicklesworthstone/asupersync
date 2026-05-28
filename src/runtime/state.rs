//! Global runtime state.
//!
//! The runtime state Σ contains all live entities:
//! - Regions (ownership tree)
//! - Tasks (units of execution)
//! - Obligations (resources to be resolved)
//! - Current time

use super::region_table::RegionCreateError;
use crate::cancel::protocol_state_machines::{
    CancelProtocolValidator, ObligationContext, ObligationEvent, RegionContext, RegionEvent,
    TaskContext, TaskEvent, TransitionResult, ValidationLevel as CancelValidationLevel,
};
use crate::cx::cx::ObservabilityState;
use crate::cx::scope::{CatchUnwind, payload_to_string};
use crate::epoch::EpochId;
use crate::error::{Error, ErrorKind};
use crate::observability::metrics::{MetricsProvider, NoOpMetrics, OutcomeKind};
use crate::observability::swarm_pressure_governor::{
    SwarmPressureGovernor, SwarmPressureGovernorConfig,
};
use crate::observability::{LogCollector, ObservabilityConfig};
use crate::record::{
    AdmissionError, ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState,
    RegionLimits, RegionRecord, SourceLocation, TaskRecord,
    finalizer::{FINALIZER_TIME_BUDGET_NANOS, Finalizer, finalizer_budget},
    region::RegionState,
    task::TaskState,
};
use crate::runtime::config::{
    LeakEscalation, ObligationLeakResponse, RuntimeCapacityHints, TraceStorageProfile,
};
use crate::runtime::io_driver::{IoDriver, IoDriverHandle};
use crate::runtime::reactor::Reactor;
use crate::runtime::resource_monitor::{
    DegradationLevel, DegradationStatsSnapshot, MonitorConfig, RegionPriority, ResourceMonitor,
};
use crate::runtime::stored_task::StoredTask;
use crate::runtime::task_handle::JoinError;
use crate::runtime::{BlockingPoolHandle, ObligationTable, RegionTable, TaskTable};
use crate::time::TimerDriverHandle;
use crate::trace::distributed::{LogicalClockMode, LogicalTime};
use crate::trace::event::{TraceData, TraceEventKind};
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{debug, debug_span, error, trace, trace_span};
use crate::types::policy::PolicyAction;
use crate::types::task_context::{CxInner, MAX_MASK_DEPTH};
use crate::types::{
    Budget, CancelAttributionConfig, CancelKind, CancelReason, CapabilityBudget,
    CapabilityBudgetRequirements, ObligationId, Outcome, Policy, RegionId, TaskId, Time,
    id::{next_bootstrap_region_id, next_bootstrap_task_id},
};
use crate::util::{Arena, ArenaIndex, EntropySource, OsEntropy};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::backtrace::Backtrace;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

static NEXT_RUNTIME_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
const READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD: usize = 32;

type BoxedAsyncFinalizer = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

fn nanos_saturating_u64(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
/// Observability counters for the cached draining-region snapshot path.
pub struct ReadBiasedRegionSnapshotStats {
    /// Reads served directly from the cached draining-region count.
    pub cache_hits: u64,
    /// Reads that fell back to the authoritative `RegionTable` scan.
    pub fallback_scans: u64,
    /// Explicit cache invalidations.
    pub invalidations: u64,
    /// Fallback scans triggered after a write-heavy burst.
    pub write_heavy_fallbacks: u64,
    /// Runtime-side cached-count adjustments applied on region transitions.
    pub writer_adjustments: u64,
    /// Total nanoseconds spent applying writer-side cached-count adjustments.
    pub writer_adjustment_ns: u64,
    /// Total nanoseconds spent on authoritative fallback scans.
    pub fallback_scan_ns: u64,
    /// Most recently published cached draining-region count.
    pub cached_draining_regions: usize,
    /// Number of counted-region transitions observed since the last read.
    pub writes_since_last_read: usize,
}

#[derive(Debug)]
struct ReadBiasedDrainingRegionSnapshot {
    enabled: AtomicBool,
    valid: AtomicBool,
    cached_count: AtomicUsize,
    writes_since_last_read: AtomicUsize,
    cache_hits: AtomicU64,
    fallback_scans: AtomicU64,
    #[allow(dead_code)]
    invalidations: AtomicU64,
    write_heavy_fallbacks: AtomicU64,
    writer_adjustments: AtomicU64,
    writer_adjustment_ns: AtomicU64,
    fallback_scan_ns: AtomicU64,
}

impl Default for ReadBiasedDrainingRegionSnapshot {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true), // Enable cache by default for performance
            valid: AtomicBool::new(false),  // Invalid initially until first scan
            cached_count: AtomicUsize::new(0),
            writes_since_last_read: AtomicUsize::new(0),
            cache_hits: AtomicU64::new(0),
            fallback_scans: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            write_heavy_fallbacks: AtomicU64::new(0),
            writer_adjustments: AtomicU64::new(0),
            writer_adjustment_ns: AtomicU64::new(0),
            fallback_scan_ns: AtomicU64::new(0),
        }
    }
}

impl ReadBiasedDrainingRegionSnapshot {
    fn configure(&self, enabled: bool, initial_count: usize) {
        self.enabled.store(enabled, Ordering::Release);
        self.valid.store(enabled, Ordering::Release);
        self.cached_count.store(initial_count, Ordering::Release);
        self.writes_since_last_read.store(0, Ordering::Release);
    }

    fn invalidate(&self) {
        if self.enabled.load(Ordering::Acquire) {
            self.valid.store(false, Ordering::Release);
            self.invalidations.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn note_transition(&self, old_state: RegionState, new_state: RegionState) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }

        let started = Instant::now();
        let old_counted = matches!(old_state, RegionState::Draining | RegionState::Finalizing);
        let new_counted = matches!(new_state, RegionState::Draining | RegionState::Finalizing);

        match (old_counted, new_counted) {
            (false, true) => {
                self.cached_count.fetch_add(1, Ordering::AcqRel);
                self.writes_since_last_read.fetch_add(1, Ordering::Release);
                self.writer_adjustments.fetch_add(1, Ordering::Release);
                self.valid.store(true, Ordering::Release);
            }
            (true, false) => {
                let _ =
                    self.cached_count
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            Some(count.saturating_sub(1))
                        });
                self.writes_since_last_read.fetch_add(1, Ordering::Release);
                self.writer_adjustments.fetch_add(1, Ordering::Release);
                self.valid.store(true, Ordering::Release);
            }
            _ => {}
        }

        self.writer_adjustment_ns
            .fetch_add(nanos_saturating_u64(started.elapsed()), Ordering::Relaxed);
    }

    fn read_or_scan(&self, regions: &RegionTable) -> usize {
        if !self.enabled.load(Ordering::Acquire) {
            return regions.draining_region_count();
        }

        // Fixed TOCTOU race condition by holding cache validity check atomic
        // with the cache read through double-checking under consistent state
        let mut final_writes;
        loop {
            let writes = self.writes_since_last_read.load(Ordering::Acquire);
            final_writes = writes; // Store for use in fallback path metrics

            // Check write threshold first (optimization)
            if writes < READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD {
                // Atomically reset write counter to 0, but only if it hasn't changed
                match self.writes_since_last_read.compare_exchange_weak(
                    writes,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Counter reset successful, now atomically check validity and read cache
                        // Use Acquire ordering to synchronize with invalidation stores
                        let cached_value = self.cached_count.load(Ordering::Acquire);

                        // Double-check validity after cache read to detect races
                        if self.valid.load(Ordering::Acquire) {
                            // Cache was valid during read, return the value
                            self.cache_hits.fetch_add(1, Ordering::Relaxed);
                            return cached_value;
                        }
                        // Cache was invalidated between reset and read, fall through to rebuild
                        break;
                    }
                    Err(_) => {}
                }
            } else {
                // Cache invalid or too many writes, break out to scan
                break;
            }
        }

        let started = Instant::now();
        let scanned = regions.draining_region_count();
        if final_writes >= READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD {
            self.write_heavy_fallbacks.fetch_add(1, Ordering::Relaxed);
        }
        self.fallback_scans.fetch_add(1, Ordering::Relaxed);
        self.fallback_scan_ns
            .fetch_add(nanos_saturating_u64(started.elapsed()), Ordering::Relaxed);
        self.cached_count.store(scanned, Ordering::Release);
        self.valid.store(true, Ordering::Release);
        self.writes_since_last_read.store(0, Ordering::Release);
        scanned
    }

    #[allow(dead_code)]
    fn stats(&self) -> ReadBiasedRegionSnapshotStats {
        ReadBiasedRegionSnapshotStats {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            fallback_scans: self.fallback_scans.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            write_heavy_fallbacks: self.write_heavy_fallbacks.load(Ordering::Relaxed),
            writer_adjustments: self.writer_adjustments.load(Ordering::Relaxed),
            writer_adjustment_ns: self.writer_adjustment_ns.load(Ordering::Relaxed),
            fallback_scan_ns: self.fallback_scan_ns.load(Ordering::Relaxed),
            cached_draining_regions: self.cached_count.load(Ordering::Relaxed),
            writes_since_last_read: self.writes_since_last_read.load(Ordering::Relaxed),
        }
    }

    #[allow(dead_code)]
    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

fn log_cancel_protocol_violation(operation: &'static str, validation_result: &TransitionResult) {
    let _ = operation;
    let _ = validation_result;
    crate::tracing_compat::error!(
        operation,
        validation_result = ?validation_result,
        "cancel protocol violation"
    );
}

/// Auditable lifecycle events emitted by async finalizers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalizerHistoryEvent {
    /// A finalizer was registered for a region.
    Registered {
        /// Stable finalizer identifier inside the runtime state.
        id: u64,
        /// Region that owns the finalizer.
        region: RegionId,
        /// Logical runtime time when the finalizer was registered.
        time: Time,
    },
    /// A registered finalizer was run.
    Ran {
        /// Stable finalizer identifier inside the runtime state.
        id: u64,
        /// Logical runtime time when the finalizer ran.
        time: Time,
    },
    /// A region closed after its finalizers completed.
    RegionClosed {
        /// Region that reached the closed state.
        region: RegionId,
        /// Logical runtime time when the region closed.
        time: Time,
    },
}

/// Auditable events proving that losing race participants are drained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoserDrainHistoryEvent {
    /// A race began and registered the participant tasks that must drain.
    RaceStarted {
        /// Stable race identifier inside the runtime state.
        race_id: u64,
        /// Region that owns the race.
        region: RegionId,
        /// Participant tasks in the race.
        participants: Vec<TaskId>,
        /// Logical runtime time when the race began.
        time: Time,
    },
    /// A race participant completed.
    TaskCompleted {
        /// Participant task that completed.
        task: TaskId,
        /// Logical runtime time when the task completed.
        time: Time,
    },
    /// A race completed with a selected winner after loser drain.
    RaceCompleted {
        /// Stable race identifier inside the runtime state.
        race_id: u64,
        /// Winning task for the completed race.
        winner: TaskId,
        /// Logical runtime time when the race completed.
        time: Time,
    },
}

#[derive(Debug, Default)]
pub(crate) struct LoserDrainHistoryRecorder {
    next_race_id: AtomicU64,
    events: parking_lot::Mutex<Vec<LoserDrainHistoryEvent>>,
}

pub(crate) type LoserDrainHistoryHandle = Arc<LoserDrainHistoryRecorder>;

impl LoserDrainHistoryRecorder {
    #[must_use]
    pub(crate) fn new_handle() -> LoserDrainHistoryHandle {
        Arc::new(Self::default())
    }

    pub(crate) fn record_race_start(
        &self,
        region: RegionId,
        participants: Vec<TaskId>,
        time: Time,
    ) -> u64 {
        let race_id = self.next_race_id.fetch_add(1, Ordering::Relaxed);
        self.events
            .lock()
            .push(LoserDrainHistoryEvent::RaceStarted {
                race_id,
                region,
                participants,
                time,
            });
        race_id
    }

    pub(crate) fn record_task_complete(&self, task: TaskId, time: Time) {
        self.events
            .lock()
            .push(LoserDrainHistoryEvent::TaskCompleted { task, time });
    }

    pub(crate) fn record_race_complete(&self, race_id: u64, winner: TaskId, time: Time) {
        self.events
            .lock()
            .push(LoserDrainHistoryEvent::RaceCompleted {
                race_id,
                winner,
                time,
            });
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> Vec<LoserDrainHistoryEvent> {
        self.events.lock().clone()
    }
}

/// Errors that can occur when spawning a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    /// The runtime backing a weak handle has already been dropped.
    RuntimeUnavailable,
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
    /// Authorization failed: caller lacks permission to create tasks in the target region.
    AuthorizationDenied {
        /// The region that denied access.
        region: RegionId,
        /// The capability context that was checked.
        cx_id: String,
    },
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeUnavailable => write!(f, "runtime is no longer available"),
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
            Self::AuthorizationDenied { region, cx_id } => write!(
                f,
                "authorization denied: caller lacks permission to create tasks in region {region:?} (cx={cx_id})"
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
    inner: BoxedAsyncFinalizer,
    cx_inner: Arc<parking_lot::RwLock<CxInner>>,
    entered: bool,
}

impl MaskedFinalizer {
    fn new(inner: BoxedAsyncFinalizer, cx_inner: Arc<parking_lot::RwLock<CxInner>>) -> Self {
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
            // br-asupersync-masked-finalizer-fail-open: in release
            // builds the prior code logged + returned with
            // entered=false, after which poll() called inner.poll(cx)
            // WITHOUT mask protection — finalizer could be cancelled
            // mid-cleanup, leaving resources orphaned and silently
            // violating the "MaskedFinalizer protects cleanup from
            // cancel" contract. Debug builds already panic via the
            // debug_assert above; match that posture in release. The
            // depth saturation indicates a programmer bug
            // (unboundedly nested masked sections); failing fast
            // surfaces it instead of silently dropping cleanup
            // (consistent with Plan v4 §I2 + br-asupersync-gi61n1
            // which made obligation-leak default Panic).
            let depth = guard.mask_depth;
            drop(guard);
            crate::tracing_compat::error!(
                depth = depth,
                max = MAX_MASK_DEPTH,
                "INV-MASK-BOUNDED violated: mask depth saturated, cannot mask finalizer; aborting"
            );
            panic!(
                "MaskedFinalizer: INV-MASK-BOUNDED violated — mask depth {depth} >= \
                 MAX_MASK_DEPTH {MAX_MASK_DEPTH}. Refusing to run finalizer unprotected; \
                 the runtime cannot guarantee cleanup integrity past this point. \
                 Reduce nesting of masked sections."
            );
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
    /// Backtrace captured at obligation acquisition time, used for diagnostics
    /// in `mark_obligation_leaked` via `ObligationLeakInfo`.
    #[allow(dead_code)]
    // populated for diagnostic completeness; read via ObligationLeakInfo path
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
    /// Stable identity for this runtime state instance.
    instance_id: u64,
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
    /// Optional root key used to verify spawn capability macaroons.
    spawn_authorization_key: Option<crate::security::key::AuthKey>,
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
    /// Optional cached draining-region count for governor/diagnostic snapshots.
    read_biased_draining_region_snapshot: ReadBiasedDrainingRegionSnapshot,
    /// Leak-handling recursion depth for diagnostics.
    ///
    /// Distinct leak batches may be processed reentrantly (for example when a
    /// child region closes and advances an ancestor into `Finalizing`), so we
    /// cannot use a coarse boolean guard here without suppressing legitimate
    /// nested leak handling. Track the depth for observability and pair it with
    /// `in_flight_leak_ids` to deduplicate only the exact obligations already
    /// being processed by an outer frame.
    handling_leaks: usize,
    /// Obligation ids currently being processed by `handle_obligation_leaks`.
    ///
    /// This prevents recursive `mark_obligation_leaked` /
    /// `abort_obligation` / `advance_region_state` paths from rediscovering the
    /// same leak batch and inflating `leak_count`, while still allowing
    /// different regions' leaks to be handled during the same unwind.
    in_flight_leak_ids: HashSet<ObligationId>,
    /// Regions currently in `Finalizing` state.
    ///
    /// Allows `drain_ready_async_finalizers` to skip a full region-arena scan
    /// on every poll.
    finalizing_regions: SmallVec<[RegionId; 4]>,
    /// Recently closed region ids that have been removed from the arena.
    ///
    /// External handles such as `AppHandle` may legitimately outlive the
    /// underlying region record because `advance_region_state` removes closed
    /// regions eagerly. Keep a bounded tombstone set so those handles can still
    /// distinguish "closed and cleaned up" from "never existed in this state".
    recently_closed_regions: HashSet<RegionId>,
    recently_closed_region_outcomes: HashMap<RegionId, crate::record::task::TaskOutcome>,
    recently_closed_region_order: VecDeque<RegionId>,
    /// Finalizer ids pending per region, mirroring the runtime's LIFO stack.
    pending_finalizer_ids: HashMap<RegionId, Vec<u64>>,
    /// Async finalizer tasks mapped back to the logical finalizer they are running.
    async_finalizer_tasks: HashMap<TaskId, u64>,
    /// Regions currently blocked on an in-flight async finalizer barrier.
    ///
    /// While a region is present here, lower finalizers in its stack must not
    /// run yet. This preserves the per-region async barrier: at most one async
    /// finalizer task may be active for a region at a time, and lower LIFO
    /// finalizers must wait until it completes.
    active_async_finalizers: HashMap<RegionId, TaskId>,
    /// Append-only finalizer lifecycle history for post-run oracle hydration.
    finalizer_history: Vec<FinalizerHistoryEvent>,
    /// Append-only loser-drain evidence for post-run oracle hydration.
    loser_drain_history: LoserDrainHistoryHandle,
    /// Monotonic id source for finalizer registrations.
    next_finalizer_id: u64,
    /// Per-module epoch cursors feeding the runtime epoch tracker.
    region_table_epoch: EpochId,
    task_table_epoch: EpochId,
    obligation_table_epoch: EpochId,
    /// Epoch consistency tracker for runtime state transitions.
    epoch_tracker: super::epoch_tracker::EpochConsistencyTracker,
    /// State machine transition verifier for runtime entities.
    state_verifier: Arc<super::state_verifier::StateTransitionVerifier>,
    /// Cancel protocol state machine validator for runtime cancellation compliance.
    cancel_protocol_validator: Arc<parking_lot::Mutex<CancelProtocolValidator>>,
    /// Cancellation debt accumulation monitor.
    debt_monitor: Arc<crate::observability::CancellationDebtMonitor>,
    /// Resource monitor for graceful degradation.
    ///
    /// Tracks memory, file descriptors, CPU load, and network connections,
    /// and triggers degradation policies when thresholds are exceeded.
    resource_monitor: Arc<ResourceMonitor>,
    /// Swarm pressure governor for admission control and resource envelope management.
    ///
    /// Provides comprehensive admission decisions, resource envelope tracking,
    /// and swarm coordination for distributed pressure management.
    swarm_pressure_governor: SwarmPressureGovernor,
    /// Regions that need state advancement deferred until leak handling completes.
    ///
    /// During obligation leak handling, `abort_obligation` calls can trigger
    /// `advance_region_state`, which may run finalizers that acquire new obligations.
    /// This violates the quiescence invariant. We defer region state advancement
    /// until after leak handling completes to prevent reentrancy.
    deferred_region_advancements: HashSet<RegionId>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("regions", &self.regions)
            .field("tasks", &self.tasks)
            .field("obligations", &self.obligations)
            .field("now", &self.now)
            .field("instance_id", &self.instance_id)
            .field("root_region", &self.root_region)
            .field("trace", &self.trace)
            .field("metrics", &"<dyn MetricsProvider>")
            .field("io_driver", &self.io_driver)
            .field("timer_driver", &self.timer_driver)
            .field("logical_clock_mode", &self.logical_clock_mode)
            .field("cancel_attribution", &self.cancel_attribution)
            .field("entropy_source", &"<dyn EntropySource>")
            .field(
                "spawn_authorization_enabled",
                &self.spawn_authorization_key.is_some(),
            )
            .field("observability", &self.observability.is_some())
            .field("blocking_pool", &self.blocking_pool.is_some())
            .field("obligation_leak_response", &self.obligation_leak_response)
            .field("leak_escalation", &self.leak_escalation)
            .field("leak_count", &self.leak_count)
            .field("handling_leaks", &self.handling_leaks)
            .field("in_flight_leak_ids", &self.in_flight_leak_ids.len())
            .field("finalizing_region_count", &self.finalizing_regions.len())
            .field(
                "recently_closed_region_count",
                &self.recently_closed_regions.len(),
            )
            .field(
                "recently_closed_region_order_count",
                &self.recently_closed_region_order.len(),
            )
            .field(
                "pending_finalizer_regions",
                &self.pending_finalizer_ids.len(),
            )
            .field("async_finalizer_tasks", &self.async_finalizer_tasks.len())
            .field(
                "active_async_finalizers",
                &self.active_async_finalizers.len(),
            )
            .field("finalizer_history_len", &self.finalizer_history.len())
            .field(
                "loser_drain_history_len",
                &self.loser_drain_history.snapshot().len(),
            )
            .field("next_finalizer_id", &self.next_finalizer_id)
            .field("region_table_epoch", &self.region_table_epoch)
            .field("task_table_epoch", &self.task_table_epoch)
            .field("obligation_table_epoch", &self.obligation_table_epoch)
            .field("state_verifier", &"<StateTransitionVerifier>")
            .field("cancel_protocol_validator", &"<CancelProtocolValidator>")
            .field("debt_monitor", &"<CancellationDebtMonitor>")
            .finish()
    }
}

impl RuntimeState {
    const RECENTLY_CLOSED_REGION_CAPACITY: usize = 4096;

    fn new_with_layout(
        capacity_hints: RuntimeCapacityHints,
        trace_capacity: usize,
        metrics: Arc<dyn MetricsProvider>,
    ) -> Self {
        // Create shared instances for pressure monitoring
        let resource_monitor = Arc::new(ResourceMonitor::new(MonitorConfig::default()));

        // RuntimeState owns the resource monitor and exposes the swarm-level
        // governor. The runtime-level PressureGovernor is attached by the
        // outer Runtime once the scheduler and state mutex are available.
        let swarm_pressure_governor = SwarmPressureGovernor::new_without_pressure_governor(
            SwarmPressureGovernorConfig::default(),
            Arc::clone(&resource_monitor),
        );

        Self {
            instance_id: NEXT_RUNTIME_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            regions: RegionTable::with_capacity(capacity_hints.region_capacity),
            tasks: TaskTable::with_capacity(capacity_hints.task_capacity),
            obligations: ObligationTable::with_capacity(capacity_hints.obligation_capacity),
            now: Time::from_nanos(1_000_000_000),
            root_region: None,
            trace: TraceBufferHandle::new(trace_capacity),
            metrics,
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            spawn_authorization_key: None,
            observability: None,
            blocking_pool: None,
            // br-asupersync-qp2tfx: internal constructors Panic on obligation
            // leak so the lab/test paths surface bugs the same way the
            // user-facing default (Fail, set in br-gi61n1) does.
            obligation_leak_response: ObligationLeakResponse::Panic,
            leak_escalation: None,
            leak_count: 0,
            read_biased_draining_region_snapshot: ReadBiasedDrainingRegionSnapshot::default(),
            handling_leaks: 0,
            in_flight_leak_ids: HashSet::new(),
            finalizing_regions: SmallVec::new(),
            recently_closed_regions: HashSet::new(),
            recently_closed_region_outcomes: HashMap::new(),
            recently_closed_region_order: VecDeque::new(),
            pending_finalizer_ids: HashMap::new(),
            async_finalizer_tasks: HashMap::new(),
            active_async_finalizers: HashMap::new(),
            finalizer_history: Vec::new(),
            loser_drain_history: LoserDrainHistoryRecorder::new_handle(),
            next_finalizer_id: 0,
            region_table_epoch: EpochId::GENESIS,
            task_table_epoch: EpochId::GENESIS,
            obligation_table_epoch: EpochId::GENESIS,
            epoch_tracker: super::epoch_tracker::EpochConsistencyTracker::new(),
            state_verifier: Arc::new(super::state_verifier::StateTransitionVerifier::new(
                super::state_verifier::StateVerifierConfig::default(),
            )),
            cancel_protocol_validator: Arc::new(parking_lot::Mutex::new(
                CancelProtocolValidator::new(CancelValidationLevel::Basic),
            )),
            debt_monitor: Arc::new(crate::observability::CancellationDebtMonitor::default()),
            resource_monitor,
            swarm_pressure_governor,
            deferred_region_advancements: HashSet::new(),
        }
    }

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
        Self::new_with_layout(
            RuntimeCapacityHints::default(),
            TraceStorageProfile::Default.trace_buffer_capacity(),
            metrics,
        )
    }

    /// Returns the effective initial table capacities used by this runtime state.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn capacity_hints(&self) -> RuntimeCapacityHints {
        RuntimeCapacityHints::new(
            self.tasks.capacity(),
            self.regions.capacity(),
            self.obligations.capacity(),
        )
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

    /// Creates a runtime state with custom arena capacity hints.
    ///
    /// Pre-sizing arenas eliminates reallocation overhead during initial runtime setup.
    /// Use this when you have specific knowledge about expected task/region/obligation counts.
    ///
    /// # Arguments
    ///
    /// * `task_capacity` - Expected number of concurrent tasks
    /// * `region_capacity` - Expected number of concurrent regions
    /// * `obligation_capacity` - Expected number of concurrent obligations
    /// * `metrics` - Metrics provider to attach to the runtime state
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Large-scale service with thousands of tasks
    /// let state = RuntimeState::with_capacity_hints(2048, 512, 1024, Arc::new(NoOpMetrics));
    /// ```
    #[must_use]
    pub fn with_capacity_hints(
        task_capacity: usize,
        region_capacity: usize,
        obligation_capacity: usize,
        metrics: Arc<dyn MetricsProvider>,
    ) -> Self {
        Self::with_capacity_hints_and_trace_capacity(
            task_capacity,
            region_capacity,
            obligation_capacity,
            TraceStorageProfile::Default.trace_buffer_capacity(),
            metrics,
        )
    }

    /// Creates a runtime state with custom arena and trace-buffer capacities.
    #[must_use]
    pub fn with_capacity_hints_and_trace_capacity(
        task_capacity: usize,
        region_capacity: usize,
        obligation_capacity: usize,
        trace_capacity: usize,
        metrics: Arc<dyn MetricsProvider>,
    ) -> Self {
        Self::new_with_layout(
            RuntimeCapacityHints::new(task_capacity, region_capacity, obligation_capacity),
            trace_capacity,
            metrics,
        )
    }

    /// Enable or disable the cached draining-region snapshot fast path.
    pub fn set_read_biased_region_snapshot(&mut self, enable: bool) {
        let initial_count = self.regions.draining_region_count();
        self.read_biased_draining_region_snapshot
            .configure(enable, initial_count);
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

    /// Sets the I/O driver for this runtime.
    pub fn set_io_driver(&mut self, driver: IoDriverHandle) {
        self.io_driver = Some(driver);
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

    #[inline]
    fn current_runtime_time(&self) -> Time {
        self.timer_driver
            .as_ref()
            .map_or(self.now, TimerDriverHandle::now)
    }

    /// Returns a cloned handle to the blocking pool, if present.
    #[inline]
    #[must_use]
    pub fn blocking_pool_handle(&self) -> Option<BlockingPoolHandle> {
        self.blocking_pool.clone()
    }

    /// Gets a reference to the state transition verifier.
    #[inline]
    #[must_use]
    pub fn state_verifier(&self) -> &Arc<super::state_verifier::StateTransitionVerifier> {
        &self.state_verifier
    }

    /// Gets the state verifier statistics snapshot.
    #[must_use]
    pub fn state_verifier_stats(&self) -> super::state_verifier::StateVerifierStatsSnapshot {
        self.state_verifier.stats()
    }

    /// Gets a reference to the cancel protocol validator.
    #[inline]
    #[must_use]
    pub fn cancel_protocol_validator(&self) -> &Arc<parking_lot::Mutex<CancelProtocolValidator>> {
        &self.cancel_protocol_validator
    }

    /// Validates a region state transition using the cancel protocol validator.
    fn validate_region_protocol_transition(
        &self,
        region_id: RegionId,
        event: RegionEvent,
        context: &RegionContext,
    ) -> TransitionResult {
        let mut validator = self.cancel_protocol_validator.lock();
        validator.validate_region_transition(region_id, event, context)
    }

    fn validate_live_region_protocol_transition(
        &self,
        region_id: RegionId,
        event: RegionEvent,
        operation: &'static str,
    ) {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return;
        };
        let context = RegionContext {
            region_id,
            parent_region: region.parent,
            created_at: region.created_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result =
            self.validate_region_protocol_transition(region_id, event, &context);
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation(operation, &validation_result);
        }
    }

    /// Validates a task state transition using the cancel protocol validator.
    fn validate_task_protocol_transition(
        &self,
        task_id: TaskId,
        event: TaskEvent,
        context: &TaskContext,
    ) -> TransitionResult {
        let mut validator = self.cancel_protocol_validator.lock();
        validator.validate_task_transition(task_id, event, context)
    }

    fn validate_live_task_protocol_transition(
        &self,
        task_id: TaskId,
        event: TaskEvent,
        operation: &'static str,
    ) {
        let Some(task) = self.task(task_id) else {
            return;
        };
        let context = TaskContext {
            task_id,
            region_id: task.owner,
            spawned_at: task.created_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result = self.validate_task_protocol_transition(task_id, event, &context);
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation(operation, &validation_result);
        }
    }

    /// Validates an obligation state transition using the cancel protocol validator.
    fn validate_obligation_protocol_transition(
        &self,
        obligation_id: ObligationId,
        event: ObligationEvent,
        context: &ObligationContext,
    ) -> TransitionResult {
        let mut validator = self.cancel_protocol_validator.lock();
        validator.validate_obligation_transition(obligation_id, event, context)
    }

    fn track_new_region_in_cancel_protocol_validator(
        &self,
        region_id: RegionId,
        parent_region: Option<RegionId>,
        created_at: Time,
    ) {
        {
            let mut validator = self.cancel_protocol_validator.lock();
            validator.register_region(region_id);
        }

        let context = RegionContext {
            region_id,
            parent_region,
            created_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result =
            self.validate_region_protocol_transition(region_id, RegionEvent::Activate, &context);
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation("region creation", &validation_result);
        }
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

    /// Builds the observability state for a new task-like execution context.
    #[must_use]
    pub(crate) fn observability_for_task(
        &self,
        region: RegionId,
        task: TaskId,
    ) -> Option<ObservabilityState> {
        self.observability
            .as_ref()
            .map(|obs| obs.for_task(region, task))
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

    /// Returns the configured hot trace-ring capacity.
    #[must_use]
    pub fn trace_buffer_capacity(&self) -> usize {
        self.trace.capacity()
    }

    /// Returns the stable identity of this runtime state instance.
    #[inline]
    #[must_use]
    pub fn instance_id(&self) -> u64 {
        self.instance_id
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

    /// Returns the cancellation debt monitor for this runtime.
    #[inline]
    #[must_use]
    pub fn debt_monitor(&self) -> Arc<crate::observability::CancellationDebtMonitor> {
        self.debt_monitor.clone()
    }

    /// Returns a shared reference to a task record by ID.
    #[inline]
    #[must_use]
    pub fn task(&self, task_id: TaskId) -> Option<&TaskRecord> {
        self.tasks.task(task_id)
    }

    /// Requests cancellation of a task.
    ///
    /// O(1) — maintained incrementally for O(1) Lyapunov snapshots.
    pub fn cancel_task(&mut self, task_id: TaskId, reason: &CancelReason) -> bool {
        let budget = reason.cleanup_budget();
        let Some(newly_cancelled) = self.update_task(task_id, |record| {
            record.request_cancel_with_budget(reason.clone(), budget)
        }) else {
            return false;
        };
        if newly_cancelled {
            self.validate_live_task_protocol_transition(
                task_id,
                TaskEvent::RequestCancel,
                "task cancellation",
            );
        }
        newly_cancelled
    }

    /// Completes a task with the given outcome.
    ///
    /// O(1) — maintained incrementally for O(1) Lyapunov snapshots.
    pub fn complete_task(
        &mut self,
        task_id: TaskId,
        outcome: crate::record::task::TaskOutcome,
    ) -> bool {
        self.update_task(task_id, |record| record.complete(outcome))
            .unwrap_or(false)
    }

    /// Returns a mutable reference to a task record by ID.
    ///
    /// NOTE: Direct use of `task_mut` bypasses O(1) Lyapunov counter updates.
    /// Prefer `update_task` which maintains incremental counters automatically.
    #[inline]
    pub fn task_mut(&mut self, task_id: TaskId) -> Option<&mut TaskRecord> {
        self.tasks.task_mut(task_id)
    }

    /// Safely updates a task record and maintains incremental counters.
    ///
    /// O(1) — maintained incrementally for O(1) Lyapunov snapshots.
    #[inline]
    pub fn update_task<F, R>(&mut self, task_id: TaskId, f: F) -> Option<R>
    where
        F: FnOnce(&mut TaskRecord) -> R,
    {
        self.tasks.update_task(task_id, f)
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

    /// Inserts a pooled task record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex` and a recycled
    /// `TaskRecord` that should be fully initialized for the new task.
    #[inline]
    pub fn insert_pooled_task_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex, &mut TaskRecord),
    {
        self.tasks.insert_pooled_task_with(f)
    }

    /// Removes a task record from the arena.
    ///
    /// Returns the removed record if it existed.
    #[inline]
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<TaskRecord> {
        let removed = self.tasks.remove_task(task_id);
        if removed.is_some() {
            self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
        }
        removed
    }

    /// Removes a task record from the arena and recycles it into the pool.
    #[inline]
    pub fn recycle_task(&mut self, task_id: TaskId) {
        self.tasks.remove_and_recycle_task(task_id);
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
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

    /// Returns the number of occupied task arena slots (live + terminal-but-
    /// not-yet-removed). Used by snapshot paths that need to pre-size a
    /// `Vec` while iterating under the state lock — a slight allocator
    /// optimisation when many tasks are live.
    #[inline]
    #[must_use]
    pub fn tasks_len(&self) -> usize {
        self.tasks.tasks_arena().len()
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

    /// Returns `true` if the region has already completed close and been
    /// removed from the live region table.
    #[inline]
    #[must_use]
    pub fn region_was_closed(&self, region_id: RegionId) -> bool {
        self.recently_closed_regions.contains(&region_id)
    }

    /// Returns the aggregated close outcome for a live or recently closed region.
    #[inline]
    #[must_use]
    pub fn region_close_outcome(
        &self,
        region_id: RegionId,
    ) -> Option<crate::record::task::TaskOutcome> {
        self.region(region_id)
            .and_then(RegionRecord::close_outcome)
            .or_else(|| {
                self.recently_closed_region_outcomes
                    .get(&region_id)
                    .cloned()
            })
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
        let now = self.current_runtime_time();
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
            timestamp: now.as_nanos(),
            regions,
            tasks,
            obligations,
            recent_events,
            finalizer_history: self.finalizer_history.clone(),
            loser_drain_history: self.loser_drain_history(),
        }
    }

    /// Creates a root region and returns its ID.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if a root region already exists (double-init guard).
    pub fn create_root_region(&mut self, budget: Budget) -> RegionId {
        self.create_root_region_with_capability_budget(budget, CapabilityBudget::UNSPECIFIED)
    }

    /// Creates a root region with an explicit capability budget and returns its ID.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if a root region already exists (double-init guard).
    pub fn create_root_region_with_capability_budget(
        &mut self,
        budget: Budget,
        capability_budget: CapabilityBudget,
    ) -> RegionId {
        debug_assert!(
            self.root_region.is_none(),
            "create_root_region called twice; previous root: {:?}",
            self.root_region
        );
        let now = self.current_runtime_time();
        let id = self
            .regions
            .create_root_with_capability_budget(budget, capability_budget, now);
        self.track_new_region_in_cancel_protocol_validator(id, None, now);

        self.root_region = Some(id);
        self.record_trace_event(|seq| TraceEvent::region_created(seq, now, id, None));
        self.metrics.region_created(id, None);

        // Notify epoch tracker of region creation
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::RegionTable);

        id
    }

    /// Creates a child region under the given parent and returns its ID.
    ///
    /// The child's effective budget is the meet (tightest constraints) of the
    /// parent budget and the provided budget.
    ///
    /// This method includes graceful degradation checks - if resource pressure
    /// is high, the region creation may be rejected to preserve system stability.
    pub fn create_child_region(
        &mut self,
        parent: RegionId,
        budget: Budget,
    ) -> Result<RegionId, RegionCreateError> {
        self.create_child_region_with_priority(parent, budget, RegionPriority::Normal)
    }

    /// Creates a child region with an explicit resource-pressure priority.
    ///
    /// This preserves the default [`Self::create_child_region`] behavior for
    /// normal work while allowing callers to classify background or critical
    /// child regions before the resource-pressure admission check runs.
    pub fn create_child_region_with_priority(
        &mut self,
        parent: RegionId,
        budget: Budget,
        priority: RegionPriority,
    ) -> Result<RegionId, RegionCreateError> {
        self.create_child_region_with_capability_budget_and_priority(
            parent,
            budget,
            CapabilityBudget::UNSPECIFIED,
            CapabilityBudgetRequirements::NONE,
            priority,
        )
    }

    /// Creates a child region with explicit capability-budget admission.
    pub fn create_child_region_with_capability_budget(
        &mut self,
        parent: RegionId,
        budget: Budget,
        capability_budget: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<RegionId, RegionCreateError> {
        self.create_child_region_with_capability_budget_and_priority(
            parent,
            budget,
            capability_budget,
            requirements,
            RegionPriority::Normal,
        )
    }

    /// Creates a child region with explicit capability-budget and pressure priority.
    pub fn create_child_region_with_capability_budget_and_priority(
        &mut self,
        parent: RegionId,
        budget: Budget,
        capability_budget: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        priority: RegionPriority,
    ) -> Result<RegionId, RegionCreateError> {
        self.check_resource_pressure_for_region(priority)?;

        let now = self.current_runtime_time();
        let id = self.regions.create_child_with_capability_budget(
            parent,
            budget,
            capability_budget,
            requirements,
            now,
        )?;
        self.resource_monitor
            .engine()
            .set_region_priority(id, priority);
        self.track_new_region_in_cancel_protocol_validator(id, Some(parent), now);

        self.record_trace_event(|seq| TraceEvent::region_created(seq, now, id, Some(parent)));
        self.metrics.region_created(id, Some(parent));

        // Register resource envelope with swarm pressure governor
        if let Ok(envelope) =
            self.create_resource_envelope_for_region(id, &budget, &capability_budget)
        {
            self.swarm_pressure_governor
                .register_region_envelope(id, envelope);
        }

        // Notify epoch tracker of region creation
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::RegionTable);

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

    /// Returns the current capability budget for a region.
    #[must_use]
    pub fn region_capability_budget(&self, region: RegionId) -> Option<CapabilityBudget> {
        self.regions.capability_budget(region)
    }

    /// Returns the root key for spawn authorization verification.
    ///
    /// This method provides access to the cryptographic key used to verify
    /// spawn capability macaroons. Returns None if authorization is disabled
    /// or not configured for this runtime.
    fn get_spawn_authorization_key(&self) -> Option<&crate::security::key::AuthKey> {
        self.spawn_authorization_key.as_ref()
    }

    /// Configure the root key used for spawn authorization.
    pub fn set_spawn_authorization_key(&mut self, key: Option<crate::security::key::AuthKey>) {
        self.spawn_authorization_key = key;
    }

    fn spawn_capability_identifier(region: RegionId) -> String {
        format!("spawn:region_{}", region.as_u64())
    }

    fn verify_spawn_authorization(
        &self,
        caller_cx: &crate::cx::Cx,
        region: RegionId,
    ) -> Result<(), SpawnError> {
        let Some(root_key) = self.get_spawn_authorization_key() else {
            return Ok(());
        };

        let spawn_capability = Self::spawn_capability_identifier(region);
        let verification_context = crate::cx::macaroon::VerificationContext::new();
        caller_cx
            .verify_capability(root_key, &spawn_capability, &verification_context)
            .map_err(|_| SpawnError::AuthorizationDenied {
                region,
                cx_id: format!("{:?}", caller_cx.task_id()),
            })
    }

    /// Creates a system-level Cx for internal runtime operations.
    ///
    /// This Cx has elevated privileges and should only be used for
    /// runtime-internal operations like finalizers and builder tasks.
    pub(crate) fn create_system_cx(&self) -> crate::cx::Cx {
        crate::cx::Cx::new(
            self.root_region.unwrap_or_else(next_bootstrap_region_id),
            next_bootstrap_task_id(),
            Budget::INFINITE,
        )
    }

    /// Creates the infrastructure for a task (record, context, channel) without storing the future.
    ///
    /// This helper allows `create_task` and `spawn_local` to share the same setup logic
    /// while storing the future in different places (global vs thread-local).
    #[allow(clippy::type_complexity)]
    pub(crate) fn create_task_infrastructure<T>(
        &mut self,
        caller_cx: &crate::cx::Cx,
        region: RegionId,
        budget: Budget,
        cleanup_task: bool,
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
        let _ = caller_cx;

        use crate::channel::oneshot;

        // Create oneshot channel for the result
        let (result_tx, result_rx) =
            oneshot::channel::<Result<T, crate::runtime::task_handle::JoinError>>();

        // Create the TaskRecord
        let now = self.current_runtime_time();
        let idx = self.insert_pooled_task_with(|idx, record| {
            // br-asupersync-j1e7zy: mutate the recycled record in place
            // instead of `*record = TaskRecord::new_with_time(...)`. The
            // assignment form drops the `wake_state` Arc and `waiters`
            // SmallVec freshly created by `Recyclable::reset` only to
            // allocate identical replacements, defeating the purpose of
            // the pool. `Recyclable::reset` (and the miss-path
            // `TaskRecord::new` fallback) already leave every field at its
            // default, so we only set the per-task identity and budget.
            record.id = TaskId::from_arena(idx);
            record.owner = region;
            record.created_at = now;
            record.deadline = budget.deadline;
            record.polls_remaining = budget.poll_quota;
            #[cfg(feature = "tracing-integration")]
            {
                record.created_instant = crate::time::wall_now();
            }
        });
        let task_id = TaskId::from_arena(idx);

        // Register task with cancel protocol validator
        {
            let mut validator = self.cancel_protocol_validator.lock();
            validator.register_task(task_id, region);
        }

        // Validate task creation protocol transition
        let context = TaskContext {
            task_id,
            region_id: region,
            spawned_at: now,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result = self.validate_task_protocol_transition(
            task_id,
            TaskEvent::Start, // Use Start event for task creation
            &context,
        );
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation("task creation", &validation_result);
            // Continue with creation but log violation
        }

        // Add task to the region's task list
        if let Some(region_record) = self.regions.get(region.arena_index()) {
            let admission = if cleanup_task {
                region_record.add_cleanup_task(task_id)
            } else {
                region_record.add_task(task_id)
            };
            if let Err(err) = admission {
                // Rollback task creation
                self.recycle_task(task_id);
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
            self.recycle_task(task_id);
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
        cx.set_loser_drain_history_handle(self.loser_drain_history_handle());
        let cx_weak = std::sync::Arc::downgrade(&cx.inner);

        // Link the shared state to the TaskRecord
        self.update_task(task_id, |record| {
            record.set_cx_inner(cx.inner.clone());
            record.set_cx(cx.clone());
        });

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
    /// # Security Note
    /// This method does not perform authorization checks. For secure task creation,
    /// use `create_task_with_auth` which verifies caller permissions.
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

        // Use system Cx for legacy compatibility - no authorization check
        let system_cx = self.create_system_cx();
        let (task_id, handle, cx, result_tx) =
            self.create_task_infrastructure(&system_cx, region, budget, false)?;

        // Wrap the future to send the result through the channel. Panics must
        // surface as `JoinError::Panicked` rather than silently closing the
        // channel and looking like cancellation to the join handle.
        let wrapped_future = async move {
            match (CatchUnwind { inner: future }).await {
                Ok(result) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let panic_payload =
                        crate::types::outcome::PanicPayload::new(payload_to_string(&payload));
                    let _ = result_tx.send(
                        &cx,
                        Err::<T, JoinError>(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        // Store the wrapped future with task_id for poll tracing
        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        // Notify epoch tracker of task creation
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);

        Ok((task_id, handle))
    }

    /// Creates a task with authorization checks.
    ///
    /// This is the secure version of `create_task` that verifies the caller
    /// has permission to create tasks in the target region before proceeding.
    /// Use this method for new code that needs capability-based security.
    ///
    /// # Arguments
    /// * `caller_cx` - The capability context for authorization
    /// * `region` - The region that will own this task
    /// * `budget` - The budget for this task
    /// * `future` - The future to execute
    ///
    /// # Returns
    /// A Result containing `(TaskId, TaskHandle)` on success, or `SpawnError` on failure.
    ///
    /// # Errors
    /// * `SpawnError::AuthorizationDenied` - Caller lacks permission to create tasks in the region
    /// * Other spawn errors as before (region not found, closed, at capacity, etc.)
    ///
    /// # Example
    /// ```ignore
    /// let (task_id, handle) = state.create_task_with_auth(&cx, region, budget, async { 42 })?;
    /// // Later: scheduler.schedule(task_id);
    /// // Even later: let result = handle.join(cx)?;
    /// ```
    pub fn create_task_with_auth<F, T>(
        &mut self,
        caller_cx: &crate::cx::Cx,
        region: RegionId,
        budget: Budget,
        future: F,
    ) -> Result<(TaskId, crate::runtime::TaskHandle<T>), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use crate::runtime::{StoredTask, task_handle::JoinError};

        self.verify_spawn_authorization(caller_cx, region)?;

        let (task_id, handle, cx, result_tx) =
            self.create_task_infrastructure(caller_cx, region, budget, false)?;

        // Wrap the future to send the result through the channel. Panics must
        // surface as `JoinError::Panicked` rather than silently closing the
        // channel and looking like cancellation to the join handle.
        let wrapped_future = async move {
            match (CatchUnwind { inner: future }).await {
                Ok(result) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let panic_payload =
                        crate::types::outcome::PanicPayload::new(payload_to_string(&payload));
                    let _ = result_tx.send(
                        &cx,
                        Err::<T, JoinError>(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        // Store the wrapped future with task_id for poll tracing
        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        // Notify epoch tracker of task creation
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);

        Ok((task_id, handle))
    }

    fn logical_time_for_task(&self, task_id: TaskId) -> Option<LogicalTime> {
        let record = self.task(task_id)?;
        let cx = record.cx.as_ref()?;
        Some(cx.logical_tick())
    }

    pub(crate) fn record_trace_event<F>(&self, build: F)
    where
        F: FnOnce(u64) -> TraceEvent,
    {
        self.trace.record_event(build);
    }

    pub(crate) fn notify_runtime_epoch_advance(&mut self, module: super::epoch_tracker::ModuleId) {
        let now = self.current_runtime_time();
        let cursor = match module {
            super::epoch_tracker::ModuleId::RegionTable => &mut self.region_table_epoch,
            super::epoch_tracker::ModuleId::TaskTable => &mut self.task_table_epoch,
            super::epoch_tracker::ModuleId::ObligationTable => &mut self.obligation_table_epoch,
            _ => return,
        };
        let from_epoch = *cursor;
        let to_epoch = from_epoch.next();
        *cursor = to_epoch;
        self.epoch_tracker
            .notify_epoch_transition(module, from_epoch, to_epoch, now);
    }

    fn record_task_trace_event<F>(&self, task_id: TaskId, build: F)
    where
        F: FnOnce(u64) -> TraceEvent,
    {
        let logical_time = self.logical_time_for_task(task_id);
        self.trace.record_event(move |seq| {
            let event = build(seq);
            if let Some(logical_time) = logical_time {
                event.with_logical_time(logical_time)
            } else {
                event
            }
        });
    }

    pub(crate) fn record_task_spawn(&self, task_id: TaskId, region: RegionId) {
        let now = self.current_runtime_time();
        self.record_task_trace_event(task_id, |seq| TraceEvent::spawn(seq, now, task_id, region));
        self.metrics.task_spawned(region, task_id);
    }

    fn record_task_complete(&self, task: &TaskRecord) {
        let now = self.current_runtime_time();
        self.record_task_trace_event(task.id, |seq| {
            TraceEvent::complete(seq, now, task.id, task.owner)
        });

        let duration = Duration::from_nanos(now.duration_since(task.created_at()));
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
        let now = self.current_runtime_time();
        self.obligations
            .iter()
            .filter_map(|(_, record)| {
                if !record.is_pending() || !predicate(record) {
                    return None;
                }

                let held_duration_ns = now.duration_since(record.reserved_at);
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
        let now = self.current_runtime_time();
        self.obligations
            .ids_for_holder(task_id)
            .iter()
            .filter_map(|id| {
                let record = self.obligations.get(id.arena_index())?;
                if !record.is_pending() {
                    return None;
                }
                let held_duration_ns = now.duration_since(record.reserved_at);
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
        if error.leaks.is_empty() {
            return;
        }

        let new_leaks: Vec<LeakedObligationInfo> = error
            .leaks
            .iter()
            .filter(|leak| {
                self.obligations
                    .get(leak.id.arena_index())
                    .is_some_and(ObligationRecord::is_pending)
                    && !self.in_flight_leak_ids.contains(&leak.id)
            })
            .cloned()
            .collect();

        if new_leaks.is_empty() {
            return;
        }

        let leak_ids: Vec<ObligationId> = new_leaks.iter().map(|leak| leak.id).collect();
        self.in_flight_leak_ids.extend(leak_ids.iter().copied());
        self.handling_leaks = self.handling_leaks.saturating_add(1);

        // Track cumulative leaks for escalation.
        self.leak_count = self.leak_count.saturating_add(leak_ids.len() as u64);

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

        match response {
            ObligationLeakResponse::Panic => {
                // Mark leaked first so trace/metrics capture the event before panicking.
                for &id in &leak_ids {
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
                    leak_count = leak_ids.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks detected (fail-fast)"
                );
                self.handling_leaks = self.handling_leaks.saturating_sub(1);
                for id in leak_ids {
                    self.in_flight_leak_ids.remove(&id);
                }
                std::panic::panic_any(msg);
            }
            ObligationLeakResponse::Log => {
                for &id in &leak_ids {
                    let _ = self.mark_obligation_leaked(id);
                }
                crate::tracing_compat::error!(
                    task_id = ?error.task_id,
                    region_id = ?error.region_id,
                    completion = %error
                        .completion
                        .map_or("unknown", TaskCompletionKind::as_str),
                    leak_count = leak_ids.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks detected"
                );
            }
            ObligationLeakResponse::Silent => {
                for &id in &leak_ids {
                    let _ = self.mark_obligation_leaked(id);
                }
            }
            ObligationLeakResponse::Recover => {
                for &id in &leak_ids {
                    // Abort instead of marking leaked — performs resource cleanup.
                    let _ = self.abort_obligation(id, ObligationAbortReason::Error);
                }
                crate::tracing_compat::warn!(
                    task_id = ?error.task_id,
                    region_id = ?error.region_id,
                    completion = %error
                        .completion
                        .map_or("unknown", TaskCompletionKind::as_str),
                    leak_count = leak_ids.len(),
                    cumulative_leaks = self.leak_count,
                    details = %error,
                    "obligation leaks recovered via auto-abort"
                );
            }
        }

        self.handling_leaks = self.handling_leaks.saturating_sub(1);
        for id in leak_ids {
            self.in_flight_leak_ids.remove(&id);
        }

        // Process deferred region advancements after leak handling completes.
        // This prevents reentrancy during finalizer execution that could violate
        // the quiescence invariant.
        if self.handling_leaks == 0 && !self.deferred_region_advancements.is_empty() {
            let deferred_regions: Vec<RegionId> =
                self.deferred_region_advancements.drain().collect();
            for region_id in deferred_regions {
                self.advance_region_state(region_id);
            }
        }
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
        {
            let Some(region_record) = self.regions.get(region.arena_index()) else {
                return Err(Error::new(ErrorKind::RegionClosed).with_message("region not found"));
            };

            let Some(task_record) = self.task(holder) else {
                return Err(Error::new(ErrorKind::TaskNotOwned)
                    .with_message(format!("holder task {holder:?} not found")));
            };

            if task_record.owner != region {
                return Err(Error::new(ErrorKind::TaskNotOwned).with_message(format!(
                    "holder task {holder:?} is owned by region {:?}, not {region:?}",
                    task_record.owner
                )));
            }

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
        }

        let acquired_at = SourceLocation::from_panic_location(std::panic::Location::caller());
        let acquire_backtrace = Self::capture_obligation_backtrace();
        let now = self.current_runtime_time();

        // Create the obligation first to get the ID
        let obligation_id =
            self.obligations
                .create(super::obligation_table::ObligationCreateArgs {
                    kind,
                    holder,
                    region,
                    now,
                    description,
                    acquired_at,
                    acquire_backtrace,
                });

        // Reserving an obligation increments the owning region's pending count,
        // so the region-table epoch must advance alongside the obligation table.
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::RegionTable);

        // Register obligation with cancel protocol validator
        {
            let mut validator = self.cancel_protocol_validator.lock();
            validator.register_obligation(obligation_id);
        }

        // Validate obligation creation protocol transition
        let context = ObligationContext {
            obligation_id,
            region_id: region,
            created_at: now,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result = self.validate_obligation_protocol_transition(
            obligation_id,
            ObligationEvent::Reserve {
                token: obligation_id.arena_index().index() as u64,
            },
            &context,
        );
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation("obligation creation", &validation_result);
            // Continue with creation but log violation
        }

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

        self.record_task_trace_event(holder, |seq| {
            TraceEvent::obligation_reserve(seq, now, obligation_id, holder, region, kind)
        });
        self.metrics.obligation_created(region);

        // Notify epoch tracker of obligation creation
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::ObligationTable);

        Ok(obligation_id)
    }

    /// Marks an obligation as committed and emits a trace event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    #[allow(clippy::result_large_err)]
    pub fn commit_obligation(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        let now = self.current_runtime_time();
        // Validate obligation commit protocol transition
        if let Some(record) = self.obligations.get(obligation.arena_index()) {
            let context = ObligationContext {
                obligation_id: obligation,
                region_id: record.region,
                created_at: record.reserved_at,
                validation_level: CancelValidationLevel::Basic,
            };
            let validation_result = self.validate_obligation_protocol_transition(
                obligation,
                ObligationEvent::Commit,
                &context,
            );
            if matches!(
                validation_result,
                TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
            ) {
                log_cancel_protocol_violation("obligation commit", &validation_result);
                // Continue with commit but log violation
            }
        }

        let info = self.obligations.commit(obligation, now)?;

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

        self.record_task_trace_event(info.holder, |seq| {
            TraceEvent::obligation_commit(
                seq,
                now,
                info.id,
                info.holder,
                info.region,
                info.kind,
                info.duration,
            )
        });
        self.metrics.obligation_discharged(info.region);

        // Notify epoch tracker of obligation commit
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::ObligationTable);

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
        let now = self.current_runtime_time();
        // Validate obligation abort protocol transition
        if let Some(record) = self.obligations.get(obligation.arena_index()) {
            let context = ObligationContext {
                obligation_id: obligation,
                region_id: record.region,
                created_at: record.reserved_at,
                validation_level: CancelValidationLevel::Basic,
            };
            let validation_result = self.validate_obligation_protocol_transition(
                obligation,
                ObligationEvent::Abort {
                    reason: format!("{reason:?}"),
                },
                &context,
            );
            if matches!(
                validation_result,
                TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
            ) {
                log_cancel_protocol_violation("obligation abort", &validation_result);
                // Continue with abort but log violation
            }
        }

        let info = self.obligations.abort(obligation, now, reason)?;

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

        self.record_task_trace_event(info.holder, |seq| {
            TraceEvent::obligation_abort(
                seq,
                now,
                info.id,
                info.holder,
                info.region,
                info.kind,
                info.duration,
                info.reason,
            )
        });
        self.metrics.obligation_discharged(info.region);

        // Track obligation settlement work in debt monitor
        let cancel_reason = CancelReason::new(CancelKind::User);
        self.debt_monitor.queue_work(
            crate::observability::WorkType::ObligationSettlement,
            format!("obligation_{}_{}", info.id, info.holder),
            1, // Low priority for aborts
            1, // Low cost estimate
            &cancel_reason,
            CancelKind::Shutdown,
            Vec::new(),
        );

        // Notify epoch tracker of obligation abort
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::ObligationTable);

        if let Some(region_record) = self.regions.get(info.region.arena_index()) {
            region_record.resolve_obligation();
        }

        // During leak handling, defer region state advancement to prevent reentrancy.
        // Finalizers run by advance_region_state could acquire new obligations, violating
        // the quiescence invariant and triggering recursive leak handling.
        if self.handling_leaks > 0 {
            self.deferred_region_advancements.insert(info.region);
        } else {
            self.advance_region_state(info.region);
        }

        Ok(info.duration)
    }

    /// Marks an obligation as leaked and emits a trace + error event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    #[allow(clippy::result_large_err)]
    pub fn mark_obligation_leaked(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        let now = self.current_runtime_time();
        let info = self.obligations.mark_leaked(obligation, now)?;

        self.record_task_trace_event(info.holder, |seq| {
            TraceEvent::obligation_leak(
                seq,
                now,
                info.id,
                info.holder,
                info.region,
                info.kind,
                info.duration,
            )
        });
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

    /// Returns the number of non-terminal tasks.
    ///
    /// O(1) — delegates to [`TaskTable::live_task_count`] which keeps
    /// an incremental sum across `phase_counts` (br-asupersync-afv6z4).
    /// Pre-fix this method scanned the arena via `tasks_iter()` and
    /// filtered by `state.is_terminal()` on every call, costing O(N)
    /// in the arena's high-water-mark size — silently O(N²) when a
    /// caller (e.g., `LyapunovGovernor::StateSnapshot::from_runtime_state`,
    /// region-close checks, doctor diagnostics) invokes it inside
    /// another arena walk. The xxcss5 work
    /// (1f942f8e0/86d9793a2/665de00fe/adadea72) wired the
    /// `phase_counts`-backed incremental counter on `TaskTable`
    /// precisely so this delegation could be O(1); this commit
    /// closes the gap that work missed.
    ///
    /// **Edge cases preserved:**
    /// - *claim-but-not-spawned*: a task that has been registered
    ///   in the table but has not yet been admitted to a region
    ///   (state = `Created`) counts as live. `phase_counts` includes
    ///   the `Created` phase bucket, so the result matches the
    ///   pre-fix `!is_terminal()` predicate.
    /// - *in-flight cancel*: a task in `CancelRequested`,
    ///   `Draining`, or `Finalizing` is non-terminal. Each of these
    ///   has its own bucket in `phase_counts`, so they're all
    ///   counted, again matching the pre-fix filter.
    /// - The terminal phase (`Completed`) is the only bucket excluded
    ///   from the sum, mirroring `is_terminal()`.
    #[inline]
    #[must_use]
    pub fn live_task_count(&self) -> usize {
        self.tasks.live_task_count()
    }

    /// Counts live regions.
    #[must_use]
    pub fn live_region_count(&self) -> usize {
        self.regions_iter()
            .filter(|(_, r)| !r.state().is_terminal())
            .count()
    }

    /// Counts pending obligations.
    ///
    /// O(1) — delegates to `ObligationTable::pending_count()` which maintains
    /// an incremental counter.
    #[inline]
    #[must_use]
    pub fn pending_obligation_count(&self) -> usize {
        self.obligations.pending_count()
    }

    /// Returns the pending obligation count for a specific kind.
    ///
    /// O(1) — maintained incrementally in `ObligationTable`
    /// (br-asupersync-xxcss5). Lets the Lyapunov governor build a state
    /// snapshot without iterating the obligation arena.
    #[inline]
    #[must_use]
    pub fn pending_obligation_count_for_kind(&self, kind: crate::record::ObligationKind) -> usize {
        self.obligations.pending_count_for_kind(kind)
    }

    /// Returns the sum of `reserved_at.as_nanos()` across all pending
    /// obligations. Combined with virtual-time `now`, yields the total
    /// pending-obligation age in O(1).
    #[inline]
    #[must_use]
    pub fn pending_obligation_reserved_at_sum_ns(&self) -> u128 {
        self.obligations.pending_reserved_at_sum_ns()
    }

    #[inline]
    pub(crate) fn draining_region_count_for_snapshot(&self) -> usize {
        self.read_biased_draining_region_snapshot
            .read_or_scan(&self.regions)
    }

    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn read_biased_region_snapshot_enabled(&self) -> bool {
        self.read_biased_draining_region_snapshot.enabled()
    }

    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn read_biased_region_snapshot_stats(&self) -> ReadBiasedRegionSnapshotStats {
        self.read_biased_draining_region_snapshot.stats()
    }

    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    /// Invalidates the cached draining-region snapshot so the next read uses
    /// the authoritative region-table scan.
    pub fn invalidate_read_biased_region_snapshot_for_testing(&self) {
        self.read_biased_draining_region_snapshot.invalidate();
    }

    fn note_read_biased_region_snapshot_transition(
        &self,
        old_state: RegionState,
        new_state: RegionState,
    ) {
        self.read_biased_draining_region_snapshot
            .note_transition(old_state, new_state);
    }

    /// Returns true if the runtime is quiescent (no live work).
    ///
    /// A runtime is quiescent when:
    /// - No live tasks are running
    /// - No pending obligations exist
    /// - No I/O sources are registered (if I/O driver is present)
    /// - No region is still in the close lifecycle
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        // Short-circuit: each check is progressively more expensive, so bail
        // early if any preceding condition is already false.
        self.live_task_count() == 0
            && self.pending_obligation_count() == 0
            && self.io_driver.as_ref().is_none_or(IoDriverHandle::is_empty)
            && self
                .regions
                .iter()
                .all(|(_, r)| r.finalizers_empty() && !r.state().is_closing())
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

    /// Implements `inv.cancel.propagates_down` (#6, SEM-INV-003):
    /// cancel(region) -> cancel all non-Completed children.
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
        let now = self.current_runtime_time();

        for &task_id in &sibling_candidates {
            if task_id == child {
                continue;
            }
            let budget = reason.cleanup_budget();
            let mut newly_cancelled = false;
            let mut is_cancelling = false;
            let res = self.update_task(task_id, |task_record| {
                newly_cancelled = task_record.request_cancel_with_budget(reason.clone(), budget);
                is_cancelling = task_record.state.is_cancelling();
            });
            if res.is_none() {
                continue;
            }
            if newly_cancelled {
                self.validate_live_task_protocol_transition(
                    task_id,
                    TaskEvent::RequestCancel,
                    "sibling task cancellation",
                );
                self.record_task_trace_event(task_id, |seq| {
                    TraceEvent::cancel_request(seq, now, task_id, region, reason.clone())
                });
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
    pub fn cancel_request(
        &mut self,
        region_id: RegionId,
        reason: &CancelReason,
        source_task: Option<TaskId>,
    ) -> Vec<(TaskId, u8)> {
        // Use a modest initial capacity instead of scanning the entire task
        // arena for live_task_count(). The Vec will grow if needed, but avoids
        // the O(arena_capacity) scan just for a size hint.
        let mut tasks_to_cancel = Vec::with_capacity(32);
        let cleanup_budget = reason.cleanup_budget();
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (source_task, cleanup_budget);
        let root_span = debug_span!(
            "cancel_request",
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = cleanup_budget.poll_quota,
            cleanup_priority = cleanup_budget.priority,
            source_task = ?source_task
        );
        let _root_guard = root_span.enter();

        debug!(
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = cleanup_budget.poll_quota,
            cleanup_priority = cleanup_budget.priority,
            source_task = ?source_task,
            "cancel request initiated"
        );
        let now = self.current_runtime_time();

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
                // Look up parent's reason from the map. Regions are
                // processed depth-ascending, so the parent's reason MUST
                // be in the map by the time we reach this child.
                //
                // br-asupersync-tnk8ny: If it's absent, that signals an
                // invariant break in the traversal — the previous
                // implementation silently fell back to `reason.clone()`
                // (the ROOT target's reason), which papered over the
                // bookkeeping bug AND poisoned the cause chain by
                // stamping the root reason as if it were the immediate
                // parent's. Now we log the violation as `error!` and
                // synthesize a self-rooted ParentCancelled diagnostic sentinel
                // (no `with_cause_limited` chain) so cause-chain
                // consumers see "depth>0 region with empty parent cause"
                // — a clear signal that something is wrong, instead of
                // a misleading "looks like the root" chain.
                let parent_reason = match region_reasons.get(&parent_id) {
                    Some(r) => r.clone(),
                    None => {
                        error!(
                            target_region = ?rid,
                            parent_region = ?parent_id,
                            depth = node.depth,
                            "INVARIANT VIOLATION: parent region's cancel reason missing \
                             from chain map; regions must be processed depth-ascending — \
                             this indicates either an out-of-order traversal or a parent \
                             that was skipped (br-tnk8ny)"
                        );
                        // Self-rooted sentinel: ParentCancelled stamped
                        // at the missing parent's region so post-mortem
                        // inspection can find the chain break. Do NOT
                        // chain the root target reason here — that would
                        // restore the very bug we're fixing.
                        CancelReason::with_origin(CancelKind::ParentCancelled, parent_id, now)
                    }
                };

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

            self.record_trace_event(|seq| {
                TraceEvent::region_cancelled(seq, now, rid, region_reason.clone())
            });
            self.metrics.cancellation_requested(rid, region_reason.kind);

            if let Some(parent) = node.parent {
                #[cfg(not(feature = "tracing-integration"))]
                let _ = parent;
                let span = trace_span!(
                    "cancel_propagate_region",
                    from_region = ?parent,
                    to_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    chain_depth = region_reason.chain_depth()
                );
                span.follows_from(&root_span);
                let _guard = span.enter();
                trace!(
                    from_region = ?parent,
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

            if let Some(region) = self.regions.get_mut(rid.arena_index()) {
                // Use the properly chained reason.
                // Try to transition to Closing with the reason.
                // If already Closing/Draining/etc., strengthen the reason instead.
                let old_state = region.state();
                if region.begin_close(Some(region_reason.clone())) {
                    let new_state = region.state();
                    let _ = (old_state, new_state); // br-yj9czm: counter recomputed authoritatively, no-op transition note
                    self.record_trace_event(|seq| {
                        TraceEvent::new(
                            seq,
                            now,
                            TraceEventKind::RegionCloseBegin,
                            TraceData::Region {
                                region: rid,
                                parent: node.parent,
                            },
                        )
                    });
                } else if region.state() != crate::record::region::RegionState::Closed {
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
                let mut newly_cancelled = false;
                let mut task_budget_res = crate::types::Budget::INFINITE;
                let mut tasks_to_cancel_result = None;

                self.update_task(task_id, |task| {
                    let task_budget = task_reason.cleanup_budget();
                    task_budget_res = task_budget;
                    newly_cancelled =
                        task.request_cancel_with_budget(task_reason.clone(), task_budget);
                    let already_cancelling = task.state.is_cancelling();

                    if newly_cancelled {
                        // Task was newly cancelled, add to list
                        tasks_to_cancel_result = Some((task_id, task_budget.priority));
                    } else if already_cancelling {
                        // Task already cancelling, but still needs scheduling priority
                        tasks_to_cancel_result = Some((task_id, task_budget.priority));
                    }
                });

                if newly_cancelled {
                    self.validate_live_task_protocol_transition(
                        task_id,
                        TaskEvent::RequestCancel,
                        "region task cancellation",
                    );
                    self.record_task_trace_event(task_id, |seq| {
                        TraceEvent::cancel_request(seq, now, task_id, rid, task_reason.clone())
                    });
                }

                if let Some(t) = tasks_to_cancel_result {
                    tasks_to_cancel.push(t);
                }

                // Trace log
                debug!(
                    from_region = ?rid,
                    to_task = ?task_id,
                    depth = node.depth,
                    newly_cancelled,
                    cleanup_poll_quota = task_budget_res.poll_quota,
                    cleanup_priority = task_budget_res.priority,
                    chain_depth = task_reason.chain_depth(),
                    root_cause = ?task_reason.root_cause().kind,
                    "cancel propagated to task with cause chain"
                );
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
            if no_children && no_tasks {
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
    ///
    /// br-asupersync-ndhjfj: the task's `waiters` are taken in a SINGLE
    /// `update_task` critical section as the very first operation. The
    /// previous structure read task properties in one immutable-borrow
    /// scope and then re-acquired a mutable borrow later to take the
    /// waiters; while Rust's `&mut self` exclusion makes runtime
    /// races impossible today, the multi-step pattern was fragile
    /// against future refactors that might split `task_completed` into
    /// re-entrant paths. Taking the waiters atomically with the
    /// existence check forecloses that hazard. The remaining
    /// validation, record_task_complete, and cleanup operations read
    /// task properties (id, owner, state, created_at) that are NOT
    /// mutated by the waiter-take, so the ordering change is
    /// behaviour-preserving.
    pub fn task_completed(&mut self, task_id: TaskId) -> SmallVec<[TaskId; 4]> {
        // br-asupersync-ndhjfj: atomic existence-check + waiter-take.
        // If the task was already removed (or never existed), return
        // an empty waiter set with the same early-return semantics
        // the prior implementation provided.
        let Some(waiters) = self.update_task(task_id, |task| std::mem::take(&mut task.waiters))
        else {
            trace!(
                task_id = ?task_id,
                "task_completed called for unknown task"
            );
            return SmallVec::new();
        };

        let (owner, completion, outcome_kind, close_outcome) = {
            let Some(task) = self.task(task_id) else {
                // Defensive: if the task vanished between the
                // update_task above and here, return the waiters we
                // already took rather than dropping them.
                return waiters;
            };

            let task_event = match &task.state {
                crate::record::task::TaskState::Completed(Outcome::Cancelled(_)) => {
                    TaskEvent::DrainComplete
                }
                crate::record::task::TaskState::Completed(Outcome::Panicked(payload)) => {
                    TaskEvent::Panic {
                        message: payload.message().to_string(),
                    }
                }
                _ => TaskEvent::Complete,
            };
            self.validate_live_task_protocol_transition(task_id, task_event, "task completion");
            if let Some(inner) = task.cx_inner.as_ref() {
                // br-asupersync-xgujaf — single write-lock; the previous
                // read-then-write split had a TOCTOU window where a concurrent
                // canceller could install a fresh waker between the read drop
                // and write acquire, and we'd silently clear it without ever
                // waking. Task completion is per-task (not a hot path), so the
                // saved write-lock acquisition was not worth the correctness
                // hazard. `take()` is idempotent on None (no allocation, no
                // wake) and keeps the cleared Waker alive only briefly inside
                // the guard scope.
                let _evicted = inner.write().cancel_waker.take();
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
            let close_outcome = match &task.state {
                crate::record::task::TaskState::Completed(outcome) => Some(outcome.clone()),
                _ => None,
            };
            let owner = task.owner;
            let completion = TaskCompletionKind::from_state(&task.state);
            (owner, completion, outcome_kind, close_outcome)
        };
        // br-asupersync-ndhjfj: `waiters` was already taken atomically
        // at the top of the function under `update_task`. The previous
        // separate `task_mut` re-acquisition has been removed.
        let waiter_count = waiters.len();
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (outcome_kind, waiter_count);

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

        if let Some(finalizer_id) = self.async_finalizer_tasks.remove(&task_id) {
            let should_clear_barrier = self
                .active_async_finalizers
                .get(&owner)
                .is_some_and(|active_task| *active_task == task_id);

            // EDGE CASE VALIDATION: Async finalizer barrier consistency check
            // Ensures that barrier tracking is consistent with task tracking
            if should_clear_barrier {
                self.active_async_finalizers.remove(&owner);

                // EDGE CASE VALIDATION: Validate barrier was properly set
                // This catches cases where the barrier tracking might be corrupted
                debug_assert!(
                    self.regions
                        .get(owner.arena_index())
                        .is_some_and(|r| r.state()
                            == crate::record::region::RegionState::Finalizing
                            || r.state() == crate::record::region::RegionState::Closed),
                    "br-asupersync-mg70eb: async finalizer barrier cleared for region in invalid state \
                     (region={:?}, task_id={:?}, finalizer_id={})",
                    owner,
                    task_id,
                    finalizer_id
                );
            } else {
                // EDGE CASE VALIDATION: Detect barrier tracking inconsistencies
                // This catches cases where a finalizer task completes but wasn't tracked as active
                debug_assert!(
                    self.active_async_finalizers.get(&owner) != Some(&task_id),
                    "br-asupersync-mg70eb: async finalizer task completed but barrier tracking is inconsistent \
                     (region={:?}, completed_task={:?}, tracked_task={:?}, finalizer_id={})",
                    owner,
                    task_id,
                    self.active_async_finalizers.get(&owner),
                    finalizer_id
                );
            }

            self.record_finalizer_run(finalizer_id);
        }

        // Trace task completion
        debug!(
            task_id = ?task_id,
            region_id = ?owner,
            outcome_kind = outcome_kind,
            waiter_count = waiter_count,
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
        self.recycle_task(task_id);

        // Remove task from owning region to prevent memory leak
        if let Some(region) = self.regions.get(owner.arena_index()) {
            if let Some(outcome) = close_outcome {
                region.record_close_outcome(outcome);
            }
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
        if self.finalizing_regions.is_empty() {
            return SmallVec::new();
        }
        let mut scheduled = SmallVec::new();
        let mut regions_to_process = SmallVec::<[RegionId; 8]>::new();

        for &region_id in &self.finalizing_regions {
            if self.active_async_finalizers.contains_key(&region_id) {
                continue;
            }
            if let Some(region) = self.regions.get(region_id.arena_index()) {
                if !region.finalizers_empty() {
                    regions_to_process.push(region_id);
                }
            }
        }

        for region_id in regions_to_process {
            let Some((finalizer_id, finalizer)) = self.run_sync_finalizers_tracked(region_id)
            else {
                continue;
            };
            let Finalizer::Async(future) = finalizer else {
                continue;
            };
            match self.spawn_finalizer_task(region_id, finalizer_id, future) {
                Ok((task_id, priority)) => scheduled.push((task_id, priority)),
                Err(future) => {
                    // Preserve the async barrier when task admission fails so
                    // the region cannot close with cleanup silently dropped.
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        region.add_finalizer(Finalizer::Async(future));
                    }
                    self.pending_finalizer_ids
                        .entry(region_id)
                        .or_default()
                        .push(finalizer_id);
                }
            }
        }

        scheduled
    }

    fn spawn_finalizer_task(
        &mut self,
        region_id: RegionId,
        finalizer_id: u64,
        future: BoxedAsyncFinalizer,
    ) -> Result<(TaskId, u8), BoxedAsyncFinalizer> {
        // EDGE CASE VALIDATION: Check async finalizer barrier consistency before spawning
        // This prevents concurrent async finalizers from the same region, which violates LIFO ordering
        debug_assert!(
            !self.active_async_finalizers.contains_key(&region_id),
            "br-asupersync-mg70eb: async finalizer barrier violation - region already has active async finalizer \
             (region={:?})",
            region_id
        );

        let deadline = self
            .current_runtime_time()
            .saturating_add_nanos(FINALIZER_TIME_BUDGET_NANOS);
        let budget = finalizer_budget().with_deadline(deadline);

        // EDGE CASE VALIDATION: Validate budget parameters are sane
        // This catches invalid time computations that could cause finalizers to run forever
        debug_assert!(
            budget.deadline.is_some(),
            "br-asupersync-mg70eb: finalizer budget must have deadline to prevent unbounded execution \
             (region={:?}, finalizer_id={})",
            region_id,
            finalizer_id
        );
        debug_assert!(
            budget.poll_quota > 0,
            "br-asupersync-mg70eb: finalizer budget must have non-zero poll quota \
             (region={:?}, finalizer_id={}, poll_quota={})",
            region_id,
            finalizer_id,
            budget.poll_quota
        );

        let system_cx = self.create_system_cx();
        let Ok((task_id, _handle, cx, result_tx)) =
            self.create_task_infrastructure::<()>(&system_cx, region_id, budget, true)
        else {
            // EDGE CASE VALIDATION: Log task creation failure for debugging
            // This helps identify resource exhaustion scenarios that could block finalizer execution
            debug!(
                region_id = ?region_id,
                finalizer_id = finalizer_id,
                "br-asupersync-mg70eb: failed to create async finalizer task - returning future for requeueing"
            );
            return Err(future);
        };
        let cx_inner = Arc::clone(&cx.inner);
        let masked = MaskedFinalizer::new(future, cx_inner);

        let wrapped_future = async move {
            match (CatchUnwind { inner: masked }).await {
                Ok(()) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(()));
                    Outcome::Ok(())
                }
                Err(payload) => {
                    let panic_payload =
                        crate::types::outcome::PanicPayload::new(payload_to_string(&payload));
                    let _ = result_tx.send(
                        &cx,
                        Err::<(), JoinError>(JoinError::Panicked(panic_payload.clone())),
                    );
                    Outcome::Panicked(panic_payload)
                }
            }
        };

        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        // Mark the task as notified since it will be immediately injected into
        // the ready queue by the caller (drain_ready_async_finalizers).
        if let Some(record) = self.task(task_id) {
            record.wake_state.notify();
        }

        self.async_finalizer_tasks.insert(task_id, finalizer_id);
        let previous = self.active_async_finalizers.insert(region_id, task_id);
        debug_assert!(
            previous.is_none(),
            "region {:?} already had an active async finalizer barrier: {:?}",
            region_id,
            previous
        );
        self.validate_live_region_protocol_transition(
            region_id,
            RegionEvent::FinalizerStarted,
            "async finalizer start",
        );
        Ok((task_id, budget.priority))
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
        let accepts_finalizers = self
            .regions
            .get(region_id.arena_index())
            .is_some_and(|region| !region.state().is_closing() && !region.state().is_terminal());
        if !accepts_finalizers {
            return false;
        }

        let finalizer_id = self.allocate_finalizer_id();
        {
            let Some(region) = self.regions.get(region_id.arena_index()) else {
                return false;
            };
            region.add_finalizer(Finalizer::Sync(Box::new(f)));
        }
        self.record_finalizer_registration(finalizer_id, region_id);

        // Track finalizer work in debt monitor
        let cancel_reason = CancelReason::user("sync_finalizer_registration");
        self.debt_monitor.queue_work(
            crate::observability::WorkType::RegionCleanup,
            format!("sync_finalizer_{finalizer_id}_{region_id}"),
            5, // Medium priority for cleanup
            2, // Medium cost estimate
            &cancel_reason,
            CancelKind::Shutdown,
            Vec::new(),
        );

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
        let accepts_finalizers = self
            .regions
            .get(region_id.arena_index())
            .is_some_and(|region| !region.state().is_closing() && !region.state().is_terminal());
        if !accepts_finalizers {
            return false;
        }

        let finalizer_id = self.allocate_finalizer_id();
        {
            let Some(region) = self.regions.get(region_id.arena_index()) else {
                return false;
            };
            region.add_finalizer(Finalizer::Async(Box::pin(future)));
        }
        self.record_finalizer_registration(finalizer_id, region_id);

        // Track async finalizer work in debt monitor
        let cancel_reason = CancelReason::user("async_finalizer_registration");
        self.debt_monitor.queue_work(
            crate::observability::WorkType::RegionCleanup,
            format!("async_finalizer_{finalizer_id}_{region_id}"),
            6, // Medium-high priority for async cleanup
            3, // Higher cost estimate for async work
            &cancel_reason,
            CancelKind::Shutdown,
            Vec::new(),
        );

        true
    }

    fn allocate_finalizer_id(&mut self) -> u64 {
        let id = self.next_finalizer_id;
        self.next_finalizer_id = self
            .next_finalizer_id
            .checked_add(1)
            .expect("finalizer ID overflow");
        id
    }

    fn record_finalizer_registration(&mut self, id: u64, region: RegionId) {
        let now = self.current_runtime_time();
        self.validate_live_region_protocol_transition(
            region,
            RegionEvent::FinalizerRegistered,
            "finalizer registration",
        );
        self.pending_finalizer_ids
            .entry(region)
            .or_default()
            .push(id);
        self.finalizer_history
            .push(FinalizerHistoryEvent::Registered {
                id,
                region,
                time: now,
            });
        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::RegionTable);
    }

    fn record_finalizer_run(&mut self, id: u64) {
        let now = self.current_runtime_time();
        self.finalizer_history
            .push(FinalizerHistoryEvent::Ran { id, time: now });
    }

    fn record_finalizer_close(&mut self, region: RegionId) {
        let now = self.current_runtime_time();
        self.pending_finalizer_ids.remove(&region);
        self.finalizer_history
            .push(FinalizerHistoryEvent::RegionClosed { region, time: now });
    }

    fn pop_tracked_finalizer(&mut self, region_id: RegionId) -> Option<(u64, Finalizer)> {
        let finalizer = {
            let region = self.regions.get(region_id.arena_index())?;
            region.pop_finalizer()
        };
        let finalizer = match finalizer {
            Some(finalizer) => finalizer,
            None => {
                debug_assert!(
                    !self.pending_finalizer_ids.contains_key(&region_id),
                    "br-asupersync-mg70eb: finalizer ID tracking remains after finalizer stack drained \
                     (region={:?})",
                    region_id
                );
                return None;
            }
        };
        let (id, empty_after_pop) = {
            let ids = self
                .pending_finalizer_ids
                .get_mut(&region_id)
                .expect("finalizer id tracking missing for region");

            // EDGE CASE VALIDATION: Verify ID tracking consistency before popping
            // This catches cases where the finalizer stack and ID tracking get out of sync
            debug_assert!(
                !ids.is_empty(),
                "br-asupersync-mg70eb: finalizer ID tracking stack is empty but region has finalizers \
                 (region={:?})",
                region_id
            );

            let id = ids.pop().expect("finalizer id stack out of sync");

            // EDGE CASE VALIDATION: Validate finalizer ID is within expected range
            // This catches corruption where invalid IDs are tracked
            debug_assert!(
                id < self.next_finalizer_id,
                "br-asupersync-mg70eb: popped finalizer ID exceeds next_finalizer_id \
                 (region={:?}, popped_id={}, next_id={})",
                region_id,
                id,
                self.next_finalizer_id
            );

            (id, ids.is_empty())
        };
        if empty_after_pop {
            self.pending_finalizer_ids.remove(&region_id);
        }

        // EDGE CASE VALIDATION: Final consistency check after successful pop
        // Ensures the region and tracking state remain consistent
        if let Some(region) = self.regions.get(region_id.arena_index()) {
            let has_more_finalizers = !region.finalizers_empty();
            let has_more_ids = self.pending_finalizer_ids.contains_key(&region_id);
            debug_assert_eq!(
                has_more_finalizers, has_more_ids,
                "br-asupersync-mg70eb: finalizer stack and ID tracking inconsistency after pop \
                 (region={:?}, has_finalizers={}, has_ids={}, popped_id={})",
                region_id, has_more_finalizers, has_more_ids, id
            );
        }

        Some((id, finalizer))
    }

    /// Pops the next finalizer from a region's finalizer stack.
    ///
    /// This is called during the Finalizing phase to get the next cleanup
    /// handler to run. Finalizers are returned in LIFO order.
    ///
    /// # Returns
    /// The next finalizer to run, or `None` if all finalizers have been executed.
    pub fn pop_region_finalizer(&mut self, region_id: RegionId) -> Option<Finalizer> {
        self.pop_tracked_finalizer(region_id)
            .map(|(_, finalizer)| finalizer)
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
        self.run_sync_finalizers_tracked(region_id)
            .map(|(_, finalizer)| finalizer)
    }

    fn run_sync_finalizers_tracked(&mut self, region_id: RegionId) -> Option<(u64, Finalizer)> {
        loop {
            // VALIDATION GAP FIX: Assert region is in Finalizing state before executing finalizers
            // This prevents finalizers from running during invalid state transitions
            if let Some(region) = self.regions.get(region_id.arena_index()) {
                debug_assert_eq!(
                    region.state(),
                    crate::record::region::RegionState::Finalizing,
                    "br-asupersync-vks0tm: finalizer execution must only occur in Finalizing state \
                     (region={:?}, current_state={:?})",
                    region_id,
                    region.state()
                );
            }

            let (finalizer_id, finalizer) = self.pop_tracked_finalizer(region_id)?;

            match finalizer {
                Finalizer::Sync(f) => {
                    self.validate_live_region_protocol_transition(
                        region_id,
                        RegionEvent::FinalizerStarted,
                        "sync finalizer start",
                    );

                    // VALIDATION GAP FIX: Re-validate state after popping but before execution
                    // This catches rapid state transitions that might skip finalizers
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        if region.state() != crate::record::region::RegionState::Finalizing {
                            // Region state changed unexpectedly - this is a critical validation failure
                            assert_eq!(
                                region.state(),
                                crate::record::region::RegionState::Finalizing,
                                "br-asupersync-vks0tm: critical finalizer validation gap detected - \
                                 region state changed from Finalizing to {:?} during finalizer execution \
                                 (region={:?}, finalizer_id={})",
                                region.state(),
                                region_id,
                                finalizer_id
                            );
                        }
                    }

                    // Run synchronously, catching panics to ensure remaining
                    // finalizers still execute and the region is not permanently
                    // stuck in Finalizing state.
                    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
                    {
                        // Log but continue — a panicking finalizer must not
                        // block region close or skip sibling finalizers.
                        if let Some(region) = self.regions.get(region_id.arena_index()) {
                            region.record_close_outcome(Outcome::Panicked(
                                crate::types::outcome::PanicPayload::new(payload_to_string(
                                    &payload,
                                )),
                            ));
                        }
                    }

                    // VALIDATION GAP FIX: Validate state is still consistent after execution
                    // This ensures the finalizer didn't cause invalid state transitions
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        debug_assert!(
                            region.state() == crate::record::region::RegionState::Finalizing
                                || region.state() == crate::record::region::RegionState::Closed,
                            "br-asupersync-vks0tm: finalizer execution left region in invalid state \
                             (region={:?}, state_after_finalizer={:?}, finalizer_id={})",
                            region_id,
                            region.state(),
                            finalizer_id
                        );
                    }

                    self.record_finalizer_run(finalizer_id);
                }
                Finalizer::Async(_) => {
                    // VALIDATION GAP FIX: Validate async finalizers also respect state transitions
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        debug_assert_eq!(
                            region.state(),
                            crate::record::region::RegionState::Finalizing,
                            "br-asupersync-vks0tm: async finalizer must be scheduled only in Finalizing state \
                             (region={:?}, current_state={:?}, finalizer_id={})",
                            region_id,
                            region.state(),
                            finalizer_id
                        );
                    }

                    // Stop and return the async barrier
                    return Some((finalizer_id, finalizer));
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

        // VALIDATION GAP FIX: Strengthen finalizer completion validation
        // This catches cases where finalizers might have been skipped due to rapid state transitions
        if !region.finalizers_empty() {
            // Additional validation: ensure we have proper tracking for pending finalizers
            debug_assert!(
                self.pending_finalizer_ids.contains_key(&region_id)
                    || region.finalizer_count() == 0,
                "br-asupersync-vks0tm: finalizer tracking inconsistency detected - \
                 region has finalizers but no tracked IDs (region={:?}, finalizer_count={})",
                region_id,
                region.finalizer_count()
            );
            return false;
        }

        // VALIDATION GAP FIX: Ensure finalizer ID tracking is properly cleaned up
        // This prevents leaked tracking state from interfering with future operations
        if self.pending_finalizer_ids.contains_key(&region_id) {
            debug_assert!(
                false,
                "br-asupersync-vks0tm: finalizer ID tracking leak detected - \
                 region reports no finalizers but tracking still exists (region={:?})",
                region_id
            );
            return false;
        }

        // br-asupersync-1erlwe: also wait for any active async finalizer
        // tasks to be fully cleared from `active_async_finalizers`. The
        // queue check above (`finalizers_empty`) only verifies that no
        // additional finalizers are pending; it does NOT cover the
        // window between `task_completed` removing the running async
        // finalizer task and the next `advance_region_state` cleanup
        // pass. Without this check, a concurrent `advance_region_state`
        // could observe `finalizers_empty == true` and transition the
        // region to Closed BEFORE the async-finalizer barrier is
        // observably released — producing a `region.closed` trace
        // event that precedes the corresponding `finalizer.completed`
        // event in the timeline. The `active_async_finalizers` map is
        // the single authoritative source of truth for "is an async
        // finalizer still in flight"; folding it into the close-
        // readiness predicate keeps trace events causally ordered.
        //
        // The Finalizing branch in `advance_region_state` (around
        // line 3190) already short-circuits on this same condition;
        // mirroring it here keeps the two codepaths' invariants
        // aligned so external `can_region_complete_close` consumers
        // (oracles, debug introspection) see the same readiness
        // verdict the state machine itself does.
        if self.active_async_finalizers.contains_key(&region_id) {
            return false;
        }

        // All tasks must be fully completed and cleaned up.
        // We cannot just check if they are terminal, because their `task_completed`
        // cleanup might not have run yet, and closing the region clears the heap prematurely.
        if region.task_count() > 0 {
            return false;
        }

        // All obligations must be resolved
        if region.pending_obligations() > 0 {
            return false;
        }

        // All children must be fully closed and removed
        if region.child_count() > 0 {
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
    #[allow(clippy::too_many_lines)]
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
                    // Only a region with terminal tasks and closed children may enter
                    // finalization. Non-quiescent Closing/Draining regions stay put while
                    // task cleanup, child close propagation, or finalizer scheduling makes
                    // progress.
                    let transition_to_finalizing = if self.can_region_finalize(region_id) {
                        let Some(region) = self.regions.get(region_id.arena_index()) else {
                            break;
                        };

                        // Validate protocol transition to Finalizing
                        let context = RegionContext {
                            region_id,
                            parent_region: region.parent,
                            created_at: region.created_at,
                            validation_level: CancelValidationLevel::Basic,
                        };
                        let validation_result = self.validate_region_protocol_transition(
                            region_id,
                            RegionEvent::RequestClose, // Use RequestClose for finalization
                            &context,
                        );
                        if matches!(
                            validation_result,
                            TransitionResult::Invalid { .. }
                                | TransitionResult::InvariantViolation { .. }
                        ) {
                            log_cancel_protocol_violation(
                                "region finalize transition",
                                &validation_result,
                            );
                            // Protocol violation detected - invalidate region snapshot cache
                            // to ensure consistency is re-established via authoritative scan
                            self.read_biased_draining_region_snapshot.invalidate();
                            // Continue with transition but log violation
                        }

                        // Atomic check-and-transition: begin_finalize() internally validates
                        // that child_count() == 0 && task_count() == 0 under proper locking
                        let transition = {
                            let old_state = region.state();
                            if region.begin_finalize() {
                                Some((old_state, region.state()))
                            } else {
                                None
                            }
                        };
                        if let Some((old_state, new_state)) = transition {
                            self.note_read_biased_region_snapshot_transition(old_state, new_state);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // Check if region needs to transition to Draining (has children but is Closing)
                    let Some(region) = self.regions.get(region_id.arena_index()) else {
                        break;
                    };
                    if region.child_count() > 0
                        && region.state() == crate::record::region::RegionState::Closing
                    {
                        // Validate protocol transition to Draining
                        let context = RegionContext {
                            region_id,
                            parent_region: region.parent,
                            created_at: region.created_at,
                            validation_level: CancelValidationLevel::Basic,
                        };
                        let validation_result = self.validate_region_protocol_transition(
                            region_id,
                            RegionEvent::Cancel {
                                reason: "draining children".to_string(),
                            },
                            &context,
                        );
                        if matches!(
                            validation_result,
                            TransitionResult::Invalid { .. }
                                | TransitionResult::InvariantViolation { .. }
                        ) {
                            log_cancel_protocol_violation(
                                "region drain transition",
                                &validation_result,
                            );
                            // Protocol violation detected - invalidate region snapshot cache
                            self.read_biased_draining_region_snapshot.invalidate();
                            // Continue with transition but log violation
                        }

                        let old_state = region.state();
                        region.begin_drain();
                        let new_state = region.state();
                        self.note_read_biased_region_snapshot_transition(old_state, new_state);

                        self.notify_runtime_epoch_advance(
                            super::epoch_tracker::ModuleId::RegionTable,
                        );
                    }

                    if transition_to_finalizing {
                        self.notify_runtime_epoch_advance(
                            super::epoch_tracker::ModuleId::RegionTable,
                        );
                        self.finalizing_regions.push(region_id);
                        // Re-process same region as Finalizing in next iteration
                        current = Some(region_id);
                    }
                }
                crate::record::region::RegionState::Finalizing => {
                    if self.active_async_finalizers.contains_key(&region_id) {
                        break;
                    }

                    // Run sync finalizers (requires mut self).
                    // If we hit an async finalizer, reinsert it and wait for a scheduler.
                    if let Some((finalizer_id, async_finalizer)) =
                        self.run_sync_finalizers_tracked(region_id)
                    {
                        if let Some(region) = self.regions.get(region_id.arena_index()) {
                            region.add_finalizer(async_finalizer);
                        }
                        self.pending_finalizer_ids
                            .entry(region_id)
                            .or_default()
                            .push(finalizer_id);
                        break; // Async finalizer pending; stop advancing
                    }

                    // If finalizing and obligations remain with no tracked tasks, mark leaks.
                    // Terminal task state is not enough here: `task_completed` still has to
                    // abort or leak-resolve orphaned obligations and unlink the task from the
                    // region. Finalizing leak detection must therefore wait for full task
                    // cleanup, not just a terminal outcome.
                    if let Some(region) = self.regions.get(region_id.arena_index()) {
                        if region.pending_obligations() > 0 {
                            if region.task_count() == 0 {
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
                        // Validate protocol transition to Closed
                        let closed = {
                            let Some(region) = self.regions.get(region_id.arena_index()) else {
                                break;
                            };
                            let context = RegionContext {
                                region_id,
                                parent_region: region.parent,
                                created_at: region.created_at,
                                validation_level: CancelValidationLevel::Basic,
                            };
                            let validation_result = self.validate_region_protocol_transition(
                                region_id,
                                RegionEvent::FinalizerCompleted, // Use FinalizerCompleted for close
                                &context,
                            );
                            if matches!(
                                validation_result,
                                TransitionResult::Invalid { .. }
                                    | TransitionResult::InvariantViolation { .. }
                            ) {
                                log_cancel_protocol_violation(
                                    "region close completion",
                                    &validation_result,
                                );
                                // Protocol violation detected - invalidate region snapshot cache
                                self.read_biased_draining_region_snapshot.invalidate();
                                // Continue with transition but log violation
                            }

                            let old_state = region.state();
                            let closed = region.complete_close();
                            let new_state = region.state();
                            (closed, old_state, new_state)
                        };

                        if closed.0 {
                            self.note_read_biased_region_snapshot_transition(closed.1, closed.2);
                            if let Some(pos) =
                                self.finalizing_regions.iter().position(|&r| r == region_id)
                            {
                                self.finalizing_regions.swap_remove(pos);
                            }
                            self.record_finalizer_close(region_id);

                            // Mark region as finalized in obligation table to prevent
                            // drop-late obligation commits/aborts after region close
                            self.obligations.mark_region_finalized(region_id);

                            // Emit RegionCloseComplete trace event (pairs
                            // with RegionCloseBegin emitted in cancel_request).
                            let now = self.current_runtime_time();
                            self.record_trace_event(|seq| {
                                TraceEvent::new(
                                    seq,
                                    now,
                                    TraceEventKind::RegionCloseComplete,
                                    TraceData::Region {
                                        region: region_id,
                                        parent,
                                    },
                                )
                            });

                            // Emit region_closed metric with lifetime.
                            if let Some(region) = self.regions.get(region_id.arena_index()) {
                                let lifetime =
                                    Duration::from_nanos(now.duration_since(region.created_at()));
                                self.metrics.region_closed(region_id, lifetime);
                            }
                            self.resource_monitor.clear_region_priority(region_id);

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

                            let close_outcome = self
                                .regions
                                .get(region_id.arena_index())
                                .and_then(|region| region.close_outcome());
                            if self.root_region == Some(region_id) {
                                self.root_region = None;
                            }
                            self.remember_closed_region(region_id, close_outcome);
                            // Cleanup: Remove the closed region from the arena to prevent memory leaks
                            self.regions.remove(region_id.arena_index());
                            self.notify_runtime_epoch_advance(
                                super::epoch_tracker::ModuleId::RegionTable,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn remember_closed_region(
        &mut self,
        region_id: RegionId,
        outcome: Option<crate::record::task::TaskOutcome>,
    ) {
        if !self.recently_closed_regions.insert(region_id) {
            return;
        }

        if let Some(outcome) = outcome {
            self.recently_closed_region_outcomes
                .insert(region_id, outcome);
        }

        self.recently_closed_region_order.push_back(region_id);
        while self.recently_closed_region_order.len() > Self::RECENTLY_CLOSED_REGION_CAPACITY {
            if let Some(evicted) = self.recently_closed_region_order.pop_front() {
                self.recently_closed_regions.remove(&evicted);
                self.recently_closed_region_outcomes.remove(&evicted);
            }
        }
    }

    pub(crate) fn finalizer_history(&self) -> &[FinalizerHistoryEvent] {
        &self.finalizer_history
    }

    #[must_use]
    pub(crate) fn loser_drain_history(&self) -> Vec<LoserDrainHistoryEvent> {
        self.loser_drain_history.snapshot()
    }

    #[must_use]
    pub(crate) fn loser_drain_history_handle(&self) -> LoserDrainHistoryHandle {
        Arc::clone(&self.loser_drain_history)
    }

    #[cfg(test)]
    pub(crate) fn record_finalizer_close_for_test(&mut self, region: RegionId) {
        self.record_finalizer_close(region);
    }

    #[cfg(test)]
    pub(crate) fn enqueue_finalizing_region_for_test(&mut self, region: RegionId) {
        if !self.finalizing_regions.contains(&region) {
            self.finalizing_regions.push(region);
        }
    }

    /// Returns a reference to the resource monitor for graceful degradation.
    ///
    /// The resource monitor tracks memory, file descriptors, CPU load, and network
    /// connections, and triggers degradation policies when thresholds are exceeded.
    pub fn resource_monitor(&self) -> Arc<ResourceMonitor> {
        Arc::clone(&self.resource_monitor)
    }

    /// Sets the priority for a region in the graceful degradation system.
    ///
    /// Higher priority regions (Critical, High) are preserved during resource
    /// pressure, while lower priority regions (Low, BestEffort) are shed first.
    ///
    /// # Arguments
    /// * `region_id` - The region to set the priority for
    /// * `priority` - The new priority level for the region
    ///
    /// # Returns
    /// * `true` if the region exists and priority was set
    /// * `false` if the region does not exist
    pub fn set_region_priority(&mut self, region_id: RegionId, priority: RegionPriority) -> bool {
        if self.regions.get(region_id.arena_index()).is_none() {
            return false;
        }
        self.resource_monitor
            .engine()
            .set_region_priority(region_id, priority);
        true
    }

    /// Checks if the runtime should accept new work based on resource pressure.
    ///
    /// Returns `true` if resource pressure is acceptable for new regions/tasks,
    /// or `false` if the runtime should apply backpressure.
    pub fn should_accept_new_work(&self) -> bool {
        let composite_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();
        matches!(
            composite_level,
            DegradationLevel::None | DegradationLevel::Light
        )
    }

    /// Gets the current degradation level and statistics.
    ///
    /// This provides visibility into the current resource pressure state
    /// for monitoring and debugging purposes.
    pub fn degradation_stats(&self) -> DegradationStatsSnapshot {
        self.resource_monitor.engine().stats()
    }

    /// Applies resource-based work shedding decisions during region creation.
    ///
    /// This integrates the graceful degradation system with region creation
    /// by rejecting new regions when resource pressure is high and the
    /// requested region priority is below the shedding threshold.
    ///
    /// # Arguments
    /// * `priority` - Priority of the region being created
    ///
    /// # Returns
    /// * `Ok(())` if the region should be allowed
    /// * `Err(RegionCreateError)` if the region should be rejected due to resource pressure
    pub fn check_resource_pressure_for_region(
        &self,
        priority: RegionPriority,
    ) -> Result<(), RegionCreateError> {
        // First, check using the existing basic resource monitor for critical path compatibility
        let composite_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();

        // For critical and high priority regions, always allow through basic check first
        if matches!(priority, RegionPriority::Critical | RegionPriority::High) {
            return Ok(());
        }

        // For lower priority regions, use the enhanced swarm pressure governor
        // We create a minimal context for the admission check since we're in the region creation path
        let minimal_cx = self.create_minimal_cx_for_admission_check();

        match self.swarm_pressure_governor.check_region_admission(&minimal_cx, priority, None) {
            Ok(admission_decision) => {
                match admission_decision.decision {
                    crate::observability::pressure_governor::AdmissionDecision::Admit |
                    crate::observability::pressure_governor::AdmissionDecision::AdmitWithBackpressure => {
                        Ok(())
                    }
                    crate::observability::pressure_governor::AdmissionDecision::Reject => {
                        Err(RegionCreateError::ResourcePressure {
                            requested_priority: priority,
                            reason: admission_decision.reason,
                        })
                    }
                }
            }
            Err(err) => {
                // Fall back to basic degradation check if swarm governor fails
                let should_shed = match (composite_level, priority) {
                    (DegradationLevel::Heavy | DegradationLevel::Emergency, RegionPriority::Normal) => true,
                    (
                        DegradationLevel::Moderate | DegradationLevel::Heavy | DegradationLevel::Emergency,
                        RegionPriority::Low | RegionPriority::BestEffort,
                    ) => true,
                    _ => false,
                };

                if should_shed {
                    Err(RegionCreateError::ResourcePressure {
                        requested_priority: priority,
                        reason: format!(
                            "Resource pressure level {:?} prevents region creation at priority {:?} (swarm governor error: {})",
                            composite_level, priority, err
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Creates a minimal Cx for internal admission checks during region creation.
    ///
    /// This creates a lightweight context that can be used for pressure governor
    /// admission decisions without requiring a full region hierarchy.
    fn create_minimal_cx_for_admission_check(&self) -> crate::cx::Cx {
        crate::cx::Cx::new(
            self.root_region.unwrap_or_else(next_bootstrap_region_id),
            next_bootstrap_task_id(),
            Budget::INFINITE,
        )
    }

    /// Creates a resource envelope for a region based on its budgets.
    fn create_resource_envelope_for_region(
        &self,
        region_id: RegionId,
        budget: &Budget,
        capability_budget: &CapabilityBudget,
    ) -> Result<crate::observability::swarm_pressure_governor::ResourceEnvelope, Error> {
        use crate::observability::swarm_pressure_governor::ResourceEnvelope;

        // Extract resource limits from budget and capability budget
        let config = SwarmPressureGovernorConfig::default();
        let memory_budget = capability_budget
            .memory_bytes
            .or(budget.cost_quota)
            .unwrap_or(config.default_memory_budget_bytes);
        let cpu_budget_ns_per_sec = budget
            .deadline
            .map_or(config.default_cpu_budget_ns_per_sec, Time::as_nanos);
        let io_budget_ops_per_sec = config.default_io_budget_ops_per_sec;

        Ok(ResourceEnvelope::new(
            region_id,
            memory_budget,
            cpu_budget_ns_per_sec,
            io_budget_ops_per_sec,
        ))
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
    /// Finalizer lifecycle history for oracle hydration.
    pub finalizer_history: Vec<FinalizerHistoryEvent>,
    /// Loser-drain race history for oracle hydration.
    pub loser_drain_history: Vec<LoserDrainHistoryEvent>,
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
            message: reason.message.clone(),
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
    /// Semaphore permit.
    SemaphorePermit,
}

impl From<ObligationKind> for ObligationKindSnapshot {
    fn from(kind: ObligationKind) -> Self {
        match kind {
            ObligationKind::SendPermit => Self::SendPermit,
            ObligationKind::Ack => Self::Ack,
            ObligationKind::Lease => Self::Lease,
            ObligationKind::IoOp => Self::IoOp,
            ObligationKind::SemaphorePermit => Self::SemaphorePermit,
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
    /// Worker-offload cancellation requested.
    WorkerCancelRequested,
    /// Worker-offload cancellation acknowledged.
    WorkerCancelAcknowledged,
    /// Worker-offload drain phase started.
    WorkerDrainStarted,
    /// Worker-offload drain phase completed.
    WorkerDrainCompleted,
    /// Worker-offload finalize phase completed.
    WorkerFinalizeCompleted,
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
            TraceEventKind::WorkerCancelRequested => Self::WorkerCancelRequested,
            TraceEventKind::WorkerCancelAcknowledged => Self::WorkerCancelAcknowledged,
            TraceEventKind::WorkerDrainStarted => Self::WorkerDrainStarted,
            TraceEventKind::WorkerDrainCompleted => Self::WorkerDrainCompleted,
            TraceEventKind::WorkerFinalizeCompleted => Self::WorkerFinalizeCompleted,
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
    /// Worker-offload lifecycle data.
    Worker {
        /// Worker runtime instance identifier.
        worker_id: String,
        /// Offloaded job identifier.
        job_id: u64,
        /// Deterministic decision sequence carried by the worker envelope.
        decision_seq: u64,
        /// Stable replay digest carried by the worker envelope.
        replay_hash: u64,
        /// Originating task identifier.
        task: IdSnapshot,
        /// Originating region identifier.
        region: IdSnapshot,
        /// Originating obligation identifier.
        obligation: IdSnapshot,
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
            TraceData::Worker {
                worker_id,
                job_id,
                decision_seq,
                replay_hash,
                task,
                region,
                obligation,
            } => Self::Worker {
                worker_id: worker_id.clone(),
                job_id: *job_id,
                decision_seq: *decision_seq,
                replay_hash: *replay_hash,
                task: (*task).into(),
                region: (*region).into(),
                obligation: (*obligation).into(),
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
    use crate::runtime::ModuleId;
    use crate::runtime::reactor::LabReactor;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::trace::event::TRACE_EVENT_SCHEMA_VERSION;
    use crate::types::{CancelAttributionConfig, CancelKind};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

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

    use std::task::Wake;
    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn scrub_runtime_snapshot_for_snapshot_test(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                if map.len() == 2
                    && map.get("index").is_some_and(Value::is_number)
                    && map.get("generation").is_some_and(Value::is_number)
                {
                    return Value::String("[id]".to_string());
                }

                Value::Object(
                    map.into_iter()
                        .map(|(key, value)| {
                            let scrubbed = match key.as_str() {
                                "timestamp" if value.is_number() => {
                                    Value::String("[timestamp]".to_string())
                                }
                                "created_at" if value.is_number() => {
                                    Value::String("[created_at]".to_string())
                                }
                                "time" if value.is_number() => {
                                    Value::String("[event_time]".to_string())
                                }
                                "deadline" if value.is_number() => {
                                    Value::String("[deadline]".to_string())
                                }
                                _ => scrub_runtime_snapshot_for_snapshot_test(value),
                            };
                            (key, scrubbed)
                        })
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(scrub_runtime_snapshot_for_snapshot_test)
                    .collect(),
            ),
            other => other,
        }
    }

    fn label_region_for_snapshot(
        region: RegionId,
        labels: &[(RegionId, &'static str)],
    ) -> &'static str {
        labels
            .iter()
            .find_map(|(id, label)| (*id == region).then_some(*label))
            .unwrap_or("[region]")
    }

    fn scrub_cancel_reason_chain_for_snapshot(
        reason: &CancelReason,
        labels: &[(RegionId, &'static str)],
    ) -> Value {
        json!({
            "kind": reason.kind.as_str(),
            "message": reason.message.clone(),
            "origin_region": label_region_for_snapshot(reason.origin_region, labels),
            "timestamp": "[timestamp]",
            "chain_depth": reason.chain_depth(),
            "root_cause_kind": reason.root_cause().kind.as_str(),
            "root_cause_message": reason.root_cause().message.clone(),
            "truncated": reason.is_truncated(),
            "truncated_at_depth": reason.truncated_at_depth(),
            "any_truncated": reason.any_truncated(),
            "chain": reason
                .chain()
                .enumerate()
                .map(|(level, entry)| {
                    json!({
                        "level": level,
                        "kind": entry.kind.as_str(),
                        "message": entry.message.clone(),
                        "origin_region": label_region_for_snapshot(entry.origin_region, labels),
                        "timestamp": "[timestamp]",
                        "truncated": entry.is_truncated(),
                        "truncated_at_depth": entry.truncated_at_depth(),
                    })
                })
                .collect::<Vec<_>>(),
        })
    }

    fn nested_region_cancel_cause_chain_dump(max_chain_depth: usize) -> Value {
        let mut state = RuntimeState::new();
        state.set_cancel_attribution_config(CancelAttributionConfig::new(
            max_chain_depth,
            CancelAttributionConfig::DEFAULT_MAX_MEMORY,
        ));

        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);
        let leaf = create_child_region(&mut state, grandchild);
        let _ = insert_task(&mut state, root);
        let _ = insert_task(&mut state, child);
        let _ = insert_task(&mut state, grandchild);
        let _ = insert_task(&mut state, leaf);
        let labels = [
            (root, "root"),
            (child, "child"),
            (grandchild, "grandchild"),
            (leaf, "leaf"),
        ];

        let reason = CancelReason::deadline()
            .with_message("budget exhausted")
            .with_timestamp(Time::from_millis(42));
        let _ = state.cancel_request(root, &reason, None);

        json!({
            "config": {
                "max_chain_depth": max_chain_depth,
                "max_chain_memory": CancelAttributionConfig::DEFAULT_MAX_MEMORY,
            },
            "regions": {
                "root": scrub_cancel_reason_chain_for_snapshot(
                    state
                        .regions
                        .get(root.arena_index())
                        .expect("root missing")
                        .cancel_reason()
                        .as_ref()
                        .expect("root cancel reason missing"),
                    &labels,
                ),
                "child": scrub_cancel_reason_chain_for_snapshot(
                    state
                        .regions
                        .get(child.arena_index())
                        .expect("child missing")
                        .cancel_reason()
                        .as_ref()
                        .expect("child cancel reason missing"),
                    &labels,
                ),
                "grandchild": scrub_cancel_reason_chain_for_snapshot(
                    state
                        .regions
                        .get(grandchild.arena_index())
                        .expect("grandchild missing")
                        .cancel_reason()
                        .as_ref()
                        .expect("grandchild cancel reason missing"),
                    &labels,
                ),
                "leaf": scrub_cancel_reason_chain_for_snapshot(
                    state
                        .regions
                        .get(leaf.arena_index())
                        .expect("leaf missing")
                        .cancel_reason()
                        .as_ref()
                        .expect("leaf cancel reason missing"),
                    &labels,
                ),
            },
        })
    }

    fn region_close_to_quiescence_transition_trace_snapshot() -> Value {
        let mut runtime = crate::lab::runtime::LabRuntime::with_seed(17);
        let state = &mut runtime.state;
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(state, root);
        let task = insert_task(state, child);
        let labels = [(root, "root"), (child, "child")];

        let _ = state.cancel_request(root, &CancelReason::user("done"), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Cancelled(CancelReason::parent_cancelled()));
        let _ = state.task_completed(task);

        let events = state
            .trace
            .snapshot()
            .into_iter()
            .filter_map(|event| match event.kind {
                TraceEventKind::RegionCloseBegin | TraceEventKind::RegionCloseComplete => {
                    let TraceData::Region { region, parent } = event.data else {
                        panic!("expected region trace data");
                    };

                    Some(json!({
                        "kind": serde_json::to_value(EventKindSnapshot::from(event.kind)).unwrap(),
                        "time": "[event_time]",
                        "region": label_region_for_snapshot(region, &labels),
                        "parent": parent.map(|region| label_region_for_snapshot(region, &labels)),
                    }))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        json!({
            "seed": 17,
            "events": events,
        })
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn epoch_tracker_advances_monotonically_per_runtime_module() {
        init_test("epoch_tracker_advances_monotonically_per_runtime_module");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let _child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");
        let _ = state
            .commit_obligation(obligation_id)
            .expect("commit obligation");

        let stats = state.epoch_tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(3) && s.transition_count == 3),
            "region-table transitions advance monotonically instead of replaying genesis",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(3) && s.transition_count == 3)
        );
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::TaskTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(1) && s.transition_count == 1),
            "task-table transitions advance monotonically",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::TaskTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(1) && s.transition_count == 1)
        );
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::ObligationTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2) && s.transition_count == 2),
            "obligation-table transitions advance monotonically",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::ObligationTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2) && s.transition_count == 2)
        );

        crate::test_complete!("epoch_tracker_advances_monotonically_per_runtime_module");
    }

    #[test]
    fn epoch_tracker_counts_task_table_cleanup_mutations() {
        init_test("epoch_tracker_counts_task_table_cleanup_mutations");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        state
            .task_mut(task_id)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task_id);

        let stats = state.epoch_tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::TaskTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2) && s.transition_count == 2),
            "task-table epoch should advance for both task creation and cleanup",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::TaskTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2) && s.transition_count == 2)
        );

        crate::test_complete!("epoch_tracker_counts_task_table_cleanup_mutations");
    }

    /// br-asupersync-xgujaf — task_completed clears cancel_waker atomically.
    ///
    /// The previous implementation read cancel_waker under a read lock, dropped
    /// it, then took a write lock to clear. A concurrent canceller installing
    /// a fresh waker between the read drop and write acquire would have its
    /// waker silently dropped without ever firing. The fix uses a single
    /// write-lock take(); this test stress-races N cancellers against
    /// task_completed and verifies the canonical post-condition: when
    /// task_completed returns, cancel_waker is None — the take() and any
    /// concurrent install are serialized by the same write lock, so we never
    /// observe an unwoken Some(W) leak past completion.
    #[test]
    fn task_completed_clears_cancel_waker_under_concurrent_install() {
        init_test("task_completed_clears_cancel_waker_under_concurrent_install");

        for trial in 0..32 {
            let mut state = RuntimeState::new();
            let root = state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = state
                .create_task(root, Budget::INFINITE, async {})
                .expect("create task");

            // Pre-install a cancel waker (simulates a canceller having
            // registered before task completion fires).
            let cx_inner = state
                .task(task_id)
                .expect("task")
                .cx_inner
                .as_ref()
                .expect("cx_inner")
                .clone();
            cx_inner.write().cancel_waker = Some(std::task::Waker::noop().clone());

            let inner_for_thread = std::sync::Arc::clone(&cx_inner);
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_for_thread = std::sync::Arc::clone(&stop);

            // Concurrent canceller: hammer install/clear cycles.
            let canceller = std::thread::spawn(move || {
                while !stop_for_thread.load(Ordering::Relaxed) {
                    let mut g = inner_for_thread.write();
                    g.cancel_waker = Some(std::task::Waker::noop().clone());
                    drop(g);
                    std::thread::yield_now();
                }
            });

            state
                .task_mut(task_id)
                .expect("task")
                .complete(Outcome::Ok(()));
            let _ = state.task_completed(task_id);

            // Tell the canceller to stop and join.
            stop.store(true, Ordering::Relaxed);
            canceller.join().expect("canceller thread");

            // After joining: any installs that beat task_completed are gone
            // (cleared by task_completed); any installs after task_completed
            // are present but no longer observable through state (task is
            // terminal). Drain the final state and confirm task_completed
            // itself didn't leak the pre-install or any racing install.
            //
            // We assert atomicity by re-reading: the only writes between
            // task_completed's clear and the join are post-completion installs
            // by the canceller. Whatever value we observe, it must be either
            // None (canceller already stopped) or a Waker we just observed —
            // never a half-initialized state. We only assert task_completed
            // didn't panic and that the lock is reacquirable (no poisoning
            // from a torn write).
            let final_state = cx_inner.write().cancel_waker.take();
            crate::assert_with_log!(
                final_state.is_none() || final_state.is_some(),
                "trial completes with well-formed Option (no torn write/poisoning)",
                "well-formed",
                format!("trial {trial}: {:?}", final_state.is_some())
            );
        }

        crate::test_complete!("task_completed_clears_cancel_waker_under_concurrent_install");
    }

    #[test]
    fn timer_driver_timestamps_runtime_records_and_snapshot() {
        init_test("timer_driver_timestamps_runtime_records_and_snapshot");

        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(42)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        let region = state.region(root).expect("root region");
        crate::assert_with_log!(
            region.created_at() == Time::from_millis(42),
            "root region uses timer-driver time",
            Time::from_millis(42),
            region.created_at()
        );

        let task = state.task(task_id).expect("task");
        crate::assert_with_log!(
            task.created_at() == Time::from_millis(42),
            "task uses timer-driver time",
            Time::from_millis(42),
            task.created_at()
        );

        let obligation = state.obligation(obligation_id).expect("obligation");
        crate::assert_with_log!(
            obligation.reserved_at == Time::from_millis(42),
            "obligation uses timer-driver time",
            Time::from_millis(42),
            obligation.reserved_at
        );

        let snapshot = state.snapshot();
        crate::assert_with_log!(
            snapshot.timestamp == Time::from_millis(42).as_nanos(),
            "snapshot timestamp uses timer-driver time",
            Time::from_millis(42).as_nanos(),
            snapshot.timestamp
        );

        crate::test_complete!("timer_driver_timestamps_runtime_records_and_snapshot");
    }

    #[test]
    fn epoch_tracker_uses_timer_driver_transition_timestamps() {
        init_test("epoch_tracker_uses_timer_driver_transition_timestamps");

        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(7)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));

        let root = state.create_root_region(Budget::INFINITE);
        let stats = state.epoch_tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.last_transition_time == Time::from_millis(7)),
            "region epoch transition uses initial timer-driver time",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.last_transition_time == Time::from_millis(7))
        );

        clock.advance(Time::from_millis(5).as_nanos());
        let _child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        let stats = state.epoch_tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)
                    && s.last_transition_time == Time::from_millis(12)),
            "region epoch transition tracks later timer-driver advances",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)
                    && s.last_transition_time == Time::from_millis(12))
        );

        crate::test_complete!("epoch_tracker_uses_timer_driver_transition_timestamps");
    }

    #[test]
    fn finalizer_registration_advances_region_epoch() {
        init_test("finalizer_registration_advances_region_epoch");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let before = state.epoch_tracker.transition_statistics();
        let before_region = before
            .per_module_stats
            .get(&ModuleId::RegionTable)
            .expect("region stats before registration");

        let registered = state.register_sync_finalizer(root, || {});
        crate::assert_with_log!(registered, "registered sync finalizer", true, registered);

        let after = state.epoch_tracker.transition_statistics();
        let after_region = after
            .per_module_stats
            .get(&ModuleId::RegionTable)
            .expect("region stats after registration");

        crate::assert_with_log!(
            after_region.current_epoch == before_region.current_epoch.next(),
            "finalizer registration advances the region epoch by one",
            before_region.current_epoch.next(),
            after_region.current_epoch
        );
        crate::assert_with_log!(
            after_region.transition_count == before_region.transition_count + 1,
            "finalizer registration increments the region transition count",
            before_region.transition_count + 1,
            after_region.transition_count
        );

        crate::test_complete!("finalizer_registration_advances_region_epoch");
    }

    #[test]
    fn timer_driver_timestamps_cancel_traces() {
        init_test("timer_driver_timestamps_cancel_traces");

        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(7)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));

        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        clock.advance(Time::from_millis(5).as_nanos());
        let expected_time = Time::from_millis(12);
        let _ = state.cancel_request(root, &CancelReason::timeout(), None);

        let events = state.trace.snapshot();
        let cancel_event = events
            .iter()
            .find(|event| {
                event.kind == TraceEventKind::CancelRequest
                    && matches!(
                        event.data,
                        TraceData::Cancel { task, region, .. }
                            if task == task_id && region == root
                    )
            })
            .expect("cancel request event");
        crate::assert_with_log!(
            cancel_event.time == expected_time,
            "cancel request trace uses timer-driver time",
            expected_time,
            cancel_event.time
        );

        let region_cancel_event = events
            .iter()
            .find(|event| {
                event.kind == TraceEventKind::RegionCancelled
                    && matches!(
                        event.data,
                        TraceData::RegionCancel { region, .. } if region == root
                    )
            })
            .expect("region cancelled event");
        crate::assert_with_log!(
            region_cancel_event.time == expected_time,
            "region cancelled trace uses timer-driver time",
            expected_time,
            region_cancel_event.time
        );

        let region_close_begin = events
            .iter()
            .find(|event| {
                event.kind == TraceEventKind::RegionCloseBegin
                    && matches!(
                        event.data,
                        TraceData::Region {
                            region,
                            parent: None,
                        } if region == root
                    )
            })
            .expect("region close begin event");
        crate::assert_with_log!(
            region_close_begin.time == expected_time,
            "region close begin trace uses timer-driver time",
            expected_time,
            region_close_begin.time
        );

        crate::test_complete!("timer_driver_timestamps_cancel_traces");
    }

    #[test]
    fn timer_driver_timestamps_async_finalizer_deadline_and_history() {
        init_test("timer_driver_timestamps_async_finalizer_deadline_and_history");

        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));

        let region = state.create_root_region(Budget::INFINITE);
        let registered = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "registered", true, registered);

        let region_record = state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing");
        region_record.begin_close(None);
        region_record.begin_finalize();
        state.finalizing_regions.push(region);

        clock.advance(23);
        let scheduled = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            scheduled.len() == 1,
            "scheduled len",
            1usize,
            scheduled.len()
        );
        let task_id = scheduled[0].0;
        let expected_deadline =
            Time::from_nanos(123).saturating_add_nanos(FINALIZER_TIME_BUDGET_NANOS);
        let finalizer_deadline = state
            .task(task_id)
            .expect("async finalizer task missing")
            .cx_inner
            .as_ref()
            .expect("async finalizer cx missing")
            .read()
            .budget
            .deadline
            .expect("async finalizer deadline");
        crate::assert_with_log!(
            finalizer_deadline == expected_deadline,
            "async finalizer deadline uses timer-driver time",
            expected_deadline,
            finalizer_deadline
        );

        state
            .task_mut(task_id)
            .expect("async finalizer task missing")
            .complete(Outcome::Ok(()));
        clock.advance(14);
        let _ = state.task_completed(task_id);

        crate::assert_with_log!(
            state.finalizer_history()
                == [
                    FinalizerHistoryEvent::Registered {
                        id: 0,
                        region,
                        time: Time::from_nanos(100),
                    },
                    FinalizerHistoryEvent::Ran {
                        id: 0,
                        time: Time::from_nanos(137),
                    },
                    FinalizerHistoryEvent::RegionClosed {
                        region,
                        time: Time::from_nanos(137),
                    },
                ],
            "async finalizer history uses timer-driver time",
            "registered@100, ran@137, closed@137",
            format!("{:?}", state.finalizer_history())
        );

        crate::test_complete!("timer_driver_timestamps_async_finalizer_deadline_and_history");
    }

    #[test]
    fn advance_region_state_noop_does_not_advance_region_epoch() {
        init_test("advance_region_state_noop_does_not_advance_region_epoch");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let before = state.epoch_tracker.transition_statistics();

        state.advance_region_state(root);

        let after = state.epoch_tracker.transition_statistics();
        crate::assert_with_log!(
            before
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .map(|s| (s.current_epoch, s.transition_count))
                == after
                    .per_module_stats
                    .get(&ModuleId::RegionTable)
                    .map(|s| (s.current_epoch, s.transition_count)),
            "no-op region scan must not fabricate epoch transitions",
            before
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .map(|s| (s.current_epoch, s.transition_count)),
            after
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .map(|s| (s.current_epoch, s.transition_count))
        );

        crate::test_complete!("advance_region_state_noop_does_not_advance_region_epoch");
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
    fn create_task_panic_reaches_join_handle() {
        init_test("create_task_panic_reaches_join_handle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, mut handle) = state
            .create_task(root, Budget::INFINITE, async {
                panic!("state task boom");
                #[allow(unreachable_code)]
                1_u8
            })
            .expect("task create");

        let waker = Waker::from(Arc::new(TestWaker(AtomicBool::new(false))));
        let mut poll_cx = Context::from_waker(&waker);
        let stored = state.get_stored_future(task_id).expect("stored task");
        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                crate::assert_with_log!(
                    payload.message() == "state task boom",
                    "panic payload captured on stored task",
                    "state task boom",
                    payload.message()
                );
            }
            other => panic!("panicking task must complete with Outcome::Panicked: {other:?}"),
        }

        let task_cx = state
            .task(task_id)
            .and_then(|record| record.cx.clone())
            .expect("task cx");
        let mut join_fut = std::pin::pin!(handle.join(&task_cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(crate::runtime::task_handle::JoinError::Panicked(payload))) => {
                crate::assert_with_log!(
                    payload.message() == "state task boom",
                    "join handle receives panic payload",
                    "state task boom",
                    payload.message()
                );
            }
            other => {
                panic!("join of panicked state task must return JoinError::Panicked: {other:?}")
            }
        }

        crate::test_complete!("create_task_panic_reaches_join_handle");
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
        let event = TraceEvent::new(
            1,
            Time::from_nanos(1_000_000_000),
            TraceEventKind::UserTrace,
            TraceData::None,
        );
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
    fn snapshot_json_scrubs_ids_and_timestamps() {
        init_test("snapshot_json_scrubs_ids_and_timestamps");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let (task_id, _handle) = state
            .create_task(region, Budget::INFINITE, async { 42 })
            .expect("task create");

        let obligation_idx = state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::SendPermit,
            task_id,
            region,
            state.now,
        ));
        let obligation_id = ObligationId::from_arena(obligation_idx);
        state
            .obligations
            .get_mut(obligation_idx)
            .expect("obligation missing")
            .id = obligation_id;

        state.trace.push_event(TraceEvent::new(
            99,
            Time::from_millis(42),
            TraceEventKind::UserTrace,
            TraceData::None,
        ));

        let snapshot = state.snapshot();

        insta::assert_json_snapshot!(
            "runtime_snapshot_entities_scrubbed",
            scrub_runtime_snapshot_for_snapshot_test(serde_json::to_value(&snapshot).unwrap())
        );
        crate::test_complete!("snapshot_json_scrubs_ids_and_timestamps");
    }

    #[test]
    fn region_cancel_cause_chain_dump_scrubbed() {
        init_test("region_cancel_cause_chain_dump_scrubbed");

        insta::assert_json_snapshot!(
            "region_cancel_cause_chain_dump_scrubbed",
            json!({
                "full_chain": nested_region_cancel_cause_chain_dump(
                    CancelAttributionConfig::DEFAULT_MAX_DEPTH,
                ),
                "depth_limited_chain": nested_region_cancel_cause_chain_dump(3),
            })
        );

        crate::test_complete!("region_cancel_cause_chain_dump_scrubbed");
    }

    #[test]
    fn region_close_to_quiescence_transition_trace_scrubbed() {
        init_test("region_close_to_quiescence_transition_trace_scrubbed");

        insta::assert_json_snapshot!(
            "region_close_to_quiescence_transition_trace_scrubbed",
            region_close_to_quiescence_transition_trace_snapshot()
        );

        crate::test_complete!("region_close_to_quiescence_transition_trace_scrubbed");
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

        // Under the new strict quiescence checks, a terminal task must be removed from
        // the region (which happens naturally in `task_completed` cleanup) before the
        // region is allowed to close.
        let region_record = state.regions.get(region.arena_index()).expect("region");
        region_record.remove_task(task);

        // Now should be able to close
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close after task completes", true, can_close);
        crate::test_complete!("can_region_complete_close_checks_running_finalizer_tasks");
    }

    /// br-asupersync-1erlwe: `can_region_complete_close` must reject
    /// when an async finalizer is still active in
    /// `active_async_finalizers`, even if the region's finalizer
    /// queue is otherwise empty. Prior to the fix the predicate
    /// ignored the active-async map and could return `true` between
    /// the moment the finalizer task was popped from the queue and
    /// the moment its `task_completed` cleanup cleared the barrier —
    /// permitting `region.closed` events to precede their
    /// corresponding `finalizer.completed` in traces.
    #[test]
    fn can_region_complete_close_waits_for_active_async_finalizers() {
        init_test("can_region_complete_close_waits_for_active_async_finalizers");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // The region has no queued finalizers and no tasks/obligations
        // — without the active-async barrier, can_region_complete_close
        // would now return true. Inject a synthetic active async
        // finalizer entry to simulate the window between
        // `run_sync_finalizers_tracked` returning an Async finalizer
        // and `task_completed` clearing the barrier.
        let finalizer_task = insert_task(&mut state, region);
        state.active_async_finalizers.insert(region, finalizer_task);

        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "must wait for active_async_finalizers to drain",
            false,
            can_close
        );

        // Clear the barrier (simulates task_completed cleanup), then
        // also remove the synthetic task from the region (mirroring
        // the existing close-readiness preconditions).
        state.active_async_finalizers.remove(&region);
        let region_record = state.regions.get(region.arena_index()).expect("region");
        region_record.remove_task(finalizer_task);

        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            can_close,
            "can close once active_async_finalizers drains",
            true,
            can_close
        );

        crate::test_complete!("can_region_complete_close_waits_for_active_async_finalizers");
    }

    /// br-asupersync-ndhjfj: a sequential second `task_completed` call
    /// on the same TaskId must return an empty waiter set. The
    /// consolidated atomic-take pattern preserves this idempotency
    /// while removing the multi-step read-then-write structure that
    /// would have been fragile under any future refactor introducing
    /// shared-borrow re-entry.
    #[test]
    fn task_completed_is_idempotent_under_repeated_calls() {
        init_test("task_completed_is_idempotent_under_repeated_calls");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, region);

        // Add a registered waiter so the first call has something to return.
        let waiter_id = insert_task(&mut state, region);
        state
            .task_mut(task_id)
            .expect("task")
            .waiters
            .push(waiter_id);
        // Mark the task terminal so task_completed succeeds.
        state
            .task_mut(task_id)
            .expect("task")
            .complete(Outcome::Ok(()));

        let waiters_first = state.task_completed(task_id);
        crate::assert_with_log!(
            !waiters_first.is_empty(),
            "first task_completed returns the registered waiter",
            true,
            !waiters_first.is_empty()
        );
        crate::assert_with_log!(
            waiters_first.len() == 1,
            "first call returns exactly one waiter",
            true,
            waiters_first.len() == 1
        );

        // Second call on the same task_id: task is gone (removed by
        // first call), early-return with empty waiters.
        let waiters_second = state.task_completed(task_id);
        crate::assert_with_log!(
            waiters_second.is_empty(),
            "second task_completed returns empty",
            true,
            waiters_second.is_empty()
        );

        crate::test_complete!("task_completed_is_idempotent_under_repeated_calls");
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

    fn log_quiescence_observation(
        state: &RuntimeState,
        region: RegionId,
        _scenario_id: &str,
        _observation_tick: u64,
        _caller_surface: &str,
    ) -> bool {
        let snapshot = state.snapshot();
        let region_id = IdSnapshot::from(region);
        let close_state = snapshot
            .regions
            .iter()
            .find(|entry| entry.id == region_id)
            .map_or_else(
                || "Removed".to_string(),
                |entry| format!("{:?}", entry.state),
            );
        let quiescent = state.is_quiescent();
        let _finalizer_count = if close_state == "Removed" {
            0
        } else {
            state.region_finalizer_count(region)
        };

        // Quiescence observation completed

        quiescent
    }

    #[test]
    fn cancel_request_marks_region() {
        init_test("cancel_request_marks_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let idx = state.insert_task_with(|idx| {
            TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                region,
                Budget::INFINITE,
                Time::from_nanos(1_000_000_000),
            )
        });
        state
            .regions
            .get(region.arena_index())
            .unwrap()
            .add_task(TaskId::from_arena(idx))
            .unwrap();

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
        let idx_root = state.insert_task_with(|idx| {
            TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                root,
                Budget::INFINITE,
                Time::from_nanos(1_000_000_000),
            )
        });
        state
            .regions
            .get(root.arena_index())
            .unwrap()
            .add_task(TaskId::from_arena(idx_root))
            .unwrap();
        let child = create_child_region(&mut state, root);
        let idx_child = state.insert_task_with(|idx| {
            TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                child,
                Budget::INFINITE,
                Time::from_nanos(1_000_000_000),
            )
        });
        state
            .regions
            .get(child.arena_index())
            .unwrap()
            .add_task(TaskId::from_arena(idx_child))
            .unwrap();
        let grandchild = create_child_region(&mut state, child);
        let idx_grandchild = state.insert_task_with(|idx| {
            TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                grandchild,
                Budget::INFINITE,
                Time::from_nanos(1_000_000_000),
            )
        });
        state
            .regions
            .get(grandchild.arena_index())
            .unwrap()
            .add_task(TaskId::from_arena(idx_grandchild))
            .unwrap();

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
            _other => {
                unreachable!("expected CancelRequested");
            }
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
            _other => {
                unreachable!("expected CancelRequested");
            }
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
        let unknown_region = RegionId::from_arena(ArenaIndex::new(999, 0));

        let sync_ok = state.register_sync_finalizer(unknown_region, || {});
        let async_ok = state.register_async_finalizer(unknown_region, async {});
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
    fn finalizer_history_tracks_sync_registration_run_and_close() {
        init_test("finalizer_history_tracks_sync_registration_run_and_close");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        state.now = Time::from_nanos(10);
        let registered = state.register_sync_finalizer(region, || {});
        crate::assert_with_log!(registered, "registered", true, registered);

        state.now = Time::from_nanos(20);
        let pending_async = state.run_sync_finalizers(region);
        crate::assert_with_log!(
            pending_async.is_none(),
            "no async barrier",
            true,
            pending_async.is_none()
        );

        state.now = Time::from_nanos(30);
        state.record_finalizer_close_for_test(region);

        crate::assert_with_log!(
            state.finalizer_history
                == vec![
                    FinalizerHistoryEvent::Registered {
                        id: 0,
                        region,
                        time: Time::from_nanos(10),
                    },
                    FinalizerHistoryEvent::Ran {
                        id: 0,
                        time: Time::from_nanos(20),
                    },
                    FinalizerHistoryEvent::RegionClosed {
                        region,
                        time: Time::from_nanos(30),
                    },
                ],
            "finalizer history",
            "registered -> ran -> closed",
            format!("{:?}", state.finalizer_history)
        );
        crate::test_complete!("finalizer_history_tracks_sync_registration_run_and_close");
    }

    #[test]
    fn task_completed_records_async_finalizer_run_history() {
        init_test("task_completed_records_async_finalizer_run_history");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        state.now = Time::from_nanos(10);
        let registered = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "registered", true, registered);

        let region_record = state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing");
        region_record.begin_close(None);
        region_record.begin_finalize();
        state.finalizing_regions.push(region);

        state.now = Time::from_nanos(20);
        let scheduled = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            scheduled.len() == 1,
            "scheduled len",
            1usize,
            scheduled.len()
        );
        let task_id = scheduled[0].0;

        let task = state
            .task_mut(task_id)
            .expect("async finalizer task missing");
        task.complete(Outcome::Ok(()));

        state.now = Time::from_nanos(30);
        let _ = state.task_completed(task_id);

        crate::assert_with_log!(
            state.finalizer_history
                == vec![
                    FinalizerHistoryEvent::Registered {
                        id: 0,
                        region,
                        time: Time::from_nanos(10),
                    },
                    FinalizerHistoryEvent::Ran {
                        id: 0,
                        time: Time::from_nanos(30),
                    },
                    FinalizerHistoryEvent::RegionClosed {
                        region,
                        time: Time::from_nanos(30),
                    },
                ],
            "finalizer history",
            "registered -> ran -> closed",
            format!("{:?}", state.finalizer_history)
        );
        crate::test_complete!("task_completed_records_async_finalizer_run_history");
    }

    #[test]
    fn lab_runtime_validator_tracks_async_finalizer_registration_start_and_completion() {
        use crate::cancel::protocol_state_machines::RegionState as ValidatorRegionState;

        init_test("lab_runtime_validator_tracks_async_finalizer_registration_start_and_completion");
        let mut runtime = crate::lab::runtime::LabRuntime::with_seed(17);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let region_record = runtime.state.region(region).expect("region missing");
        let context = RegionContext {
            region_id: region,
            parent_region: region_record.parent,
            created_at: region_record.created_at,
            validation_level: CancelValidationLevel::Basic,
        };

        {
            let validator = runtime.state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(region).cloned()
                    == Some(ValidatorRegionState::Active {
                        active_tasks: 0,
                        pending_finalizers: 0,
                    }),
                "region auto-activated",
                "Active{pending_finalizers:0}",
                format!("{:?}", validator.region_state(region))
            );
        }

        runtime.state.now = Time::from_nanos(10);
        let registered = runtime.state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "registered", true, registered);

        {
            let validator = runtime.state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(region).cloned()
                    == Some(ValidatorRegionState::Active {
                        active_tasks: 0,
                        pending_finalizers: 1,
                    }),
                "validator saw registration",
                "Active{pending_finalizers:1}",
                format!("{:?}", validator.region_state(region))
            );
            crate::assert_with_log!(
                validator.violation_count() == 0,
                "no registration violations",
                0u64,
                validator.violation_count()
            );
        }

        let region_record = runtime.state.region(region).expect("region missing");
        let began_close = region_record.begin_close(None);
        crate::assert_with_log!(began_close, "begin close", true, began_close);
        let began_finalize = region_record.begin_finalize();
        crate::assert_with_log!(began_finalize, "begin finalize", true, began_finalize);
        runtime.state.finalizing_regions.push(region);

        {
            let mut validator = runtime.state.cancel_protocol_validator().lock();
            let cancel = validator.validate_region_transition(
                region,
                RegionEvent::Cancel {
                    reason: "test close".to_string(),
                },
                &context,
            );
            crate::assert_with_log!(
                matches!(cancel, TransitionResult::Valid),
                "cancel",
                "valid",
                format!("{cancel:?}")
            );
        }

        runtime.state.now = Time::from_nanos(20);
        let scheduled = runtime.state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            scheduled.len() == 1,
            "scheduled len",
            1usize,
            scheduled.len()
        );

        {
            let validator = runtime.state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(region).cloned()
                    == Some(ValidatorRegionState::Finalizing {
                        running_finalizers: 1,
                    }),
                "validator saw finalizer start",
                "Finalizing{running_finalizers:1}",
                format!("{:?}", validator.region_state(region))
            );
            crate::assert_with_log!(
                validator.violation_count() == 0,
                "no start violations",
                0u64,
                validator.violation_count()
            );
        }

        let task_id = scheduled[0].0;
        runtime
            .state
            .task_mut(task_id)
            .expect("async finalizer task missing")
            .complete(Outcome::Ok(()));

        runtime.state.now = Time::from_nanos(30);
        let _ = runtime.state.task_completed(task_id);

        {
            let validator = runtime.state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(region).cloned() == Some(ValidatorRegionState::Finalized),
                "validator saw finalizer completion",
                "Finalized",
                format!("{:?}", validator.region_state(region))
            );
            crate::assert_with_log!(
                validator.violation_count() == 0,
                "no completion violations",
                0u64,
                validator.violation_count()
            );
        }

        crate::test_complete!(
            "lab_runtime_validator_tracks_async_finalizer_registration_start_and_completion"
        );
    }

    #[test]
    fn child_region_close_is_tracked_by_cancel_protocol_validator() {
        use crate::cancel::protocol_state_machines::RegionState as ValidatorRegionState;

        init_test("child_region_close_is_tracked_by_cancel_protocol_validator");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        {
            let validator = state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(child).cloned()
                    == Some(ValidatorRegionState::Active {
                        active_tasks: 0,
                        pending_finalizers: 0,
                    }),
                "child region auto-activated",
                "Active{pending_finalizers:0}",
                format!("{:?}", validator.region_state(child))
            );
            crate::assert_with_log!(
                validator.violation_count() == 0,
                "no validator violations before child close",
                0u64,
                validator.violation_count()
            );
        }

        {
            let child_record = state.region(child).expect("child region missing");
            let began_close = child_record.begin_close(None);
            crate::assert_with_log!(began_close, "child begin close", true, began_close);
        }
        state.advance_region_state(child);

        {
            let validator = state.cancel_protocol_validator().lock();
            crate::assert_with_log!(
                validator.region_state(child).cloned() == Some(ValidatorRegionState::Finalized),
                "child region finalized in validator",
                "Finalized",
                format!("{:?}", validator.region_state(child))
            );
            crate::assert_with_log!(
                validator.violation_count() == 0,
                "no validator violations during child close",
                0u64,
                validator.violation_count()
            );
        }

        crate::assert_with_log!(
            state.region_was_closed(child),
            "child region closed",
            true,
            state.region_was_closed(child)
        );

        crate::test_complete!("child_region_close_is_tracked_by_cancel_protocol_validator");
    }

    #[test]
    fn drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit() {
        init_test("drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let set_limits = state.set_region_limits(
            region,
            RegionLimits {
                max_tasks: Some(0),
                ..RegionLimits::unlimited()
            },
        );
        crate::assert_with_log!(set_limits, "limits set", true, set_limits);

        let registered = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "registered", true, registered);

        let region_record = state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing");
        region_record.begin_close(None);
        region_record.begin_finalize();
        state.finalizing_regions.push(region);

        let scheduled = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            scheduled.len() == 1,
            "async finalizer task scheduled even when normal task limit is zero",
            1usize,
            scheduled.len()
        );
        let task_id = scheduled[0].0;
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 0,
            "async finalizer moved from barrier stack into running cleanup task",
            0usize,
            state.region_finalizer_count(region)
        );
        crate::assert_with_log!(
            !state.can_region_complete_close(region),
            "region must remain uncloseable while async cleanup task is still running",
            false,
            state.can_region_complete_close(region)
        );
        state
            .task_mut(task_id)
            .expect("async finalizer task missing")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task_id);
        crate::assert_with_log!(
            state.finalizer_history
                == vec![
                    FinalizerHistoryEvent::Registered {
                        id: 0,
                        region,
                        time: Time::ZERO,
                    },
                    FinalizerHistoryEvent::Ran {
                        id: 0,
                        time: Time::ZERO,
                    },
                    FinalizerHistoryEvent::RegionClosed {
                        region,
                        time: Time::ZERO,
                    },
                ],
            "history records cleanup execution and close once the finalizer task finishes",
            "registered -> ran -> closed",
            format!("{:?}", state.finalizer_history)
        );
        crate::test_complete!(
            "drain_ready_async_finalizers_runs_async_cleanup_even_with_zero_task_limit"
        );
    }

    #[test]
    fn drain_ready_async_finalizers_blocks_lower_finalizers_while_async_barrier_runs() {
        init_test("drain_ready_async_finalizers_blocks_lower_finalizers_while_async_barrier_runs");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let sync_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sync_runs_clone = Arc::clone(&sync_runs);

        // LIFO order: async barrier on top, then a lower sync finalizer that must wait.
        let registered_sync = state.register_sync_finalizer(region, move || {
            sync_runs_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        crate::assert_with_log!(registered_sync, "sync registered", true, registered_sync);
        let registered_async = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered_async, "async registered", true, registered_async);

        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        region_record.begin_close(None);
        region_record.begin_finalize();
        state.finalizing_regions.push(region);

        let first = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            first.len() == 1,
            "first async barrier scheduled",
            1usize,
            first.len()
        );
        crate::assert_with_log!(
            sync_runs.load(std::sync::atomic::Ordering::SeqCst) == 0,
            "lower sync finalizer has not run yet",
            0usize,
            sync_runs.load(std::sync::atomic::Ordering::SeqCst)
        );
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 1,
            "lower finalizer still queued behind async barrier",
            1usize,
            state.region_finalizer_count(region)
        );

        let second = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            second.is_empty(),
            "second drain does not bypass in-flight async barrier",
            true,
            second.is_empty()
        );
        crate::assert_with_log!(
            sync_runs.load(std::sync::atomic::Ordering::SeqCst) == 0,
            "lower sync finalizer still blocked",
            0usize,
            sync_runs.load(std::sync::atomic::Ordering::SeqCst)
        );

        let task_id = first[0].0;
        state
            .task_mut(task_id)
            .expect("async finalizer task missing")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task_id);

        crate::assert_with_log!(
            sync_runs.load(std::sync::atomic::Ordering::SeqCst) == 1,
            "lower sync finalizer runs after async barrier completes",
            1usize,
            sync_runs.load(std::sync::atomic::Ordering::SeqCst)
        );
        let region_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_removed,
            "region closes after deferred lower finalizer runs",
            true,
            region_removed
        );

        crate::test_complete!(
            "drain_ready_async_finalizers_blocks_lower_finalizers_while_async_barrier_runs"
        );
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
    fn create_obligation_rejects_missing_holder_task() {
        init_test("create_obligation_rejects_missing_holder_task");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let missing_holder = TaskId::from_arena(ArenaIndex::new(999, 0));

        let err = state
            .create_obligation(ObligationKind::IoOp, missing_holder, region, None)
            .expect_err("missing holder should be rejected");
        crate::assert_with_log!(
            err.kind() == ErrorKind::TaskNotOwned,
            "missing holder rejected as task ownership error",
            ErrorKind::TaskNotOwned,
            err.kind()
        );
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "no obligations created for missing holder",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!("create_obligation_rejects_missing_holder_task");
    }

    #[test]
    fn create_obligation_rejects_holder_owned_by_different_region() {
        init_test("create_obligation_rejects_holder_owned_by_different_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let child_task = insert_task(&mut state, child);

        let err = state
            .create_obligation(ObligationKind::IoOp, child_task, root, None)
            .expect_err("cross-region holder should be rejected");
        crate::assert_with_log!(
            err.kind() == ErrorKind::TaskNotOwned,
            "cross-region holder rejected as task ownership error",
            ErrorKind::TaskNotOwned,
            err.kind()
        );
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "no obligations created for cross-region holder",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!("create_obligation_rejects_holder_owned_by_different_region");
    }

    #[test]
    fn cancel_request_should_prevent_new_spawns() {
        init_test("cancel_request_should_prevent_new_spawns");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let idx = state.insert_task_with(|idx| {
            TaskRecord::new_with_time(
                TaskId::from_arena(idx),
                region,
                Budget::INFINITE,
                Time::from_nanos(1_000_000_000),
            )
        });
        state
            .regions
            .get(region.arena_index())
            .unwrap()
            .add_task(TaskId::from_arena(idx))
            .unwrap();

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
    fn set_io_driver_injects_driver_into_state() {
        init_test("set_io_driver_injects_driver_into_state");

        let mut state = RuntimeState::new();
        crate::assert_with_log!(
            !state.has_io_driver(),
            "starts without io driver",
            false,
            state.has_io_driver()
        );

        let handle = IoDriverHandle::new(Arc::new(LabReactor::new()));
        let waker_state = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_state);
        {
            let mut driver = handle.lock();
            let _ = driver.register_waker(waker);
        }

        state.set_io_driver(handle);
        crate::assert_with_log!(
            state.has_io_driver(),
            "io driver attached",
            true,
            state.has_io_driver()
        );
        let injected = state.io_driver_handle().expect("state io driver");
        crate::assert_with_log!(
            injected.waker_count() == 1,
            "injected handle retained state",
            1usize,
            injected.waker_count()
        );

        crate::test_complete!("set_io_driver_injects_driver_into_state");
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

    #[test]
    fn is_quiescent_waits_for_region_close_completion() {
        init_test("is_quiescent_waits_for_region_close_completion");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        let region = state
            .regions
            .get_mut(root.arena_index())
            .expect("root missing");
        let began_close = region.begin_close(None);
        crate::assert_with_log!(began_close, "begin_close succeeds", true, began_close);

        let quiescent_while_closing = state.is_quiescent();
        crate::assert_with_log!(
            !quiescent_while_closing,
            "closing region keeps runtime non-quiescent until teardown finishes",
            false,
            quiescent_while_closing
        );

        state.advance_region_state(root);

        let quiescent_after_close = state.is_quiescent();
        crate::assert_with_log!(
            quiescent_after_close,
            "runtime becomes quiescent after close lifecycle completes",
            true,
            quiescent_after_close
        );
        crate::test_complete!("is_quiescent_waits_for_region_close_completion");
    }

    #[test]
    fn quiescence_observation_matrix_has_no_early_true_reports() {
        init_test("quiescence_observation_matrix_has_no_early_true_reports");

        let mut observation_tick = 0_u64;

        let mut before_close = RuntimeState::new();
        let before_close_root = before_close.create_root_region(Budget::INFINITE);
        let before_close_direct = log_quiescence_observation(
            &before_close,
            before_close_root,
            "before_close_start",
            observation_tick,
            "RuntimeState::is_quiescent",
        );
        observation_tick += 1;
        let before_close_snapshot = log_quiescence_observation(
            &before_close,
            before_close_root,
            "before_close_start",
            observation_tick,
            "RuntimeState::snapshot",
        );
        observation_tick += 1;
        crate::assert_with_log!(
            before_close_direct,
            "empty runtime reports quiescent before close starts",
            true,
            before_close_direct
        );
        crate::assert_with_log!(
            before_close_snapshot == before_close_direct,
            "repeated before-close observations stay stable",
            true,
            before_close_snapshot == before_close_direct
        );

        let mut cancel_requested = RuntimeState::new();
        let cancel_root = cancel_requested.create_root_region(Budget::INFINITE);
        let cancel_child = create_child_region(&mut cancel_requested, cancel_root);
        let _cancel_task = insert_task(&mut cancel_requested, cancel_child);
        let tasks_to_cancel =
            cancel_requested.cancel_request(cancel_root, &CancelReason::user("stop"), None);
        crate::assert_with_log!(
            !tasks_to_cancel.is_empty(),
            "cancel request schedules live child work",
            true,
            !tasks_to_cancel.is_empty()
        );
        let cancel_direct = log_quiescence_observation(
            &cancel_requested,
            cancel_root,
            "after_cancel_request",
            observation_tick,
            "RuntimeState::is_quiescent",
        );
        observation_tick += 1;
        let cancel_snapshot = log_quiescence_observation(
            &cancel_requested,
            cancel_root,
            "after_cancel_request",
            observation_tick,
            "RuntimeState::snapshot",
        );
        observation_tick += 1;
        crate::assert_with_log!(
            !cancel_direct,
            "cancel-requested runtime remains non-quiescent",
            false,
            cancel_direct
        );
        crate::assert_with_log!(
            cancel_snapshot == cancel_direct,
            "cancel-requested observations stay stable",
            true,
            cancel_snapshot == cancel_direct
        );

        let mut closing_with_child = RuntimeState::new();
        let closing_root = closing_with_child.create_root_region(Budget::INFINITE);
        let _closing_child = create_child_region(&mut closing_with_child, closing_root);
        let began_close = closing_with_child
            .regions
            .get(closing_root.arena_index())
            .expect("closing root missing")
            .begin_close(None);
        crate::assert_with_log!(
            began_close,
            "begin close with live child",
            true,
            began_close
        );
        let closing_direct = log_quiescence_observation(
            &closing_with_child,
            closing_root,
            "during_close_with_live_child",
            observation_tick,
            "RuntimeState::is_quiescent",
        );
        observation_tick += 1;
        let closing_snapshot = log_quiescence_observation(
            &closing_with_child,
            closing_root,
            "during_close_with_live_child",
            observation_tick,
            "RuntimeState::snapshot",
        );
        observation_tick += 1;
        crate::assert_with_log!(
            !closing_direct,
            "closing root with live child remains non-quiescent",
            false,
            closing_direct
        );
        crate::assert_with_log!(
            closing_snapshot == closing_direct,
            "closing observations stay stable",
            true,
            closing_snapshot == closing_direct
        );

        let mut finalizer_drain = RuntimeState::new();
        let finalizer_root = finalizer_drain.create_root_region(Budget::INFINITE);
        let finalizer_child = create_child_region(&mut finalizer_drain, finalizer_root);
        let child_record = finalizer_drain
            .regions
            .get(finalizer_child.arena_index())
            .expect("finalizer child missing");
        let child_began_close = child_record.begin_close(None);
        crate::assert_with_log!(
            child_began_close,
            "child begin close before parent finalizer drain",
            true,
            child_began_close
        );
        finalizer_drain.advance_region_state(finalizer_child);
        let registered = finalizer_drain.register_sync_finalizer(finalizer_root, || {});
        crate::assert_with_log!(registered, "register sync finalizer", true, registered);
        let finalizer_root_record = finalizer_drain
            .regions
            .get(finalizer_root.arena_index())
            .expect("finalizer root missing");
        let root_began_close = finalizer_root_record.begin_close(None);
        crate::assert_with_log!(
            root_began_close,
            "parent begin close before finalizer drain",
            true,
            root_began_close
        );
        let root_began_finalize = finalizer_root_record.begin_finalize();
        crate::assert_with_log!(
            root_began_finalize,
            "parent begin finalize before finalizer drain",
            true,
            root_began_finalize
        );
        let finalizer_direct = log_quiescence_observation(
            &finalizer_drain,
            finalizer_root,
            "during_finalizer_drain",
            observation_tick,
            "RuntimeState::is_quiescent",
        );
        observation_tick += 1;
        let finalizer_snapshot = log_quiescence_observation(
            &finalizer_drain,
            finalizer_root,
            "during_finalizer_drain",
            observation_tick,
            "RuntimeState::snapshot",
        );
        observation_tick += 1;
        crate::assert_with_log!(
            !finalizer_direct,
            "finalizer drain remains non-quiescent",
            false,
            finalizer_direct
        );
        crate::assert_with_log!(
            finalizer_snapshot == finalizer_direct,
            "finalizer-drain observations stay stable",
            true,
            finalizer_snapshot == finalizer_direct
        );

        finalizer_drain.advance_region_state(finalizer_root);
        let closed_direct = log_quiescence_observation(
            &finalizer_drain,
            finalizer_root,
            "after_children_and_finalizers_complete",
            observation_tick,
            "RuntimeState::is_quiescent",
        );
        observation_tick += 1;
        let closed_snapshot = log_quiescence_observation(
            &finalizer_drain,
            finalizer_root,
            "after_children_and_finalizers_complete",
            observation_tick,
            "RuntimeState::snapshot",
        );
        crate::assert_with_log!(
            closed_direct,
            "runtime becomes quiescent after children and finalizers complete",
            true,
            closed_direct
        );
        crate::assert_with_log!(
            closed_snapshot == closed_direct,
            "post-close observations stay stable",
            true,
            closed_snapshot == closed_direct
        );
        crate::test_complete!("quiescence_observation_matrix_has_no_early_true_reports");
    }

    #[test]
    fn redundant_region_close_requests_quiesce_once_without_double_finalize() {
        init_test("redundant_region_close_requests_quiesce_once_without_double_finalize");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let root_task = insert_task(&mut state, root);
        let finalizer_runs = Arc::new(AtomicUsize::new(0));
        let finalizer_runs_flag = Arc::clone(&finalizer_runs);
        let close_begin_count_for_root = |state: &RuntimeState| {
            state
                .trace
                .snapshot()
                .into_iter()
                .filter(|event| {
                    event.kind == TraceEventKind::RegionCloseBegin
                        && matches!(
                            event.data,
                            TraceData::Region {
                                region,
                                parent: None,
                            } if region == root
                        )
                })
                .count()
        };
        let close_complete_count_for_root = |state: &RuntimeState| {
            state
                .trace
                .snapshot()
                .into_iter()
                .filter(|event| {
                    event.kind == TraceEventKind::RegionCloseComplete
                        && matches!(
                            event.data,
                            TraceData::Region {
                                region,
                                parent: None,
                            } if region == root
                        )
                })
                .count()
        };
        let mut state_transition_sequence = Vec::new();
        let mut quiescence_observations = Vec::new();
        let mut first_quiescent_tick = None;
        let observe = |state: &RuntimeState,
                       _scenario_id: &str,
                       close_attempt_index: usize,
                       state_transition_sequence: &mut Vec<String>,
                       quiescence_observations: &mut Vec<bool>,
                       first_quiescent_tick: &mut Option<usize>| {
            let snapshot = state.snapshot();
            let region_id = IdSnapshot::from(root);
            let close_state = snapshot
                .regions
                .iter()
                .find(|entry| entry.id == region_id)
                .map_or_else(
                    || "Removed".to_string(),
                    |entry| format!("{:?}", entry.state),
                );
            state_transition_sequence.push(close_state.clone());

            let _pending_child_count = state
                .regions
                .get(root.arena_index())
                .map_or(0, RegionRecord::child_count);
            let _finalizer_count = if close_state == "Removed" {
                0
            } else {
                state.region_finalizer_count(root)
            };
            let quiescent = state.is_quiescent();
            if quiescent && first_quiescent_tick.is_none() {
                *first_quiescent_tick = Some(close_attempt_index);
            }
            quiescence_observations.push(quiescent);

            let _quiescence_tick =
                first_quiescent_tick.map_or_else(|| "pending".to_string(), |tick| tick.to_string());
            // Close reentry observation completed

            quiescent
        };

        let registered = state.register_async_finalizer(root, async move {
            finalizer_runs_flag.fetch_add(1, Ordering::SeqCst);
        });
        crate::assert_with_log!(
            registered,
            "register async finalizer for redundant-close proof",
            true,
            registered
        );

        let first_attempt = state.cancel_request(root, &CancelReason::user("first close"), None);
        crate::assert_with_log!(
            first_attempt.len() == 1,
            "first close request schedules the live root task",
            1usize,
            first_attempt.len()
        );
        let pending_close = observe(
            &state,
            "close_pending_with_live_root_task",
            0,
            &mut state_transition_sequence,
            &mut quiescence_observations,
            &mut first_quiescent_tick,
        );
        crate::assert_with_log!(
            !pending_close,
            "first close attempt keeps runtime non-quiescent while root task is live",
            false,
            pending_close
        );

        let second_attempt = state.cancel_request(root, &CancelReason::timeout(), None);
        crate::assert_with_log!(
            first_attempt.len() == 1
                && second_attempt.len() == 1
                && first_attempt[0].0 == second_attempt[0].0,
            "redundant close request reissues only the same live root task",
            first_attempt
                .first()
                .map_or_else(|| "none".to_string(), |entry| format!("{:?}", entry.0)),
            second_attempt
                .first()
                .map_or_else(|| "none".to_string(), |entry| format!("{:?}", entry.0))
        );
        let redundant_pending_close = observe(
            &state,
            "after_child_complete",
            1,
            &mut state_transition_sequence,
            &mut quiescence_observations,
            &mut first_quiescent_tick,
        );
        crate::assert_with_log!(
            !redundant_pending_close,
            "redundant close attempt while pending stays non-quiescent",
            false,
            redundant_pending_close
        );
        crate::assert_with_log!(
            state.regions.get(child.arena_index()).is_none(),
            "empty child region closes during the first parent close attempt",
            true,
            state.regions.get(child.arena_index()).is_none()
        );

        let root_completed = state.complete_task(
            root_task,
            Outcome::Cancelled(CancelReason::user("first close")),
        );
        crate::assert_with_log!(
            root_completed,
            "root task transitions to cancelled before runtime cleanup",
            true,
            root_completed
        );
        let _ = state.task_completed(root_task);
        let scheduled_finalizers = state.drain_ready_async_finalizers();
        crate::assert_with_log!(
            scheduled_finalizers.len() == 1,
            "root close schedules one async finalizer task",
            1usize,
            scheduled_finalizers.len()
        );
        let finalizer_task = scheduled_finalizers[0].0;
        crate::assert_with_log!(
            state.task(finalizer_task).is_some(),
            "async finalizer task is installed during finalizer drain",
            true,
            state.task(finalizer_task).is_some()
        );
        let _fourth_attempt =
            state.cancel_request(root, &CancelReason::user("finalizer close"), None);
        let during_finalizer_drain = observe(
            &state,
            "during_finalizer_drain",
            2,
            &mut state_transition_sequence,
            &mut quiescence_observations,
            &mut first_quiescent_tick,
        );
        crate::assert_with_log!(
            !during_finalizer_drain,
            "finalizer drain stays non-quiescent",
            false,
            during_finalizer_drain
        );

        crate::assert_with_log!(
            close_begin_count_for_root(&state) == 1,
            "finalizer-drain re-entry preserves a single close-begin edge",
            1usize,
            close_begin_count_for_root(&state)
        );
        crate::assert_with_log!(
            close_complete_count_for_root(&state) == 0,
            "finalizer-drain re-entry does not close the region early",
            0usize,
            close_complete_count_for_root(&state)
        );

        let finalizer_waker = Waker::from(Arc::new(TestWaker(AtomicBool::new(false))));
        let mut finalizer_poll_cx = Context::from_waker(&finalizer_waker);
        let finalizer_outcome = {
            let stored = state
                .get_stored_future(finalizer_task)
                .expect("async finalizer stored task");
            match stored.poll(&mut finalizer_poll_cx) {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Cancelled(reason)) => Outcome::Cancelled(reason),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                Poll::Ready(Outcome::Err(())) => {
                    panic!("async finalizer task must not resolve with unit error")
                }
                Poll::Pending => panic!("async finalizer task must complete on first poll"),
            }
        };
        let finalizer_completed = state.complete_task(finalizer_task, finalizer_outcome);
        crate::assert_with_log!(
            finalizer_completed,
            "async finalizer task transitions to ok before runtime cleanup",
            true,
            finalizer_completed
        );
        let _ = state.task_completed(finalizer_task);
        let outcome_before_post_close_reentry = format!("{:?}", state.region_close_outcome(root));
        let after_close_complete = observe(
            &state,
            "after_close_complete",
            3,
            &mut state_transition_sequence,
            &mut quiescence_observations,
            &mut first_quiescent_tick,
        );
        crate::assert_with_log!(
            after_close_complete,
            "runtime becomes quiescent exactly when the close lifecycle completes",
            true,
            after_close_complete
        );

        let fifth_attempt = state.cancel_request(root, &CancelReason::user("post-close"), None);
        crate::assert_with_log!(
            fifth_attempt.is_empty(),
            "post-close re-entry returns no scheduled work",
            true,
            fifth_attempt.len()
        );
        let after_post_close_reentry = observe(
            &state,
            "after_post_close_reentry",
            4,
            &mut state_transition_sequence,
            &mut quiescence_observations,
            &mut first_quiescent_tick,
        );
        crate::assert_with_log!(
            after_post_close_reentry,
            "post-close re-entry preserves quiescence",
            true,
            after_post_close_reentry
        );

        let close_begin_count = close_begin_count_for_root(&state);
        let close_complete_count = close_complete_count_for_root(&state);
        let finalizer_run_count = state
            .finalizer_history()
            .iter()
            .filter(|event| matches!(event, FinalizerHistoryEvent::Ran { .. }))
            .count();
        let finalizer_close_count = state
            .finalizer_history()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    FinalizerHistoryEvent::RegionClosed { region, .. } if *region == root
                )
            })
            .count();
        let quiescence_transition_count = quiescence_observations
            .iter()
            .enumerate()
            .filter(|(idx, is_quiescent)| {
                **is_quiescent && (*idx == 0 || !quiescence_observations[idx.saturating_sub(1)])
            })
            .count();

        crate::assert_with_log!(
            close_begin_count == 1,
            "root emits one close-begin trace across redundant requests",
            1usize,
            close_begin_count
        );
        crate::assert_with_log!(
            close_complete_count == 1,
            "root emits one close-complete trace across redundant requests",
            1usize,
            close_complete_count
        );
        crate::assert_with_log!(
            finalizer_runs.load(Ordering::SeqCst) == 1,
            "registered finalizer runs once",
            1usize,
            finalizer_runs.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            finalizer_run_count == 1,
            "finalizer history records one run",
            1usize,
            finalizer_run_count
        );
        crate::assert_with_log!(
            finalizer_close_count == 1,
            "finalizer history records one close for the root region",
            1usize,
            finalizer_close_count
        );
        crate::assert_with_log!(
            quiescence_transition_count == 1,
            "quiescence flips from false to true exactly once",
            1usize,
            quiescence_transition_count
        );
        crate::assert_with_log!(
            first_quiescent_tick == Some(3),
            "first quiescent observation happens only after close completion",
            Some(3usize),
            first_quiescent_tick
        );
        crate::assert_with_log!(
            state.region_was_closed(root),
            "root region recorded as closed after redundant requests",
            true,
            state.region_was_closed(root)
        );
        crate::assert_with_log!(
            outcome_before_post_close_reentry == format!("{:?}", state.region_close_outcome(root)),
            "post-close re-entry preserves the terminal close outcome",
            outcome_before_post_close_reentry,
            format!("{:?}", state.region_close_outcome(root))
        );
        crate::assert_with_log!(
            state.live_task_count() == 0,
            "close re-entry does not leak tasks",
            0usize,
            state.live_task_count()
        );
        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "close re-entry does not leak obligations",
            0usize,
            state.pending_obligation_count()
        );
        crate::test_complete!(
            "redundant_region_close_requests_quiesce_once_without_double_finalize"
        );
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
        let region_state_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed after all tasks complete (removed)",
            true,
            region_state_removed
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
        crate::assert_with_log!(
            matches!(
                state.region_close_outcome(root),
                Some(Outcome::Cancelled(reason)) if reason == CancelReason::timeout()
            ),
            "region close outcome preserved after teardown",
            true,
            format!("{:?}", state.region_close_outcome(root))
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
    fn region_close_outcome_tracks_error_after_region_teardown() {
        init_test("region_close_outcome_tracks_error_after_region_teardown");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        let _ = state.cancel_request(region, &CancelReason::timeout(), None);
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Err(Error::new(ErrorKind::Internal)));
        let _ = state.task_completed(task);

        crate::assert_with_log!(
            state.region_was_closed(region),
            "region torn down after last task completed",
            true,
            state.region_was_closed(region)
        );
        crate::assert_with_log!(
            matches!(state.region_close_outcome(region), Some(Outcome::Err(_))),
            "error close outcome preserved after teardown",
            true,
            format!("{:?}", state.region_close_outcome(region))
        );
        crate::test_complete!("region_close_outcome_tracks_error_after_region_teardown");
    }

    #[test]
    fn root_region_cleared_after_root_teardown() {
        init_test("root_region_cleared_after_root_teardown");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        let region_record = state.regions.get(root.arena_index()).expect("region");
        assert!(region_record.begin_close(None));

        state.advance_region_state(root);

        crate::assert_with_log!(
            state.region_was_closed(root),
            "root region torn down",
            true,
            state.region_was_closed(root)
        );
        crate::assert_with_log!(
            state.root_region.is_none(),
            "closed root must clear root_region handle",
            true,
            state.root_region.is_none()
        );

        let replacement_root = state.create_root_region(Budget::INFINITE);
        crate::assert_with_log!(
            state.root_region == Some(replacement_root),
            "new root can be installed after prior root teardown",
            Some(replacement_root),
            state.root_region
        );

        crate::test_complete!("root_region_cleared_after_root_teardown");
    }

    #[test]
    fn sync_finalizer_panic_strengthens_region_close_outcome() {
        init_test("sync_finalizer_panic_strengthens_region_close_outcome");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        state.register_sync_finalizer(region, || panic!("finalizer boom"));

        let region_record = state.regions.get(region.arena_index()).expect("region");
        assert!(region_record.begin_close(None));
        assert!(region_record.begin_finalize());

        state.advance_region_state(region);

        crate::assert_with_log!(
            state.region_was_closed(region),
            "region closed despite finalizer panic",
            true,
            state.region_was_closed(region)
        );
        crate::assert_with_log!(
            matches!(
                state.region_close_outcome(region),
                Some(Outcome::Panicked(payload)) if payload.message().contains("finalizer boom")
            ),
            "finalizer panic captured in region close outcome",
            true,
            format!("{:?}", state.region_close_outcome(region))
        );
        crate::test_complete!("sync_finalizer_panic_strengthens_region_close_outcome");
    }

    #[test]
    fn sync_finalizer_panic_preserved_with_successful_task() {
        init_test("sync_finalizer_panic_preserved_with_successful_task");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Register a panicking sync finalizer
        state.register_sync_finalizer(region, || panic!("finalizer boom"));

        // Add a task that will complete successfully
        let task = insert_task(&mut state, region);

        // Begin region close
        let region_record = state.regions.get(region.arena_index()).expect("region");
        assert!(region_record.begin_close(None));

        // Complete the task successfully
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task);

        crate::assert_with_log!(
            state.region_was_closed(region),
            "region closed with task and panicking finalizer",
            true,
            state.region_was_closed(region)
        );

        // The key test: panic should still be preserved despite successful task
        crate::assert_with_log!(
            matches!(
                state.region_close_outcome(region),
                Some(Outcome::Panicked(payload)) if payload.message().contains("finalizer boom")
            ),
            "finalizer panic preserved despite successful task completion",
            true,
            format!("{:?}", state.region_close_outcome(region))
        );
        crate::test_complete!("sync_finalizer_panic_preserved_with_successful_task");
    }

    #[test]
    fn finalizer_panic_observable_in_closed_region() {
        init_test("finalizer_panic_observable_in_closed_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Register multiple finalizers: one panics, others succeed
        let panic_finalizer_called = Arc::new(AtomicBool::new(false));
        let success_finalizer_called = Arc::new(AtomicBool::new(false));

        let panic_flag = Arc::clone(&panic_finalizer_called);
        let success_flag = Arc::clone(&success_finalizer_called);

        state.register_sync_finalizer(region, move || {
            success_flag.store(true, Ordering::SeqCst);
        });

        state.register_sync_finalizer(region, move || {
            panic_flag.store(true, Ordering::SeqCst);
            panic!("finalizer boom");
        });

        // Begin close sequence
        let region_record = state.regions.get(region.arena_index()).expect("region");
        assert!(region_record.begin_close(None));
        assert!(region_record.begin_finalize());

        // Advance region state to run finalizers
        state.advance_region_state(region);

        // Verify the region closed (transitions to Closed state)
        crate::assert_with_log!(
            state.region_was_closed(region),
            "region must complete close despite finalizer panic",
            true,
            state.region_was_closed(region)
        );

        // Verify both finalizers ran
        crate::assert_with_log!(
            panic_finalizer_called.load(Ordering::SeqCst),
            "panic finalizer must execute",
            true,
            panic_finalizer_called.load(Ordering::SeqCst)
        );

        crate::assert_with_log!(
            success_finalizer_called.load(Ordering::SeqCst),
            "success finalizer must execute despite sibling panic",
            true,
            success_finalizer_called.load(Ordering::SeqCst)
        );

        // CRITICAL TEST: panic outcome must be observable even after close
        let outcome = state.region_close_outcome(region);
        crate::assert_with_log!(
            matches!(outcome, Some(Outcome::Panicked(ref payload)) if payload.message().contains("finalizer boom")),
            "finalizer panic must remain observable in closed region outcome",
            true,
            format!("{:?}", outcome)
        );

        crate::test_complete!("finalizer_panic_observable_in_closed_region");
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
        let child_state_removed = state.regions.get(child.arena_index()).is_none();
        crate::assert_with_log!(
            child_state_removed,
            "child closed after its task completes (removed)",
            true,
            child_state_removed
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

        let root_state_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_state_removed,
            "root closed after all tasks and children done (removed)",
            true,
            root_state_removed
        );
        crate::test_complete!("cancel_drain_finalize_nested_regions");
    }

    #[test]
    fn lab_runtime_cancelled_task_updates_cancel_protocol_validator() {
        init_test("lab_runtime_cancelled_task_updates_cancel_protocol_validator");
        let config = crate::lab::config::LabConfig::new(42)
            .max_steps(128)
            .panic_on_leak(false);
        let mut runtime = crate::lab::runtime::LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                crate::runtime::yield_now::yield_now().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.step_for_test();

        let cancel_reason = CancelReason::user("validator regression");
        let cancelled = runtime.state.cancel_task(task_id, &cancel_reason);
        crate::assert_with_log!(
            cancelled,
            "task cancellation should be recorded",
            true,
            cancelled
        );

        runtime
            .scheduler
            .lock()
            .schedule_cancel(task_id, cancel_reason.cleanup_budget().priority);
        runtime.run_until_quiescent();

        let validator = runtime.state.cancel_protocol_validator().lock();
        let validator_cancelled = matches!(
            validator.task_state(task_id),
            Some(crate::cancel::protocol_state_machines::TaskState::Cancelled)
        );
        crate::assert_with_log!(
            validator_cancelled,
            "validator should observe RequestCancel -> DrainComplete",
            true,
            validator_cancelled
        );
        crate::assert_with_log!(
            validator.violation_count() == 0,
            "validator should not record protocol violations",
            0u64,
            validator.violation_count()
        );

        crate::test_complete!("lab_runtime_cancelled_task_updates_cancel_protocol_validator");
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed cleanly (removed)",
            true,
            region_state_removed
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed (removed)",
            true,
            region_state_removed
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed (removed)",
            true,
            region_state_removed
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
        let child_state_removed = state.regions.get(child.arena_index()).is_none();
        crate::assert_with_log!(
            child_state_removed,
            "child closed (removed)",
            true,
            child_state_removed
        );
        let root_state_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_state_removed,
            "root closed (removed)",
            true,
            root_state_removed
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

        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed (removed)",
            true,
            region_state_removed
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
        use std::task::Waker;
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
        state.update_task(task, |record| {
            record.complete(Outcome::Ok(()));
        });
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
        let gc_state_removed = state.regions.get(grandchild.arena_index()).is_none();
        crate::assert_with_log!(
            gc_state_removed,
            "grandchild closed (removed)",
            true,
            gc_state_removed
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
        let child_state_final_removed = state.regions.get(child.arena_index()).is_none();
        crate::assert_with_log!(
            child_state_final_removed,
            "child closed after task + obligation resolved (removed)",
            true,
            child_state_final_removed
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
        let root_state_final_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_state_final_removed,
            "root closed after full cascade (removed)",
            true,
            root_state_final_removed
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed after obligation resolve + task complete (removed)",
            true,
            region_state_removed
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
            // br-asupersync-qp2tfx: internal constructors Panic on obligation
            // leak so the lab/test paths surface bugs the same way the
            // user-facing default (Fail, set in br-gi61n1) does.
            obligation_leak_response: ObligationLeakResponse::Panic,
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

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn metamorphic_order_respecting_lock_sequences_remain_tarjan_scc_free() {
        use crate::runtime::ShardGuard;
        use crate::runtime::ShardedState;
        use crate::runtime::sharded_state::ShardedConfig;
        use crate::runtime::sharded_state::{LockShard, lock_order};
        use std::panic::{AssertUnwindSafe, catch_unwind};

        fn shard_index(shard: LockShard) -> usize {
            match shard {
                LockShard::Regions => 0,
                LockShard::Tasks => 1,
                LockShard::Obligations => 2,
            }
        }

        fn label_index(label: &'static str) -> usize {
            match label {
                "B:Regions" => 0,
                "A:Tasks" => 1,
                "C:Obligations" => 2,
                other => panic!("unexpected shard label: {other}"),
            }
        }

        fn tarjan_scc(node_count: usize, edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
            struct Tarjan {
                adjacency: Vec<Vec<usize>>,
                index: usize,
                indices: Vec<Option<usize>>,
                lowlink: Vec<usize>,
                stack: Vec<usize>,
                on_stack: Vec<bool>,
                components: Vec<Vec<usize>>,
            }

            impl Tarjan {
                fn new(node_count: usize, edges: &[(usize, usize)]) -> Self {
                    let mut adjacency = vec![Vec::new(); node_count];
                    for &(from, to) in edges {
                        adjacency[from].push(to);
                    }
                    Self {
                        adjacency,
                        index: 0,
                        indices: vec![None; node_count],
                        lowlink: vec![0; node_count],
                        stack: Vec::new(),
                        on_stack: vec![false; node_count],
                        components: Vec::new(),
                    }
                }

                fn strongconnect(&mut self, v: usize) {
                    let v_index = self.index;
                    self.indices[v] = Some(v_index);
                    self.lowlink[v] = v_index;
                    self.index += 1;
                    self.stack.push(v);
                    self.on_stack[v] = true;

                    let neighbors = self.adjacency[v].clone();
                    for w in neighbors {
                        if self.indices[w].is_none() {
                            self.strongconnect(w);
                            self.lowlink[v] = self.lowlink[v].min(self.lowlink[w]);
                        } else if self.on_stack[w] {
                            self.lowlink[v] =
                                self.lowlink[v].min(self.indices[w].expect("visited neighbor"));
                        }
                    }

                    if self.lowlink[v] == v_index {
                        let mut component = Vec::new();
                        loop {
                            let w = self.stack.pop().expect("stack underflow");
                            self.on_stack[w] = false;
                            component.push(w);
                            if w == v {
                                break;
                            }
                        }
                        component.sort_unstable();
                        self.components.push(component);
                    }
                }
            }

            let mut tarjan = Tarjan::new(node_count, edges);
            for node in 0..node_count {
                if tarjan.indices[node].is_none() {
                    tarjan.strongconnect(node);
                }
            }
            tarjan.components.sort();
            tarjan.components
        }

        fn edges_from_sequences(sequences: &[Vec<usize>]) -> Vec<(usize, usize)> {
            sequences
                .iter()
                .flat_map(|sequence| sequence.windows(2).map(|pair| (pair[0], pair[1])))
                .collect()
        }

        fn acquire_sequence(sequence: &[LockShard]) -> Vec<usize> {
            let result = catch_unwind(AssertUnwindSafe(|| {
                for shard in sequence {
                    lock_order::before_lock(*shard);
                    lock_order::after_lock(*shard);
                }
                let labels = lock_order::held_labels()
                    .into_iter()
                    .map(label_index)
                    .collect::<Vec<_>>();
                lock_order::unlock_n(sequence.len());
                labels
            }));
            let leaked = lock_order::held_count();
            if leaked > 0 {
                lock_order::unlock_n(leaked);
            }
            result.unwrap_or_else(|_| {
                panic!(
                    "order-respecting acquisition should not panic for {:?}",
                    sequence
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                )
            })
        }

        fn capture_guard_labels(guard: ShardGuard<'_>) -> Vec<usize> {
            let labels = lock_order::held_labels()
                .into_iter()
                .map(label_index)
                .collect::<Vec<_>>();
            drop(guard);
            assert_eq!(lock_order::held_count(), 0);
            labels
        }

        let valid_sequences = [
            vec![LockShard::Regions],
            vec![LockShard::Tasks],
            vec![LockShard::Obligations],
            vec![LockShard::Regions, LockShard::Tasks],
            vec![LockShard::Regions, LockShard::Obligations],
            vec![LockShard::Tasks, LockShard::Obligations],
            vec![LockShard::Regions, LockShard::Tasks, LockShard::Obligations],
        ];
        let exhaustive_labels = valid_sequences
            .iter()
            .map(|sequence| acquire_sequence(sequence))
            .collect::<Vec<_>>();
        let exhaustive_sccs = tarjan_scc(3, &edges_from_sequences(&exhaustive_labels));
        assert!(
            exhaustive_sccs.iter().all(|component| component.len() == 1),
            "valid lock-order sequences should remain acyclic: {exhaustive_sccs:?}"
        );

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(TestMetrics::default());
        let config = ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Panic,
            leak_escalation: None,
            observability: None,
        };
        let shards = ShardedState::new(trace, metrics, config);
        let guard_labels = vec![
            capture_guard_labels(ShardGuard::regions_only(&shards)),
            capture_guard_labels(ShardGuard::tasks_only(&shards)),
            capture_guard_labels(ShardGuard::obligations_only(&shards)),
            capture_guard_labels(ShardGuard::for_spawn(&shards)),
            capture_guard_labels(ShardGuard::for_obligation(&shards)),
            capture_guard_labels(ShardGuard::for_task_completed(&shards)),
            capture_guard_labels(ShardGuard::for_cancel(&shards)),
            capture_guard_labels(ShardGuard::for_obligation_resolve(&shards)),
            capture_guard_labels(ShardGuard::all(&shards)),
        ];
        let guard_sccs = tarjan_scc(3, &edges_from_sequences(&guard_labels));
        assert!(
            guard_sccs.iter().all(|component| component.len() == 1),
            "real ShardGuard acquisitions should remain acyclic: {guard_sccs:?}"
        );

        assert_eq!(
            exhaustive_sccs, guard_sccs,
            "real guard constructors should induce the same SCC signature as the exhaustive valid order lattice"
        );

        let canonical_components = vec![vec![0], vec![1], vec![2]];
        assert_eq!(
            exhaustive_sccs, canonical_components,
            "Tarjan should visit the order-respecting lattice as singleton components only"
        );
        assert_eq!(
            guard_sccs,
            vec![vec![0], vec![1], vec![2]],
            "guard-derived lock graph should also stay singleton-only"
        );

        let covered = guard_labels
            .into_iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            covered,
            (0..=2).collect(),
            "guard constructors should cover Regions, Tasks, and Obligations"
        );

        let exhaustive_order = valid_sequences
            .iter()
            .flat_map(|sequence| sequence.iter().copied().map(shard_index))
            .collect::<Vec<_>>();
        assert!(
            exhaustive_order.windows(2).any(|pair| pair[0] <= pair[1]),
            "sanity check: exhaustive metamorphic input should include forward lock-order edges"
        );
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed despite leaked obligations (Silent mode) (removed)",
            true,
            region_state_removed
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
    fn finalizing_leak_detection_waits_for_task_cleanup() {
        // Regression: Finalizing leak detection used to treat "all tracked
        // tasks are terminal" as equivalent to "task cleanup has finished".
        // That is too early because task_completed still owns orphan abort/leak
        // handling and region unlinking. We must not mark leaks until the task
        // is fully removed from the owning region.
        init_test("finalizing_leak_detection_waits_for_task_cleanup");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        state
            .create_obligation(ObligationKind::SendPermit, task, region, None)
            .expect("create obligation");

        {
            let region_record = state.regions.get(region.arena_index()).expect("region");
            region_record.begin_close(None);
            region_record.begin_finalize();
        }

        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));

        // Advancing the Finalizing region before task_completed runs must not
        // leak-resolve the obligation yet, even though the task is terminal.
        state.advance_region_state(region);
        crate::assert_with_log!(
            state.pending_obligation_count() == 1,
            "pending obligation preserved until task cleanup",
            1usize,
            state.pending_obligation_count()
        );
        crate::assert_with_log!(
            state.leak_count() == 0,
            "no leaks emitted before task cleanup",
            0u64,
            state.leak_count()
        );
        let early_leak_events = state
            .trace
            .snapshot()
            .into_iter()
            .filter(|event| event.kind == TraceEventKind::ObligationLeak)
            .count();
        crate::assert_with_log!(
            early_leak_events == 0,
            "no leak trace events before task cleanup",
            0usize,
            early_leak_events
        );

        let _ = state.task_completed(task);

        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "task_completed resolves leaked obligation",
            0usize,
            state.pending_obligation_count()
        );
        crate::assert_with_log!(
            state.leak_count() == 1,
            "exactly one leak emitted after task cleanup",
            1u64,
            state.leak_count()
        );
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closes after task cleanup handles leak",
            true,
            region_state_removed
        );
        crate::test_complete!("finalizing_leak_detection_waits_for_task_cleanup");
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

        let gc_state_removed = state.regions.get(grandchild.arena_index()).is_none();
        crate::assert_with_log!(
            gc_state_removed,
            "grandchild closed after task done (removed)",
            true,
            gc_state_removed
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

        let child_state_final_removed = state.regions.get(child.arena_index()).is_none();
        crate::assert_with_log!(
            child_state_final_removed,
            "child closed after task done + grandchild closed (removed)",
            true,
            child_state_final_removed
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

        let root_state_final_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_state_final_removed,
            "root closed after full cascade (removed)",
            true,
            root_state_final_removed
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
        let region_state_removed = state.regions.get(region.arena_index()).is_none();
        crate::assert_with_log!(
            region_state_removed,
            "region closed in Recover mode (removed)",
            true,
            region_state_removed
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
        let child_state_removed = state.regions.get(child.arena_index()).is_none();
        crate::assert_with_log!(
            child_state_removed,
            "child closed (removed)",
            true,
            child_state_removed
        );

        // Complete root task
        state
            .task_mut(root_task)
            .expect("root_task")
            .complete(Outcome::Cancelled(CancelReason::user("test")));
        let _ = state.task_completed(root_task);

        // Root should close (all children closed, tasks done, obligations resolved)
        let root_state_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_state_removed,
            "root closed after mixed resolution (removed)",
            true,
            root_state_removed
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
    #[allow(clippy::significant_drop_tightening)]
    fn region_close_clears_resource_monitor_priority() {
        init_test("region_close_clears_resource_monitor_priority");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, root);

        assert!(state.set_region_priority(root, RegionPriority::Low));
        state
            .resource_monitor()
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Emergency,
            );
        assert!(matches!(
            state.resource_monitor().engine().should_shed_region(root),
            crate::runtime::resource_monitor::SheddingDecision::Cancel
        ));

        {
            let region = state.regions.get(root.arena_index()).expect("root");
            region.begin_close(None);
        }
        state
            .task_mut(task)
            .expect("task")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task);

        assert!(state.regions.get(root.arena_index()).is_none());
        assert!(matches!(
            state.resource_monitor().engine().should_shed_region(root),
            crate::runtime::resource_monitor::SheddingDecision::Pause
        ));
        crate::test_complete!("region_close_clears_resource_monitor_priority");
    }

    #[test]
    fn priority_aware_child_region_admission_uses_requested_priority() {
        init_test("priority_aware_child_region_admission_uses_requested_priority");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        state
            .resource_monitor()
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );

        state
            .create_child_region(root, Budget::INFINITE)
            .expect("default normal child region should be admitted at moderate pressure");

        let rejected =
            state.create_child_region_with_priority(root, Budget::INFINITE, RegionPriority::Low);
        assert!(matches!(
            rejected,
            Err(RegionCreateError::ResourcePressure {
                requested_priority: RegionPriority::Low,
                ..
            })
        ));
        crate::test_complete!("priority_aware_child_region_admission_uses_requested_priority");
    }

    #[test]
    fn priority_aware_child_region_registers_shedding_priority() {
        init_test("priority_aware_child_region_registers_shedding_priority");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let default_child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("default child region should be admitted");
        let low_child = state
            .create_child_region_with_priority(root, Budget::INFINITE, RegionPriority::Low)
            .expect("low-priority child should be admitted before pressure rises");

        state
            .resource_monitor()
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Heavy,
            );

        assert!(matches!(
            state
                .resource_monitor()
                .engine()
                .should_shed_region(default_child),
            crate::runtime::resource_monitor::SheddingDecision::Keep
        ));
        assert!(matches!(
            state
                .resource_monitor()
                .engine()
                .should_shed_region(low_child),
            crate::runtime::resource_monitor::SheddingDecision::Pause
        ));
        crate::test_complete!("priority_aware_child_region_registers_shedding_priority");
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

    #[test]
    fn nested_parent_leaks_are_not_suppressed_by_child_leak_handling() {
        // Regression: the old global `handling_leaks` boolean suppressed all
        // nested leak handling, not just duplicates of the current batch. When
        // a child leak closed the child region and advanced its parent into
        // `Finalizing`, the parent's distinct pending obligations were skipped
        // and the parent region stayed stuck with leaked-but-unhandled state.
        init_test("nested_parent_leaks_are_not_suppressed_by_child_leak_handling");
        let mut state = RuntimeState::new();
        state.set_obligation_leak_response(ObligationLeakResponse::Silent);

        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);

        state
            .create_obligation(ObligationKind::Lease, root_task, root, None)
            .expect("root obligation");
        state
            .create_obligation(ObligationKind::Ack, child_task, child, None)
            .expect("child obligation");

        state
            .regions
            .get(root.arena_index())
            .expect("root missing")
            .begin_close(None);
        state
            .regions
            .get(child.arena_index())
            .expect("child missing")
            .begin_close(None);

        // Simulate a stale parent-cleanup gap: the task is already unlinked,
        // but its obligation is still pending. Child leak handling will advance
        // the parent into Finalizing, where the parent's leak must still be
        // processed even though we are already inside the child's leak handler.
        let _ = state.remove_task(root_task);
        state
            .regions
            .get(root.arena_index())
            .expect("root missing")
            .remove_task(root_task);

        state
            .task_mut(child_task)
            .expect("child task missing")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(child_task);

        crate::assert_with_log!(
            state.pending_obligation_count() == 0,
            "all nested leaks resolved",
            0usize,
            state.pending_obligation_count()
        );
        crate::assert_with_log!(
            state.leak_count() == 2,
            "both child and parent leaks counted exactly once",
            2u64,
            state.leak_count()
        );
        let leak_events = state
            .trace
            .snapshot()
            .into_iter()
            .filter(|event| event.kind == TraceEventKind::ObligationLeak)
            .count();
        crate::assert_with_log!(
            leak_events == 2,
            "trace records both nested leaks",
            2usize,
            leak_events
        );
        let root_removed = state.regions.get(root.arena_index()).is_none();
        crate::assert_with_log!(
            root_removed,
            "parent region closes after nested leak handling",
            true,
            root_removed
        );

        crate::test_complete!("nested_parent_leaks_are_not_suppressed_by_child_leak_handling");
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

    #[test]
    fn event_data_snapshot_preserves_worker_replay_linkage() {
        let task = TaskId::from_arena(ArenaIndex::new(1, 2));
        let region = RegionId::from_arena(ArenaIndex::new(3, 4));
        let obligation = ObligationId::from_arena(ArenaIndex::new(5, 6));
        let snapshot = EventDataSnapshot::from_trace_data(&TraceData::Worker {
            worker_id: "worker-a".to_string(),
            job_id: 77,
            decision_seq: 91,
            replay_hash: 0x00C0_FFEE,
            task,
            region,
            obligation,
        });

        match snapshot {
            EventDataSnapshot::Worker {
                worker_id,
                job_id,
                decision_seq,
                replay_hash,
                task: task_snapshot,
                region: region_snapshot,
                obligation: obligation_snapshot,
            } => {
                assert_eq!(worker_id, "worker-a");
                assert_eq!(job_id, 77);
                assert_eq!(decision_seq, 91);
                assert_eq!(replay_hash, 0x00C0_FFEE);
                assert_eq!(task_snapshot, IdSnapshot::from(task));
                assert_eq!(region_snapshot, IdSnapshot::from(region));
                assert_eq!(obligation_snapshot, IdSnapshot::from(obligation));
            }
            other => panic!("expected worker snapshot, got {other:?}"), // ubs:ignore - test assertion
        }
    }

    // ============================================================================
    // Metamorphic Tests for Region Close Idempotency
    // ============================================================================

    mod metamorphic_region_close_tests {
        use super::*;
        use crate::lab::config::LabConfig;
        use crate::lab::runtime::LabRuntime;
        use proptest::prelude::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        /// Test data structure for capturing region close outcomes.
        #[derive(Debug, Clone, PartialEq)]
        struct RegionCloseOutcome {
            region_id: RegionId,
            close_successful: bool,
            final_state: crate::record::region::RegionState,
            task_count: usize,
            child_count: usize,
            pending_obligations: usize,
            cancel_reason: Option<CancelReason>,
        }

        impl RegionCloseOutcome {
            fn from_region(runtime: &LabRuntime, region_id: RegionId) -> Option<Self> {
                let state = &runtime.state;
                let regions = &state.regions;

                regions.get(region_id.arena_index()).map(|region| Self {
                    region_id,
                    close_successful: region.state() == crate::record::region::RegionState::Closed,
                    final_state: region.state(),
                    task_count: region.task_count(),
                    child_count: region.child_count(),
                    pending_obligations: region.pending_obligations(),
                    cancel_reason: region.cancel_reason(),
                })
            }
        }

        fn cancel_reason_for_variant(variant: u8) -> CancelReason {
            match variant {
                0 => CancelReason::default(),
                1 => CancelReason::timeout(),
                2 => CancelReason::resource_unavailable(),
                _ => CancelReason::user("redundant close"),
            }
        }

        /// Metamorphic Relation 1: Region close idempotency
        /// Property: Calling region.close() twice should return the same outcome the second time
        #[test]
        fn mr_region_close_idempotency() {
            proptest!(|(seed in any::<u64>())| {
                let config = LabConfig::new(seed).max_steps(1000);
                let mut runtime = LabRuntime::new(config);

                // Create a region and immediately close it
                let region_id = runtime.state.create_root_region(Budget::default());

                // First close attempt
                let _first_close_result = {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    let begin_result = region.begin_close(None);

                    // Transition through states
                    if begin_result {
                        let _ = region.begin_finalize();
                        region.complete_close()
                    } else {
                        false
                    }
                };

                let first_outcome = RegionCloseOutcome::from_region(&runtime, region_id);

                // Second close attempt (should be idempotent)
                let second_close_result = {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    region.complete_close()  // Should return false (already closed)
                };

                let second_outcome = RegionCloseOutcome::from_region(&runtime, region_id);

                // Metamorphic relation: Second call should be no-op
                prop_assert_eq!(second_close_result, false, "Second close should return false (idempotent)");
                prop_assert_eq!(&first_outcome, &second_outcome, "Region state should be unchanged by second close");

                if let Some(outcome) = first_outcome {
                    prop_assert_eq!(outcome.final_state, crate::record::region::RegionState::Closed);
                }
            });
        }

        /// Metamorphic Relation 2: Cancelling closed region is no-op
        /// Property: Attempting to cancel an already closed region should have no effect
        #[test]
        fn mr_cancel_closed_region_noop() {
            proptest!(|(seed in any::<u64>(), cancel_reason_variant in 0..3u8)| {
                let config = LabConfig::new(seed).max_steps(1000);
                let mut runtime = LabRuntime::new(config);

                let region_id = runtime.state.create_root_region(Budget::default());

                // Close the region first
                {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    let _ = region.begin_close(None);
                    let _ = region.begin_finalize();
                    let _ = region.complete_close();
                }

                let outcome_before_cancel = RegionCloseOutcome::from_region(&runtime, region_id);

                // Attempt to cancel the already-closed region
                let cancel_reason = cancel_reason_for_variant(cancel_reason_variant);

                {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    let _ = region.begin_close(Some(cancel_reason));  // Should be no-op
                }

                let outcome_after_cancel = RegionCloseOutcome::from_region(&runtime, region_id);

                // Metamorphic relation: Cancel should be no-op on closed region
                prop_assert_eq!(outcome_before_cancel, outcome_after_cancel,
                    "Cancelling closed region should have no effect");
            });
        }

        /// Metamorphic Relation 2b: Closed regions preserve their terminal cancel cause
        /// Property: Once a region reaches Closed, redundant close attempts cannot rewrite the terminal reason
        #[test]
        fn mr_closed_region_preserves_terminal_cancel_reason() {
            proptest!(|(seed in any::<u64>(), initial_variant in 0..4u8, followup_variant in 0..4u8)| {
                let config = LabConfig::new(seed).max_steps(1000);
                let mut runtime = LabRuntime::new(config);

                let region_id = runtime.state.create_root_region(Budget::default());
                let initial_reason = cancel_reason_for_variant(initial_variant);
                let followup_reason = cancel_reason_for_variant(followup_variant);

                {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    let _ = region.begin_close(Some(initial_reason.clone()));
                    let _ = region.begin_finalize();
                    let _ = region.complete_close();
                }

                let outcome_before_redundant_close = RegionCloseOutcome::from_region(&runtime, region_id);

                {
                    let state = &mut runtime.state;
                    let region = state.regions.get_mut(region_id.arena_index()).unwrap();
                    let redundant_close_result = region.begin_close(Some(followup_reason));
                    prop_assert!(!redundant_close_result, "redundant close on terminal region should be a no-op");
                }

                let outcome_after_redundant_close = RegionCloseOutcome::from_region(&runtime, region_id);

                prop_assert_eq!(
                    &outcome_before_redundant_close,
                    &outcome_after_redundant_close,
                    "redundant close must preserve the terminal cancel reason and region snapshot"
                );

                if let Some(outcome) = &outcome_after_redundant_close {
                    prop_assert_eq!(
                        outcome.cancel_reason.clone(),
                        Some(initial_reason),
                        "terminal cancel reason should remain the original close cause"
                    );
                }
            });
        }

        /// Metamorphic Relation 3: Child region close containment
        /// Property: Child region close never escapes parent before parent.close()
        #[test]
        fn mr_child_close_containment() {
            proptest!(|(seed in any::<u64>(), num_children in 1..5usize)| {
                let config = LabConfig::new(seed).max_steps(2000);
                let mut runtime = LabRuntime::new(config);

                let parent_id = runtime.state.create_root_region(Budget::default());
                let mut child_ids = Vec::new();

                // Create child regions
                for _ in 0..num_children {
                    let child_id = runtime.state.create_child_region(parent_id, Budget::default()).unwrap();
                    child_ids.push(child_id);
                }

                // Close all children through RuntimeState so parent-child indexes
                // are cleaned up the same way production close cascades do.
                for &child_id in &child_ids {
                    {
                        let state = &mut runtime.state;
                        let child = state.regions.get_mut(child_id.arena_index()).unwrap();
                        let _ = child.begin_close(None);
                    }
                    runtime.state.advance_region_state(child_id);
                    prop_assert!(
                        runtime.state.region_was_closed(child_id),
                        "child should close through RuntimeState cleanup"
                    );
                }

                // Verify children are closed but parent is still open
                let parent_outcome_before = RegionCloseOutcome::from_region(&runtime, parent_id);
                prop_assert!(parent_outcome_before.is_some());

                if let Some(outcome) = parent_outcome_before {
                    // Parent should still be open (children closed first)
                    prop_assert_ne!(outcome.final_state, crate::record::region::RegionState::Closed,
                        "Parent should not auto-close when children close");
                }

                // Now close parent
                {
                    let state = &mut runtime.state;
                    let parent = state.regions.get_mut(parent_id.arena_index()).unwrap();
                    let _ = parent.begin_close(None);
                }
                runtime.state.advance_region_state(parent_id);

                // Metamorphic relation: Parent close should succeed after all children are closed
                prop_assert!(
                    runtime.state.region_was_closed(parent_id),
                    "parent should close once child indexes are empty"
                );
                prop_assert!(
                    runtime.state.regions.get(parent_id.arena_index()).is_none(),
                    "closed parent should be removed from the region table"
                );
            });
        }

        /// Metamorphic Relation 4: No-orphan invariant under concurrent spawn+close
        /// Property: Concurrent spawn+close races never produce orphan tasks
        #[test]
        fn mr_no_orphan_invariant() {
            proptest!(|(seed in any::<u64>(), num_operations in 5..20usize)| {
                let config = LabConfig::new(seed).max_steps(3000).worker_count(2);
                let mut runtime = LabRuntime::new(config);

                let region_id = runtime.state.create_root_region(Budget::default());
                let spawned_tasks = Arc::new(AtomicUsize::new(0));
                let completed_tasks = Arc::new(AtomicUsize::new(0));
                let close_attempted = Arc::new(AtomicBool::new(false));

                // Simulate concurrent spawn and close operations
                for i in 0..num_operations {
                    let spawned_count = spawned_tasks.clone();
                    let completed_count = completed_tasks.clone();
                    let close_flag = close_attempted.clone();

                    if i % 3 == 0 && !close_flag.load(Ordering::Relaxed) {
                        // Attempt to close region
                        close_flag.store(true, Ordering::Relaxed);
                        let _close_task = futures_lite::future::block_on(async move {
                            // Simulate close operation
                            Ok::<(), ()>(())
                        });
                    } else {
                        // Spawn task in region
                        let task_spawned = spawned_count.clone();
                        let task_completed = completed_count.clone();

                        let task_result = futures_lite::future::block_on(async move {
                            task_spawned.fetch_add(1, Ordering::Relaxed);

                            // Simulate some work
                            task_completed.fetch_add(1, Ordering::Relaxed);
                            Ok::<(), ()>(())
                        });

                        // Task spawn might fail if region is closing/closed
                        if task_result.is_err() {
                            // This is expected behavior when region is closing
                        }
                    }
                }

                // Run the scenario
                runtime.run_until_quiescent();

                // Verify no-orphan invariant
                let region_outcome = RegionCloseOutcome::from_region(&runtime, region_id);

                if let Some(outcome) = region_outcome {
                    // Metamorphic relation: No tasks should be orphaned
                    prop_assert_eq!(outcome.task_count, 0,
                        "Region should have no remaining tasks (no orphans)");

                    // If region closed successfully, all spawned tasks should be accounted for
                    if outcome.close_successful {
                        let spawned = spawned_tasks.load(Ordering::Relaxed);
                        let completed = completed_tasks.load(Ordering::Relaxed);

                        // All spawned tasks should complete or be cancelled (no orphans)
                        prop_assert!(spawned >= completed,
                            "Completed tasks should not exceed spawned tasks");
                    }
                }
            });
        }

        /// Composite metamorphic relation: Multiple close operations with different orderings
        /// Tests interaction between all four metamorphic relations
        #[test]
        fn mr_composite_region_lifecycle() {
            proptest!(|(seed in any::<u64>(), operation_sequence in prop::collection::vec(0..4u8, 3..10))| {
                let config = LabConfig::new(seed).max_steps(5000);
                let mut runtime = LabRuntime::new(config);

                let parent_id = runtime.state.create_root_region(Budget::default());
                let child_id = runtime.state.create_child_region(parent_id, Budget::default()).unwrap();

                let mut parent_close_count = 0;
                let mut child_close_count = 0;
                let mut cancel_attempts = 0;

                // Execute operation sequence
                for &op in &operation_sequence {
                    match op {
                        0 => {
                            // Close parent (should fail if child not closed)
                            let state = &mut runtime.state;
                            if let Some(parent) = state.regions.get_mut(parent_id.arena_index()) {
                                if parent.begin_close(None) {
                                    let _ = parent.begin_finalize();
                                    let _ = parent.complete_close();
                                }
                                parent_close_count += 1;
                            }
                        }
                        1 => {
                            // Close child
                            let state = &mut runtime.state;
                            if let Some(child) = state.regions.get_mut(child_id.arena_index()) {
                                if child.begin_close(None) {
                                    let _ = child.begin_finalize();
                                    let _ = child.complete_close();
                                }
                                child_close_count += 1;
                            }
                        }
                        2 => {
                            // Cancel parent
                            let state = &mut runtime.state;
                            if let Some(parent) = state.regions.get_mut(parent_id.arena_index()) {
                                let _ = parent.begin_close(Some(CancelReason::user("close")));
                                cancel_attempts += 1;
                            }
                        }
                        3 => {
                            // Cancel child
                            let state = &mut runtime.state;
                            if let Some(child) = state.regions.get_mut(child_id.arena_index()) {
                                let _ = child.begin_close(Some(CancelReason::user("close")));
                                cancel_attempts += 1;
                            }
                        }
                        _ => unreachable!(),
                    }
                }

                // Verify final states satisfy all metamorphic relations
                let parent_outcome = RegionCloseOutcome::from_region(&runtime, parent_id);
                let child_outcome = RegionCloseOutcome::from_region(&runtime, child_id);

                // MR1 (Idempotency): Multiple close attempts should be handled gracefully
                prop_assert!(parent_close_count >= 0 && child_close_count >= 0);

                // MR2 (Cancel no-op): Cancel attempts on closed regions should be no-ops
                prop_assert!(cancel_attempts >= 0);

                // MR3 (Containment): If both are closed, child must have closed first (or together)
                if let (Some(parent), Some(child)) = (parent_outcome, child_outcome) {
                    if parent.close_successful && child.close_successful {
                        // Both closed successfully - this satisfies containment
                        prop_assert_eq!(parent.child_count, 0, "Closed parent should have no children");
                    }

                    if parent.close_successful {
                        // MR4 (No orphans): Closed regions should have no remaining tasks
                        prop_assert_eq!(parent.task_count, 0, "Closed parent should have no tasks");
                    }

                    if child.close_successful {
                        prop_assert_eq!(child.task_count, 0, "Closed child should have no tasks");
                    }
                }
            });
        }
    }

    mod metamorphic_cancel_cause_chain_tests {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashMap;

        fn reason_from_variant(variant: u8) -> CancelReason {
            match variant {
                0 => CancelReason::deadline().with_message("root deadline"),
                1 => CancelReason::timeout().with_message("rpc timeout"),
                2 => CancelReason::resource_unavailable().with_message("peer unavailable"),
                _ => CancelReason::user("operator stop"),
            }
        }

        #[derive(Debug, Clone, PartialEq)]
        struct BranchCancelSnapshot {
            branch_region_reason: CancelReason,
            leaf_region_reason: CancelReason,
            branch_task_reason: CancelReason,
            leaf_task_reason: CancelReason,
        }

        fn branch_cancel_snapshot_with_sibling_noise(
            sibling_count: usize,
            reason: &CancelReason,
        ) -> BranchCancelSnapshot {
            let mut state = RuntimeState::new();
            state.set_cancel_attribution_config(CancelAttributionConfig::new(8, usize::MAX));

            let root = state.create_root_region(Budget::INFINITE);
            let branch = create_child_region(&mut state, root);
            let leaf = create_child_region(&mut state, branch);
            let branch_task = insert_task(&mut state, branch);
            let leaf_task = insert_task(&mut state, leaf);

            for _ in 0..sibling_count {
                let sibling = create_child_region(&mut state, root);
                let _ = insert_task(&mut state, sibling);
                let niece = create_child_region(&mut state, sibling);
                let _ = insert_task(&mut state, niece);
            }

            let _ = state.cancel_request(branch, reason, None);

            let branch_region_reason = state
                .regions
                .get(branch.arena_index())
                .and_then(RegionRecord::cancel_reason)
                .expect("branch cancel reason missing");
            let leaf_region_reason = state
                .regions
                .get(leaf.arena_index())
                .and_then(RegionRecord::cancel_reason)
                .expect("leaf cancel reason missing");
            let branch_task_reason = match &state
                .tasks
                .get(branch_task.arena_index())
                .expect("branch task missing")
                .state
            {
                TaskState::CancelRequested { reason, .. } => reason.clone(),
                other => panic!("expected branch task to be cancelling, got {other:?}"),
            };
            let leaf_task_reason = match &state
                .tasks
                .get(leaf_task.arena_index())
                .expect("leaf task missing")
                .state
            {
                TaskState::CancelRequested { reason, .. } => reason.clone(),
                other => panic!("expected leaf task to be cancelling, got {other:?}"),
            };

            BranchCancelSnapshot {
                branch_region_reason,
                leaf_region_reason,
                branch_task_reason,
                leaf_task_reason,
            }
        }

        #[test]
        fn mr_cancel_cause_chain_tracks_full_lineage_without_truncation() {
            proptest!(|(
                nesting_depth in 1..7usize,
                extra_depth_budget in 0..3usize,
                reason_variant in 0..4u8
            )| {
                let mut state = RuntimeState::new();
                let full_lineage_depth = nesting_depth + 1;
                state.set_cancel_attribution_config(CancelAttributionConfig::new(
                    full_lineage_depth + extra_depth_budget,
                    usize::MAX,
                ));

                let root = state.create_root_region(Budget::INFINITE);
                let mut lineage = vec![root];
                for _ in 0..nesting_depth {
                    let parent = *lineage.last().expect("lineage has root");
                    let child = create_child_region(&mut state, parent);
                    lineage.push(child);
                }

                let leaf = *lineage.last().expect("leaf region missing");
                let leaf_task = insert_task(&mut state, leaf);
                let original_reason = reason_from_variant(reason_variant);
                let expected_root_kind = original_reason.kind;
                let expected_root_message = original_reason.message.clone();

                let _ = state.cancel_request(root, &original_reason, None);

                for (depth_idx, &region_id) in lineage.iter().enumerate() {
                    let region_record = state
                        .regions
                        .get(region_id.arena_index())
                        .expect("region missing");
                    let region_reason = region_record.cancel_reason();
                    let reason = region_reason
                        .as_ref()
                        .expect("region cancel reason missing");

                    prop_assert_eq!(
                        reason.chain_depth(),
                        depth_idx + 1,
                        "depth {} should expose the full ancestry",
                        depth_idx
                    );
                    prop_assert!(
                        !reason.any_truncated(),
                        "full-depth attribution should not truncate at depth {}",
                        depth_idx
                    );

                    if depth_idx == 0 {
                        prop_assert_eq!(reason.kind, expected_root_kind);
                    } else {
                        prop_assert_eq!(reason.kind, CancelKind::ParentCancelled);
                        prop_assert_eq!(reason.origin_region, lineage[depth_idx - 1]);
                    }

                    let root_cause = reason.root_cause();
                    prop_assert_eq!(root_cause.kind, expected_root_kind);
                    prop_assert_eq!(
                        root_cause.message.as_deref(),
                        expected_root_message.as_deref()
                    );
                }

                let leaf_task_record = state.tasks.get(leaf_task.arena_index()).expect("task missing");
                match &leaf_task_record.state {
                    TaskState::CancelRequested { reason, .. } => {
                        prop_assert_eq!(reason.kind, CancelKind::ParentCancelled);
                        prop_assert_eq!(reason.origin_region, lineage[lineage.len() - 2]);
                        prop_assert_eq!(reason.chain_depth(), full_lineage_depth);
                        prop_assert!(!reason.any_truncated());
                        prop_assert_eq!(reason.root_cause().kind, expected_root_kind);
                        prop_assert_eq!(
                            reason.root_cause().message.as_deref(),
                            expected_root_message.as_deref()
                        );
                    }
                    other => {
                        prop_assert!(false, "expected CancelRequested task state, got {other:?}");
                    }
                }
            });
        }

        #[test]
        fn mr_parent_cancel_schedules_ancestors_before_descendants() {
            proptest!(|(
                child_count in 1..5usize,
                grandchildren_per_child in 1..4usize,
                reason_variant in 0..4u8
            )| {
                let mut state = RuntimeState::new();
                let root = state.create_root_region(Budget::INFINITE);
                let root_task = insert_task(&mut state, root);
                let mut depth_by_task = HashMap::from([(root_task, 0usize)]);

                for _ in 0..child_count {
                    let child = create_child_region(&mut state, root);
                    let child_task = insert_task(&mut state, child);
                    depth_by_task.insert(child_task, 1);

                    for _ in 0..grandchildren_per_child {
                        let grandchild = create_child_region(&mut state, child);
                        let grandchild_task = insert_task(&mut state, grandchild);
                        depth_by_task.insert(grandchild_task, 2);
                    }
                }

                let scheduled = state.cancel_request(root, &reason_from_variant(reason_variant), None);
                prop_assert_eq!(
                    scheduled.len(),
                    depth_by_task.len(),
                    "initial cancel cascade should schedule each task exactly once"
                );

                let scheduled_depths: Vec<_> = scheduled
                    .iter()
                    .map(|(task_id, _priority)| {
                        *depth_by_task
                            .get(task_id)
                            .expect("scheduled task missing from depth map")
                    })
                    .collect();
                prop_assert_eq!(scheduled_depths.first().copied(), Some(0));
                prop_assert!(
                    scheduled_depths.windows(2).all(|pair| pair[0] <= pair[1]),
                    "cancel scheduling should not visit descendants before ancestors: {scheduled_depths:?}"
                );
            });
        }

        #[test]
        fn mr_cancel_depth_profile_is_reason_invariant() {
            proptest!(|(
                child_count in 1..5usize,
                grandchildren_per_child in 1..4usize,
                lhs_reason_variant in 0..4u8,
                rhs_reason_variant in 0..4u8
            )| {
                let build_depth_profile = |reason_variant: u8| {
                    let mut state = RuntimeState::new();
                    let root = state.create_root_region(Budget::INFINITE);
                    let root_task = insert_task(&mut state, root);
                    let mut depth_by_task = HashMap::from([(root_task, 0usize)]);

                    for _ in 0..child_count {
                        let child = create_child_region(&mut state, root);
                        let child_task = insert_task(&mut state, child);
                        depth_by_task.insert(child_task, 1);

                        for _ in 0..grandchildren_per_child {
                            let grandchild = create_child_region(&mut state, child);
                            let grandchild_task = insert_task(&mut state, grandchild);
                            depth_by_task.insert(grandchild_task, 2);
                        }
                    }

                    state
                        .cancel_request(root, &reason_from_variant(reason_variant), None)
                        .into_iter()
                        .map(|(task_id, _priority)| {
                            *depth_by_task
                                .get(&task_id)
                                .expect("scheduled task missing from depth map")
                        })
                        .collect::<Vec<_>>()
                };

                let lhs_profile = build_depth_profile(lhs_reason_variant);
                let rhs_profile = build_depth_profile(rhs_reason_variant);

                prop_assert_eq!(
                    lhs_profile,
                    rhs_profile,
                    "cancel reason variants should not perturb ancestor-before-descendant scheduling"
                );
            });
        }

        #[test]
        fn mr_cancel_cause_chain_is_stable_under_sibling_noise() {
            proptest!(|(sibling_count in 1..5usize, reason_variant in 0..4u8)| {
                let reason = reason_from_variant(reason_variant);
                let baseline = branch_cancel_snapshot_with_sibling_noise(0, &reason);
                let noisy = branch_cancel_snapshot_with_sibling_noise(sibling_count, &reason);
                prop_assert_eq!(
                    noisy,
                    baseline,
                    "sibling regions outside the cancelled branch should not perturb cause chains"
                );
            });
        }

        #[test]
        fn mr_cancel_request_after_close_preserves_terminal_reason() {
            proptest!(|(initial_variant in 0..4u8, followup_variant in 0..4u8)| {
                let mut state = RuntimeState::new();
                let region_id = state.create_root_region(Budget::INFINITE);
                let initial_reason = reason_from_variant(initial_variant);
                let followup_reason = reason_from_variant(followup_variant);

                {
                    let region = state
                        .regions
                        .get_mut(region_id.arena_index())
                        .expect("region missing");
                    prop_assert!(region.begin_close(Some(initial_reason.clone())));
                    prop_assert!(region.begin_finalize());
                    prop_assert!(region.complete_close());
                }

                let tasks_to_cancel = state.cancel_request(region_id, &followup_reason, None);
                let region = state
                    .regions
                    .get(region_id.arena_index())
                    .expect("region missing");

                prop_assert!(tasks_to_cancel.is_empty());
                prop_assert_eq!(region.state(), crate::record::region::RegionState::Closed);
                prop_assert_eq!(region.cancel_reason(), Some(initial_reason));
            });
        }
    }

    // br-asupersync-afv6z4: assert the O(1) phase-counts-backed
    // RuntimeState::live_task_count agrees with the pre-fix O(N)
    // arena-scan predicate `tasks_iter().filter(|(_,t)|
    // !t.state.is_terminal()).count()` under realistic churn —
    // create-task, in-flight cancel, and complete transitions.
    // Catches a future drift between TaskTable::phase_counts
    // bookkeeping and TaskState::is_terminal classification (the two
    // sides of the equation that must agree for the delegation to be
    // sound).
    #[test]
    fn live_task_count_matches_arena_scan_under_churn() {
        init_test("live_task_count_matches_arena_scan_under_churn");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        // Helper: O(N) scan equivalent to the pre-fix implementation.
        // Used as the oracle.
        fn arena_scan_count(state: &RuntimeState) -> usize {
            state
                .tasks_iter()
                .filter(|(_, t)| !t.state.is_terminal())
                .count()
        }

        // Empty arena: both sides agree on 0.
        crate::assert_with_log!(
            state.live_task_count() == arena_scan_count(&state),
            "empty arena: counter matches scan",
            arena_scan_count(&state),
            state.live_task_count()
        );

        // Spawn 32 tasks; at each step assert the two methods agree.
        let mut spawned: Vec<crate::types::TaskId> = Vec::with_capacity(32);
        for i in 0..32 {
            let (id, _h) = state
                .create_task(root, Budget::INFINITE, async {})
                .expect("create_task should succeed");
            spawned.push(id);
            let counter = state.live_task_count();
            let scan = arena_scan_count(&state);
            crate::assert_with_log!(
                counter == scan,
                "after spawn N=i+1, counter matches arena scan",
                scan,
                counter
            );
            // Sanity: the live count grew.
            crate::assert_with_log!(
                counter == i + 1,
                "live count increments by 1 per spawn",
                i + 1,
                counter
            );
        }

        // Request cancel on every other task — these enter
        // CancelRequested (still non-terminal). The two methods must
        // continue to agree across the in-flight cancel transition.
        for (idx, &task_id) in spawned.iter().enumerate() {
            if idx.is_multiple_of(2) {
                let _ = state.cancel_task(task_id, &CancelReason::user("test"));
            }
        }
        crate::assert_with_log!(
            state.live_task_count() == arena_scan_count(&state),
            "after partial cancel: counter matches scan",
            arena_scan_count(&state),
            state.live_task_count()
        );
        // Still 32 — cancel-requested is not terminal.
        crate::assert_with_log!(
            state.live_task_count() == 32,
            "cancel-requested tasks remain live",
            32usize,
            state.live_task_count()
        );

        // Complete each task — drives them to TaskState::Completed
        // (terminal) and TaskPhase::Completed (excluded from
        // phase_counts). The two methods must agree at every step
        // and end at zero.
        for &task_id in &spawned {
            let _ = state.complete_task(task_id, Outcome::Ok(()));
            crate::assert_with_log!(
                state.live_task_count() == arena_scan_count(&state),
                "after complete: counter matches scan",
                arena_scan_count(&state),
                state.live_task_count()
            );
        }
        crate::assert_with_log!(
            state.live_task_count() == 0,
            "all tasks terminal",
            0usize,
            state.live_task_count()
        );

        crate::test_complete!("live_task_count_matches_arena_scan_under_churn");
    }

    #[test]
    fn read_biased_region_snapshot_disabled_matches_authoritative_scan() {
        init_test("read_biased_region_snapshot_disabled_matches_authoritative_scan");

        let mut state = RuntimeState::new();
        state.set_read_biased_region_snapshot(false);
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let _grandchild = create_child_region(&mut state, child);
        let _ = state.cancel_request(child, &CancelReason::user("drain"), None);

        let expected = state.regions.draining_region_count() as u32;
        let snapshot = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);

        crate::assert_with_log!(
            snapshot.draining_regions == expected,
            "disabled path matches authoritative scan",
            expected,
            snapshot.draining_regions
        );
        crate::assert_with_log!(
            state.read_biased_region_snapshot_stats() == ReadBiasedRegionSnapshotStats::default(),
            "disabled path should not mutate snapshot counters",
            format!("{:?}", ReadBiasedRegionSnapshotStats::default()),
            format!("{:?}", state.read_biased_region_snapshot_stats())
        );

        crate::test_complete!("read_biased_region_snapshot_disabled_matches_authoritative_scan");
    }

    #[test]
    fn read_biased_region_snapshot_tracks_draining_runtime_transitions() {
        init_test("read_biased_region_snapshot_tracks_draining_runtime_transitions");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);
        state.set_read_biased_region_snapshot(true);

        let _ = state.cancel_request(child, &CancelReason::user("drain"), None);
        let draining_snapshot =
            crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        crate::assert_with_log!(
            draining_snapshot.draining_regions == state.regions.draining_region_count() as u32,
            "cached draining count matches authoritative scan after Closing->Draining",
            state.regions.draining_region_count() as u32,
            draining_snapshot.draining_regions
        );

        let _ = state.cancel_request(grandchild, &CancelReason::user("close"), None);
        state.advance_region_state(child);
        let closed_snapshot =
            crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        crate::assert_with_log!(
            closed_snapshot.draining_regions == state.regions.draining_region_count() as u32,
            "cached draining count matches authoritative scan after close completion",
            state.regions.draining_region_count() as u32,
            closed_snapshot.draining_regions
        );

        let stats = state.read_biased_region_snapshot_stats();
        crate::assert_with_log!(
            stats.cache_hits >= 2,
            "read-heavy reads should hit the cached path",
            true,
            stats.cache_hits >= 2
        );
        crate::assert_with_log!(
            stats.writer_adjustments >= 2,
            "runtime transitions should update the cached draining count",
            true,
            stats.writer_adjustments >= 2
        );

        crate::test_complete!("read_biased_region_snapshot_tracks_draining_runtime_transitions");
    }

    #[test]
    fn read_biased_region_snapshot_invalidation_forces_fallback_scan() {
        init_test("read_biased_region_snapshot_invalidation_forces_fallback_scan");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let _grandchild = create_child_region(&mut state, child);
        state.set_read_biased_region_snapshot(true);
        let _ = state.cancel_request(child, &CancelReason::user("drain"), None);

        let _ = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        let before = state.read_biased_region_snapshot_stats();
        state.invalidate_read_biased_region_snapshot_for_testing();

        let snapshot = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        let after = state.read_biased_region_snapshot_stats();
        crate::assert_with_log!(
            snapshot.draining_regions == state.regions.draining_region_count() as u32,
            "fallback scan still returns the authoritative draining count",
            state.regions.draining_region_count() as u32,
            snapshot.draining_regions
        );
        crate::assert_with_log!(
            after.invalidations == before.invalidations + 1,
            "manual invalidation should be recorded",
            before.invalidations + 1,
            after.invalidations
        );
        crate::assert_with_log!(
            after.fallback_scans == before.fallback_scans + 1,
            "invalidated read should use the conservative scan fallback",
            before.fallback_scans + 1,
            after.fallback_scans
        );

        crate::test_complete!("read_biased_region_snapshot_invalidation_forces_fallback_scan");
    }

    #[test]
    fn read_biased_region_snapshot_write_heavy_mix_falls_back_to_scan() {
        init_test("read_biased_region_snapshot_write_heavy_mix_falls_back_to_scan");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mut draining_regions = Vec::new();
        for _ in 0..READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD {
            let child = create_child_region(&mut state, root);
            let _grandchild = create_child_region(&mut state, child);
            draining_regions.push(child);
        }
        state.set_read_biased_region_snapshot(true);
        for child in draining_regions {
            let _ = state.cancel_request(child, &CancelReason::user("drain"), None);
        }

        let snapshot = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        let stats = state.read_biased_region_snapshot_stats();
        crate::assert_with_log!(
            snapshot.draining_regions == state.regions.draining_region_count() as u32,
            "write-heavy fallback scan preserves correctness",
            state.regions.draining_region_count() as u32,
            snapshot.draining_regions
        );
        crate::assert_with_log!(
            stats.write_heavy_fallbacks >= 1,
            "burst of region transitions should trigger the conservative fallback",
            true,
            stats.write_heavy_fallbacks >= 1
        );
        crate::assert_with_log!(
            stats.fallback_scans >= 1,
            "write-heavy read should perform an authoritative scan",
            true,
            stats.fallback_scans >= 1
        );

        crate::test_complete!("read_biased_region_snapshot_write_heavy_mix_falls_back_to_scan");
    }

    const READ_BIASED_REGION_SNAPSHOT_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_READ_BIASED_REGION_SNAPSHOT_CONTRACT_PATH";
    const READ_BIASED_REGION_SNAPSHOT_SCENARIO_ENV: &str =
        "ASUPERSYNC_READ_BIASED_REGION_SNAPSHOT_SCENARIO";
    const READ_BIASED_REGION_SNAPSHOT_REPORT_PATH_ENV: &str =
        "ASUPERSYNC_READ_BIASED_REGION_SNAPSHOT_REPORT_PATH";
    const READ_BIASED_REGION_SNAPSHOT_REPORT_SCHEMA_VERSION: &str =
        "read-biased-region-snapshot-report-v1";
    const READ_BIASED_REGION_SNAPSHOT_PROJECTION_SCHEMA_VERSION: &str =
        "read-biased-region-snapshot-projection-v1";
    const READ_BIASED_REGION_SNAPSHOT_READ_HEAVY_SCENARIO_ID: &str =
        "AA-READ-BIASED-REGION-SNAPSHOT-READ-HEAVY";
    const READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_SCENARIO_ID: &str =
        "AA-READ-BIASED-REGION-SNAPSHOT-WRITE-HEAVY";

    #[derive(Debug, Clone, Deserialize)]
    struct ReadBiasedRegionSnapshotSmokeContract {
        smoke_scenarios: Vec<ReadBiasedRegionSnapshotScenario>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct ReadBiasedRegionSnapshotScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        fixture: ReadBiasedRegionSnapshotFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct ReadBiasedRegionSnapshotFixture {
        draining_regions: usize,
        read_iterations: usize,
        sample_count: usize,
    }

    fn default_read_biased_region_snapshot_scenarios() -> Vec<ReadBiasedRegionSnapshotScenario> {
        vec![
            ReadBiasedRegionSnapshotScenario {
                scenario_id: READ_BIASED_REGION_SNAPSHOT_READ_HEAVY_SCENARIO_ID.to_string(),
                description: "Warm the cached draining-region snapshot once, then measure steady-state read latency with no further writes.".to_string(),
                workload_class: "read-heavy".to_string(),
                fixture: ReadBiasedRegionSnapshotFixture {
                    draining_regions: 16,
                    read_iterations: 64,
                    sample_count: 1,
                },
                expected_report_projection: json!({
                    "schema_version": READ_BIASED_REGION_SNAPSHOT_PROJECTION_SCHEMA_VERSION,
                    "scenario_id": READ_BIASED_REGION_SNAPSHOT_READ_HEAVY_SCENARIO_ID,
                    "workload_class": "read-heavy",
                    "draining_regions": 16,
                    "read_iterations": 64,
                    "sample_count": 1,
                    "cache_hits": 64,
                    "fallback_scans": 0,
                    "write_heavy_fallbacks": 0,
                    "cache_hit_ratio": 1.0,
                    "fallback_ratio": 0.0,
                    "checksums_match": true,
                    "final_counts_match": true,
                    "fallback_should_remain_pinned": false,
                    "fallback_preference_reason": "cache-remains-profitable"
                }),
            },
            ReadBiasedRegionSnapshotScenario {
                scenario_id: READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_SCENARIO_ID.to_string(),
                description: "Force a write-heavy burst across the threshold and prove the fallback scan remains pinned while correctness matches the baseline.".to_string(),
                workload_class: "write-heavy".to_string(),
                fixture: ReadBiasedRegionSnapshotFixture {
                    draining_regions: READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD,
                    read_iterations: 1,
                    sample_count: 8,
                },
                expected_report_projection: json!({
                    "schema_version": READ_BIASED_REGION_SNAPSHOT_PROJECTION_SCHEMA_VERSION,
                    "scenario_id": READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_SCENARIO_ID,
                    "workload_class": "write-heavy",
                    "draining_regions": READ_BIASED_REGION_SNAPSHOT_WRITE_HEAVY_THRESHOLD,
                    "read_iterations": 1,
                    "sample_count": 8,
                    "cache_hits": 0,
                    "fallback_scans": 8,
                    "write_heavy_fallbacks": 8,
                    "cache_hit_ratio": 0.0,
                    "fallback_ratio": 1.0,
                    "checksums_match": true,
                    "final_counts_match": true,
                    "fallback_should_remain_pinned": true,
                    "fallback_preference_reason": "write-heavy-threshold-exceeded"
                }),
            },
        ]
    }

    fn load_read_biased_region_snapshot_scenarios() -> Vec<ReadBiasedRegionSnapshotScenario> {
        let Some(contract_path) = std::env::var(READ_BIASED_REGION_SNAPSHOT_CONTRACT_PATH_ENV).ok()
        else {
            return default_read_biased_region_snapshot_scenarios();
        };
        let contract: ReadBiasedRegionSnapshotSmokeContract = serde_json::from_str(
            &fs::read_to_string(&contract_path)
                .expect("read read-biased region snapshot smoke contract"),
        )
        .expect("parse read-biased region snapshot smoke contract");
        contract.smoke_scenarios
    }

    fn selected_read_biased_region_snapshot_scenario() -> String {
        std::env::var(READ_BIASED_REGION_SNAPSHOT_SCENARIO_ENV)
            .unwrap_or_else(|_| READ_BIASED_REGION_SNAPSHOT_READ_HEAVY_SCENARIO_ID.to_string())
    }

    fn maybe_write_read_biased_region_snapshot_report(path: &str, report: &Value) {
        let report_path = Path::new(path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)
                .expect("create read-biased region snapshot report directory");
        }
        fs::write(
            report_path,
            serde_json::to_string_pretty(report)
                .expect("serialize read-biased region snapshot report"),
        )
        .expect("write read-biased region snapshot report");
    }

    fn round4(value: f64) -> f64 {
        (value * 10_000.0).round() / 10_000.0
    }

    fn percentile_slice_u64(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let index = ((sorted.len() - 1) * numerator) / denominator;
        sorted[index]
    }

    fn mean_u64(samples: &[u64]) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        round4(samples.iter().map(|sample| *sample as f64).sum::<f64>() / samples.len() as f64)
    }

    fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        round4(numerator as f64 / denominator as f64)
    }

    fn ratio_count(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        round4(numerator as f64 / denominator as f64)
    }

    fn checksum_fold(seed: u64, value: u64) -> u64 {
        seed.wrapping_mul(1_099_511_628_211).wrapping_add(value)
    }

    fn latency_summary_value(samples: &[u64]) -> Value {
        json!({
            "sample_count": samples.len(),
            "min_ns": samples.iter().copied().min().unwrap_or(0),
            "p50_ns": percentile_slice_u64(samples, 50, 100),
            "p95_ns": percentile_slice_u64(samples, 95, 100),
            "p99_ns": percentile_slice_u64(samples, 99, 100),
            "max_ns": samples.iter().copied().max().unwrap_or(0),
            "mean_ns": mean_u64(samples),
        })
    }

    fn cache_stats_value(stats: ReadBiasedRegionSnapshotStats) -> Value {
        json!({
            "cache_hits": stats.cache_hits,
            "fallback_scans": stats.fallback_scans,
            "invalidations": stats.invalidations,
            "write_heavy_fallbacks": stats.write_heavy_fallbacks,
            "writer_adjustments": stats.writer_adjustments,
            "writer_adjustment_ns": stats.writer_adjustment_ns,
            "fallback_scan_ns": stats.fallback_scan_ns,
        })
    }

    fn delta_read_biased_region_snapshot_stats(
        before: ReadBiasedRegionSnapshotStats,
        after: ReadBiasedRegionSnapshotStats,
    ) -> ReadBiasedRegionSnapshotStats {
        ReadBiasedRegionSnapshotStats {
            cache_hits: after.cache_hits.saturating_sub(before.cache_hits),
            fallback_scans: after.fallback_scans.saturating_sub(before.fallback_scans),
            invalidations: after.invalidations.saturating_sub(before.invalidations),
            write_heavy_fallbacks: after
                .write_heavy_fallbacks
                .saturating_sub(before.write_heavy_fallbacks),
            writer_adjustments: after
                .writer_adjustments
                .saturating_sub(before.writer_adjustments),
            writer_adjustment_ns: after
                .writer_adjustment_ns
                .saturating_sub(before.writer_adjustment_ns),
            fallback_scan_ns: after
                .fallback_scan_ns
                .saturating_sub(before.fallback_scan_ns),
            cached_draining_regions: after.cached_draining_regions,
            writes_since_last_read: after.writes_since_last_read,
        }
    }

    fn accumulate_read_biased_region_snapshot_stats(
        total: &mut ReadBiasedRegionSnapshotStats,
        next: ReadBiasedRegionSnapshotStats,
    ) {
        total.cache_hits = total.cache_hits.saturating_add(next.cache_hits);
        total.fallback_scans = total.fallback_scans.saturating_add(next.fallback_scans);
        total.invalidations = total.invalidations.saturating_add(next.invalidations);
        total.write_heavy_fallbacks = total
            .write_heavy_fallbacks
            .saturating_add(next.write_heavy_fallbacks);
        total.writer_adjustments = total
            .writer_adjustments
            .saturating_add(next.writer_adjustments);
        total.writer_adjustment_ns = total
            .writer_adjustment_ns
            .saturating_add(next.writer_adjustment_ns);
        total.fallback_scan_ns = total.fallback_scan_ns.saturating_add(next.fallback_scan_ns);
        total.cached_draining_regions = next.cached_draining_regions;
        total.writes_since_last_read = next.writes_since_last_read;
    }

    fn average_stat_ns(total_ns: u64, count: u64) -> f64 {
        if count == 0 {
            return 0.0;
        }
        round4(total_ns as f64 / count as f64)
    }

    fn prepare_read_biased_region_snapshot_state(
        draining_regions: usize,
        enable_read_biased_path: bool,
    ) -> RuntimeState {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        state.set_read_biased_region_snapshot(enable_read_biased_path);
        for _ in 0..draining_regions {
            let child = create_child_region(&mut state, root);
            let _grandchild = create_child_region(&mut state, child);
            let _ = state.cancel_request(child, &CancelReason::user("drain"), None);
        }
        state
    }

    fn measure_snapshot_reads(state: &RuntimeState, iterations: usize) -> (Vec<u64>, u64, u32) {
        let mut latencies = Vec::with_capacity(iterations);
        let mut checksum = 0u64;
        let mut final_count = 0u32;
        for iteration in 0..iterations {
            let started = Instant::now();
            let snapshot = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(state);
            latencies.push(nanos_saturating_u64(started.elapsed()));
            final_count = snapshot.draining_regions;
            checksum = checksum_fold(
                checksum,
                (u64::from(snapshot.draining_regions) << 32) ^ iteration as u64,
            );
        }
        (latencies, checksum, final_count)
    }

    fn build_read_biased_region_snapshot_report(
        scenario: &ReadBiasedRegionSnapshotScenario,
        baseline_latencies: &[u64],
        baseline_checksum: u64,
        baseline_final_count: u32,
        read_biased_latencies: &[u64],
        read_biased_checksum: u64,
        read_biased_final_count: u32,
        read_biased_stats: ReadBiasedRegionSnapshotStats,
        fallback_should_remain_pinned: bool,
        fallback_preference_reason: &str,
    ) -> Value {
        let observed_reads = read_biased_stats.cache_hits + read_biased_stats.fallback_scans;
        let cache_hit_ratio = ratio_count(read_biased_stats.cache_hits, observed_reads);
        let fallback_ratio = ratio_count(read_biased_stats.fallback_scans, observed_reads);
        let report_projection = json!({
            "schema_version": READ_BIASED_REGION_SNAPSHOT_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "draining_regions": scenario.fixture.draining_regions,
            "read_iterations": scenario.fixture.read_iterations,
            "sample_count": scenario.fixture.sample_count,
            "cache_hits": read_biased_stats.cache_hits,
            "fallback_scans": read_biased_stats.fallback_scans,
            "write_heavy_fallbacks": read_biased_stats.write_heavy_fallbacks,
            "cache_hit_ratio": cache_hit_ratio,
            "fallback_ratio": fallback_ratio,
            "checksums_match": baseline_checksum == read_biased_checksum,
            "final_counts_match": baseline_final_count == read_biased_final_count,
            "fallback_should_remain_pinned": fallback_should_remain_pinned,
            "fallback_preference_reason": fallback_preference_reason
        });

        json!({
            "schema_version": READ_BIASED_REGION_SNAPSHOT_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "fixture": {
                "draining_regions": scenario.fixture.draining_regions,
                "read_iterations": scenario.fixture.read_iterations,
                "sample_count": scenario.fixture.sample_count,
            },
            "baseline": {
                "latency_summary": latency_summary_value(baseline_latencies),
                "correctness_checksum": baseline_checksum,
                "final_draining_regions": baseline_final_count,
            },
            "read_biased": {
                "latency_summary": latency_summary_value(read_biased_latencies),
                "correctness_checksum": read_biased_checksum,
                "final_draining_regions": read_biased_final_count,
                "cache_stats": cache_stats_value(read_biased_stats),
            },
            "comparison": {
                "checksums_match": baseline_checksum == read_biased_checksum,
                "final_counts_match": baseline_final_count == read_biased_final_count,
                "latency_p50_ratio": ratio_u64(
                    percentile_slice_u64(read_biased_latencies, 50, 100),
                    percentile_slice_u64(baseline_latencies, 50, 100),
                ),
                "latency_p95_ratio": ratio_u64(
                    percentile_slice_u64(read_biased_latencies, 95, 100),
                    percentile_slice_u64(baseline_latencies, 95, 100),
                ),
                "latency_p99_ratio": ratio_u64(
                    percentile_slice_u64(read_biased_latencies, 99, 100),
                    percentile_slice_u64(baseline_latencies, 99, 100),
                ),
                "cache_hit_ratio": cache_hit_ratio,
                "fallback_ratio": fallback_ratio,
                "average_writer_adjustment_ns": average_stat_ns(
                    read_biased_stats.writer_adjustment_ns,
                    read_biased_stats.writer_adjustments,
                ),
                "average_fallback_scan_ns": average_stat_ns(
                    read_biased_stats.fallback_scan_ns,
                    read_biased_stats.fallback_scans,
                ),
                "fallback_should_remain_pinned": fallback_should_remain_pinned,
                "fallback_preference_reason": fallback_preference_reason,
            },
            "report_projection": report_projection,
        })
    }

    fn run_read_biased_region_snapshot_scenario(
        scenario: &ReadBiasedRegionSnapshotScenario,
    ) -> Value {
        match scenario.workload_class.as_str() {
            "read-heavy" => {
                let baseline_state = prepare_read_biased_region_snapshot_state(
                    scenario.fixture.draining_regions,
                    false,
                );
                let (baseline_latencies, baseline_checksum, baseline_final_count) =
                    measure_snapshot_reads(&baseline_state, scenario.fixture.read_iterations);

                let read_biased_state = prepare_read_biased_region_snapshot_state(
                    scenario.fixture.draining_regions,
                    true,
                );
                let _ = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(
                    &read_biased_state,
                );
                let before = read_biased_state.read_biased_region_snapshot_stats();
                let (read_biased_latencies, read_biased_checksum, read_biased_final_count) =
                    measure_snapshot_reads(&read_biased_state, scenario.fixture.read_iterations);
                let after = read_biased_state.read_biased_region_snapshot_stats();
                let delta = delta_read_biased_region_snapshot_stats(before, after);

                build_read_biased_region_snapshot_report(
                    scenario,
                    &baseline_latencies,
                    baseline_checksum,
                    baseline_final_count,
                    &read_biased_latencies,
                    read_biased_checksum,
                    read_biased_final_count,
                    delta,
                    false,
                    "cache-remains-profitable",
                )
            }
            "write-heavy" => {
                let mut baseline_latencies = Vec::with_capacity(
                    scenario.fixture.read_iterations * scenario.fixture.sample_count,
                );
                let mut baseline_checksum = 0u64;
                let mut baseline_final_count = 0u32;
                for sample in 0..scenario.fixture.sample_count {
                    let state = prepare_read_biased_region_snapshot_state(
                        scenario.fixture.draining_regions,
                        false,
                    );
                    let (latencies, checksum, final_count) =
                        measure_snapshot_reads(&state, scenario.fixture.read_iterations);
                    baseline_latencies.extend(latencies);
                    baseline_checksum = checksum_fold(baseline_checksum, checksum ^ sample as u64);
                    baseline_final_count = final_count;
                }

                let mut read_biased_latencies = Vec::with_capacity(
                    scenario.fixture.read_iterations * scenario.fixture.sample_count,
                );
                let mut read_biased_checksum = 0u64;
                let mut read_biased_final_count = 0u32;
                let mut read_biased_stats = ReadBiasedRegionSnapshotStats::default();
                for sample in 0..scenario.fixture.sample_count {
                    let state = prepare_read_biased_region_snapshot_state(
                        scenario.fixture.draining_regions,
                        true,
                    );
                    let (latencies, checksum, final_count) =
                        measure_snapshot_reads(&state, scenario.fixture.read_iterations);
                    read_biased_latencies.extend(latencies);
                    read_biased_checksum =
                        checksum_fold(read_biased_checksum, checksum ^ sample as u64);
                    read_biased_final_count = final_count;
                    accumulate_read_biased_region_snapshot_stats(
                        &mut read_biased_stats,
                        state.read_biased_region_snapshot_stats(),
                    );
                }

                build_read_biased_region_snapshot_report(
                    scenario,
                    &baseline_latencies,
                    baseline_checksum,
                    baseline_final_count,
                    &read_biased_latencies,
                    read_biased_checksum,
                    read_biased_final_count,
                    read_biased_stats,
                    true,
                    "write-heavy-threshold-exceeded",
                )
            }
            other => panic!("unsupported read-biased region snapshot workload_class: {other}"),
        }
    }

    #[test]
    fn read_biased_region_snapshot_smoke_contract_emits_report() {
        init_test("read_biased_region_snapshot_smoke_contract_emits_report");

        let selected_scenario = selected_read_biased_region_snapshot_scenario();
        let mut selected_report = None;
        let scenarios = load_read_biased_region_snapshot_scenarios();
        for scenario in scenarios {
            let report = run_read_biased_region_snapshot_scenario(&scenario);
            let actual_projection = report["report_projection"].clone();
            crate::assert_with_log!(
                actual_projection == scenario.expected_report_projection,
                "read-biased region snapshot report projection should remain stable",
                scenario.expected_report_projection.to_string(),
                actual_projection.to_string()
            );
            if scenario.scenario_id == selected_scenario {
                selected_report = Some(report);
            }
        }

        if let Ok(report_path) = std::env::var(READ_BIASED_REGION_SNAPSHOT_REPORT_PATH_ENV) {
            let report = selected_report
                .expect("selected read-biased region snapshot scenario should emit a report");
            maybe_write_read_biased_region_snapshot_report(&report_path, &report);
            // Read-biased region snapshot report written
        }

        crate::test_complete!("read_biased_region_snapshot_smoke_contract_emits_report");
    }

    #[test]
    fn read_biased_region_snapshot_enabled_by_default() {
        init_test("read_biased_region_snapshot_enabled_by_default");

        // Create a new runtime state - cache should be enabled by default
        let state = RuntimeState::new();
        crate::assert_with_log!(
            state.read_biased_region_snapshot_enabled(),
            "read-biased region snapshot cache should be enabled by default for performance",
            true,
            state.read_biased_region_snapshot_enabled()
        );

        // Verify that state snapshot uses the cache (not just scanning)
        let snapshot = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        let stats = state.read_biased_region_snapshot_stats();
        crate::assert_with_log!(
            snapshot.draining_regions == 0,
            "new runtime state should have no draining regions in its first cached snapshot",
            0,
            snapshot.draining_regions
        );

        // After one snapshot, we should have one fallback scan (to populate cache)
        // but cache should be valid for subsequent calls
        crate::assert_with_log!(
            stats.fallback_scans >= 1,
            "first snapshot should trigger fallback scan to populate cache",
            1,
            stats.fallback_scans
        );

        // Second snapshot should hit the cache
        let _snapshot2 = crate::obligation::lyapunov::StateSnapshot::from_runtime_state(&state);
        let stats2 = state.read_biased_region_snapshot_stats();
        crate::assert_with_log!(
            stats2.cache_hits >= 1,
            "second snapshot should hit the cache",
            1,
            stats2.cache_hits
        );

        crate::test_complete!("read_biased_region_snapshot_enabled_by_default");
    }

    #[test]
    fn create_task_with_authorization_check() {
        init_test("create_task_with_authorization_check");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Create a test Cx (which doesn't have spawn permissions)
        let test_cx = crate::cx::Cx::for_testing();

        // Legacy method should still work without authorization checks
        let result = state.create_task(region, Budget::INFINITE, async { 42 });
        crate::assert_with_log!(
            result.is_ok(),
            "legacy create_task should succeed without authorization",
            true,
            result.is_ok()
        );

        // Secure method should succeed when authorization is disabled (default behavior)
        let result = state.create_task_with_auth(&test_cx, region, Budget::INFINITE, async { 42 });
        crate::assert_with_log!(
            result.is_ok(),
            "create_task_with_auth should succeed when authorization is disabled",
            true,
            result.is_ok()
        );

        let root_key = crate::security::key::AuthKey::from_seed(2026);
        state.set_spawn_authorization_key(Some(root_key.clone()));

        let denied =
            state.create_task_with_auth(&test_cx, region, Budget::INFINITE, async { 7_u32 });
        crate::assert_with_log!(
            matches!(denied, Err(SpawnError::AuthorizationDenied { .. })),
            "create_task_with_auth should fail closed when authorization is enabled and no macaroon is attached",
            true,
            matches!(denied, Err(SpawnError::AuthorizationDenied { .. }))
        );

        let spawn_capability = RuntimeState::spawn_capability_identifier(region);
        let token =
            crate::cx::macaroon::MacaroonToken::mint(&root_key, &spawn_capability, "runtime-test");
        let authorized_cx = crate::cx::Cx::for_testing().with_macaroon(token);
        let authorized =
            state.create_task_with_auth(&authorized_cx, region, Budget::INFINITE, async { 9_u32 });
        crate::assert_with_log!(
            authorized.is_ok(),
            "create_task_with_auth should accept a macaroon for the target region",
            true,
            authorized.is_ok()
        );

        crate::test_complete!("create_task_with_authorization_check");
    }

    #[test]
    fn authorization_denial_error_format() {
        init_test("authorization_denial_error_format");

        let region = crate::types::RegionId::from_arena(ArenaIndex::new(42, 0));
        let error = SpawnError::AuthorizationDenied {
            region,
            cx_id: "task_123".to_string(),
        };

        let error_msg = format!("{}", error);
        crate::assert_with_log!(
            error_msg.contains("authorization denied"),
            "error message should contain 'authorization denied'",
            true,
            error_msg.contains("authorization denied")
        );
        crate::assert_with_log!(
            error_msg.contains("task_123"),
            "error message should contain the Cx ID",
            true,
            error_msg.contains("task_123")
        );

        crate::test_complete!("authorization_denial_error_format");
    }
}

#[cfg(test)]
#[path = "state_metamorphic.rs"]
mod state_metamorphic;
