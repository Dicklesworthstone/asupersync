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
    task::{CheckpointCancelAck, HandleCancelRoute, TaskState},
};
use crate::runtime::config::{
    LeakEscalation, ObligationLeakResponse, RuntimeCapacityHints, TraceStorageProfile,
};
use crate::runtime::io_driver::{IoDriver, IoDriverHandle};
use crate::runtime::reactor::Reactor;
use crate::runtime::resource_monitor::{
    DegradationLevel, DegradationStatsSnapshot, MonitorConfig, RegionPriority, ResourceMonitor,
};
use crate::runtime::stored_task::{LocalStoredTask, StoredTask};
use crate::runtime::task_handle::JoinError;
use crate::runtime::{BlockingPoolHandle, ObligationTable, RegionTable, TaskTable};
use crate::time::TimerDriverHandle;
use crate::trace::distributed::{LogicalClockMode, LogicalTime};
use crate::trace::event::{TraceData, TraceEventKind};
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{debug, debug_span, trace};
use crate::types::policy::PolicyAction;
use crate::types::task_context::{
    CancelWakeEffects, CancelWaker, CancellationEffects, CxInner, MAX_MASK_DEPTH,
};
use crate::types::{
    Budget, CancelAttributionConfig, CancelKind, CancelReason, CapabilityBudget,
    CapabilityBudgetRequirements, ObligationId, Outcome, RegionId, TaskId, Time,
    id::{next_bootstrap_region_id, next_bootstrap_task_id},
};
use crate::util::{Arena, ArenaIndex, DetEntropy, EntropySource, OsEntropy};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::backtrace::Backtrace;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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

/// One-shot accounting token for a finalizer handed to an external driver.
///
/// The driver must execute or otherwise retire the associated [`Finalizer`],
/// then pass this receipt to
/// [`RuntimeState::complete_manual_finalizer`] or
/// [`RuntimeState::abandon_manual_finalizer`]. Dropping an unsettled receipt is
/// fail-closed: the owning region remains in `Finalizing`, and no lower
/// finalizer can be handed out.
#[derive(Debug)]
#[must_use = "an externally driven finalizer must be completed or abandoned"]
pub struct ManualFinalizerReceipt {
    runtime_instance_id: u64,
    region_id: RegionId,
    finalizer_id: u64,
    settled: bool,
}

impl ManualFinalizerReceipt {
    /// Returns the region that owns the externally driven finalizer.
    #[must_use]
    pub const fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Returns the runtime-local identifier of the externally driven finalizer.
    #[must_use]
    pub const fn finalizer_id(&self) -> u64 {
        self.finalizer_id
    }

    /// Returns whether this receipt has already been completed or abandoned.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled
    }
}

/// Failure returned while settling a [`ManualFinalizerReceipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualFinalizerReceiptError {
    /// The receipt was already completed or abandoned.
    AlreadySettled,
    /// The receipt belongs to a different [`RuntimeState`] instance.
    WrongRuntime,
    /// The receipt no longer names the region's active manual finalizer.
    NotActive,
}

impl fmt::Display for ManualFinalizerReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySettled => f.write_str("manual finalizer receipt is already settled"),
            Self::WrongRuntime => {
                f.write_str("manual finalizer receipt belongs to a different runtime")
            }
            Self::NotActive => {
                f.write_str("manual finalizer receipt is not the active receipt for its region")
            }
        }
    }
}

impl std::error::Error for ManualFinalizerReceiptError {}

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

/// Owned direct-observer effects produced by task completion.
///
/// The task cleanup and waiter extraction are complete before this value is
/// returned. Callers must publish callback-free waiter/finalizer queue work,
/// release any runtime-state lock, and commit any execution guard before
/// dispatching the observer token. A legacy foreign-waker callback may run
/// afterward as a separate, uncontained boundary. This abstraction defers only
/// the `MetricsProvider::task_completed` callback and the completion
/// debug/unknown trace emitted directly by [`RuntimeState::task_completed`]. It
/// also carries detached cancellation-Waker targets across the outer lock;
/// it does not make transitive obligation cleanup, region advancement,
/// finalizers, foreign wakers, or unrelated destructors callback-free.
#[must_use = "task completion effects must wake waiters and dispatch observers"]
pub struct TaskCompletionEffects {
    waiters: SmallVec<[TaskId; 4]>,
    observer: TaskCompletionObserver,
    retired_cancel_wakers: TaskCompletionRetirements,
}

impl TaskCompletionEffects {
    fn unknown(task_id: TaskId, panic_count: &Arc<AtomicU64>) -> Self {
        Self {
            waiters: SmallVec::new(),
            observer: TaskCompletionObserver::unknown(task_id, panic_count),
            retired_cancel_wakers: TaskCompletionRetirements::empty(),
        }
    }

    /// Splits waiter work from the opaque one-shot observer token.
    ///
    /// Callback-free waiter/finalizer queue work must be published, any
    /// runtime-state lock released, and any execution guard committed before
    /// [`TaskCompletionObserver::dispatch`] is called. A legacy foreign-waker
    /// callback may follow dispatch as a separate, uncontained boundary.
    #[must_use]
    pub fn into_parts(self) -> (SmallVec<[TaskId; 4]>, TaskCompletionObserver) {
        let Self {
            waiters,
            mut observer,
            retired_cancel_wakers,
        } = self;
        observer.retired_cancel_wakers = retired_cancel_wakers;
        (waiters, observer)
    }

    /// Extracts waiter ids while deliberately suppressing observer delivery.
    ///
    /// This is reserved for panic-unwind cleanup guards or failed-start paths
    /// that cannot release a caller-owned outer lock: those contexts must never
    /// invoke user metrics providers or tracing subscribers. Suppression emits
    /// no direct completion metric or completion debug/unknown trace and does
    /// not increment the observer-panic counter because dispatch was never
    /// attempted. The undispatched observer payload, including any final
    /// metrics-provider handle, and detached cancellation-Waker targets are
    /// deliberately leaked on this exceptional path because the caller may
    /// still own an outer runtime-state lock. Ordinary delivery uses
    /// [`Self::into_parts`]; unwind paths that can later retire detached
    /// cancellation Wakers use
    /// [`Self::into_waiters_and_retirements_without_observers`].
    pub(crate) fn into_waiters_without_observers(self) -> SmallVec<[TaskId; 4]> {
        let Self {
            waiters,
            observer: _,
            retired_cancel_wakers,
        } = self;
        // This suppression path may still be running beneath a caller-owned
        // runtime-state lock. Abandoning the token intentionally leaks its
        // opaque observer payload, while dropping the retirement token leaks
        // detached wake targets rather than invoking RawWaker destructors.
        drop(retired_cancel_wakers);
        waiters
    }

    /// Splits callback-free waiters from cancellation-Waker retirement for a
    /// panic/unwind path that still owns an outer runtime-state lock. The
    /// undispatched observer payload is leaked; the caller must retire the
    /// returned cancellation Wakers only after releasing that lock.
    pub(crate) fn into_waiters_and_retirements_without_observers(
        self,
    ) -> (SmallVec<[TaskId; 4]>, TaskCompletionRetirements) {
        let Self {
            waiters,
            observer: _,
            retired_cancel_wakers,
        } = self;
        (waiters, retired_cancel_wakers)
    }
}

/// Cancellation-Waker payloads detached during task completion.
///
/// Call [`Self::retire`] only after releasing every outer runtime-state lock.
#[must_use = "cancellation Wakers must be retired after releasing runtime-state locks"]
pub(crate) struct TaskCompletionRetirements {
    targets: Option<SmallVec<[Arc<CancelWaker>; 4]>>,
}

impl TaskCompletionRetirements {
    fn empty() -> Self {
        Self {
            targets: Some(SmallVec::new()),
        }
    }

    fn new(targets: SmallVec<[Arc<CancelWaker>; 4]>) -> Self {
        Self {
            targets: Some(targets),
        }
    }

    pub(crate) fn retire(mut self) {
        let mut targets = self.targets.take().unwrap_or_default();
        while let Some(target) = targets.pop() {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(target);
            })) {
                // This boundary is commonly reached during task-panic cleanup.
                // Do not let a hostile RawWaker destructor trigger a double
                // panic; leak only its already-failed panic payload.
                std::mem::forget(payload);
            }
        }
    }
}

impl Drop for TaskCompletionRetirements {
    fn drop(&mut self) {
        let Some(targets) = self.targets.take() else {
            return;
        };
        // Abandonment can occur while an outer runtime-state lock is live or
        // during panic unwind. Leaking these already-detached handles is the
        // fail-closed alternative to arbitrary RawWaker destruction there.
        for target in targets {
            std::mem::forget(target);
        }
    }
}

/// Opaque one-shot token for the direct task-completion observer callbacks.
///
/// Dispatch consumes the token, so a given completion observation cannot be
/// attempted more than once through this API. Abandoning the token may happen
/// beneath a caller-owned outer runtime-state lock, so its [`Drop`]
/// implementation deliberately leaks an undispatched payload rather than
/// running an arbitrary metrics-provider destructor there.
#[must_use = "task completion observers must be dispatched after waiter publication"]
pub struct TaskCompletionObserver {
    payload: Option<TaskCompletionObserverPayload>,
    panic_count: Option<Arc<AtomicU64>>,
    retired_cancel_wakers: TaskCompletionRetirements,
    epoch_telemetry: Option<super::epoch_tracker::EpochTelemetryDispatch>,
}

enum TaskCompletionObserverPayload {
    Completed {
        metrics: Arc<dyn MetricsProvider>,
        task_id: TaskId,
        region_id: RegionId,
        outcome_kind: OutcomeKind,
        outcome_label: &'static str,
        duration: Duration,
        waiter_count: usize,
    },
    UnknownTask {
        task_id: TaskId,
    },
}

impl TaskCompletionObserver {
    fn completed(
        metrics: Arc<dyn MetricsProvider>,
        task_id: TaskId,
        region_id: RegionId,
        outcome_kind: OutcomeKind,
        outcome_label: &'static str,
        duration: Duration,
        waiter_count: usize,
        panic_count: &Arc<AtomicU64>,
    ) -> Self {
        Self {
            payload: Some(TaskCompletionObserverPayload::Completed {
                metrics,
                task_id,
                region_id,
                outcome_kind,
                outcome_label,
                duration,
                waiter_count,
            }),
            panic_count: Some(Arc::clone(panic_count)),
            retired_cancel_wakers: TaskCompletionRetirements::empty(),
            epoch_telemetry: None,
        }
    }

    fn unknown(task_id: TaskId, panic_count: &Arc<AtomicU64>) -> Self {
        Self {
            payload: Some(TaskCompletionObserverPayload::UnknownTask { task_id }),
            panic_count: Some(Arc::clone(panic_count)),
            retired_cancel_wakers: TaskCompletionRetirements::empty(),
            epoch_telemetry: None,
        }
    }

    fn attach_epoch_telemetry(&mut self, telemetry: super::epoch_tracker::EpochTelemetryDispatch) {
        if !telemetry.is_empty() {
            debug_assert!(self.epoch_telemetry.is_none());
            self.epoch_telemetry = Some(telemetry);
        }
    }

    /// Runs observer delivery and final metrics-provider retirement behind
    /// separate unwind boundaries. If the metrics callback panics, tracing is
    /// intentionally skipped rather than retrying either callback and risking
    /// duplicate completion reports. Separating retirement prevents a hostile
    /// provider destructor from double-panicking during callback unwind. Any
    /// caught panic increments this runtime's callback-free atomic failure
    /// counter once for this dispatch without invoking another observer.
    pub fn dispatch(mut self) {
        let Some(panic_count) = self.panic_count.take() else {
            return;
        };
        let Some(payload) = self.payload.take() else {
            return;
        };
        let retired_cancel_wakers = std::mem::replace(
            &mut self.retired_cancel_wakers,
            TaskCompletionRetirements::empty(),
        );
        // The caller has released runtime-state locks before observer dispatch.
        // Retire arbitrary RawWaker payloads at this callback boundary.
        retired_cancel_wakers.retire();
        if let Some(epoch_telemetry) = self.epoch_telemetry.take() {
            epoch_telemetry.dispatch();
        }
        let observer_panicked = match payload {
            TaskCompletionObserverPayload::Completed {
                metrics,
                task_id,
                region_id,
                outcome_kind,
                outcome_label,
                duration,
                waiter_count,
            } => {
                let callback_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        metrics.task_completed(task_id, outcome_kind, duration);
                        #[cfg(not(feature = "tracing-integration"))]
                        let _ = (region_id, outcome_label, waiter_count);
                        debug!(
                            task_id = ?task_id,
                            region_id = ?region_id,
                            outcome_kind = outcome_label,
                            waiter_count,
                            "task cleanup from runtime state"
                        );
                    }));
                let callback_panicked = if let Err(payload) = callback_result {
                    // A panic payload is arbitrary user-owned data. Its
                    // destructor can panic too, so leak exactly this payload.
                    std::mem::forget(payload);
                    true
                } else {
                    false
                };
                let retirement_panicked = if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(metrics)))
                {
                    // Provider destruction is an independent hostile
                    // boundary after callback unwind has been contained.
                    std::mem::forget(payload);
                    true
                } else {
                    false
                };
                callback_panicked || retirement_panicked
            }
            TaskCompletionObserverPayload::UnknownTask { task_id } => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #[cfg(not(feature = "tracing-integration"))]
                    let _ = task_id;
                    trace!(
                        task_id = ?task_id,
                        "task_completed called for unknown task"
                    );
                }));
                if let Err(payload) = result {
                    std::mem::forget(payload);
                    true
                } else {
                    false
                }
            }
        };
        if observer_panicked {
            panic_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for TaskCompletionObserver {
    fn drop(&mut self) {
        let Some(payload) = self.payload.take() else {
            return;
        };
        // Suppression and unwind guards may abandon this token while an outer
        // runtime-state lock is still live. A completed payload can own the
        // final Arc to an arbitrary metrics provider, whose destructor may
        // re-enter that same lock or panic. Leak only the undispatched payload;
        // normal `dispatch` takes it first and retires it outside the lock.
        std::mem::forget(payload);
    }
}

/// Origin of a task-spawn observation.
///
/// This is deliberately narrower than a public spawn taxonomy. It only
/// selects the diagnostic fields and whether admission also emits the
/// mailbox/local `TaskAdmitted` trace event.
#[derive(Clone, Copy)]
pub(crate) enum TaskSpawnSource {
    Direct,
    Scope,
    Mailbox,
    Local,
}

impl TaskSpawnSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Scope => "scope",
            Self::Mailbox => "mailbox",
            Self::Local => "local",
        }
    }

    const fn emits_admitted_trace(self) -> bool {
        matches!(self, Self::Mailbox | Self::Local)
    }
}

/// Owned one-shot task-spawn observer effects.
///
/// Creation and admission paths build this token while runtime state is
/// locked, but must not dispatch it until the stored task and its executable
/// lane are visible. Dispatch consumes the token, contains metrics/tracing
/// panics, and retires the arbitrary metrics provider behind a separate unwind
/// boundary. Legacy state-threaded paths that own no scheduler lane may place
/// the token at the front of the stored future so first poll becomes the
/// out-of-lock delivery boundary.
#[must_use = "task spawn effects must be dispatched after executable publication"]
pub struct TaskSpawnEffects {
    payload: Option<TaskSpawnEffectsPayload>,
    panic_count: Option<Arc<AtomicU64>>,
    epoch_telemetry: Option<super::epoch_tracker::EpochTelemetryDispatch>,
}

struct TaskSpawnEffectsPayload {
    metrics: Arc<dyn MetricsProvider>,
    trace: TraceBufferHandle,
    task_id: TaskId,
    region_id: RegionId,
    spawned_at: Time,
    logical_time: Option<LogicalTime>,
    budget: Budget,
    source: TaskSpawnSource,
}

impl TaskSpawnEffects {
    fn new(
        metrics: Arc<dyn MetricsProvider>,
        trace: TraceBufferHandle,
        task_id: TaskId,
        region_id: RegionId,
        spawned_at: Time,
        logical_time: Option<LogicalTime>,
        budget: Budget,
        source: TaskSpawnSource,
        panic_count: &Arc<AtomicU64>,
    ) -> Self {
        Self {
            payload: Some(TaskSpawnEffectsPayload {
                metrics,
                trace,
                task_id,
                region_id,
                spawned_at,
                logical_time,
                budget,
                source,
            }),
            panic_count: Some(Arc::clone(panic_count)),
            epoch_telemetry: None,
        }
    }

    fn attach_epoch_telemetry(&mut self, telemetry: super::epoch_tracker::EpochTelemetryDispatch) {
        if !telemetry.is_empty() {
            debug_assert!(self.epoch_telemetry.is_none());
            self.epoch_telemetry = Some(telemetry);
        }
    }

    /// Delivers the spawn trace/metric/diagnostic once, outside runtime locks.
    ///
    /// The trace and metric preserve their historical order. Mailbox and local
    /// admissions then emit `TaskAdmitted`; the publication diagnostic follows
    /// last.
    /// A panic skips the remaining callbacks rather than retrying and risking
    /// duplicate spawn observations.
    pub fn dispatch(mut self) {
        let Some(panic_count) = self.panic_count.take() else {
            return;
        };
        let Some(payload) = self.payload.take() else {
            return;
        };
        let TaskSpawnEffectsPayload {
            metrics,
            trace,
            task_id,
            region_id,
            spawned_at,
            logical_time,
            budget,
            source,
        } = payload;

        if let Some(epoch_telemetry) = self.epoch_telemetry.take() {
            epoch_telemetry.dispatch();
        }

        let callback_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trace.record_event(|seq| {
                let event = TraceEvent::spawn(seq, spawned_at, task_id, region_id);
                match logical_time.clone() {
                    Some(logical_time) => event.with_logical_time(logical_time),
                    None => event,
                }
            });
            metrics.task_spawned(region_id, task_id);
            if source.emits_admitted_trace() {
                trace.record_event(|seq| {
                    let event = TraceEvent::task_admitted(seq, spawned_at, task_id, region_id);
                    match logical_time {
                        Some(logical_time) => event.with_logical_time(logical_time),
                        None => event,
                    }
                });
            }

            let _span = debug_span!(
                "task_spawn",
                task_id = ?task_id,
                region_id = ?region_id,
                initial_state = "Created",
                budget_deadline = ?budget.deadline,
                budget_poll_quota = budget.poll_quota,
                budget_cost_quota = ?budget.cost_quota,
                budget_priority = budget.priority,
                budget_source = source.as_str(),
            )
            .entered();
            debug!(
                task_id = ?task_id,
                region_id = ?region_id,
                initial_state = "Created",
                poll_quota = budget.poll_quota,
                budget_source = source.as_str(),
                "task published for execution"
            );
            let _ = (budget, source.as_str());
        }));
        let callback_panicked = if let Err(payload) = callback_result {
            // Panic payload destruction is an arbitrary user boundary too.
            std::mem::forget(payload);
            true
        } else {
            false
        };
        let retirement_panicked = if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(metrics)))
        {
            std::mem::forget(payload);
            true
        } else {
            false
        };
        if callback_panicked || retirement_panicked {
            panic_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for TaskSpawnEffects {
    fn drop(&mut self) {
        let Some(payload) = self.payload.take() else {
            return;
        };
        // Abandonment can occur beneath a caller-owned runtime-state lock or
        // during unwind. The payload may own the final Arc to an arbitrary
        // metrics provider, so leak only this undispatched observer payload.
        std::mem::forget(payload);
    }
}

/// Outcome of [`RuntimeState::admit_spawn_request`].
///
/// Not `Debug`: the denied arm carries the request parts, whose erased
/// future and completion slots are opaque.
pub enum SpawnAdmission {
    /// The request was admitted; after releasing the state lock, the caller
    /// must publish the task's callback-free runnable lane through
    /// `cancel_publication`, then dispatch the returned Wakers.
    Admitted {
        /// Canonical arena task id (replaces the provisional mailbox id).
        task_id: TaskId,
        /// Scheduling priority from the request budget.
        priority: u8,
        /// One-shot abort handoff. Its publication closure selects and
        /// publishes the ready or cancel lane under the admission gate; the
        /// returned Wakers run only after scheduler locks are released.
        cancel_publication: crate::runtime::spawn_mailbox::AdmissionPublication,
        /// One-shot spawn observer delivery, dispatched only after the task's
        /// runnable lane has been physically published.
        spawn_effects: TaskSpawnEffects,
    },
    /// The request was denied; the caller must resolve it after releasing
    /// the state lock (`resolve_cancelled` for `RegionClosed`/`RegionNotFound`,
    /// `resolve_failed` otherwise).
    Denied {
        /// The unresolved request parts (slots + credit intact).
        parts: crate::runtime::spawn_mailbox::SpawnRequestParts,
        /// Why admission refused.
        error: SpawnError,
    },
}

/// Outcome of [`RuntimeState::admit_local_spawn_request`]
/// (br-asupersync-i9y5wb / A2.2a).
///
/// Mirrors [`SpawnAdmission`] for the owner-pinned local lane; the
/// admitted arm carries the built [`LocalStoredTask`] because local tasks
/// are stored thread-locally by the calling worker, not centrally.
pub enum LocalSpawnAdmission {
    /// Admitted; after releasing the state lock, the calling worker must store
    /// the task in its thread-local slot and publish its callback-free ready or
    /// cancel lane through `cancel_publication`. Admission has already pinned
    /// the task record to the owner worker.
    Admitted {
        /// Canonical arena task id (replaces the provisional mailbox id).
        task_id: TaskId,
        /// Scheduling priority from the request budget.
        priority: u8,
        /// The local task, ready for thread-local storage.
        stored: LocalStoredTask,
        /// One-shot abort handoff. The caller must first store the local task,
        /// then publish its callback-free runnable lane through this token and
        /// dispatch the returned Wakers after releasing scheduler locks.
        cancel_publication: crate::runtime::spawn_mailbox::AdmissionPublication,
        /// One-shot spawn observer delivery, dispatched only after thread-local
        /// storage and the owner-local runnable lane are both visible.
        spawn_effects: TaskSpawnEffects,
    },
    /// Denied; the caller must resolve the request after releasing the
    /// state lock (`resolve_cancelled` for `RegionClosed`/`RegionNotFound`,
    /// `resolve_failed` otherwise).
    Denied {
        /// The unresolved request (slots + credit intact).
        request: crate::runtime::spawn_mailbox::LocalSpawnRequest,
        /// Why admission refused.
        error: SpawnError,
    },
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
    /// The one-shot canonical-identity slot was already reserved by another
    /// spawn request.
    AdmissionSlotAlreadyReserved {
        /// Provisional mailbox identity of the rejected request.
        task_id: TaskId,
    },
}

impl SpawnError {
    /// Returns the stable machine-readable error code for this variant.
    ///
    /// Codes are allocated from the `ASUP-E00x` range (core runtime spawn
    /// errors) of the asupersync error-code registry and are stable across
    /// releases: agents and tooling may match on them. The same code is
    /// embedded as the leading `[ASUP-ENNN]` token of the [`Display`]
    /// rendering.
    ///
    /// [`Display`]: std::fmt::Display
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RuntimeUnavailable => "ASUP-E001",
            Self::RegionNotFound(_) => "ASUP-E002",
            Self::RegionClosed(_) => "ASUP-E003",
            Self::LocalSchedulerUnavailable => "ASUP-E004",
            Self::NameRegistrationFailed { .. } => "ASUP-E005",
            Self::RegionAtCapacity { .. } => "ASUP-E006",
            Self::AuthorizationDenied { .. } => "ASUP-E007",
            Self::AdmissionSlotAlreadyReserved { .. } => "ASUP-E008",
        }
    }
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeUnavailable => write!(
                f,
                "[ASUP-E001] runtime is no longer available — the runtime behind this \
                 handle was dropped or shut down; spawn before shutdown begins, or hold \
                 a strong runtime reference for the spawner's lifetime"
            ),
            Self::RegionNotFound(id) => write!(
                f,
                "[ASUP-E002] region not found: {id:?} — the region id is stale (its \
                 region already closed); spawn into a live ancestor or re-check the \
                 handle that produced this id"
            ),
            Self::RegionClosed(id) => write!(
                f,
                "[ASUP-E003] region closed: {id:?} — the target region is closing or \
                 closed and admits no new tasks; spawn into a live region, or treat \
                 this as the normal spawn-vs-shutdown race and stop spawning"
            ),
            Self::LocalSchedulerUnavailable => write!(
                f,
                "[ASUP-E004] local spawn requires an active worker scheduler — \
                 spawn_local only works from a worker thread; use spawn for Send \
                 tasks or move this call inside runtime worker context"
            ),
            Self::NameRegistrationFailed { name, reason } => write!(
                f,
                "[ASUP-E005] name registration failed: name={name} reason={reason} — \
                 the service name is already leased or invalid; pick a unique name or \
                 release/await the existing lease first"
            ),
            Self::RegionAtCapacity {
                region,
                limit,
                live,
            } => write!(
                f,
                "[ASUP-E006] region admission limit reached: region={region:?} \
                 limit={limit} live={live} — back-pressure point: await task \
                 completions before spawning more, or raise the region's admission \
                 limit if the capacity was misconfigured"
            ),
            Self::AuthorizationDenied { region, cx_id } => write!(
                f,
                "[ASUP-E007] authorization denied: caller lacks permission to create \
                 tasks in region {region:?} (cx={cx_id}) — the capability context was \
                 narrowed without spawn rights; pass a Cx with HasSpawn for this \
                 region, or spawn via the owning scope instead"
            ),
            Self::AdmissionSlotAlreadyReserved { task_id } => write!(
                f,
                "[ASUP-E008] admission identity slot already reserved: task={task_id:?} — \
                 each spawn request requires a fresh AdmittedTaskSlot; create the slot \
                 alongside its TaskHandle and never reuse it for another request"
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
    /// Callback-free count of panics caught while dispatching the direct
    /// task-completion metrics/trace observer token.
    task_completion_observer_panics: Arc<AtomicU64>,
    /// Callback-free count of panics caught while dispatching a one-shot task
    /// spawn metrics/trace observer token.
    task_spawn_observer_panics: Arc<AtomicU64>,
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
    /// Producer-side spawn gateway, cloned into every Cx at build time
    /// (br-asupersync-hwjqyo / A2.2).
    spawn_gateway: Option<std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    /// Cancellation effects produced by mutation paths that cannot return a
    /// value, principally `RegionRunner::drop`. The state-lock owner must take
    /// these batches, publish their task ids, and dispatch their Wakers only
    /// after releasing the outer lock.
    pending_cancel_dispatches: Vec<CancellationEffects<Vec<(TaskId, u8)>>>,
    /// Lock-free scheduler hint that avoids taking the state lock when the
    /// deferred cancellation queue is empty.
    pending_cancel_dispatch_ready: Arc<AtomicBool>,
    /// Concrete scheduler wake target for deferred cancellation work.
    ///
    /// This is deliberately a `WorkerCoordinator`, not an arbitrary callback:
    /// `defer_cancel_dispatch` may run beneath an outer runtime-state lock and
    /// may only publish a Parker permit there. Reactor wakeups and user code
    /// remain outside this notification boundary.
    pending_cancel_dispatch_coordinator:
        Option<std::sync::Weak<crate::runtime::scheduler::three_lane::WorkerCoordinator>>,
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
    /// Regions whose top finalizer is currently owned by an external driver.
    ///
    /// The runtime-local finalizer id is the one-shot receipt identity. A
    /// region remains here until the driver explicitly completes or abandons
    /// the receipt; dropping the receipt therefore fails closed.
    active_manual_finalizers: HashMap<RegionId, u64>,
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
    ///
    /// This is a `BTreeSet`, not a `HashSet`, on purpose (GH#55): the deferred
    /// regions are drained and advanced in iteration order, and
    /// `advance_region_state` closes regions and walks the parent chain, waking
    /// and cancelling tasks as it goes. Draining a hash set would apply those
    /// advancements in ambient-hash-seed order, making lab replay diverge
    /// between runs with the same `LabConfig::seed`. Ordering by `RegionId`
    /// keeps the drain deterministic by construction rather than by remembering
    /// to sort at each use site.
    deferred_region_advancements: BTreeSet<RegionId>,
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
            .field(
                "task_completion_observer_panics",
                &self.task_completion_observer_panics.load(Ordering::Relaxed),
            )
            .field(
                "task_spawn_observer_panics",
                &self.task_spawn_observer_panics.load(Ordering::Relaxed),
            )
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
            .field(
                "pending_cancel_dispatches",
                &self.pending_cancel_dispatches.len(),
            )
            .field(
                "has_pending_cancel_dispatch_coordinator",
                &self.pending_cancel_dispatch_coordinator.is_some(),
            )
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
            .field(
                "active_manual_finalizers",
                &self.active_manual_finalizers.len(),
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
            task_completion_observer_panics: Arc::new(AtomicU64::new(0)),
            task_spawn_observer_panics: Arc::new(AtomicU64::new(0)),
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            spawn_authorization_key: None,
            observability: None,
            blocking_pool: None,
            spawn_gateway: None,
            pending_cancel_dispatches: Vec::new(),
            pending_cancel_dispatch_ready: Arc::new(AtomicBool::new(false)),
            pending_cancel_dispatch_coordinator: None,
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
            active_manual_finalizers: HashMap::new(),
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
            deferred_region_advancements: BTreeSet::new(),
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

    /// Returns the producer-side spawn gateway, if installed
    /// (br-asupersync-hwjqyo / A2.2).
    #[inline]
    #[must_use]
    pub(crate) fn spawn_gateway(
        &self,
    ) -> Option<std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>> {
        self.spawn_gateway.clone()
    }

    /// Installs the producer-side spawn gateway. Cloned into every `Cx`
    /// built after this point so `Cx::spawn` works without the state lock.
    pub(crate) fn set_spawn_gateway(
        &mut self,
        gateway: std::sync::Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
    ) {
        self.spawn_gateway = Some(gateway);
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
        validator.validate_task_transition_without_logging(task_id, event, context)
    }

    fn validate_live_task_protocol_transition(
        &self,
        task_id: TaskId,
        event: TaskEvent,
        operation: &'static str,
    ) {
        if let Some(validation_result) = self.live_task_protocol_violation(task_id, event) {
            log_cancel_protocol_violation(operation, &validation_result);
        }
    }

    fn live_task_protocol_violation(
        &self,
        task_id: TaskId,
        event: TaskEvent,
    ) -> Option<TransitionResult> {
        let Some(task) = self.task(task_id) else {
            return None;
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
            Some(validation_result)
        } else {
            None
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

    /// Returns the number of direct task-completion observer dispatches whose
    /// metrics callback, final provider destructor, or tracing subscriber
    /// panicked.
    ///
    /// The counter is updated atomically without invoking another callback, so
    /// it remains safe on the observer-panic path.
    #[inline]
    #[must_use]
    pub fn task_completion_observer_panic_count(&self) -> u64 {
        self.task_completion_observer_panics.load(Ordering::Relaxed)
    }

    /// Returns the number of task-spawn observer dispatches whose metrics
    /// callback, tracing callback, or final provider destructor panicked.
    ///
    /// The counter is atomic and callback-free, so a hostile observer cannot
    /// recursively trigger another observation while this value is updated.
    #[inline]
    #[must_use]
    pub fn task_spawn_observer_panic_count(&self) -> u64 {
        self.task_spawn_observer_panics.load(Ordering::Relaxed)
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

    /// Records the protocol request event for a cancellation first observed
    /// and acknowledged inside a task poll.
    ///
    /// The receipt contains plain state/reason data. An invalid transition is
    /// returned as a preformatted closed value so the caller can enqueue its
    /// tracing diagnostic with the cancellation effects and release every
    /// task-table/runtime-state lock before subscriber dispatch.
    pub(crate) fn checkpoint_cancel_materialization_violation(
        &self,
        task_id: TaskId,
        receipt: &CheckpointCancelAck,
    ) -> Option<String> {
        if !receipt.newly_materialized() {
            return None;
        }
        let context = TaskContext {
            task_id,
            region_id: receipt.region_id,
            spawned_at: receipt.spawned_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result =
            self.validate_task_protocol_transition(task_id, TaskEvent::RequestCancel, &context);
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            Some(format!("{validation_result:?}"))
        } else {
            None
        }
    }

    /// Sharded counterpart to checkpoint validation with an explicit proof
    /// that terminal retirement may already have overtaken the copied receipt.
    pub(crate) fn external_checkpoint_cancel_materialization_violation(
        &self,
        task_id: TaskId,
        receipt: &CheckpointCancelAck,
        allow_retired_noop: bool,
    ) -> Option<String> {
        if !receipt.newly_materialized() {
            return None;
        }
        let context = TaskContext {
            task_id,
            region_id: receipt.region_id,
            spawned_at: receipt.spawned_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result = {
            let mut validator = self.cancel_protocol_validator.lock();
            if allow_retired_noop && validator.task_state(task_id).is_none() {
                return None;
            }
            validator.validate_task_transition_without_logging(
                task_id,
                TaskEvent::RequestCancel,
                &context,
            )
        };
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            Some(format!("{validation_result:?}"))
        } else {
            None
        }
    }

    /// Records the protocol request event for a handle command applied to an
    /// authoritative TaskRecord owned by an external scheduler shard.
    ///
    /// The shard mutation must finish before this is called. Only copied task
    /// identity data crosses the boundary, and any invalid result is returned
    /// as a closed value for post-lock diagnostic dispatch.
    pub(crate) fn external_handle_cancel_request_violation(
        &self,
        task_id: TaskId,
        region_id: RegionId,
        spawned_at: Time,
        allow_retired_noop: bool,
    ) -> Option<String> {
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result = {
            let mut validator = self.cancel_protocol_validator.lock();
            // External completion validates and removes the task machine in one
            // validator critical section. When the caller proves the record was
            // already detached, a missing machine means completion overtook this
            // copied receipt and synthesized the request before terminal
            // validation. A still-live unregistered fixture remains a violation.
            if allow_retired_noop && validator.task_state(task_id).is_none() {
                return None;
            }
            validator.validate_task_transition_without_logging(
                task_id,
                TaskEvent::RequestCancel,
                &context,
            )
        };
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            Some(format!("{validation_result:?}"))
        } else {
            None
        }
    }

    fn validate_and_retire_external_task_protocol(
        &self,
        task_id: TaskId,
        task_event: TaskEvent,
        context: &TaskContext,
        cancellation_materialized: bool,
    ) {
        let (request_result, completion_result) = {
            let mut validator = self.cancel_protocol_validator.lock();
            let request_result = if cancellation_materialized
                && matches!(
                    validator.task_state(task_id),
                    Some(crate::cancel::protocol_state_machines::TaskState::Running)
                ) {
                Some(validator.validate_task_transition_without_logging(
                    task_id,
                    TaskEvent::RequestCancel,
                    context,
                ))
            } else {
                None
            };
            let completion_result =
                validator.validate_task_transition_without_logging(task_id, task_event, context);
            // Keep terminal validation and retirement indivisible so a delayed
            // external request receipt cannot land between them.
            validator.remove_task(task_id);
            (request_result, completion_result)
        };
        if let Some(result) = request_result
            && matches!(
                result,
                TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
            )
        {
            log_cancel_protocol_violation(
                "external-shard synthesized cancellation request",
                &result,
            );
        }
        if matches!(
            completion_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation("external-shard task completion", &completion_result);
        }
    }

    /// Consumes a task checkpoint acknowledgement through the runtime-owned
    /// task table and records a missing RequestCancel validator event exactly
    /// once when the Cx observation won the race with command delivery.
    pub(crate) fn consume_task_checkpoint_cancel_ack(
        &mut self,
        task_id: TaskId,
    ) -> CancellationEffects<Option<CheckpointCancelAck>> {
        let Some(effects) = self.update_task(task_id, TaskRecord::consume_checkpoint_cancel_ack)
        else {
            return CancellationEffects::ready(None);
        };
        let (receipt, mut wakes) = effects.into_parts();
        if let Some(receipt) = receipt.as_ref()
            && let Some(validation_result) =
                self.checkpoint_cancel_materialization_violation(task_id, receipt)
        {
            wakes.push_cancel_protocol_violation(
                "checkpoint cancellation materialization",
                validation_result,
            );
        }
        CancellationEffects::new(receipt, wakes)
    }

    /// Requests cancellation of a task.
    ///
    /// O(1) — maintained incrementally for O(1) Lyapunov snapshots.
    pub fn cancel_task(
        &mut self,
        task_id: TaskId,
        reason: &CancelReason,
    ) -> CancellationEffects<bool> {
        let budget = reason.cleanup_budget();
        let Some(effects) = self.update_task(task_id, |record| {
            record.request_cancel_with_budget_and_publication(reason.clone(), budget)
        }) else {
            return CancellationEffects::ready(false);
        };
        let ((newly_cancelled, changed, publication), mut wakes) = effects.into_parts();
        if newly_cancelled {
            if let Some(validation_result) =
                self.live_task_protocol_violation(task_id, TaskEvent::RequestCancel)
            {
                wakes.push_cancel_protocol_violation(
                    "task cancellation",
                    format!("{validation_result:?}"),
                );
            }
        }
        CancellationEffects::new(changed && publication.is_published(), wakes)
    }

    /// Applies a task-handle cancellation command and returns the effective
    /// cancel-lane priority captured with the initial-publication decision.
    ///
    /// Unlike [`Self::cancel_task`], a stronger request for an already
    /// cancelling task still returns a priority so the scheduler can promote
    /// its existing lane entry. The publication bit comes from the same Cx
    /// critical section as the cancellation mutation, preventing admission
    /// from racing a later gate re-read.
    pub(crate) fn cancel_task_for_handle(
        &mut self,
        task_id: TaskId,
        reason: &CancelReason,
    ) -> CancellationEffects<Option<HandleCancelRoute>> {
        let Some(effects) =
            self.update_task(task_id, |record| record.request_cancel_for_handle(reason))
        else {
            return CancellationEffects::ready(None);
        };
        let (update, mut wakes) = effects.into_parts();
        if update.newly_cancelled {
            if let Some(validation_result) =
                self.live_task_protocol_violation(task_id, TaskEvent::RequestCancel)
            {
                wakes.push_cancel_protocol_violation(
                    "task-handle cancellation",
                    format!("{validation_result:?}"),
                );
            }
        }
        CancellationEffects::new(update.route, wakes)
    }

    /// Publishes a delegated handle-cancel lane while this RuntimeState keeps
    /// the authoritative task record unavailable to already-awake workers.
    /// The closure must only mutate scheduler queues and return a closed token;
    /// Wakers, evidence, tracing, and worker notification happen after this
    /// method releases RuntimeState.
    pub(crate) fn publish_handle_cancel_lane<T>(
        &mut self,
        task_id: TaskId,
        publish_lane: impl FnOnce(u8, bool, Option<usize>) -> Option<T>,
    ) -> CancellationEffects<Option<T>> {
        self.update_task(task_id, |record| {
            record.publish_delegated_cancel_lane(publish_lane)
        })
        .unwrap_or_else(|| CancellationEffects::ready(None))
    }

    /// Parks an otherwise-unreturnable cancellation batch for the owner of the
    /// outer runtime-state lock.
    ///
    /// This operation is callback-free. Abandoning `RuntimeState` before the
    /// batch is taken leaks the opaque value and Waker targets rather than
    /// invoking their destructors under an unknown lock.
    pub(crate) fn defer_cancel_dispatch(
        &mut self,
        effects: CancellationEffects<Vec<(TaskId, u8)>>,
    ) {
        self.pending_cancel_dispatches.reserve(1);
        self.pending_cancel_dispatches.push(effects);
        self.pending_cancel_dispatch_ready
            .store(true, Ordering::Release);
        if let Some(coordinator) = self
            .pending_cancel_dispatch_coordinator
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            // Publish a concrete Parker permit after the queue+flag release.
            // This closes the final-check/park race without invoking an
            // arbitrary notifier or reactor callback beneath RuntimeState.
            coordinator.wake_one_parker();
        }
    }

    /// Installs the concrete parked-worker notifier for deferred cancellation.
    pub(crate) fn set_pending_cancel_dispatch_coordinator(
        &mut self,
        coordinator: &Arc<crate::runtime::scheduler::three_lane::WorkerCoordinator>,
    ) {
        self.pending_cancel_dispatch_coordinator = Some(Arc::downgrade(coordinator));
    }

    /// Returns the lock-free hint used by scheduler workers to discover
    /// deferred cancellation batches without adding a state-lock acquisition
    /// to the empty hot path.
    pub(crate) fn pending_cancel_dispatch_ready_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.pending_cancel_dispatch_ready)
    }

    /// Returns whether callback-free cancellation work still awaits owner-side
    /// publication. Used to avoid polling ordinary ready work ahead of a
    /// reentrant cancellation request.
    #[inline]
    pub(crate) fn has_deferred_cancel_dispatches(&self) -> bool {
        self.pending_cancel_dispatch_ready.load(Ordering::Acquire)
    }

    /// Takes callback-free cancellation batches for post-unlock publication
    /// and dispatch by the state-lock owner.
    pub(crate) fn take_deferred_cancel_dispatches(
        &mut self,
    ) -> Vec<CancellationEffects<Vec<(TaskId, u8)>>> {
        let pending = std::mem::take(&mut self.pending_cancel_dispatches);
        self.pending_cancel_dispatch_ready
            .store(false, Ordering::Release);
        pending
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
        // Drop the task's cancel-protocol state machine now that the task is
        // fully retired. Without this, `task_machines` grows without bound — one
        // ~100-byte entry per task ever spawned, since `register_task` runs on
        // every spawn and `TaskId`s carry generations so recycled slots mint
        // fresh keys rather than overwriting
        // (br-asupersync-cancelvalidator-leak-mdvuf9).
        self.cancel_protocol_validator.lock().remove_task(task_id);
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
            TaskSpawnEffects,
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
        .with_logical_clock(logical_clock)
        .with_spawn_gateway(self.spawn_gateway.clone())
        .with_pending_spawn_counter(
            self.regions
                .get(region.arena_index())
                .map(crate::record::RegionRecord::pending_spawn_handle),
        );
        cx.set_trace_buffer(self.trace_handle());
        cx.set_loser_drain_history_handle(self.loser_drain_history_handle());
        let cx_weak = std::sync::Arc::downgrade(&cx.inner);

        // Link the shared state to the TaskRecord
        self.update_task(task_id, |record| {
            record.set_cx_inner(cx.inner.clone());
            record.set_cx(cx.clone());
        });

        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
        let spawn_effects =
            self.prepare_task_spawn_effects(task_id, region, budget, TaskSpawnSource::Direct, now);

        // Create the TaskHandle
        let handle = crate::runtime::TaskHandle::new(task_id, result_rx, cx_weak);

        Ok((task_id, handle, cx, result_tx, spawn_effects))
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
        let (task_id, handle, cx, result_tx, spawn_effects) =
            self.create_task_infrastructure(&system_cx, region, budget, false)?;

        // Wrap the future to send the result through the channel. Panics must
        // surface as `JoinError::Panicked` rather than silently closing the
        // channel and looking like cancellation to the join handle.
        let wrapped_future = async move {
            // This legacy state-threaded API does not own a scheduler lane.
            // First poll proves the stored task was published and runs outside
            // the caller's runtime-state lock.
            spawn_effects.dispatch();
            match (CatchUnwind { inner: future }).await {
                Ok(result) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let message = payload_to_string(&payload);
                    std::mem::forget(payload);
                    let panic_payload = crate::types::outcome::PanicPayload::new(message);
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

        Ok((task_id, handle))
    }

    /// Creates and stores a direct task while returning its one-shot spawn
    /// effects to the caller.
    ///
    /// This is for runtime owners that also own the scheduler publication
    /// boundary. They must inject the returned task into a ready/cancel lane,
    /// release scheduler locks, and then dispatch the returned effects.
    pub(crate) fn create_task_with_deferred_spawn_effects<F, T>(
        &mut self,
        region: RegionId,
        budget: Budget,
        future: F,
    ) -> Result<(TaskId, crate::runtime::TaskHandle<T>, TaskSpawnEffects), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use crate::runtime::task_handle::JoinError;

        let system_cx = self.create_system_cx();
        let (task_id, handle, cx, result_tx, spawn_effects) =
            self.create_task_infrastructure(&system_cx, region, budget, false)?;
        let wrapped_future = async move {
            match (CatchUnwind { inner: future }).await {
                Ok(result) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let message = payload_to_string(&payload);
                    std::mem::forget(payload);
                    let panic_payload = crate::types::outcome::PanicPayload::new(message);
                    let _ = result_tx.send(
                        &cx,
                        Err::<T, JoinError>(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        self.tasks
            .store_spawned_task(task_id, StoredTask::new_with_id(wrapped_future, task_id));

        Ok((task_id, handle, spawn_effects))
    }

    /// Admits one spawn-mailbox request into the runtime
    /// (br-asupersync-dx-core-api-v2-u1z5hn.1.3).
    ///
    /// Runs under the state lock the scheduler already holds at its
    /// admission point. Mirrors [`Self::create_task_infrastructure`] —
    /// task-record allocation, cancel-protocol registration, region
    /// admission, capability-context linkage, spawn trace — but the future
    /// arrives pre-erased (the producer owns the completion slot), so no
    /// oneshot channel or [`crate::runtime::TaskHandle`] is built.
    ///
    /// The request's provisional task id (spawn-mailbox namespace) is
    /// replaced by the canonical arena id; `StoredTask::set_task_id` records
    /// the mapping for poll tracing, and the `TaskAdmitted` trace event
    /// carries the arena id (pairing with `TaskSpawnEnqueued` by per-region
    /// FIFO order). The pending-spawn credit is released only after the task
    /// is in the region's task list and its future stored
    /// (decrement-after-successor-visibility).
    ///
    /// On denial the request travels back to the caller, who must resolve it
    /// (`resolve_cancelled` / `resolve_failed`) **after** releasing the state
    /// lock — completion slots are user code and must not run under the
    /// runtime lock.
    pub(crate) fn admit_spawn_request(
        &mut self,
        parts: crate::runtime::spawn_mailbox::SpawnRequestParts,
    ) -> SpawnAdmission {
        if parts
            .admitted_slot
            .as_ref()
            .is_some_and(|slot| !slot.try_reserve())
        {
            let error = SpawnError::AdmissionSlotAlreadyReserved {
                task_id: parts.task_id,
            };
            return SpawnAdmission::Denied { parts, error };
        }
        let region = parts.region;
        let budget = parts.budget;
        let (task_id, cx, now) = match self.admit_spawn_record(region, budget) {
            Ok(admitted) => admitted,
            Err(error) => return SpawnAdmission::Denied { parts, error },
        };
        self.finish_send_spawn_admission(parts, task_id, &cx, now)
    }

    /// Payload-agnostic core of mailbox spawn admission, shared by the
    /// Send mailbox path ([`Self::admit_spawn_request`]) and the
    /// owner-pinned local lane ([`Self::admit_local_spawn_request`],
    /// br-asupersync-i9y5wb / A2.2a): region liveness, task-record
    /// creation, cancel-protocol registration, region quota admission
    /// (with rollback), and the admission-built capability context.
    fn admit_spawn_record(
        &mut self,
        region: RegionId,
        budget: Budget,
    ) -> Result<(TaskId, crate::cx::Cx, Time), SpawnError> {
        // Region liveness first: missing or non-Open regions deny without
        // touching the task table.
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return Err(SpawnError::RegionNotFound(region));
        };
        if !region_record.state().can_accept_work() {
            return Err(SpawnError::RegionClosed(region));
        }

        let now = self.current_runtime_time();
        let idx = self.insert_pooled_task_with(|idx, record| {
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

        {
            let mut validator = self.cancel_protocol_validator.lock();
            validator.register_task(task_id, region);
        }
        let context = TaskContext {
            task_id,
            region_id: region,
            spawned_at: now,
            validation_level: CancelValidationLevel::Basic,
        };
        let validation_result =
            self.validate_task_protocol_transition(task_id, TaskEvent::Start, &context);
        if matches!(
            validation_result,
            TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. }
        ) {
            log_cancel_protocol_violation("mailbox spawn admission", &validation_result);
        }

        // Region admission (quota + closed re-check under the region lock).
        let admission = self
            .regions
            .get(region.arena_index())
            .expect("region checked above")
            .add_task(task_id);
        if let Err(err) = admission {
            self.recycle_task(task_id);
            let error = match err {
                AdmissionError::Closed => SpawnError::RegionClosed(region),
                AdmissionError::LimitReached { limit, live, .. } => SpawnError::RegionAtCapacity {
                    region,
                    limit,
                    live,
                },
            };
            return Err(error);
        }

        // Capability context, linked exactly as create_task_infrastructure
        // does, so cancellation and observability behave identically.
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
        .with_logical_clock(logical_clock)
        .with_spawn_gateway(self.spawn_gateway.clone())
        .with_pending_spawn_counter(
            self.regions
                .get(region.arena_index())
                .map(crate::record::RegionRecord::pending_spawn_handle),
        );
        // Mailbox admission is visible in RuntimeState before its caller can
        // publish the first scheduler lane. Cancellation mutates this Cx while
        // the gate is false but delegates lane/Waker publication to the
        // AdmissionPublication handoff.
        cx.inner.write().runnable_publication =
            crate::types::task_context::RunnablePublication::Unpublished;
        cx.set_trace_buffer(self.trace_handle());
        cx.set_loser_drain_history_handle(self.loser_drain_history_handle());
        self.update_task(task_id, |record| {
            record.set_cx_inner(cx.inner.clone());
            record.set_cx(cx.clone());
        });

        Ok((task_id, cx, now))
    }

    /// Send-path admission tail: stores the payload centrally under the
    /// canonical arena id and publishes the admitted identity.
    fn finish_send_spawn_admission(
        &mut self,
        parts: crate::runtime::spawn_mailbox::SpawnRequestParts,
        task_id: TaskId,
        cx: &crate::cx::Cx,
        now: Time,
    ) -> SpawnAdmission {
        let region = parts.region;
        let budget = parts.budget;
        // Store the work under the canonical arena id. Factory payloads are
        // wrapped in a LazyFactoryTask so the user factory runs at first
        // poll on a worker — never here under the state lock
        // (br-asupersync-4h8lye / A2.1).
        let crate::runtime::spawn_mailbox::SpawnRequestParts {
            payload,
            pending_reservation,
            admitted_slot,
            ..
        } = parts;
        let stored = match payload {
            crate::runtime::spawn_mailbox::SpawnPayload::Task(mut task) => {
                task.set_task_id(task_id);
                task
            }
            crate::runtime::spawn_mailbox::SpawnPayload::Factory(factory) => {
                StoredTask::new_with_id(
                    crate::runtime::spawn_mailbox::LazyFactoryTask::new(factory, cx.clone()),
                    task_id,
                )
            }
        };
        self.tasks.store_spawned_task(task_id, stored);
        let cx_inner = std::sync::Arc::downgrade(&cx.inner);
        if let Some(slot) = admitted_slot.as_ref() {
            slot.publish_reserved(crate::runtime::spawn_mailbox::AdmittedTask::pending(
                task_id,
                cx_inner.clone(),
            ));
        }
        let cancel_publication =
            crate::runtime::spawn_mailbox::AdmissionPublication::new(cx_inner, admitted_slot);

        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
        let spawn_effects =
            self.prepare_task_spawn_effects(task_id, region, budget, TaskSpawnSource::Mailbox, now);

        // Successor state (task list + stored future) is visible; release
        // the pending-spawn credit last.
        drop(pending_reservation);

        SpawnAdmission::Admitted {
            task_id,
            priority: budget.priority,
            cancel_publication,
            spawn_effects,
        }
    }

    /// Admits an owner-pinned local spawn request
    /// (br-asupersync-i9y5wb / A2.2a).
    ///
    /// Shares the full admission core with [`Self::admit_spawn_request`]
    /// (record, cancel-protocol registration, region quota, Cx linkage,
    /// pending-credit release ordering); only storage differs. The built
    /// [`LocalStoredTask`] is returned to the calling worker, which must
    /// store it in its thread-local task slot and schedule it on the
    /// non-stealable local queue after releasing the state lock. Denials are
    /// returned for out-of-lock resolution exactly like the Send path.
    pub(crate) fn admit_local_spawn_request(
        &mut self,
        request: crate::runtime::spawn_mailbox::LocalSpawnRequest,
    ) -> LocalSpawnAdmission {
        let Some(worker_id) = crate::runtime::scheduler::three_lane::current_worker_id() else {
            return LocalSpawnAdmission::Denied {
                request,
                error: SpawnError::LocalSchedulerUnavailable,
            };
        };
        if request
            .admitted_slot
            .as_ref()
            .is_some_and(|slot| !slot.try_reserve())
        {
            let error = SpawnError::AdmissionSlotAlreadyReserved {
                task_id: request.task_id,
            };
            return LocalSpawnAdmission::Denied { request, error };
        }
        let region = request.region;
        let budget = request.budget;
        let (task_id, cx, now) = match self.admit_spawn_record(region, budget) {
            Ok(admitted) => admitted,
            Err(error) => return LocalSpawnAdmission::Denied { request, error },
        };
        self.update_task(task_id, |record| {
            record.pin_to_worker(worker_id);
        });

        let crate::runtime::spawn_mailbox::LocalSpawnRequest {
            factory,
            pending_reservation,
            admitted_slot,
            ..
        } = request;

        // The factory runs at first poll on the owner worker — never here
        // under the state lock (same discipline as the Send path).
        let stored = LocalStoredTask::new_with_id(
            crate::runtime::spawn_mailbox::LocalLazyFactoryTask::new(factory, cx.clone()),
            task_id,
        );
        let cx_inner = std::sync::Arc::downgrade(&cx.inner);
        if let Some(slot) = admitted_slot.as_ref() {
            slot.publish_reserved(crate::runtime::spawn_mailbox::AdmittedTask::pending(
                task_id,
                cx_inner.clone(),
            ));
        }
        let cancel_publication =
            crate::runtime::spawn_mailbox::AdmissionPublication::new(cx_inner, admitted_slot);

        self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
        let spawn_effects =
            self.prepare_task_spawn_effects(task_id, region, budget, TaskSpawnSource::Local, now);

        // The task is already visible in the region's task list
        // (admission core ran `add_task`), so the pending credit can be
        // released before the worker finishes thread-local storage.
        drop(pending_reservation);

        LocalSpawnAdmission::Admitted {
            task_id,
            priority: budget.priority,
            stored,
            cancel_publication,
            spawn_effects,
        }
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

        let (task_id, handle, cx, result_tx, spawn_effects) =
            self.create_task_infrastructure(caller_cx, region, budget, false)?;

        // Wrap the future to send the result through the channel. Panics must
        // surface as `JoinError::Panicked` rather than silently closing the
        // channel and looking like cancellation to the join handle.
        let wrapped_future = async move {
            spawn_effects.dispatch();
            match (CatchUnwind { inner: future }).await {
                Ok(result) => {
                    let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let message = payload_to_string(&payload);
                    std::mem::forget(payload);
                    let panic_payload = crate::types::outcome::PanicPayload::new(message);
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

    /// Creates one bounded epoch telemetry delivery token for use after
    /// publishing the associated mutation and releasing runtime locks. The
    /// token does not remove receipts from the outbox until it is dispatched.
    #[must_use]
    pub fn take_epoch_telemetry(&self) -> super::epoch_tracker::EpochTelemetryDispatch {
        self.epoch_tracker.drain_telemetry()
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

    pub(crate) fn prepare_task_spawn_effects(
        &self,
        task_id: TaskId,
        region: RegionId,
        budget: Budget,
        source: TaskSpawnSource,
        spawned_at: Time,
    ) -> TaskSpawnEffects {
        let mut effects = TaskSpawnEffects::new(
            Arc::clone(&self.metrics),
            self.trace_handle(),
            task_id,
            region,
            spawned_at,
            self.logical_time_for_task(task_id),
            budget,
            source,
            &self.task_spawn_observer_panics,
        );
        effects.attach_epoch_telemetry(self.take_epoch_telemetry());
        effects
    }

    fn prepare_task_completion_observer(
        &self,
        task: &TaskRecord,
        waiter_count: usize,
    ) -> TaskCompletionObserver {
        let now = self.current_runtime_time();
        self.record_task_trace_event(task.id, |seq| {
            TraceEvent::complete(seq, now, task.id, task.owner)
        });

        let duration = Duration::from_nanos(now.duration_since(task.created_at()));
        let outcome_kind = match &task.state {
            TaskState::Completed(outcome) => OutcomeKind::from(outcome),
            _ => OutcomeKind::Err,
        };
        let outcome_label = match &task.state {
            TaskState::Completed(Outcome::Ok(())) => "Ok",
            TaskState::Completed(Outcome::Err(_)) => "Err",
            TaskState::Completed(Outcome::Cancelled(_)) => "Cancelled",
            TaskState::Completed(Outcome::Panicked(_)) => "Panicked",
            _ => "Unknown",
        };

        TaskCompletionObserver::completed(
            Arc::clone(&self.metrics),
            task.id,
            task.owner,
            outcome_kind,
            outcome_label,
            duration,
            waiter_count,
            &self.task_completion_observer_panics,
        )
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
            for region_id in self.take_deferred_region_advancements() {
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
                token: obligation_id.as_u64().saturating_add(1),
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

        // The obligation is resolved; drop its cancel-protocol state machine so
        // `obligation_machines` doesn't leak one entry per obligation ever
        // reserved (br-asupersync-cancelvalidator-leak-mdvuf9). Finalizers run by
        // `advance_region_state` acquire fresh obligation ids, so this removal
        // does not affect them.
        self.cancel_protocol_validator
            .lock()
            .remove_obligation(obligation);

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

        // The obligation is resolved (aborted); drop its cancel-protocol state
        // machine so `obligation_machines` doesn't leak
        // (br-asupersync-cancelvalidator-leak-mdvuf9).
        self.cancel_protocol_validator
            .lock()
            .remove_obligation(obligation);

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
    /// This is called by state-threaded boot paths to register a `StoredTask`
    /// with the runtime. The task must already have a `TaskRecord` created by
    /// the scope's stored-task construction path.
    ///
    /// # Arguments
    /// * `task_id` - The ID of the task (from the TaskHandle)
    /// * `stored` - The StoredTask containing the wrapped future
    ///
    /// # Example
    /// ```ignore
    /// let handle = scope.spawn_registered(&mut state, &cx, |_| async { 42 })?;
    /// // The executor can now poll the stored task.
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
            && self.pending_cancel_dispatches.is_empty()
            && self.io_driver.as_ref().is_none_or(IoDriverHandle::is_empty)
            && self.regions.iter().all(|(_, r)| {
                r.finalizers_empty() && !r.state().is_closing() && r.pending_spawn_count() == 0
            })
    }

    /// Applies a precomputed region-policy action after a child reaches a
    /// terminal outcome.
    ///
    /// The caller must invoke `Policy::on_child_outcome` before acquiring the
    /// outer `RuntimeState` lock. Policy implementations are user code and may
    /// reenter the runtime, panic, or own hostile destructors; this mutation
    /// boundary therefore accepts only the closed callback-free action value.
    ///
    /// Returns the policy action taken and a list of tasks that need to be
    /// moved to the cancel lane in the scheduler.
    pub fn apply_policy_action(
        &mut self,
        region: RegionId,
        child: TaskId,
        action: PolicyAction,
    ) -> CancellationEffects<(PolicyAction, SmallVec<[(TaskId, u8); 4]>)> {
        let sibling_effects = if let PolicyAction::CancelSiblings(reason) = &action {
            self.cancel_sibling_tasks(region, child, reason)
        } else {
            CancellationEffects::ready(SmallVec::new())
        };
        let (tasks_to_schedule, wakes) = sibling_effects.into_parts();
        CancellationEffects::new((action, tasks_to_schedule), wakes)
    }

    /// Implements `inv.cancel.propagates_down` (#6, SEM-INV-003):
    /// cancel(region) -> cancel all non-Completed children.
    fn cancel_sibling_tasks(
        &mut self,
        region: RegionId,
        child: TaskId,
        reason: &CancelReason,
    ) -> CancellationEffects<SmallVec<[(TaskId, u8); 4]>> {
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return CancellationEffects::ready(SmallVec::new());
        };
        let sibling_candidates = region_record.task_ids_small();
        let mut tasks_to_cancel =
            SmallVec::with_capacity(sibling_candidates.len().saturating_sub(1));
        let mut wakes = CancelWakeEffects::empty();
        // Cancellation already carries its logical request time. Reusing that
        // closed value avoids invoking an arbitrary TimeSource callback while
        // callers hold the outer RuntimeState lock.
        let now = reason.timestamp;

        for &task_id in &sibling_candidates {
            if task_id == child {
                continue;
            }
            let budget = reason.cleanup_budget();
            let res = self.update_task(task_id, |task_record| {
                task_record.request_cancel_with_budget_and_publication(reason.clone(), budget)
            });
            let Some(effects) = res else {
                continue;
            };
            let ((newly_cancelled, changed, publication), task_wakes) = effects.into_parts();
            wakes.merge(task_wakes);
            if newly_cancelled {
                if let Some(validation_result) =
                    self.live_task_protocol_violation(task_id, TaskEvent::RequestCancel)
                {
                    wakes.push_cancel_protocol_violation(
                        "sibling task cancellation",
                        format!("{validation_result:?}"),
                    );
                }
                self.record_task_trace_event(task_id, |seq| {
                    TraceEvent::cancel_request(seq, now, task_id, region, reason.clone())
                });
            }
            if changed && publication.is_published() {
                tasks_to_cancel.push((task_id, budget.priority));
            }
        }
        CancellationEffects::new(tasks_to_cancel, wakes)
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
    /// The returned effect token covers auxiliary task-cancellation Wakers,
    /// task-cancel tracing, cancellation-request metrics, and cancellation
    /// protocol diagnostics. It is not a universal callback-free boundary:
    /// affected regions with no children or tasks are still advanced
    /// synchronously below, and that existing close/finalizer path may invoke
    /// finalizers, close waiters, heap payload destructors, tracing, and
    /// region-close metrics before this method returns.
    ///
    /// # Arguments
    /// * `region_id` - The region to cancel
    /// * `reason` - The reason for cancellation
    /// * `source_task` - The task that initiated cancellation, if known
    ///
    /// # Example
    /// ```ignore
    /// let effects = state.cancel_request(region, &CancelReason::timeout(), None);
    /// let (tasks_to_schedule, wakes) = effects.into_parts();
    /// for &(task_id, priority) in &tasks_to_schedule {
    ///     scheduler.move_to_cancel_lane(task_id, priority);
    /// }
    /// wakes.dispatch();
    /// ```
    #[allow(clippy::too_many_lines)]
    pub fn cancel_request(
        &mut self,
        region_id: RegionId,
        reason: &CancelReason,
        source_task: Option<TaskId>,
    ) -> CancellationEffects<Vec<(TaskId, u8)>> {
        // Use a modest initial capacity instead of scanning the entire task
        // arena for live_task_count(). The Vec will grow if needed, but avoids
        // the O(arena_capacity) scan just for a size hint.
        let mut tasks_to_cancel = Vec::with_capacity(32);
        let mut wakes = CancelWakeEffects::empty();
        let _ = source_task;
        // Cancellation already carries its logical request time. Reusing that
        // closed value avoids invoking an arbitrary TimeSource callback while
        // callers hold the outer RuntimeState lock.
        let now = reason.timestamp;

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
                // parent's. Now we synthesize a self-rooted ParentCancelled
                // diagnostic sentinel
                // (no `with_cause_limited` chain) so cause-chain
                // consumers see "depth>0 region with empty parent cause"
                // — a clear signal that something is wrong, instead of
                // a misleading "looks like the root" chain.
                let parent_reason = match region_reasons.get(&parent_id) {
                    Some(r) => r.clone(),
                    None => {
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
            let region_cancel_kind = region_reason.kind;

            self.record_trace_event(|seq| {
                TraceEvent::region_cancelled(seq, now, rid, region_reason.clone())
            });

            if let Some(region) = self.regions.get_mut(rid.arena_index()) {
                // Use the properly chained reason.
                // Try to transition to Closing with the reason.
                // If already Closing/Draining/etc., strengthen the reason instead.
                let old_state = region.state();
                // `cancel_request` is commonly called beneath the outer
                // RuntimeState lock. Use the subscriber-free transition here;
                // the runtime TraceBuffer event below remains authoritative.
                // The external Closing subscriber event/span update is omitted:
                // deferring just that transition could publish after a later
                // Draining/Closed event and rewind observer state. Task/metrics
                // cancellation observers still travel in `wakes` for dispatch.
                if region.begin_close_without_subscriber(Some(region_reason.clone())) {
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
            wakes.push_region_cancellation_metric(
                Arc::clone(&self.metrics),
                rid,
                region_cancel_kind,
            );
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
                let Some((effects, task_budget_res)) = self.update_task(task_id, |task| {
                    let task_budget = task_reason.cleanup_budget();
                    let effects = task.request_cancel_with_budget_and_publication(
                        task_reason.clone(),
                        task_budget,
                    );
                    (effects, task_budget)
                }) else {
                    continue;
                };
                let ((newly_cancelled, changed, publication), task_wakes) = effects.into_parts();
                wakes.merge(task_wakes);

                if newly_cancelled {
                    if let Some(validation_result) =
                        self.live_task_protocol_violation(task_id, TaskEvent::RequestCancel)
                    {
                        wakes.push_cancel_protocol_violation(
                            "region task cancellation",
                            format!("{validation_result:?}"),
                        );
                    }
                    self.record_task_trace_event(task_id, |seq| {
                        TraceEvent::cancel_request(seq, now, task_id, rid, task_reason.clone())
                    });
                }

                if changed && publication.is_published() {
                    tasks_to_cancel.push((task_id, task_budget_res.priority));
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
            if no_children && no_tasks {
                self.advance_region_state(node.id);
            }
        }

        CancellationEffects::new(tasks_to_cancel, wakes)
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

        // Check all tasks are terminal. An id absent from the embedded table is
        // not evidence of completion: sharded schedulers keep live records in
        // an external TaskTable and remove the id from the region only at the
        // cross-cutting completion boundary.
        let all_tasks_done = region
            .task_ids()
            .iter()
            .all(|&task_id| self.task(task_id).is_some_and(|t| t.state.is_terminal()));

        // Check all child regions are closed
        let all_children_closed = region.child_ids().iter().all(|&child_id| {
            self.regions
                .get(child_id.arena_index())
                .is_none_or(|r| r.state().is_terminal())
        });

        // Pending (not-yet-admitted) spawn requests are un-admitted children:
        // the drain phase must first admit-then-cancel or resolve them, so
        // the region cannot enter Finalizing while any credit is outstanding
        // (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
        let no_pending_spawns = region.pending_spawn_count() == 0;

        all_tasks_done && all_children_closed && no_pending_spawns
    }

    /// Notifies that a task has completed.
    ///
    /// This checks if the owning region can advance its state.
    /// Returns owned waiter and observer effects. The caller must publish
    /// callback-free waiter/finalizer queue work, release any runtime-state
    /// lock, commit any execution guard, and only then dispatch the observer
    /// payload. Legacy foreign-waker callbacks may follow as a separate,
    /// uncontained boundary.
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
    /// validation, completion tracing, and cleanup operations read
    /// task properties (id, owner, state, created_at) that are NOT
    /// mutated by the waiter-take, so the ordering change is
    /// behaviour-preserving.
    pub fn task_completed(&mut self, task_id: TaskId) -> TaskCompletionEffects {
        // br-asupersync-ndhjfj: atomic existence-check + waiter-take.
        // If the task was already removed (or never existed), return
        // an empty waiter set with the same early-return semantics
        // the prior implementation provided.
        let Some(waiters) = self.update_task(task_id, |task| std::mem::take(&mut task.waiters))
        else {
            return TaskCompletionEffects::unknown(task_id, &self.task_completion_observer_panics);
        };

        let waiter_count = waiters.len();
        let (owner, completion, close_outcome, observer, retired_cancel_wakers) = {
            let Some(task) = self.task(task_id) else {
                // Defensive: if the task vanished between the
                // update_task above and here, return the waiters we
                // already took rather than dropping them.
                return TaskCompletionEffects {
                    waiters,
                    observer: TaskCompletionObserver::unknown(
                        task_id,
                        &self.task_completion_observer_panics,
                    ),
                    retired_cancel_wakers: TaskCompletionRetirements::empty(),
                };
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
            let retired_cancel_wakers = if let Some(inner) = task.cx_inner.as_ref() {
                // br-asupersync-xgujaf — single write-lock; the previous
                // read-then-write split had a TOCTOU window where a concurrent
                // canceller could install a fresh waker between the read drop
                // and write acquire, and we'd silently clear it without ever
                // waking. Task completion is per-task (not a hot path), so the
                // saved write-lock acquisition was not worth the correctness
                // hazard. `take()` is idempotent on None (no allocation, no
                // wake) and keeps the cleared Waker alive only briefly inside
                // the guard scope.
                TaskCompletionRetirements::new({
                    let mut guard = inner.write();
                    guard.take_cancel_wakers()
                })
            } else {
                TaskCompletionRetirements::empty()
            };

            let observer = self.prepare_task_completion_observer(task, waiter_count);
            let close_outcome = match &task.state {
                crate::record::task::TaskState::Completed(outcome) => Some(outcome.clone()),
                _ => None,
            };
            let owner = task.owner;
            let completion = TaskCompletionKind::from_state(&task.state);
            (
                owner,
                completion,
                close_outcome,
                observer,
                retired_cancel_wakers,
            )
        };
        // br-asupersync-ndhjfj: `waiters` was already taken atomically
        // at the top of the function under `update_task`. The previous
        // separate `task_mut` re-acquisition has been removed.
        self.finish_task_completion(
            task_id,
            owner,
            completion,
            close_outcome,
            waiters,
            observer,
            retired_cancel_wakers,
            true,
        )
    }

    /// Completes cross-cutting runtime bookkeeping for a task record owned by
    /// an external scheduler shard.
    ///
    /// The caller removes the record from its [`TaskTable`] first and retains
    /// ownership until this method returns. That keeps the shard lock out of
    /// validator, metrics, region, obligation, and finalizer paths while still
    /// preserving the same completion semantics as [`Self::task_completed`].
    pub(crate) fn task_completed_from_external_record(
        &mut self,
        task: &mut TaskRecord,
    ) -> TaskCompletionEffects {
        let task_id = task.id;
        let waiters = std::mem::take(&mut task.waiters);
        let waiter_count = waiters.len();
        let task_event = match &task.state {
            TaskState::Completed(Outcome::Cancelled(_)) => TaskEvent::DrainComplete,
            TaskState::Completed(Outcome::Panicked(payload)) => TaskEvent::Panic {
                message: payload.message().to_string(),
            },
            _ => TaskEvent::Complete,
        };
        let context = TaskContext {
            task_id,
            region_id: task.owner,
            spawned_at: task.created_at,
            validation_level: CancelValidationLevel::Basic,
        };
        // `cancel_epoch` survives terminal completion, including a panic that
        // wins after cancellation was requested. Terminal state alone would
        // lose that ordering witness for Completed(Panicked).
        let cancellation_materialized = task.cancel_epoch > 0;
        self.validate_and_retire_external_task_protocol(
            task_id,
            task_event,
            &context,
            cancellation_materialized,
        );

        let retired_cancel_wakers =
            task.cx_inner
                .as_ref()
                .map_or_else(TaskCompletionRetirements::empty, |inner| {
                    TaskCompletionRetirements::new({
                        let mut guard = inner.write();
                        guard.take_cancel_wakers()
                    })
                });
        let observer = self.prepare_task_completion_observer(task, waiter_count);
        let close_outcome = match &task.state {
            TaskState::Completed(outcome) => Some(outcome.clone()),
            _ => None,
        };
        let owner = task.owner;
        let completion = TaskCompletionKind::from_state(&task.state);
        self.finish_task_completion(
            task_id,
            owner,
            completion,
            close_outcome,
            waiters,
            observer,
            retired_cancel_wakers,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_task_completion(
        &mut self,
        task_id: TaskId,
        owner: RegionId,
        completion: TaskCompletionKind,
        close_outcome: Option<Outcome<(), Error>>,
        waiters: SmallVec<[TaskId; 4]>,
        observer: TaskCompletionObserver,
        retired_cancel_wakers: TaskCompletionRetirements,
        remove_embedded_record: bool,
    ) -> TaskCompletionEffects {
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

            self.record_finalizer_run(owner, finalizer_id);
        }

        // Abort any pending obligations held by this task to prevent
        // orphaned obligations from blocking region close (deadlock).
        // Uses the holder secondary index for O(obligations_per_task) instead of O(arena_capacity).
        let orphaned = self.obligations.sorted_pending_ids_for_holder(task_id);
        for ob_id in orphaned {
            let _ = self.abort_obligation(ob_id, ObligationAbortReason::Cancel);
        }

        // Embedded tables still own their record here. External-shard callers
        // already detached it before taking the RuntimeState lock.
        if remove_embedded_record {
            self.recycle_task(task_id);
        } else {
            // External completion atomically retired its validator state with
            // the terminal transition before entering this common tail.
            self.notify_runtime_epoch_advance(super::epoch_tracker::ModuleId::TaskTable);
        }

        // Remove task from owning region to prevent memory leak
        if let Some(region) = self.regions.get(owner.arena_index()) {
            if let Some(outcome) = close_outcome {
                region.record_close_outcome(outcome);
            }
            region.remove_task(task_id);
        }

        // Advance region state if possible (e.g. if this was the last task)
        self.advance_region_state(owner);

        let mut observer = observer;
        observer.attach_epoch_telemetry(self.take_epoch_telemetry());
        TaskCompletionEffects {
            waiters,
            observer,
            retired_cancel_wakers,
        }
    }

    // =========================================================================
    // Async Finalizer Scheduling
    // =========================================================================

    /// Drains finalizers for regions that are ready to run them.
    ///
    /// Both sync and async finalizers cross the task-publication boundary. In
    /// particular, a sync finalizer must not run here: production callers hold
    /// the runtime-state mutex while invoking this method. Scheduling at most
    /// one finalizer task per region preserves the LIFO barrier while ensuring
    /// arbitrary user code is first polled after that mutex has been released.
    pub fn drain_ready_async_finalizers(
        &mut self,
    ) -> SmallVec<[(TaskId, u8, TaskSpawnEffects); 2]> {
        if self.finalizing_regions.is_empty() {
            return SmallVec::new();
        }
        let mut scheduled = SmallVec::new();
        let mut regions_to_process = SmallVec::<[RegionId; 8]>::new();

        for &region_id in &self.finalizing_regions {
            if self.active_async_finalizers.contains_key(&region_id)
                || self.active_manual_finalizers.contains_key(&region_id)
            {
                continue;
            }
            if let Some(region) = self.regions.get(region_id.arena_index()) {
                if !region.finalizers_empty() {
                    regions_to_process.push(region_id);
                }
            }
        }

        for region_id in regions_to_process {
            let Some((finalizer_id, finalizer)) = self.take_next_finalizer_tracked(region_id)
            else {
                continue;
            };
            let future: BoxedAsyncFinalizer = match finalizer {
                Finalizer::Sync(finalizer) => Box::pin(async move { finalizer() }),
                Finalizer::Async(future) => future,
            };
            match self.spawn_finalizer_task(region_id, finalizer_id, future) {
                Ok((task_id, priority, spawn_effects)) => {
                    scheduled.push((task_id, priority, spawn_effects));
                }
                Err(future) => {
                    // Preserve the barrier when task admission fails so the
                    // region cannot close with cleanup silently dropped. A
                    // wrapped sync callback is intentionally requeued as an
                    // async finalizer: the wrapper is now its lock-free
                    // execution boundary.
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

    /// Executes failed-start async finalizers without promoting them to tasks.
    ///
    /// `CompiledApp::start` is a legacy state-threaded bootstrap API: on a
    /// partial-start error it must synchronously retire the temporary region
    /// tree before returning, but it owns no scheduler lane or post-lock
    /// callback boundary. Creating a normal finalizer task here would either
    /// emit its spawn observer before executable publication or execute an
    /// observed task with no published lane. This narrow rollback path instead
    /// preserves finalizer LIFO/accounting while polling the raw finalizer once.
    /// A pending finalizer is fail-closed as cancelled, matching the old
    /// bootstrap behavior that force-completed its one-poll task immediately.
    pub(crate) fn drive_failed_start_async_finalizer_inline(
        &mut self,
        region_id: RegionId,
    ) -> bool {
        if self
            .regions
            .get(region_id.arena_index())
            .is_none_or(|region| region.state() != crate::record::region::RegionState::Finalizing)
        {
            return false;
        }
        if self.active_async_finalizers.contains_key(&region_id)
            || self.active_manual_finalizers.contains_key(&region_id)
        {
            return false;
        }
        let Some((finalizer_id, finalizer)) = self.run_sync_finalizers_tracked(region_id) else {
            return false;
        };
        let Finalizer::Async(future) = finalizer else {
            return false;
        };

        self.validate_live_region_protocol_transition(
            region_id,
            RegionEvent::FinalizerStarted,
            "failed-start inline async finalizer",
        );

        let deadline = self
            .current_runtime_time()
            .saturating_add_nanos(FINALIZER_TIME_BUDGET_NANOS);
        let cleanup_task = next_bootstrap_task_id();
        let cleanup_budget = finalizer_budget().with_deadline(deadline);
        let cleanup_cx = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Failed-start rollback is synchronous and one-poll only. Give it
            // runtime time/trace context and deterministic rollback entropy,
            // but deliberately no
            // spawn gateway, pending-spawn counter, I/O driver, or blocking
            // pool: work admitted through any of those handles could outlive
            // this call or keep the closing subtree non-quiescent.
            let entropy_seed = DetEntropy::mix_seed(
                region_id
                    .as_u64()
                    .wrapping_add(finalizer_id.rotate_left(29)),
            );
            let entropy: Arc<dyn EntropySource> = Arc::new(DetEntropy::new(entropy_seed));
            let logical_clock = self
                .logical_clock_mode
                .build_handle(self.timer_driver_handle());
            let cx = crate::cx::Cx::new_with_drivers(
                region_id,
                cleanup_task,
                cleanup_budget,
                None,
                None,
                None,
                self.timer_driver_handle(),
                Some(entropy),
            )
            .with_logical_clock(logical_clock);
            cx.set_trace_buffer(self.trace_handle());
            cx.set_loser_drain_history_handle(self.loser_drain_history_handle());
            cx
        })) {
            Ok(cx) => cx,
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future)))
                {
                    std::mem::forget(payload);
                }
                if let Some(region) = self.regions.get(region_id.arena_index()) {
                    region.record_close_outcome(Outcome::Panicked(
                        crate::types::PanicPayload::new(message),
                    ));
                }
                self.record_finalizer_run(region_id, finalizer_id);
                return true;
            }
        };
        let current_guard = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::cx::Cx::set_current(Some(cleanup_cx.clone()))
        })) {
            Ok(guard) => guard,
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future)))
                {
                    std::mem::forget(payload);
                }
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(cleanup_cx)))
                {
                    std::mem::forget(payload);
                }
                if let Some(region) = self.regions.get(region_id.arena_index()) {
                    region.record_close_outcome(Outcome::Panicked(
                        crate::types::PanicPayload::new(message),
                    ));
                }
                self.record_finalizer_run(region_id, finalizer_id);
                return true;
            }
        };
        let mut masked = MaskedFinalizer::new(future, Arc::clone(&cleanup_cx.inner));
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::pin::Pin::new(&mut masked).poll(&mut poll_cx)
        }));
        let polled_outcome: Outcome<(), Error> = match poll_result {
            Ok(Poll::Ready(())) => Outcome::Ok(()),
            Ok(Poll::Pending) => Outcome::Cancelled(CancelReason::shutdown()),
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                Outcome::Panicked(crate::types::PanicPayload::new(message))
            }
        };
        let close_outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(masked);
        })) {
            Ok(()) => polled_outcome,
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                Outcome::Panicked(crate::types::PanicPayload::new(message))
            }
        };

        let retirements = TaskCompletionRetirements::new({
            let mut inner = cleanup_cx.inner.write();
            inner.take_cancel_wakers()
        });
        // This state-threaded rollback path has no post-lock RawWaker
        // retirement boundary. Abandon only those detached wake targets; the
        // restricted cleanup Cx itself owns exclusively runtime-internal
        // handles and can be retired here without retaining a mailbox/driver
        // graph per failed start.
        drop(retirements);
        let close_outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(current_guard);
        })) {
            Ok(()) => close_outcome,
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                Outcome::Panicked(crate::types::PanicPayload::new(message))
            }
        };
        let close_outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(cleanup_cx);
        })) {
            Ok(()) => close_outcome,
            Err(payload) => {
                let message = payload_to_string(&payload);
                std::mem::forget(payload);
                Outcome::Panicked(crate::types::PanicPayload::new(message))
            }
        };

        if let Some(region) = self.regions.get(region_id.arena_index()) {
            region.record_close_outcome(close_outcome);
        }
        self.record_finalizer_run(region_id, finalizer_id);
        true
    }

    fn spawn_finalizer_task(
        &mut self,
        region_id: RegionId,
        finalizer_id: u64,
        future: BoxedAsyncFinalizer,
    ) -> Result<(TaskId, u8, TaskSpawnEffects), BoxedAsyncFinalizer> {
        // EDGE CASE VALIDATION: Check async finalizer barrier consistency before spawning
        // This prevents concurrent async finalizers from the same region, which violates LIFO ordering
        debug_assert!(
            !self.active_async_finalizers.contains_key(&region_id),
            "br-asupersync-mg70eb: async finalizer barrier violation - region already has active async finalizer \
             (region={:?})",
            region_id
        );
        debug_assert!(
            !self.active_manual_finalizers.contains_key(&region_id),
            "async finalizer scheduled while an external driver owns the region barrier \
             (region={region_id:?})"
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
        let Ok((task_id, _handle, cx, result_tx, spawn_effects)) =
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
                    let message = payload_to_string(&payload);
                    std::mem::forget(payload);
                    let panic_payload = crate::types::outcome::PanicPayload::new(message);
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
        Ok((task_id, budget.priority, spawn_effects))
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

    fn record_finalizer_run(&mut self, region: RegionId, id: u64) {
        self.validate_live_region_protocol_transition(
            region,
            RegionEvent::FinalizerCompleted,
            "finalizer completion",
        );
        let now = self.current_runtime_time();
        self.finalizer_history
            .push(FinalizerHistoryEvent::Ran { id, time: now });
    }

    fn record_finalizer_close(&mut self, region: RegionId) {
        debug_assert!(
            !self.active_manual_finalizers.contains_key(&region),
            "region closed with an unsettled manual finalizer receipt: {region:?}"
        );
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
    /// The next finalizer and its one-shot completion receipt, or `None` if the
    /// stack is empty or another manual finalizer is still active.
    pub fn pop_region_finalizer(
        &mut self,
        region_id: RegionId,
    ) -> Option<(Finalizer, ManualFinalizerReceipt)> {
        if self.active_manual_finalizers.contains_key(&region_id)
            || self.active_async_finalizers.contains_key(&region_id)
        {
            return None;
        }
        let (finalizer_id, finalizer) = self.pop_tracked_finalizer(region_id)?;
        Some(self.handoff_manual_finalizer(region_id, finalizer_id, finalizer))
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
    /// If an async finalizer is encountered, it and a one-shot receipt are
    /// returned immediately. The caller must await the finalizer and settle the
    /// receipt before calling this method again to process lower finalizers.
    ///
    /// # Returns
    /// An async finalizer and its receipt, or `None` if the stack is empty or a
    /// previous manual receipt is still active.
    pub fn run_sync_finalizers(
        &mut self,
        region_id: RegionId,
    ) -> Option<(Finalizer, ManualFinalizerReceipt)> {
        if self.active_manual_finalizers.contains_key(&region_id)
            || self.active_async_finalizers.contains_key(&region_id)
        {
            return None;
        }
        let (finalizer_id, finalizer) = self.run_sync_finalizers_tracked(region_id)?;
        Some(self.handoff_manual_finalizer(region_id, finalizer_id, finalizer))
    }

    fn handoff_manual_finalizer(
        &mut self,
        region_id: RegionId,
        finalizer_id: u64,
        finalizer: Finalizer,
    ) -> (Finalizer, ManualFinalizerReceipt) {
        self.validate_live_region_protocol_transition(
            region_id,
            RegionEvent::FinalizerStarted,
            "manual finalizer handoff",
        );
        let previous = self
            .active_manual_finalizers
            .insert(region_id, finalizer_id);
        debug_assert!(
            previous.is_none(),
            "region {region_id:?} already had an active manual finalizer receipt: {previous:?}"
        );
        (
            finalizer,
            ManualFinalizerReceipt {
                runtime_instance_id: self.instance_id,
                region_id,
                finalizer_id,
                settled: false,
            },
        )
    }

    /// Records successful retirement of an externally driven finalizer.
    ///
    /// The receipt is one-shot. A second settlement attempt returns
    /// [`ManualFinalizerReceiptError::AlreadySettled`] without emitting a
    /// duplicate completion event.
    pub fn complete_manual_finalizer(
        &mut self,
        receipt: &mut ManualFinalizerReceipt,
    ) -> Result<(), ManualFinalizerReceiptError> {
        self.settle_manual_finalizer(receipt, false)
    }

    /// Abandons an externally driven finalizer and releases its close barrier.
    ///
    /// Abandonment records a cancelled close outcome before terminal finalizer
    /// accounting. It does not claim that the callback completed successfully.
    pub fn abandon_manual_finalizer(
        &mut self,
        receipt: &mut ManualFinalizerReceipt,
    ) -> Result<(), ManualFinalizerReceiptError> {
        self.settle_manual_finalizer(receipt, true)
    }

    fn settle_manual_finalizer(
        &mut self,
        receipt: &mut ManualFinalizerReceipt,
        abandoned: bool,
    ) -> Result<(), ManualFinalizerReceiptError> {
        if receipt.settled {
            return Err(ManualFinalizerReceiptError::AlreadySettled);
        }
        if receipt.runtime_instance_id != self.instance_id {
            return Err(ManualFinalizerReceiptError::WrongRuntime);
        }
        if self.active_manual_finalizers.get(&receipt.region_id) != Some(&receipt.finalizer_id) {
            return Err(ManualFinalizerReceiptError::NotActive);
        }

        if abandoned && let Some(region) = self.regions.get(receipt.region_id.arena_index()) {
            region.record_close_outcome(Outcome::Cancelled(CancelReason::user(
                "manual finalizer abandoned",
            )));
        }
        self.record_finalizer_run(receipt.region_id, receipt.finalizer_id);
        self.active_manual_finalizers.remove(&receipt.region_id);
        receipt.settled = true;
        Ok(())
    }

    fn take_next_finalizer_tracked(&mut self, region_id: RegionId) -> Option<(u64, Finalizer)> {
        if let Some(region) = self.regions.get(region_id.arena_index()) {
            debug_assert_eq!(
                region.state(),
                crate::record::region::RegionState::Finalizing,
                "br-asupersync-5mty2b: finalizers may only leave the runtime-state lock in Finalizing state \
                 (region={:?}, current_state={:?})",
                region_id,
                region.state()
            );
        }
        self.pop_tracked_finalizer(region_id)
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
                        let message = payload_to_string(&payload);
                        std::mem::forget(payload);
                        if let Some(region) = self.regions.get(region_id.arena_index()) {
                            region.record_close_outcome(Outcome::Panicked(
                                crate::types::outcome::PanicPayload::new(message),
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

                    self.record_finalizer_run(region_id, finalizer_id);
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

        // An external driver owns the top LIFO finalizer until it explicitly
        // completes or abandons the one-shot receipt. A dropped receipt keeps
        // this barrier active so close cannot silently skip cleanup.
        if self.active_manual_finalizers.contains_key(&region_id) {
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

        // No spawn requests may still be sitting in the mailbox for this
        // region (br-asupersync-dx-core-api-v2-u1z5hn.1.2). Mirrors the gate
        // inside RegionRecord::complete_close.
        if region.pending_spawn_count() > 0 {
            return false;
        }

        true
    }

    /// Takes the regions whose advancement was deferred during leak handling,
    /// in ascending `RegionId` order.
    ///
    /// GH#55: the returned order is the order in which regions are closed and
    /// their parent chains walked, so it feeds directly into wake and cancel
    /// ordering. It must depend only on the region identities themselves —
    /// never on an ambient hash seed — or two lab runs with the same
    /// `LabConfig::seed` can diverge.
    fn take_deferred_region_advancements(&mut self) -> Vec<RegionId> {
        std::mem::take(&mut self.deferred_region_advancements)
            .into_iter()
            .collect()
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
                        // Child draining is not a region-protocol event: that
                        // validator intentionally has no child-count state.
                        // Project cancellation or normal close exactly once,
                        // here at the runtime's actual finalization boundary.
                        let finalization_event =
                            region
                                .cancel_reason()
                                .map_or(RegionEvent::RequestClose, |reason| RegionEvent::Cancel {
                                    reason: reason.to_string(),
                                });
                        let validation_result = self.validate_region_protocol_transition(
                            region_id,
                            finalization_event,
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
                        // RegionStateMachine has no child-count dimension, so
                        // keep this runtime-only transition out of its event
                        // projection. Finalization above emits the eventual
                        // Cancel or RequestClose after every child has closed.
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
                    if self.active_async_finalizers.contains_key(&region_id)
                        || self.active_manual_finalizers.contains_key(&region_id)
                    {
                        break;
                    }

                    // Region progression is frequently called beneath the
                    // scheduler's runtime-state mutex and from RegionRunner's
                    // destructor. Never invoke a user finalizer here. The
                    // scheduler drains the top LIFO entry into a masked task,
                    // then polls it only after releasing the state mutex.
                    if self
                        .regions
                        .get(region_id.arena_index())
                        .is_some_and(|region| !region.finalizers_empty())
                    {
                        break;
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
                        // Every registered finalizer emits its own completion
                        // transition when it actually retires. Closing a region
                        // before that accounting reaches Finalized is a protocol
                        // invariant violation, not an implicit extra completion.
                        let closed = {
                            let Some(region) = self.regions.get(region_id.arena_index()) else {
                                break;
                            };
                            let validation_result = {
                                let mut validator = self.cancel_protocol_validator.lock();
                                let validator_state = validator.region_state(region_id).cloned();
                                let already_finalized = matches!(
                                    validator_state,
                                    Some(
                                        crate::cancel::protocol_state_machines::RegionState::Finalized
                                    )
                                );
                                if already_finalized {
                                    TransitionResult::Valid
                                } else {
                                    validator.record_region_invariant_violation_without_logging(
                                        region_id,
                                        "runtime region close requires terminal finalizer accounting",
                                        format!("validator state at close: {validator_state:?}"),
                                    )
                                }
                            };
                            if matches!(
                                validation_result,
                                TransitionResult::Invalid { .. }
                                    | TransitionResult::InvariantViolation { .. }
                            ) {
                                log_cancel_protocol_violation(
                                    "region close completion",
                                    &validation_result,
                                );
                                self.read_biased_draining_region_snapshot.invalidate();
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
                            // Drop the region's cancel-protocol state machine too;
                            // otherwise `region_machines` leaks one entry per
                            // region ever opened
                            // (br-asupersync-cancelvalidator-leak-mdvuf9).
                            self.cancel_protocol_validator
                                .lock()
                                .remove_region(region_id);
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
    /// Open database transaction.
    Transaction,
}

impl From<ObligationKind> for ObligationKindSnapshot {
    fn from(kind: ObligationKind) -> Self {
        match kind {
            ObligationKind::SendPermit => Self::SendPermit,
            ObligationKind::Ack => Self::Ack,
            ObligationKind::Lease => Self::Lease,
            ObligationKind::IoOp => Self::IoOp,
            ObligationKind::SemaphorePermit => Self::SemaphorePermit,
            ObligationKind::Transaction => Self::Transaction,
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
    /// A spawn request was enqueued onto the spawn mailbox (pre-admission).
    TaskSpawnEnqueued,
    /// A mailbox spawn request was admitted into its region (task created).
    TaskAdmitted,
    /// A server request region installed its request budget.
    BudgetInstalled,
    /// A server request region's budget was consumed/resolved.
    BudgetConsumed,
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
            TraceEventKind::TaskSpawnEnqueued => Self::TaskSpawnEnqueued,
            TraceEventKind::TaskAdmitted => Self::TaskAdmitted,
            TraceEventKind::BudgetInstalled => Self::BudgetInstalled,
            TraceEventKind::BudgetConsumed => Self::BudgetConsumed,
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
    /// Server request-region budget data.
    Budget {
        /// Request task.
        task: IdSnapshot,
        /// Request region.
        region: IdSnapshot,
        /// Transport protocol token.
        protocol: String,
        /// Deadline in nanoseconds, if any.
        deadline_ns: Option<u64>,
        /// Poll quota.
        poll_quota: u64,
        /// Cost quota, if any.
        cost_quota: Option<u64>,
        /// Scheduling priority.
        priority: u8,
        /// Budget source token (install events).
        source: Option<String>,
        /// Elapsed nanoseconds (consume events).
        elapsed_ns: Option<u64>,
        /// Outcome token (consume events).
        outcome: Option<String>,
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
            TraceData::Budget {
                task,
                region,
                protocol,
                deadline_ns,
                poll_quota,
                cost_quota,
                priority,
                source,
                elapsed_ns,
                outcome,
            } => Self::Budget {
                task: (*task).into(),
                region: (*region).into(),
                protocol: protocol.clone(),
                deadline_ns: *deadline_ns,
                poll_quota: *poll_quota,
                cost_quota: *cost_quota,
                priority: *priority,
                source: source.clone(),
                elapsed_ns: *elapsed_ns,
                outcome: outcome.clone(),
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
pub(crate) mod completion_observer_test_support {
    use super::*;
    use crate::sync::ContendedMutex;
    use std::sync::{Mutex, Weak};

    struct PanickingDropPayload(Arc<AtomicUsize>);

    impl Drop for PanickingDropPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
            panic!("adversarial panic-payload destructor");
        }
    }

    /// Deterministic adversarial provider shared by completion-path tests.
    pub struct PanickingCompletionMetrics {
        state: Mutex<Option<Weak<ContendedMutex<RuntimeState>>>>,
        completion_attempts: AtomicUsize,
        reentry_successes: AtomicUsize,
        completed_state_observed: AtomicUsize,
        completion_panics_remaining: AtomicUsize,
        panic_payload_drop_counter: Option<Arc<AtomicUsize>>,
        panic_while_recording_task_panic: AtomicBool,
        provider_drop_attempts: Option<Arc<AtomicUsize>>,
        provider_drop_while_state_locked: Option<Arc<AtomicUsize>>,
        panic_on_provider_drop: bool,
    }

    impl PanickingCompletionMetrics {
        fn with_completion_panics(completion_panics_remaining: usize) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(completion_panics_remaining),
                panic_payload_drop_counter: None,
                panic_while_recording_task_panic: AtomicBool::new(false),
                provider_drop_attempts: None,
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn panic_once() -> Arc<Self> {
            Self::with_completion_panics(1)
        }

        pub(crate) fn panic_persistently() -> Arc<Self> {
            Self::with_completion_panics(usize::MAX)
        }

        pub(crate) fn panic_with_panicking_drop_payload(
            drop_counter: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(1),
                panic_payload_drop_counter: Some(drop_counter),
                panic_while_recording_task_panic: AtomicBool::new(false),
                provider_drop_attempts: None,
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn provider_drop_probe(
            drop_attempts: Arc<AtomicUsize>,
            drop_while_state_locked: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(0),
                panic_payload_drop_counter: None,
                panic_while_recording_task_panic: AtomicBool::new(false),
                provider_drop_attempts: Some(drop_attempts),
                provider_drop_while_state_locked: Some(drop_while_state_locked),
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn panic_callback_and_provider_drop(
            drop_attempts: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(1),
                panic_payload_drop_counter: None,
                panic_while_recording_task_panic: AtomicBool::new(false),
                provider_drop_attempts: Some(drop_attempts),
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: true,
            })
        }

        pub(crate) fn panic_persistently_and_trigger_guard_drop() -> Arc<Self> {
            let metrics = Self::panic_persistently();
            metrics
                .panic_while_recording_task_panic
                .store(true, Ordering::Relaxed);
            metrics
        }

        pub(crate) fn attach_state(&self, state: &Arc<ContendedMutex<RuntimeState>>) {
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(state));
        }

        pub(crate) fn completion_attempts(&self) -> usize {
            self.completion_attempts.load(Ordering::Relaxed)
        }

        pub(crate) fn reentry_successes(&self) -> usize {
            self.reentry_successes.load(Ordering::Relaxed)
        }

        pub(crate) fn completed_state_observed(&self) -> usize {
            self.completed_state_observed.load(Ordering::Relaxed)
        }

        fn should_panic_on_completion(&self) -> bool {
            self.completion_panics_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    if remaining == 0 {
                        None
                    } else if remaining == usize::MAX {
                        Some(usize::MAX)
                    } else {
                        Some(remaining - 1)
                    }
                })
                .is_ok()
        }
    }

    impl MetricsProvider for PanickingCompletionMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}

        fn task_completed(&self, task_id: TaskId, _: OutcomeKind, _: Duration) {
            self.completion_attempts.fetch_add(1, Ordering::Relaxed);
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if let Some(state) = state
                && let Ok(runtime) = state.try_lock()
            {
                self.reentry_successes.fetch_add(1, Ordering::Relaxed);
                if runtime.task(task_id).is_none() {
                    self.completed_state_observed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            if self.should_panic_on_completion() {
                if let Some(drop_counter) = &self.panic_payload_drop_counter {
                    std::panic::panic_any(PanickingDropPayload(Arc::clone(drop_counter)));
                }
                panic!("adversarial task-completion metrics callback");
            }
        }

        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

        fn region_closed(&self, _: RegionId, _: Duration) {}

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

        fn record_panic(&self, _: &'static str) {
            if self
                .panic_while_recording_task_panic
                .load(Ordering::Relaxed)
            {
                panic!("force TaskExecutionGuard unwind fallback");
            }
        }
    }

    impl Drop for PanickingCompletionMetrics {
        fn drop(&mut self) {
            let Some(drop_attempts) = &self.provider_drop_attempts else {
                return;
            };
            drop_attempts.fetch_add(1, Ordering::Relaxed);

            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if state.is_some_and(|state| state.try_lock().is_err())
                && let Some(locked_drops) = &self.provider_drop_while_state_locked
            {
                locked_drops.fetch_add(1, Ordering::Relaxed);
            }
            assert!(
                !self.panic_on_provider_drop,
                "adversarial metrics-provider destructor"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod spawn_observer_test_support {
    use super::*;
    use crate::sync::ContendedMutex;
    use std::sync::{Mutex, Weak};

    /// Reentrant, persistently panicking provider for spawn-publication tests.
    pub struct PanickingSpawnMetrics {
        state: Mutex<Option<Weak<ContendedMutex<RuntimeState>>>>,
        spawn_attempts: AtomicUsize,
        reentry_successes: AtomicUsize,
        task_records_observed: AtomicUsize,
        stored_futures_observed: AtomicUsize,
        runnable_publications_observed: AtomicUsize,
    }

    impl PanickingSpawnMetrics {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                spawn_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                task_records_observed: AtomicUsize::new(0),
                stored_futures_observed: AtomicUsize::new(0),
                runnable_publications_observed: AtomicUsize::new(0),
            })
        }

        pub(crate) fn attach_state(&self, state: &Arc<ContendedMutex<RuntimeState>>) {
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(state));
        }

        pub(crate) fn spawn_attempts(&self) -> usize {
            self.spawn_attempts.load(Ordering::Relaxed)
        }

        pub(crate) fn reentry_successes(&self) -> usize {
            self.reentry_successes.load(Ordering::Relaxed)
        }

        pub(crate) fn task_records_observed(&self) -> usize {
            self.task_records_observed.load(Ordering::Relaxed)
        }

        pub(crate) fn stored_futures_observed(&self) -> usize {
            self.stored_futures_observed.load(Ordering::Relaxed)
        }

        pub(crate) fn runnable_publications_observed(&self) -> usize {
            self.runnable_publications_observed.load(Ordering::Relaxed)
        }
    }

    impl MetricsProvider for PanickingSpawnMetrics {
        fn task_spawned(&self, _: RegionId, task_id: TaskId) {
            self.spawn_attempts.fetch_add(1, Ordering::Relaxed);
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if let Some(state) = state
                && let Ok(mut runtime) = state.try_lock()
            {
                self.reentry_successes.fetch_add(1, Ordering::Relaxed);
                if let Some(task) = runtime.task(task_id) {
                    self.task_records_observed.fetch_add(1, Ordering::Relaxed);
                    if task
                        .cx_inner
                        .as_ref()
                        .is_some_and(|inner| inner.read().runnable_publication.is_published())
                    {
                        self.runnable_publications_observed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                if runtime.get_stored_future(task_id).is_some() {
                    self.stored_futures_observed.fetch_add(1, Ordering::Relaxed);
                }
            }
            panic!("adversarial task-spawn metrics callback");
        }

        fn task_completed(&self, _: TaskId, _: OutcomeKind, _: Duration) {}
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, _: RegionId, _: Duration) {}
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
}

#[cfg(test)]
#[path = "state_metamorphic.rs"]
mod state_metamorphic;
#[cfg(test)]
#[allow(clippy::too_many_lines)]
#[path = "state_tests.rs"]
mod tests;
