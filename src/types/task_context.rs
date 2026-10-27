//! Internal task context state shared between [`crate::record::TaskRecord`] and
//! [`crate::cx::Cx`].
//!
//! This module provides core types for managing task execution context,
//! including cancellation masking, progress tracking, and capability budgets.
//! The types here bridge the runtime's internal [`crate::record::TaskRecord`]
//! bookkeeping with the user-facing [`crate::cx::Cx`] API.
//!
//! # Key Components
//!
//! - **Mask tracking**: [`MAX_MASK_DEPTH`] and mask state for cancellation masking
//! - **Progress reporting**: Checkpoint tracking for detecting stuck tasks
//! - **Capability budgets**: Resource limits that flow with task context
//! - **Runtime coordination**: State that coordinates between Cx and TaskRecord
//!
//! # Design Principles
//!
//! - **Finite masking**: Mask depth is bounded to prevent indefinite cancellation deferral
//! - **Progress observability**: Tasks must demonstrate forward progress through checkpoints
//! - **Resource accounting**: Budgets are tracked and enforced at the task level

use crate::observability::metrics::MetricsProvider;
use crate::types::{Budget, CancelKind, CancelReason, CapabilityBudget, RegionId, TaskId, Time};
use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Waker;

/// A cancellation wake target whose reference-count operations never invoke
/// user-provided `RawWaker` callbacks.
///
/// The contained `Waker` is cloned before this target is installed and is
/// retired only after the owning `CxInner` lock has been released. Cancellation
/// paths may therefore clone `Arc<CancelWaker>` while locked, then invoke the
/// actual wake callback after unlocking.
#[derive(Debug)]
#[doc(hidden)]
pub struct CancelWaker {
    waker: Waker,
}

impl CancelWaker {
    /// Prepare a wake target. Callers must invoke this without a `CxInner` guard.
    #[inline]
    #[doc(hidden)]
    pub fn new(waker: Waker) -> Self {
        Self { waker }
    }

    /// Returns whether this target wakes the same task as `other`.
    #[inline]
    pub fn will_wake(&self, other: &Waker) -> bool {
        self.waker.will_wake(other)
    }

    /// Invoke the user-provided wake callback.
    #[inline]
    pub fn wake_by_ref(&self) {
        self.waker.wake_by_ref();
    }

    /// Swap the target of an exclusively owned (recycled) instance. The
    /// returned Waker must be dropped without a `CxInner` guard.
    #[inline]
    pub(crate) fn replace_waker(&mut self, waker: Waker) -> Waker {
        std::mem::replace(&mut self.waker, waker)
    }
}

/// Retired cancellation wake targets a context keeps for reuse, so repeated
/// cancel-aware waits stop allocating once a few targets exist.
pub(crate) const CANCEL_WAKER_POOL_CAP: usize = 4;

/// A detached cancellation wake target whose retirement delivers its wake.
///
/// Task completion closes the registry and hands every target to its caller,
/// which retires them after releasing its locks. A cancellation published
/// while the task ran, whose wakes were still deferred to a dispatch that
/// completion now pre-empts, wraps each target in this, so retiring it wakes
/// the waiter instead of dropping it unwoken (br-asupersync-v8yh9s T4).
struct WakeOnRetire(Arc<CancelWaker>);

impl std::task::Wake for WakeOnRetire {
    fn wake(self: Arc<Self>) {
        self.0.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake_by_ref();
    }
}

impl Drop for WakeOnRetire {
    fn drop(&mut self) {
        // The inner target is still dropped if its wake panics; leak only the
        // panic payload, whose own drop could panic again.
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.0.wake_by_ref()))
        {
            std::mem::forget(payload);
        }
    }
}

/// One exactly-owned auxiliary cancellation wake registration.
#[derive(Debug)]
pub(crate) struct CancelWakerRegistration {
    pub(crate) token: u64,
    pub(crate) target: Arc<CancelWaker>,
}

/// The timer that cancels a context when its budget deadline passes, so a task
/// parked in a cancel-aware wait learns of the deadline without reaching a
/// checkpoint (br-asupersync-pev2xi). Dropping it, with the context, removes the
/// timer from the wheel.
#[derive(Debug)]
pub(crate) struct BudgetDeadlineTimer {
    pub(crate) timer: crate::time::TimerDriverHandle,
    pub(crate) handle: crate::time::TimerHandle,
}

impl Drop for BudgetDeadlineTimer {
    fn drop(&mut self) {
        let _ = self.timer.cancel(&self.handle);
    }
}

/// Closed task-cancellation trace events that can cross the post-lock effect
/// boundary without retaining an arbitrary callback or destructor.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CancelTaskTraceKind {
    StrengthenedRequested,
    StrengthenedCleanup,
    Requested,
}

/// Bounded closed trace receipt retained while an admitted task has no
/// scheduler-visible lane. It owns only copyable data, never callbacks,
/// providers, Wakers, or user-controlled destructors.
#[cfg(feature = "tracing-integration")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingTaskCancelTrace {
    trace_kind: CancelTaskTraceKind,
    task_id: TaskId,
    region_id: RegionId,
    previous_state: &'static str,
    cancel_kind: CancelKind,
    cleanup_poll_quota: u32,
}

#[cfg(feature = "tracing-integration")]
impl PendingTaskCancelTrace {
    pub(crate) fn new(
        trace_kind: CancelTaskTraceKind,
        task_id: TaskId,
        region_id: RegionId,
        previous_state: &'static str,
        cancel_kind: CancelKind,
        cleanup_poll_quota: u32,
    ) -> Self {
        Self {
            trace_kind,
            task_id,
            region_id,
            previous_state,
            cancel_kind,
            cleanup_poll_quota,
        }
    }

    pub(crate) fn append_to(self, effects: &mut CancelWakeEffects) {
        effects.push_task_cancel_trace(
            self.trace_kind,
            self.task_id,
            self.region_id,
            self.previous_state,
            self.cancel_kind,
            self.cleanup_poll_quota,
        );
    }
}

/// Stamps a cancelled region with the runtime clock when its cancellation
/// report is dispatched, after the canceller released its locks. The region's
/// close reports its drain time from that stamp (br-asupersync-x9mmxl).
pub(crate) struct CancelReportStamp {
    pub(crate) stamp: Arc<std::sync::atomic::AtomicU64>,
    /// The runtime's timer driver; without one the runtime's time when the
    /// cancel was requested.
    pub(crate) timer: Option<crate::time::TimerDriverHandle>,
    pub(crate) fallback_now: Time,
}

impl CancelReportStamp {
    /// The earliest report wins; a later cancel of the same region keeps it.
    fn record(&self) {
        let now = self
            .timer
            .as_ref()
            .map_or(self.fallback_now, crate::time::TimerDriverHandle::now);
        self.record_at(now);
    }

    /// Stamps a time the caller read earlier, for example before taking the
    /// state lock under which no clock may be read.
    fn record_at(&self, now: Time) {
        self.stamp
            .fetch_min(now.as_nanos(), std::sync::atomic::Ordering::AcqRel);
    }
}

enum CancelObserver {
    #[cfg(feature = "tracing-integration")]
    TaskCancelTrace {
        trace_kind: CancelTaskTraceKind,
        task_id: TaskId,
        region_id: RegionId,
        previous_state: &'static str,
        cancel_kind: CancelKind,
        cleanup_poll_quota: u32,
    },
    RegionCancellationMetric {
        metrics: Option<Arc<dyn MetricsProvider>>,
        region_id: RegionId,
        cancel_kind: CancelKind,
        drain_stamp: Option<CancelReportStamp>,
    },
    CancelProtocolViolation {
        operation: &'static str,
        validation_result: String,
    },
}

impl CancelObserver {
    fn dispatch(mut self) {
        match &mut self {
            #[cfg(feature = "tracing-integration")]
            Self::TaskCancelTrace {
                trace_kind,
                task_id,
                region_id,
                previous_state,
                cancel_kind,
                cleanup_poll_quota,
            } => {
                let trace_kind = *trace_kind;
                let task_id = *task_id;
                let region_id = *region_id;
                let previous_state = *previous_state;
                let cancel_kind = *cancel_kind;
                let cleanup_poll_quota = *cleanup_poll_quota;
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match trace_kind {
                        CancelTaskTraceKind::StrengthenedRequested => {
                            crate::tracing_compat::trace!(
                                task_id = ?task_id,
                                region_id = ?region_id,
                                cancel_kind = ?cancel_kind,
                                "cancel reason strengthened (already CancelRequested)"
                            );
                        }
                        CancelTaskTraceKind::StrengthenedCleanup => {
                            crate::tracing_compat::trace!(
                                task_id = ?task_id,
                                region_id = ?region_id,
                                cancel_kind = ?cancel_kind,
                                "cancel reason strengthened (in cleanup)"
                            );
                        }
                        CancelTaskTraceKind::Requested => {
                            crate::tracing_compat::debug!(
                                task_id = ?task_id,
                                region_id = ?region_id,
                                old_state = previous_state,
                                new_state = "CancelRequested",
                                cancel_kind = ?cancel_kind,
                                cleanup_poll_quota,
                                "task cancel requested"
                            );
                        }
                    }))
                {
                    std::mem::forget(payload);
                }
            }
            Self::RegionCancellationMetric {
                metrics,
                region_id,
                cancel_kind,
                drain_stamp,
            } => {
                let metrics = metrics
                    .take()
                    .expect("live cancellation metric observer retains its provider");
                let region_id = *region_id;
                let cancel_kind = *cancel_kind;
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if let Some(drain_stamp) = drain_stamp.as_ref() {
                        drain_stamp.record();
                    }
                    metrics.cancellation_requested(region_id, cancel_kind);
                })) {
                    std::mem::forget(payload);
                }
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(metrics)))
                {
                    std::mem::forget(payload);
                }
            }
            Self::CancelProtocolViolation {
                operation,
                validation_result,
            } => {
                let operation = *operation;
                let validation_result = validation_result.as_str();
                // The compatibility macro is a true no-op when tracing is
                // disabled, so keep the closed fields visibly consumed in
                // that feature configuration as well.
                let _ = (operation, validation_result);
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::tracing_compat::error!(
                        operation,
                        validation_result = %validation_result,
                        "cancel protocol violation"
                    );
                })) {
                    std::mem::forget(payload);
                }
            }
        }
    }

    fn suppress(mut self) {
        match &mut self {
            #[cfg(feature = "tracing-integration")]
            Self::TaskCancelTrace { .. } => {}
            Self::RegionCancellationMetric { metrics, .. } => {
                if let Some(metrics) = metrics.take() {
                    std::mem::forget(metrics);
                }
            }
            Self::CancelProtocolViolation { .. } => {}
        }
    }
}

impl Drop for CancelObserver {
    fn drop(&mut self) {
        match self {
            #[cfg(feature = "tracing-integration")]
            Self::TaskCancelTrace { .. } => {}
            Self::RegionCancellationMetric { metrics, .. } => {
                if let Some(metrics) = metrics.take() {
                    std::mem::forget(metrics);
                }
            }
            Self::CancelProtocolViolation { .. } => {}
        }
    }
}

/// Opaque cancellation callbacks detached from a state mutation.
///
/// Callers must release every task-table, region, runtime-state, and
/// application lock before calling [`Self::dispatch`]. Dropping an
/// undispatched token leaks its retained wake handles and observer callbacks:
/// that fail-closed behavior avoids invoking arbitrary `RawWaker` callbacks,
/// observability hooks, or their destructors beneath an unknown caller-owned
/// lock.
#[doc(hidden)]
#[must_use = "cancellation wake effects must be dispatched after releasing outer locks"]
pub struct CancelWakeEffects {
    targets: Option<smallvec::SmallVec<[Arc<CancelWaker>; 4]>>,
    observers: Option<smallvec::SmallVec<[CancelObserver; 1]>>,
}

impl std::fmt::Debug for CancelWakeEffects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelWakeEffects")
            .field(
                "target_count",
                &self.targets.as_ref().map_or(0, |targets| targets.len()),
            )
            .field(
                "observer_count",
                &self
                    .observers
                    .as_ref()
                    .map_or(0, |observers| observers.len()),
            )
            .finish_non_exhaustive()
    }
}

impl Default for CancelWakeEffects {
    fn default() -> Self {
        Self::empty()
    }
}

impl CancelWakeEffects {
    /// Creates an empty callback token.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            targets: Some(smallvec::SmallVec::new()),
            observers: Some(smallvec::SmallVec::new()),
        }
    }

    /// Wraps targets already snapshotted under their owning `Cx` lock.
    #[inline]
    pub(crate) fn new(targets: smallvec::SmallVec<[Arc<CancelWaker>; 4]>) -> Self {
        Self {
            targets: Some(targets),
            observers: Some(smallvec::SmallVec::new()),
        }
    }

    /// Adds a closed task-cancellation trace event for post-lock dispatch.
    #[cfg(feature = "tracing-integration")]
    pub(crate) fn push_task_cancel_trace(
        &mut self,
        trace_kind: CancelTaskTraceKind,
        task_id: TaskId,
        region_id: RegionId,
        previous_state: &'static str,
        cancel_kind: CancelKind,
        cleanup_poll_quota: u32,
    ) {
        self.observers
            .as_mut()
            .expect("dispatched cancellation effects cannot be reused")
            .push(CancelObserver::TaskCancelTrace {
                trace_kind,
                task_id,
                region_id,
                previous_state,
                cancel_kind,
                cleanup_poll_quota,
            });
    }

    /// Adds a metrics event for post-lock dispatch. The concrete provider is
    /// retired in its own unwind boundary after the callback returns or panics.
    pub(crate) fn push_region_cancellation_metric(
        &mut self,
        metrics: Arc<dyn MetricsProvider>,
        region_id: RegionId,
        cancel_kind: CancelKind,
        drain_stamp: Option<CancelReportStamp>,
    ) {
        self.observers
            .as_mut()
            .expect("dispatched cancellation effects cannot be reused")
            .push(CancelObserver::RegionCancellationMetric {
                metrics: Some(metrics),
                region_id,
                cancel_kind,
                drain_stamp,
            });
    }

    /// Adds a closed protocol-violation diagnostic for post-lock dispatch.
    /// Formatting the internal validator result before enqueueing avoids
    /// retaining a generic callback or runtime-state reference.
    pub(crate) fn push_cancel_protocol_violation(
        &mut self,
        operation: &'static str,
        validation_result: String,
    ) {
        self.observers
            .as_mut()
            .expect("dispatched cancellation effects cannot be reused")
            .push(CancelObserver::CancelProtocolViolation {
                operation,
                validation_result,
            });
    }

    /// Returns the number of distinct wake callbacks retained by this token.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.as_ref().map_or(0, |targets| targets.len())
    }

    /// Returns whether the token contains no wake callbacks.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends another token without running callbacks or final destructors.
    ///
    /// Capacity is established before ownership moves. If allocation unwinds,
    /// both tokens still own their original handles and their fail-closed Drop
    /// implementations leak them rather than invoking user code under the
    /// caller's lock.
    pub(crate) fn merge(&mut self, mut other: Self) {
        let incoming_len = other.targets.as_ref().map_or(0, |targets| targets.len());
        let incoming_observer_len = other
            .observers
            .as_ref()
            .map_or(0, |observers| observers.len());
        if incoming_len == 0 && incoming_observer_len == 0 {
            return;
        }
        let targets = self
            .targets
            .as_mut()
            .expect("dispatched cancellation wake effects cannot be reused");
        targets.reserve(incoming_len);
        let observers = self
            .observers
            .as_mut()
            .expect("dispatched cancellation effects cannot be reused");
        observers.reserve(incoming_observer_len);
        let incoming = other
            .targets
            .take()
            .expect("live cancellation wake effects retain their targets");
        let incoming_observers = other
            .observers
            .take()
            .expect("live cancellation effects retain their observers");
        targets.extend(incoming);
        observers.extend(incoming_observers);
    }

    /// Invokes every observer and wake callback, then retires every retained
    /// target.
    ///
    /// Observer, wake, and final-drop panics are isolated per target so one
    /// hostile callback cannot prevent later tasks or auxiliary waiters from
    /// observing cancellation. Panic payloads are deliberately leaked after
    /// capture: dropping an arbitrary payload can panic again at this boundary.
    pub fn dispatch(mut self) {
        let observers = self.observers.take().unwrap_or_default();
        for observer in observers {
            observer.dispatch();
        }
        let targets = self.targets.take().unwrap_or_default();
        for target in targets {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                target.wake_by_ref();
            })) {
                std::mem::forget(payload);
            }
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(target)))
            {
                std::mem::forget(payload);
            }
        }
    }

    /// Stamps the drain start of every cancelled region this token reports,
    /// running no callback. A scheduler that makes cancelled tasks runnable
    /// before it dispatches this token calls it first: otherwise another
    /// worker could finish the drain and close the region before its stamp
    /// is written, and the drain would go unreported (br-asupersync-x9mmxl).
    /// The dispatch that follows keeps the earlier stamp.
    pub(crate) fn stamp_drains(&self) {
        for stamp in self.drain_stamps() {
            stamp.record();
        }
    }

    /// Like [`Self::stamp_drains`], with a time the caller read before
    /// taking the state lock it still holds: no clock is read here.
    pub(crate) fn stamp_drains_at(&self, now: Time) {
        for stamp in self.drain_stamps() {
            stamp.record_at(now);
        }
    }

    fn drain_stamps(&self) -> impl Iterator<Item = &CancelReportStamp> {
        self.observers
            .iter()
            .flatten()
            .filter_map(|observer| match observer {
                CancelObserver::RegionCancellationMetric {
                    drain_stamp: Some(stamp),
                    ..
                } => Some(stamp),
                _ => None,
            })
    }

    /// Explicitly abandons callbacks when no post-lock dispatch boundary is
    /// available (for example, panic-unwind Drop cleanup).
    pub fn suppress(mut self) {
        if let Some(observers) = self.observers.take() {
            for observer in observers {
                observer.suppress();
            }
        }
        let Some(targets) = self.targets.take() else {
            return;
        };
        for target in targets {
            std::mem::forget(target);
        }
    }

    /// Suppresses observer delivery and retires duplicate Waker snapshots
    /// without invoking them. Call only after every outer runtime/task lock is
    /// released. Each final RawWaker destructor is isolated so a failed route
    /// cannot unwind through the cancellation consumer.
    pub(crate) fn retire_without_dispatch(mut self) {
        if let Some(observers) = self.observers.take() {
            for observer in observers {
                observer.suppress();
            }
        }
        let Some(mut targets) = self.targets.take() else {
            return;
        };
        while let Some(target) = targets.pop() {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(target)))
            {
                std::mem::forget(payload);
            }
        }
    }
}

impl Drop for CancelWakeEffects {
    fn drop(&mut self) {
        if let Some(observers) = self.observers.take() {
            std::mem::forget(observers);
        }
        let Some(targets) = self.targets.take() else {
            return;
        };
        for target in targets {
            std::mem::forget(target);
        }
    }
}

/// A state-mutation result paired with cancellation wake callbacks.
///
/// The value is available only by consuming the token through
/// [`Self::into_parts`], making both the callback-free publication step and
/// the post-lock callback boundary explicit at every `RuntimeState` call
/// site.
///
/// Abandonment leaks both the callback-free value and the retained wake
/// targets. This is deliberately conservative: an effect token may be dropped
/// while a caller-owned lock is live, so even a future `T` destructor must not
/// become a hidden callback boundary.
#[derive(Debug)]
#[doc(hidden)]
#[must_use = "cancellation effects must be consumed after releasing outer locks"]
pub struct CancellationEffects<T> {
    value: Option<T>,
    wakes: CancelWakeEffects,
}

impl<T> CancellationEffects<T> {
    /// Couples a mutation result to its deferred callbacks.
    #[inline]
    pub(crate) fn new(value: T, wakes: CancelWakeEffects) -> Self {
        Self {
            value: Some(value),
            wakes,
        }
    }

    /// Couples a result to an empty callback token.
    #[inline]
    pub(crate) fn ready(value: T) -> Self {
        Self::new(value, CancelWakeEffects::empty())
    }

    /// Stamps the drains this token reports with a time read before the
    /// caller's state lock (see [`CancelWakeEffects::stamp_drains_at`]).
    pub(crate) fn stamp_drains_at(&self, now: Time) {
        self.wakes.stamp_drains_at(now);
    }

    /// Splits the callback-free value from the token that must be dispatched
    /// after the caller releases its outermost state lock.
    #[inline]
    pub fn into_parts(mut self) -> (T, CancelWakeEffects) {
        let value = self
            .value
            .take()
            .expect("live cancellation effects retain their value");
        let wakes = std::mem::take(&mut self.wakes);
        (value, wakes)
    }
}

impl<T> Drop for CancellationEffects<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            std::mem::forget(value);
        }
    }
}

/// Maximum nesting depth for `Cx::masked()` sections.
///
/// Enforces the INV-MASK-BOUNDED invariant from the formal semantics:
/// a task's mask depth must be finite and bounded to guarantee that
/// cancellation cannot be deferred indefinitely. Exceeding this limit
/// indicates a programming error (excessive nesting of masked critical
/// sections).
pub const MAX_MASK_DEPTH: u32 = 64;

/// Maximum depth for the thread-local context stack.
///
/// Enforces a bounded limit on the depth of nested `set_current_restricted()` and
/// `push_restriction()` calls to prevent stack overflow in pathological cases.
/// Exceeding this limit indicates a programming error (excessive nesting of
/// context restrictions) and will cause a panic.
///
/// This limit is set lower than `MAX_MASK_DEPTH` as context stack operations
/// are typically less common than masking operations, but still allows for
/// reasonable nesting scenarios.
pub const MAX_CONTEXT_STACK_DEPTH: usize = 32;

/// Default number of message checkpoints retained per task.
pub const DEFAULT_CHECKPOINT_HISTORY_CAPACITY: usize = 8;

/// Hard cap on retained message checkpoints per task.
pub const MAX_CHECKPOINT_HISTORY_CAPACITY: usize = 64;

/// Maximum bytes retained for one checkpoint history message.
pub const MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES: usize = 64;

/// One retained checkpoint message entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointHistoryEntry {
    /// Runtime time when the checkpoint was recorded.
    pub at: Time,
    /// Bounded checkpoint message.
    pub message: String,
}

/// State for tracking checkpoint progress.
///
/// This struct tracks progress reporting checkpoints, which are distinct from
/// cancellation checkpoints. Progress checkpoints indicate that a task is
/// making forward progress and are useful for:
/// - Detecting stuck/stalled tasks
/// - Work-stealing scheduler decisions
/// - Observability and debugging
#[derive(Debug, Clone)]
pub struct CheckpointState {
    /// The runtime time of the last checkpoint.
    pub last_checkpoint: Option<Time>,
    /// The message from the last `checkpoint_with()` call.
    pub last_message: Option<String>,
    /// The total number of checkpoints recorded.
    pub checkpoint_count: u64,
    /// Bounded oldest-to-newest history of message checkpoints.
    history: VecDeque<CheckpointHistoryEntry>,
    /// Maximum number of message checkpoints to retain.
    history_capacity: usize,
}

impl CheckpointState {
    /// Creates a new checkpoint state with no recorded checkpoints.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a checkpoint state with a specific message-history capacity.
    #[must_use]
    pub fn with_history_capacity(capacity: usize) -> Self {
        let mut state = Self::default();
        state.set_history_capacity(capacity);
        state
    }

    /// Returns the configured message-history capacity.
    #[inline]
    #[must_use]
    pub const fn history_capacity(&self) -> usize {
        self.history_capacity
    }

    /// Configures the message-history capacity.
    pub fn set_history_capacity(&mut self, capacity: usize) {
        self.history_capacity = capacity.min(MAX_CHECKPOINT_HISTORY_CAPACITY);
        while self.history.len() > self.history_capacity {
            self.history.pop_front();
        }
        if self.history_capacity == 0 {
            self.history.clear();
        }
    }

    /// Returns the oldest-to-newest message checkpoint history.
    ///
    /// Only `checkpoint_with(msg)` calls append to this ring; messageless
    /// `checkpoint()` calls update the count and time without touching the
    /// history (see [`Self::record_at`]).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::types::{CheckpointState, Time};
    ///
    /// let mut state = CheckpointState::with_history_capacity(4);
    /// state.record_with_message_at("connect".to_string(), Time::from_nanos(1));
    /// state.record_with_message_at("auth".to_string(), Time::from_nanos(2));
    /// state.record_with_message_at("query".to_string(), Time::from_nanos(3));
    ///
    /// let trail = state.history();
    /// assert_eq!(trail.len(), 3);
    /// assert_eq!(trail.first().map(|e| e.message.as_str()), Some("connect"));
    /// assert_eq!(trail.last().map(|e| e.message.as_str()), Some("query"));
    /// ```
    #[must_use]
    pub fn history(&self) -> Vec<CheckpointHistoryEntry> {
        self.history.iter().cloned().collect()
    }

    /// Records a checkpoint without a message.
    ///
    /// br-asupersync-soyet0 — The no-suffix `record()` form reaches for
    /// `crate::time::wall_now()` directly, which is ambient authority
    /// (escapes capability-scoped time and breaks deterministic replay
    /// under [`crate::lab::LabRuntime`]). Production callers MUST use
    /// [`Self::record_at`] with `cx.now()` instead, threading time through the
    /// `Cx` they already hold. This shim is gated to test/test-internals
    /// to keep ergonomics for inline tests while preventing production
    /// regressions.
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    pub fn record(&mut self) {
        self.record_at(crate::time::wall_now());
    }

    /// Records a checkpoint at an explicit runtime time.
    #[inline]
    pub fn record_at(&mut self, at: Time) {
        self.last_checkpoint = Some(at);
        self.last_message = None;
        self.checkpoint_count += 1;
    }

    /// Records a checkpoint with a message.
    ///
    /// br-asupersync-soyet0 — Same ambient-time concern as
    /// [`Self::record`]; gated to test/test-internals. Production callers
    /// MUST use [`Self::record_with_message_at(msg, cx.now())`].
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    pub fn record_with_message(&mut self, message: String) {
        self.record_with_message_at(message, crate::time::wall_now());
    }

    /// Records a checkpoint with a message at an explicit runtime time.
    #[inline]
    pub fn record_with_message_at(&mut self, message: String, at: Time) {
        let bounded = truncate_checkpoint_history_message(&message);
        self.last_checkpoint = Some(at);
        self.last_message = Some(message);
        self.checkpoint_count += 1;
        if self.history_capacity > 0 {
            if self.history.len() == self.history_capacity {
                self.history.pop_front();
            }
            self.history.push_back(CheckpointHistoryEntry {
                at,
                message: bounded,
            });
        }
    }
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self {
            last_checkpoint: None,
            last_message: None,
            checkpoint_count: 0,
            history: VecDeque::new(),
            history_capacity: DEFAULT_CHECKPOINT_HISTORY_CAPACITY,
        }
    }
}

fn truncate_checkpoint_history_message(message: &str) -> String {
    if message.len() <= MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES {
        return message.to_owned();
    }

    let mut end = MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

/// State of a task's first scheduler-runnable publication boundary.
///
/// Mailbox admission starts at [`Self::Unpublished`]. A cached managed-handle
/// abort moves to [`Self::DelegatedCancel`], reserving the first lane for the
/// runtime-owned handle-command consumer without pretending that the lane is
/// already visible. Only the code that has physically published a lane may
/// transition to [`Self::Published`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnablePublication {
    /// No lane has been published or delegated yet.
    Unpublished,
    /// The handle-command consumer owns the initial cancel-lane publication.
    DelegatedCancel,
    /// At least one scheduler lane is physically visible for the task.
    Published,
}

impl RunnablePublication {
    #[inline]
    pub(crate) const fn is_published(self) -> bool {
        matches!(self, Self::Published)
    }

    #[inline]
    pub(crate) const fn is_delegated_cancel(self) -> bool {
        matches!(self, Self::DelegatedCancel)
    }

    #[inline]
    pub(crate) fn delegate_cancel(&mut self) {
        debug_assert!(
            matches!(self, Self::Unpublished),
            "only an unpublished admission can delegate its first cancel lane"
        );
        if matches!(self, Self::Unpublished) {
            *self = Self::DelegatedCancel;
        }
    }

    #[inline]
    pub(crate) fn mark_published(&mut self) {
        *self = Self::Published;
    }
}

/// Stable cancellation publication state shared by one capability context.
///
/// Keeping the scheduler name as a crate-private alias lets the restored 0.4.3
/// `fast_cancel: Arc<AtomicBool>` field and every runtime-owned publisher share
/// one allocation and one Release/Acquire publication point.
pub(crate) type CxCancellationState = std::sync::atomic::AtomicBool;

/// Internal state for a capability context.
///
/// This struct is shared between the user-facing `Cx` and the runtime's
/// `TaskRecord`, ensuring that cancellation signals and budget updates
/// are synchronized.
#[derive(Debug)]
pub struct CxInner {
    /// The region this context belongs to.
    pub region: RegionId,
    /// The task this context belongs to.
    pub task: TaskId,
    /// Optional task type label for adaptive monitoring/metrics.
    pub task_type: Option<String>,
    /// Current budget.
    pub budget: Budget,
    /// Baseline budget used for checkpoint accounting.
    pub budget_baseline: Budget,
    /// The native `block_on` driver charges the actual root future's polls.
    /// Its local accounting task must not also spend that quota on admission,
    /// cancellation bookkeeping, or retirement. Installed before admission
    /// publishes the task; ordinary child tasks never inherit this flag.
    pub(crate) caller_owned_poll_quota: bool,
    /// Explicit capability/resource envelope carried by this context.
    pub capability_budget: CapabilityBudget,
    /// Whether cancellation has been requested.
    pub cancel_requested: bool,
    /// The reason for cancellation, if requested.
    pub cancel_reason: Option<CancelReason>,
    /// Whether cancellation has been acknowledged at a checkpoint.
    pub cancel_acknowledged: bool,
    /// Whether the current effective cancellation still owes one Waker
    /// publication at a runtime-owned scheduler boundary.
    ///
    /// Direct `Cx` cancellation APIs snapshot and dispatch immediately and
    /// leave this false. Task-handle and checkpoint-budget producers cannot
    /// invoke callbacks at their mutation site, so they set it true and the
    /// scheduler-side reconciliation clears it after snapshotting exactly
    /// once.
    pub(crate) cancel_wakers_pending: bool,
    /// State of the task's first scheduler-runnable publication boundary.
    /// The delegated state prevents a cached handle abort from being mistaken
    /// for a lane that is already physically visible.
    pub(crate) runnable_publication: RunnablePublication,
    /// First closed task-cancellation trace produced before the task's initial
    /// scheduler lane exists. Later prepublication strengthening traces are
    /// intentionally coalesced into this bounded receipt.
    #[cfg(feature = "tracing-integration")]
    pub(crate) pending_task_cancel_trace: Option<PendingTaskCancelTrace>,
    /// Runtime-owned command gateway used by task handles to enqueue
    /// cancellation without invoking arbitrary Waker callbacks on the caller
    /// or `Drop` stack.
    pub(crate) cancel_gateway: Option<Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    /// Runtime-owned Waker used to put this task on the cancellation lane.
    pub cancel_waker: Option<Arc<CancelWaker>>,
    /// Idempotent compatibility slot for callers that cannot retain a token.
    pub(crate) untracked_cancel_waker: Option<Arc<CancelWaker>>,
    /// Exactly-owned wake registrations for cancel-aware child futures.
    pub(crate) cancel_waker_registrations: Vec<CancelWakerRegistration>,
    /// Retired, exclusively owned wake targets (holding a no-op Waker) for the
    /// next registration; at most [`CANCEL_WAKER_POOL_CAP`].
    pub(crate) cancel_waker_pool: Vec<Arc<CancelWaker>>,
    /// Monotonic source for live registration tokens. Zero is reserved for the
    /// closed-registry sentinel and is never stored in the registration table.
    pub(crate) next_cancel_waker_token: u64,
    /// Set when task completion detaches the registry permanently.
    pub(crate) cancel_waker_registry_closed: bool,
    /// Timer armed at the budget deadline (br-asupersync-pev2xi).
    pub(crate) budget_deadline_timer: Option<BudgetDeadlineTimer>,
    /// Async-finalizer infrastructure keeps its legacy masked deadline
    /// handling when its context enters a caller-driven adapter. This is
    /// separate from cleanup_phase so poll-quota inheritance is unchanged.
    pub(crate) budget_deadline_exempt: bool,
    /// Current mask depth.
    pub mask_depth: u32,
    /// The task runs cancellation or terminal lifecycle cleanup, including a
    /// GenServer's graceful drain/stop. Native poll quotas stay advisory here
    /// and do not constrain work spawned by cleanup helpers. The lab retains
    /// its stricter cleanup accounting (br-asupersync-0fvvq9).
    pub(crate) cleanup_phase: bool,
    /// Progress checkpoint state.
    pub checkpoint_state: CheckpointState,
    /// Fast atomic cancellation flag retained for 0.4.3 compatibility.
    ///
    /// Runtime mutation methods keep this flag synchronized with
    /// [`Self::cancel_requested`] and the internal publication envelope.
    pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Stable fast cancellation envelope shared with every `Cx` clone and
    /// runtime-owned cancellation producer for this context.
    cancellation: std::sync::Arc<CxCancellationState>,
    /// Fast-path checkpoint count: incremented when
    /// [`crate::cx::Cx::checkpoint`] takes the no-cancellation fast path
    /// (br-asupersync-is2xg0). Drained into
    /// [`CheckpointState::checkpoint_count`] on the next slow-path call or
    /// when the materialised view is requested.
    pub fast_path_count: std::sync::atomic::AtomicU64,
    /// Fast-path last checkpoint time (ns since [`Time::ZERO`]). 0 means no
    /// fast-path checkpoint has been recorded since the last drain. Drained
    /// into [`CheckpointState::last_checkpoint`] on the next slow-path call
    /// or when the materialised view is requested. Stored as a plain
    /// `AtomicU64` because [`Time`] is just a `u64` nanos counter.
    pub fast_path_last_checkpoint_ns: std::sync::atomic::AtomicU64,
    /// Retirement barrier the scheduler opens after this task's record reaches
    /// a terminal state in the post-lock completion dispatch, releasing any
    /// consumer that received the task's terminal result early
    /// (br-asupersync-yhueis). `None` for tasks whose join handles already
    /// carry an open barrier (standalone handles, admission denial), or paths
    /// not yet wired — those deliver immediately as before.
    pub(crate) retirement_barrier:
        Option<std::sync::Arc<crate::runtime::task_handle::RetirementBarrier>>,
    /// For a task admitted into a sealed (race-branch) region, the region
    /// that admits a spawn from this context once that region has closed
    /// (br-asupersync-k27oxe).
    pub(crate) spawn_fallback_region: Option<RegionId>,
}

impl CxInner {
    /// Creates a new CxInner.
    #[must_use]
    pub fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        let cancellation = std::sync::Arc::new(CxCancellationState::new(false));
        let fast_cancel = std::sync::Arc::clone(&cancellation);
        Self {
            region,
            task,
            task_type: None,
            budget,
            budget_baseline: budget,
            caller_owned_poll_quota: false,
            capability_budget: CapabilityBudget::UNSPECIFIED,
            cancel_requested: false,
            cancel_reason: None,
            cancel_acknowledged: false,
            cancel_wakers_pending: false,
            runnable_publication: RunnablePublication::Published,
            #[cfg(feature = "tracing-integration")]
            pending_task_cancel_trace: None,
            cancel_gateway: None,
            cancel_waker: None,
            untracked_cancel_waker: None,
            cancel_waker_registrations: Vec::new(),
            cancel_waker_pool: Vec::new(),
            next_cancel_waker_token: 0,
            cancel_waker_registry_closed: false,
            budget_deadline_timer: None,
            budget_deadline_exempt: false,
            mask_depth: 0,
            cleanup_phase: false,
            checkpoint_state: CheckpointState::new(),
            fast_cancel,
            cancellation,
            fast_path_count: std::sync::atomic::AtomicU64::new(0),
            fast_path_last_checkpoint_ns: std::sync::atomic::AtomicU64::new(0),
            retirement_barrier: None,
            spawn_fallback_region: None,
        }
    }

    /// Returns the stable cancellation envelope for contexts constructed from
    /// this exact inner lock.
    #[must_use]
    pub(crate) fn cancellation_state(&self) -> std::sync::Arc<CxCancellationState> {
        std::sync::Arc::clone(&self.cancellation)
    }

    /// Returns the published cancellation state without acquiring this
    /// context's `RwLock` again.
    #[inline]
    #[must_use]
    pub(crate) fn is_cancel_requested(&self) -> bool {
        self.cancel_requested || self.fast_cancel.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Changes lock-backed cancellation state and publishes the matching
    /// Release-ordered fast-path value as one operation.
    #[inline]
    pub(crate) fn set_cancel_requested(&mut self, value: bool) {
        self.cancel_requested = value;
        self.fast_cancel
            .store(value, std::sync::atomic::Ordering::Release);
        if !std::sync::Arc::ptr_eq(&self.fast_cancel, &self.cancellation) {
            self.publish_cancel_requested(value);
        }
    }

    /// Publishes cancellation through the one Release-ordered producer path.
    #[inline]
    pub(crate) fn publish_cancel_requested(&self, value: bool) {
        self.cancellation
            .store(value, std::sync::atomic::Ordering::Release);
    }

    /// Snapshot every distinct cancellation wake target using only safe `Arc`
    /// reference-count operations. Actual wake callbacks must run after unlock.
    pub(crate) fn cancel_waker_snapshot(&self) -> smallvec::SmallVec<[Arc<CancelWaker>; 4]> {
        let mut snapshot = smallvec::SmallVec::new();
        let mut push_unique = |candidate: &Arc<CancelWaker>| {
            if !snapshot
                .iter()
                .any(|existing: &Arc<CancelWaker>| existing.will_wake(&candidate.waker))
            {
                snapshot.push(Arc::clone(candidate));
            }
        };

        if let Some(primary) = &self.cancel_waker {
            push_unique(primary);
        }
        if let Some(untracked) = &self.untracked_cancel_waker {
            push_unique(untracked);
        }
        for registration in &self.cancel_waker_registrations {
            push_unique(&registration.target);
        }
        snapshot
    }

    /// Atomically detach every cancellation wake target for task completion.
    /// The returned targets must be dropped after all relevant locks are gone.
    /// If a published cancellation's wakes are still owed (deferred to a lane
    /// publication or checkpoint reconciliation this completion pre-empts),
    /// dropping an observer's target delivers its wake.
    pub(crate) fn take_cancel_wakers(&mut self) -> smallvec::SmallVec<[Arc<CancelWaker>; 4]> {
        let deliver_owed_wakes = self.cancel_requested && self.cancel_wakers_pending;
        self.cancel_waker_registry_closed = true;
        self.cancel_wakers_pending = false;
        // Pooled targets hold no-op Wakers, so dropping them here runs no user
        // code; a closed registry takes no new registrations to reuse them.
        self.cancel_waker_pool.clear();
        // A finished task's deadline cancels nothing: take its timer out of the
        // wheel now, not when the context drops (br-asupersync-pev2xi).
        drop(self.budget_deadline_timer.take());
        #[cfg(feature = "tracing-integration")]
        {
            // A task that retires without ever crossing admission has no lane
            // after which its trace could be emitted. Suppress the bounded,
            // copy-only receipt rather than reporting a fictitious publication.
            self.pending_task_cancel_trace = None;
        }
        // Allocate before moving any final owner out of the registry. If
        // allocation unwinds, every arbitrary RawWaker destructor remains
        // protected by its slot rather than running beneath the Cx lock.
        let target_count = usize::from(self.cancel_waker.is_some())
            + usize::from(self.untracked_cancel_waker.is_some())
            + self.cancel_waker_registrations.len();
        let mut retired = smallvec::SmallVec::with_capacity(target_count);
        retired.extend(self.cancel_waker.take());
        // The task's own lane waker has nothing left to wake; the observers
        // other code registered on this context are still owed the request.
        let observers = self.untracked_cancel_waker.take().into_iter().chain(
            self.cancel_waker_registrations
                .drain(..)
                .map(|registration| registration.target),
        );
        if deliver_owed_wakes {
            retired.extend(observers.map(|target| {
                Arc::new(CancelWaker::new(Waker::from(Arc::new(WakeOnRetire(
                    target,
                )))))
            }));
        } else {
            retired.extend(observers);
        }
        retired
    }

    /// Drains pending fast-path checkpoint accounting into the authoritative
    /// [`CheckpointState`]. Called at the top of every slow-path checkpoint
    /// and from any reader of the materialised checkpoint view. Idempotent
    /// when there is nothing to drain. (br-asupersync-is2xg0)
    pub fn drain_fast_path_checkpoint(&mut self) {
        use std::sync::atomic::Ordering;
        let count = self.fast_path_count.swap(0, Ordering::Relaxed);
        let ns = self.fast_path_last_checkpoint_ns.swap(0, Ordering::Relaxed);
        if count > 0 {
            self.checkpoint_state.checkpoint_count =
                self.checkpoint_state.checkpoint_count.saturating_add(count);
        }
        if ns != 0 {
            let drained = crate::types::Time::from_nanos(ns);
            if self
                .checkpoint_state
                .last_checkpoint
                .is_none_or(|t| drained > t)
            {
                self.checkpoint_state.last_checkpoint = Some(drained);
            }
        }
    }

    /// Returns the materialised [`CheckpointState`] (clones plus a snapshot
    /// merge of the pending fast-path atomics). Read-only — does not drain.
    /// (br-asupersync-is2xg0)
    #[must_use]
    pub fn materialised_checkpoint_state(&self) -> CheckpointState {
        use std::sync::atomic::Ordering;
        let mut state = self.checkpoint_state.clone();
        let count = self.fast_path_count.load(Ordering::Relaxed);
        if count > 0 {
            state.checkpoint_count = state.checkpoint_count.saturating_add(count);
        }
        let ns = self.fast_path_last_checkpoint_ns.load(Ordering::Relaxed);
        if ns != 0 {
            let snap = crate::types::Time::from_nanos(ns);
            if state.last_checkpoint.is_none_or(|t| snap > t) {
                state.last_checkpoint = Some(snap);
            }
        }
        state
    }
}

#[cfg(test)]
#[path = "task_context_inline_tests.rs"]
mod tests;
