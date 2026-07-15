//! Internal task context state shared between TaskRecord and Cx.
//!
//! This module provides core types for managing task execution context,
//! including cancellation masking, progress tracking, and capability budgets.
//! The types here bridge the runtime's internal [`TaskRecord`] bookkeeping
//! with the user-facing [`Cx`] API.
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
}

/// One exactly-owned auxiliary cancellation wake registration.
#[derive(Debug)]
pub(crate) struct CancelWakerRegistration {
    pub(crate) token: u64,
    pub(crate) target: Arc<CancelWaker>,
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
            } => {
                let metrics = metrics
                    .take()
                    .expect("live cancellation metric observer retains its provider");
                let region_id = *region_id;
                let cancel_kind = *cancel_kind;
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
    ) {
        self.observers
            .as_mut()
            .expect("dispatched cancellation effects cannot be reused")
            .push(CancelObserver::RegionCancellationMetric {
                metrics: Some(metrics),
                region_id,
                cancel_kind,
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
    /// [`Self::record_at(cx.now())`] instead, threading time through the
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
            history: VecDeque::with_capacity(DEFAULT_CHECKPOINT_HISTORY_CAPACITY),
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
    /// Monotonic source for live registration tokens. Zero is reserved for the
    /// closed-registry sentinel and is never stored in the registration table.
    pub(crate) next_cancel_waker_token: u64,
    /// Set when task completion detaches the registry permanently.
    pub(crate) cancel_waker_registry_closed: bool,
    /// Current mask depth.
    pub mask_depth: u32,
    /// Progress checkpoint state.
    pub checkpoint_state: CheckpointState,
    /// Fast atomic flag for cancellation (avoids RwLock on wake hot path).
    pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Fast-path checkpoint count: incremented when [`Cx::checkpoint`] takes
    /// the no-cancellation fast path (br-asupersync-is2xg0). Drained into
    /// [`CheckpointState::checkpoint_count`] on the next slow-path call or
    /// when the materialised view is requested.
    pub fast_path_count: std::sync::atomic::AtomicU64,
    /// Fast-path last checkpoint time (ns since [`Time::ZERO`]). 0 means no
    /// fast-path checkpoint has been recorded since the last drain. Drained
    /// into [`CheckpointState::last_checkpoint`] on the next slow-path call
    /// or when the materialised view is requested. Stored as a plain
    /// `AtomicU64` because [`Time`] is just a `u64` nanos counter.
    pub fast_path_last_checkpoint_ns: std::sync::atomic::AtomicU64,
}

impl CxInner {
    /// Creates a new CxInner.
    #[must_use]
    pub fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        Self {
            region,
            task,
            task_type: None,
            budget,
            budget_baseline: budget,
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
            next_cancel_waker_token: 0,
            cancel_waker_registry_closed: false,
            mask_depth: 0,
            checkpoint_state: CheckpointState::new(),
            fast_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fast_path_count: std::sync::atomic::AtomicU64::new(0),
            fast_path_last_checkpoint_ns: std::sync::atomic::AtomicU64::new(0),
        }
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
    pub(crate) fn take_cancel_wakers(&mut self) -> smallvec::SmallVec<[Arc<CancelWaker>; 4]> {
        self.cancel_waker_registry_closed = true;
        self.cancel_wakers_pending = false;
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
        retired.extend(self.untracked_cancel_waker.take());
        retired.extend(
            self.cancel_waker_registrations
                .drain(..)
                .map(|registration| registration.target),
        );
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct PanickingPayload {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for PanickingPayload {
        fn drop(&mut self) {
            let already_panicking = std::thread::panicking();
            self.drops.fetch_add(1, Ordering::SeqCst);
            if !already_panicking {
                panic!("adversarial panic-payload destructor");
            }
        }
    }

    struct AdversarialWake {
        label: &'static str,
        wake_calls: Arc<AtomicUsize>,
        retirements: Arc<AtomicUsize>,
        wake_order: Arc<Mutex<Vec<&'static str>>>,
        wake_panic_attempts: Arc<AtomicUsize>,
        drop_panic_attempts: Arc<AtomicUsize>,
        panic_payload_drops: Arc<AtomicUsize>,
        panic_on_wake: bool,
        panic_on_drop: bool,
    }

    impl AdversarialWake {
        fn record_wake(&self) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
            self.wake_order
                .lock()
                .expect("wake order lock")
                .push(self.label);
            if self.panic_on_wake {
                self.wake_panic_attempts.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    impl Wake for AdversarialWake {
        fn wake(self: Arc<Self>) {
            self.record_wake();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.record_wake();
        }
    }

    impl Drop for AdversarialWake {
        fn drop(&mut self) {
            self.retirements.fetch_add(1, Ordering::SeqCst);
            if self.panic_on_drop {
                self.drop_panic_attempts.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    struct LockAwareValue {
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
    }

    impl Drop for LockAwareValue {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct LockAwareWake {
        wake_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
    }

    impl Wake for LockAwareWake {
        fn wake(self: Arc<Self>) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for LockAwareWake {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct AdversarialCancellationMetrics {
        calls: Arc<AtomicUsize>,
        calls_while_locked: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        panic_payload_drops: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
        panic_on_call: bool,
        panic_on_drop: bool,
    }

    impl MetricsProvider for AdversarialCancellationMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}

        fn task_completed(
            &self,
            _: TaskId,
            _: crate::observability::metrics::OutcomeKind,
            _: std::time::Duration,
        ) {
        }

        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

        fn region_closed(&self, _: RegionId, _: std::time::Duration) {}

        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.calls_while_locked.fetch_add(1, Ordering::SeqCst);
            }
            if self.panic_on_call {
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }

        fn drain_completed(&self, _: RegionId, _: std::time::Duration) {}

        fn deadline_set(&self, _: RegionId, _: std::time::Duration) {}

        fn deadline_exceeded(&self, _: RegionId) {}

        fn deadline_warning(&self, _: &str, _: &'static str, _: std::time::Duration) {}

        fn deadline_violation(&self, _: &str, _: std::time::Duration) {}

        fn deadline_remaining(&self, _: &str, _: std::time::Duration) {}

        fn checkpoint_interval(&self, _: &str, _: std::time::Duration) {}

        fn task_stuck_detected(&self, _: &str) {}

        fn obligation_created(&self, _: RegionId) {}

        fn obligation_discharged(&self, _: RegionId) {}

        fn obligation_leaked(&self, _: RegionId) {}

        fn scheduler_tick(&self, _: usize, _: std::time::Duration) {}
    }

    impl Drop for AdversarialCancellationMetrics {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
            if self.panic_on_drop {
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn cancel_wake_effects_isolate_wake_and_retirement_panics() {
        init_test("cancel_wake_effects_isolate_wake_and_retirement_panics");

        let first_wakes = Arc::new(AtomicUsize::new(0));
        let second_wakes = Arc::new(AtomicUsize::new(0));
        let third_wakes = Arc::new(AtomicUsize::new(0));
        let first_retirements = Arc::new(AtomicUsize::new(0));
        let second_retirements = Arc::new(AtomicUsize::new(0));
        let third_retirements = Arc::new(AtomicUsize::new(0));
        let wake_order = Arc::new(Mutex::new(Vec::new()));
        let wake_panic_attempts = Arc::new(AtomicUsize::new(0));
        let drop_panic_attempts = Arc::new(AtomicUsize::new(0));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));

        let target = |label,
                      wake_calls: &Arc<AtomicUsize>,
                      retirements: &Arc<AtomicUsize>,
                      panic_on_wake,
                      panic_on_drop| {
            Arc::new(CancelWaker::new(Waker::from(Arc::new(AdversarialWake {
                label,
                wake_calls: Arc::clone(wake_calls),
                retirements: Arc::clone(retirements),
                wake_order: Arc::clone(&wake_order),
                wake_panic_attempts: Arc::clone(&wake_panic_attempts),
                drop_panic_attempts: Arc::clone(&drop_panic_attempts),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                panic_on_wake,
                panic_on_drop,
            }))))
        };

        let mut first_batch = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        first_batch.push(target(
            "first",
            &first_wakes,
            &first_retirements,
            true,
            true,
        ));
        let mut effects = CancelWakeEffects::new(first_batch);

        let mut later_batch = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        later_batch.push(target(
            "second",
            &second_wakes,
            &second_retirements,
            false,
            false,
        ));
        later_batch.push(target(
            "third",
            &third_wakes,
            &third_retirements,
            false,
            false,
        ));
        effects.merge(CancelWakeEffects::new(later_batch));

        assert_eq!(effects.len(), 3);
        effects.dispatch();

        assert_eq!(first_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(second_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(third_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(first_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(second_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(third_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(wake_panic_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(drop_panic_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            *wake_order.lock().expect("wake order lock"),
            vec!["first", "second", "third"]
        );

        crate::test_complete!("cancel_wake_effects_isolate_wake_and_retirement_panics");
    }

    #[test]
    fn cancellation_observers_merge_without_wakers_and_isolate_panics() {
        init_test("cancellation_observers_merge_without_wakers_and_isolate_panics");

        let caller_lock = Arc::new(Mutex::new(()));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let first_drops = Arc::new(AtomicUsize::new(0));
        let first_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let second_drops = Arc::new(AtomicUsize::new(0));
        let second_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let wake_drops = Arc::new(AtomicUsize::new(0));
        let wake_drops_while_locked = Arc::new(AtomicUsize::new(0));

        let mut targets = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        targets.push(Arc::new(CancelWaker::new(Waker::from(Arc::new(
            LockAwareWake {
                wake_calls: Arc::clone(&wake_calls),
                drops: Arc::clone(&wake_drops),
                drops_while_locked: Arc::clone(&wake_drops_while_locked),
                caller_lock: Arc::clone(&caller_lock),
            },
        )))));
        let mut effects = CancelWakeEffects::new(targets);
        effects.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&first_calls),
                calls_while_locked: Arc::clone(&first_calls_while_locked),
                drops: Arc::clone(&first_drops),
                drops_while_locked: Arc::clone(&first_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: true,
                panic_on_drop: true,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
        );

        let mut observer_only = CancelWakeEffects::empty();
        observer_only.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&second_calls),
                calls_while_locked: Arc::clone(&second_calls_while_locked),
                drops: Arc::clone(&second_drops),
                drops_while_locked: Arc::clone(&second_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: false,
                panic_on_drop: false,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
        );
        assert!(observer_only.is_empty(), "is_empty remains Waker-only");
        effects.merge(observer_only);

        let dispatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            effects.dispatch();
        }));
        assert!(dispatched.is_ok());
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first_drops.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_drops.load(Ordering::SeqCst), 1);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wake_drops.load(Ordering::SeqCst), 1);
        assert_eq!(first_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(first_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(second_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(second_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);

        crate::test_complete!("cancellation_observers_merge_without_wakers_and_isolate_panics");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn cancellation_protocol_diagnostic_contains_subscriber_panic() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                panic!("adversarial cancellation diagnostic subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let mut effects = CancelWakeEffects::empty();
        effects.push_cancel_protocol_violation(
            "hostile cancellation validation",
            "Invalid { reason: deterministic fixture }".to_owned(),
        );
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || effects.dispatch());
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock() {
        init_test("abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock");

        let caller_lock = Arc::new(Mutex::new(()));
        let value_drops = Arc::new(AtomicUsize::new(0));
        let value_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let waker_drops = Arc::new(AtomicUsize::new(0));
        let waker_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let metric_calls = Arc::new(AtomicUsize::new(0));
        let metric_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let metric_drops = Arc::new(AtomicUsize::new(0));
        let metric_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));

        let value = LockAwareValue {
            drops: Arc::clone(&value_drops),
            drops_while_locked: Arc::clone(&value_drops_while_locked),
            caller_lock: Arc::clone(&caller_lock),
        };
        let target = Arc::new(CancelWaker::new(Waker::from(Arc::new(LockAwareWake {
            wake_calls: Arc::clone(&wake_calls),
            drops: Arc::clone(&waker_drops),
            drops_while_locked: Arc::clone(&waker_drops_while_locked),
            caller_lock: Arc::clone(&caller_lock),
        }))));
        let mut targets = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        targets.push(target);
        let mut wakes = CancelWakeEffects::new(targets);
        wakes.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&metric_calls),
                calls_while_locked: Arc::clone(&metric_calls_while_locked),
                drops: Arc::clone(&metric_drops),
                drops_while_locked: Arc::clone(&metric_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: false,
                panic_on_drop: false,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
        );
        let effects = CancellationEffects::new(value, wakes);

        let guard = caller_lock.lock().expect("caller lock");
        drop(effects);
        assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        assert_eq!(value_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops_while_locked.load(Ordering::SeqCst), 0);
        drop(guard);

        assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        assert_eq!(value_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);

        crate::test_complete!(
            "abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock"
        );
    }

    #[test]
    fn test_checkpoint_state_default() {
        init_test("test_checkpoint_state_default");
        let state = CheckpointState::new();
        crate::assert_with_log!(
            state.last_checkpoint.is_none(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_none()
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 0,
            "checkpoint_count",
            0,
            state.checkpoint_count
        );
        crate::assert_with_log!(
            state.history_capacity() == DEFAULT_CHECKPOINT_HISTORY_CAPACITY,
            "checkpoint history capacity",
            DEFAULT_CHECKPOINT_HISTORY_CAPACITY,
            state.history_capacity()
        );
        crate::assert_with_log!(
            state.history().is_empty(),
            "checkpoint history empty",
            true,
            state.history().is_empty()
        );
        crate::test_complete!("test_checkpoint_state_default");
    }

    #[test]
    fn test_checkpoint_state_record() {
        init_test("test_checkpoint_state_record");
        let mut state = CheckpointState::new();
        state.record();
        crate::assert_with_log!(
            state.last_checkpoint.is_some(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_some()
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "checkpoint_count",
            1,
            state.checkpoint_count
        );
        state.record();
        crate::assert_with_log!(
            state.checkpoint_count == 2,
            "checkpoint_count 2",
            2,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_record");
    }

    #[test]
    fn test_checkpoint_state_record_at() {
        init_test("test_checkpoint_state_record_at");
        let mut state = CheckpointState::new();
        let at = Time::from_nanos(123);

        state.record_at(at);

        crate::assert_with_log!(
            state.last_checkpoint == Some(at),
            "explicit checkpoint instant stored",
            format!("{at:?}"),
            format!("{:?}", state.last_checkpoint)
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "record_at clears message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "record_at increments count",
            1,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_record_at");
    }

    #[test]
    fn test_checkpoint_state_record_with_message() {
        init_test("test_checkpoint_state_record_with_message");
        let mut state = CheckpointState::new();
        state.record_with_message("hello".to_string());
        crate::assert_with_log!(
            state.last_checkpoint.is_some(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_some()
        );
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("hello"),
            "last_message",
            Some("hello"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "checkpoint_count",
            1,
            state.checkpoint_count
        );
        state.record();
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message cleared",
            true,
            state.last_message.is_none()
        );
        crate::test_complete!("test_checkpoint_state_record_with_message");
    }

    #[test]
    fn test_checkpoint_state_record_with_message_at() {
        init_test("test_checkpoint_state_record_with_message_at");
        let mut state = CheckpointState::new();
        let at = Time::from_nanos(456);

        state.record_with_message_at("hello".to_string(), at);

        crate::assert_with_log!(
            state.last_checkpoint == Some(at),
            "explicit checkpoint instant stored",
            format!("{at:?}"),
            format!("{:?}", state.last_checkpoint)
        );
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("hello"),
            "record_with_message_at stores message",
            Some("hello"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "record_with_message_at increments count",
            1,
            state.checkpoint_count
        );
        assert_eq!(
            state.history(),
            vec![CheckpointHistoryEntry {
                at,
                message: "hello".to_string()
            }]
        );
        crate::test_complete!("test_checkpoint_state_record_with_message_at");
    }

    #[test]
    fn checkpoint_history_preserves_oldest_to_newest_with_capacity() {
        init_test("checkpoint_history_preserves_oldest_to_newest_with_capacity");
        let mut state = CheckpointState::with_history_capacity(2);

        state.record_with_message_at("one".to_string(), Time::from_nanos(1));
        state.record_with_message_at("two".to_string(), Time::from_nanos(2));
        state.record_with_message_at("three".to_string(), Time::from_nanos(3));

        assert_eq!(
            state.history(),
            vec![
                CheckpointHistoryEntry {
                    at: Time::from_nanos(2),
                    message: "two".to_string(),
                },
                CheckpointHistoryEntry {
                    at: Time::from_nanos(3),
                    message: "three".to_string(),
                },
            ]
        );
        crate::test_complete!("checkpoint_history_preserves_oldest_to_newest_with_capacity");
    }

    #[test]
    fn checkpoint_history_can_be_disabled() {
        init_test("checkpoint_history_can_be_disabled");
        let mut state = CheckpointState::with_history_capacity(0);

        state.record_with_message_at("hidden".to_string(), Time::from_nanos(9));

        assert_eq!(state.last_message.as_deref(), Some("hidden"));
        assert!(state.history().is_empty());
        crate::test_complete!("checkpoint_history_can_be_disabled");
    }

    #[test]
    fn messageless_checkpoints_never_grow_history() {
        // AC2: the messageless `checkpoint()` hot path must stay allocation-free
        // with respect to the history ring — it records count/time only and
        // never appends. Mixing messageless records around a single message
        // proves only `record_with_message_at` touches the ring.
        init_test("messageless_checkpoints_never_grow_history");
        let mut state = CheckpointState::with_history_capacity(8);

        for n in 0..100u64 {
            state.record_at(Time::from_nanos(n));
        }
        assert!(
            state.history().is_empty(),
            "messageless checkpoints must not append history"
        );

        state.record_with_message_at("only-message".to_string(), Time::from_nanos(100));
        for n in 101..200u64 {
            state.record_at(Time::from_nanos(n));
        }

        let trail = state.history();
        assert_eq!(trail.len(), 1, "exactly one message checkpoint retained");
        assert_eq!(trail[0].message, "only-message");
        assert_eq!(trail[0].at, Time::from_nanos(100));
        assert_eq!(
            state.checkpoint_count, 200,
            "every checkpoint still counted"
        );
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(199)));
        crate::test_complete!("messageless_checkpoints_never_grow_history");
    }

    #[test]
    fn checkpoint_history_truncates_long_messages_on_char_boundary() {
        init_test("checkpoint_history_truncates_long_messages_on_char_boundary");
        let mut state = CheckpointState::new();
        let message = format!(
            "{}{}",
            "a".repeat(MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES - 1),
            "é"
        );

        state.record_with_message_at(message, Time::from_nanos(1));

        let history = state.history();
        assert_eq!(history.len(), 1);
        assert_eq!(
            state
                .last_message
                .as_ref()
                .expect("last message should remain present")
                .len(),
            MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES + 1
        );
        assert_eq!(
            history[0].message.len(),
            MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES - 1
        );
        assert!(history[0].message.ends_with('a'));
        crate::test_complete!("checkpoint_history_truncates_long_messages_on_char_boundary");
    }

    #[test]
    fn test_checkpoint_state_message_overwrite() {
        init_test("test_checkpoint_state_message_overwrite");
        let mut state = CheckpointState::new();
        state.record_with_message("first".to_string());
        state.record_with_message("second".to_string());
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("second"),
            "last_message overwrite",
            Some("second"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 2,
            "checkpoint_count",
            2,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_message_overwrite");
    }

    #[test]
    fn test_cx_inner_new() {
        init_test("test_cx_inner_new");
        let region = RegionId::testing_default();
        let task = TaskId::testing_default();
        let budget = Budget::new();
        let cx = CxInner::new(region, task, budget);
        crate::assert_with_log!(cx.region == region, "region", region, cx.region);
        crate::assert_with_log!(cx.task == task, "task", task, cx.task);
        crate::assert_with_log!(cx.budget == budget, "budget", budget, cx.budget);
        crate::assert_with_log!(
            cx.budget_baseline == budget,
            "budget_baseline",
            budget,
            cx.budget_baseline
        );
        crate::assert_with_log!(
            cx.capability_budget == CapabilityBudget::UNSPECIFIED,
            "capability_budget",
            CapabilityBudget::UNSPECIFIED,
            cx.capability_budget
        );
        crate::assert_with_log!(
            !cx.cancel_requested,
            "cancel_requested",
            false,
            cx.cancel_requested
        );
        crate::assert_with_log!(
            cx.cancel_reason.is_none(),
            "cancel_reason",
            true,
            cx.cancel_reason.is_none()
        );
        crate::assert_with_log!(cx.mask_depth == 0, "mask_depth", 0, cx.mask_depth);
        crate::test_complete!("test_cx_inner_new");
    }

    // =========================================================================
    // Wave 47 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn checkpoint_state_debug_clone_default() {
        let def = CheckpointState::default();
        assert!(def.last_checkpoint.is_none());
        assert!(def.last_message.is_none());
        assert_eq!(def.checkpoint_count, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("CheckpointState"), "{dbg}");

        let mut state = CheckpointState::new();
        state.record_with_message("progress".into());
        let cloned = state.clone();
        assert_eq!(cloned.checkpoint_count, 1);
        assert_eq!(cloned.last_message.as_deref(), Some("progress"));
    }

    #[test]
    fn cx_inner_debug() {
        let region = RegionId::testing_default();
        let task = TaskId::testing_default();
        let cx = CxInner::new(region, task, Budget::new());
        let dbg = format!("{cx:?}");
        assert!(dbg.contains("CxInner"), "{dbg}");
    }

    /// br-asupersync-soyet0 — `record_at` (the explicit-time form
    /// production callers use) updates checkpoint state without
    /// reaching for `wall_now()`. This guards against a future
    /// refactor accidentally re-introducing the ambient call inside
    /// the explicit path.
    #[test]
    fn record_at_uses_supplied_time() {
        let mut state = CheckpointState::new();
        state.record_at(Time::from_nanos(42));
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(42)));
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(state.last_message, None);
    }

    /// br-asupersync-soyet0 — `record_with_message_at` clears the
    /// stored message correctly and uses the supplied time.
    #[test]
    fn record_with_message_at_uses_supplied_time() {
        let mut state = CheckpointState::new();
        state.record_with_message_at("ckpt".to_string(), Time::from_nanos(7));
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(7)));
        assert_eq!(state.last_message.as_deref(), Some("ckpt"));
        assert_eq!(state.checkpoint_count, 1);
    }
}
