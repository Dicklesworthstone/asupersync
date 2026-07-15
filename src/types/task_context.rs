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

use crate::types::{Budget, CancelReason, CapabilityBudget, RegionId, TaskId, Time};
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
