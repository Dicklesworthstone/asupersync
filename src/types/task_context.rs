//! Internal state shared between TaskRecord and Cx.

use crate::types::{Budget, CancelReason, RegionId, TaskId, Time};
use std::task::Waker;

/// Maximum nesting depth for `Cx::masked()` sections.
///
/// Enforces the INV-MASK-BOUNDED invariant from the formal semantics:
/// a task's mask depth must be finite and bounded to guarantee that
/// cancellation cannot be deferred indefinitely. Exceeding this limit
/// indicates a programming error (excessive nesting of masked critical
/// sections).
pub const MAX_MASK_DEPTH: u32 = 64;

/// State for tracking checkpoint progress.
///
/// This struct tracks progress reporting checkpoints, which are distinct from
/// cancellation checkpoints. Progress checkpoints indicate that a task is
/// making forward progress and are useful for:
/// - Detecting stuck/stalled tasks
/// - Work-stealing scheduler decisions
/// - Observability and debugging
#[derive(Debug, Clone, Default)]
pub struct CheckpointState {
    /// The runtime time of the last checkpoint.
    pub last_checkpoint: Option<Time>,
    /// The message from the last `checkpoint_with()` call.
    pub last_message: Option<String>,
    /// The total number of checkpoints recorded.
    pub checkpoint_count: u64,
}

impl CheckpointState {
    /// Creates a new checkpoint state with no recorded checkpoints.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        self.last_checkpoint = Some(at);
        self.last_message = Some(message);
        self.checkpoint_count += 1;
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
    /// Whether cancellation has been requested.
    pub cancel_requested: bool,
    /// The reason for cancellation, if requested.
    pub cancel_reason: Option<CancelReason>,
    /// Whether cancellation has been acknowledged at a checkpoint.
    pub cancel_acknowledged: bool,
    /// Waker used to schedule cancellation promptly.
    pub cancel_waker: Option<Waker>,
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
            cancel_requested: false,
            cancel_reason: None,
            cancel_acknowledged: false,
            cancel_waker: None,
            mask_depth: 0,
            checkpoint_state: CheckpointState::new(),
            fast_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fast_path_count: std::sync::atomic::AtomicU64::new(0),
            fast_path_last_checkpoint_ns: std::sync::atomic::AtomicU64::new(0),
        }
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
                .map_or(true, |t| drained > t)
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
            if state.last_checkpoint.map_or(true, |t| snap > t) {
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
        crate::test_complete!("test_checkpoint_state_record_with_message_at");
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
