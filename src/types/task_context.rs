//! Internal state shared between TaskRecord and Cx.

use crate::types::{Budget, CancelReason, RegionId, TaskId};
use std::task::Waker;
use std::time::Instant;

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
#[derive(Debug, Clone)]
pub struct CheckpointState {
    /// The timestamp of the last checkpoint.
    pub last_checkpoint: Option<Instant>,
    /// The message from the last `checkpoint_with()` call.
    pub last_message: Option<String>,
    /// The total number of checkpoints recorded.
    pub checkpoint_count: u64,
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointState {
    /// Creates a new checkpoint state with no recorded checkpoints.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_checkpoint: None,
            last_message: None,
            checkpoint_count: 0,
        }
    }

    /// Records a checkpoint without a message.
    pub fn record(&mut self) {
        self.last_checkpoint = Some(Instant::now());
        self.last_message = None;
        self.checkpoint_count += 1;
    }

    /// Records a checkpoint with a message.
    pub fn record_with_message(&mut self, message: String) {
        self.last_checkpoint = Some(Instant::now());
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
        }
    }
}

#[cfg(test)]
mod tests {
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
}
