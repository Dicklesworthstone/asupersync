//! Internal state shared between TaskRecord and Cx.

use crate::types::{Budget, CancelReason, RegionId, TaskId};
use std::time::Instant;

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
            mask_depth: 0,
            checkpoint_state: CheckpointState::new(),
        }
    }
}
