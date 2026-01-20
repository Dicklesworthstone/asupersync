//! Internal state shared between TaskRecord and Cx.

use crate::types::{Budget, CancelReason, RegionId, TaskId};

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
}

impl CxInner {
    /// Creates a new CxInner.
    #[must_use]
    pub fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        Self {
            region,
            task,
            budget,
            budget_baseline: budget,
            cancel_requested: false,
            cancel_reason: None,
            mask_depth: 0,
        }
    }
}
