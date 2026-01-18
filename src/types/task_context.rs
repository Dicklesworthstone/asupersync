//! Internal state shared between TaskRecord and Cx.

use crate::types::{Budget, RegionId, TaskId};

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
    /// Whether cancellation has been requested.
    pub cancel_requested: bool,
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
            cancel_requested: false,
            mask_depth: 0,
        }
    }
}
