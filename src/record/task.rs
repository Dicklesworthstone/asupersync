//! Task record for the runtime.
//!
//! A task is a unit of concurrent execution owned by a region.
//! This module defines the internal record structure for tracking task state.

use crate::types::{Budget, CancelReason, CxInner, Outcome, RegionId, TaskId};
use std::sync::{Arc, RwLock};

/// The concrete outcome type stored in task records (Phase 0).
pub type TaskOutcome = Outcome<(), crate::error::Error>;

/// The state of a task in its lifecycle.
#[derive(Debug, Clone)]
pub enum TaskState {
    /// Initial state after spawn.
    Created,
    /// Actively being polled.
    Running,
    /// Cancel has been requested but not yet acknowledged.
    CancelRequested {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Task has acknowledged cancel and is running cleanup code.
    Cancelling {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Cleanup done; task is running finalizers.
    Finalizing {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Terminal state.
    Completed(TaskOutcome),
}

impl TaskState {
    /// Returns true if the task is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns true if cancellation has been requested or is in progress.
    #[must_use]
    pub fn is_cancelling(&self) -> bool {
        matches!(
            self,
            Self::CancelRequested { .. } | Self::Cancelling { .. } | Self::Finalizing { .. }
        )
    }

    /// Returns true if the task can be polled.
    #[must_use]
    pub fn can_be_polled(&self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::CancelRequested { .. }
                | Self::Cancelling { .. }
                | Self::Finalizing { .. }
        )
    }
}

/// Internal record for a task in the runtime.
#[derive(Debug)]
pub struct TaskRecord {
    /// Unique identifier for this task.
    pub id: TaskId,
    /// The region that owns this task.
    pub owner: RegionId,
    /// Current state of the task.
    pub state: TaskState,
    /// Shared capability context state.
    ///
    /// This is shared with the `Cx` held by the user code.
    /// It is `None` only during initial construction or testing if not provided.
    pub cx_inner: Option<Arc<RwLock<CxInner>>>,

    /// Number of polls remaining (for budget tracking).
    pub polls_remaining: u32,
    /// Lab-only: last step this task was polled (for futurelock detection).
    pub last_polled_step: u64,
    /// Tasks waiting for this task to complete.
    pub waiters: Vec<TaskId>,
}

impl TaskRecord {
    /// Creates a new task record.
    #[must_use]
    pub fn new(id: TaskId, owner: RegionId, budget: Budget) -> Self {
        Self {
            id,
            owner,
            state: TaskState::Created,
            cx_inner: None, // Must be set via set_cx_inner or similar
            polls_remaining: budget.poll_quota,
            last_polled_step: 0,
            waiters: Vec::new(),
        }
    }

    /// Sets the shared CxInner.
    pub fn set_cx_inner(&mut self, inner: Arc<RwLock<CxInner>>) {
        self.cx_inner = Some(inner);
    }

    /// Records that the task was polled on the given lab step.
    pub fn mark_polled(&mut self, step: u64) {
        self.last_polled_step = step;
    }

    /// Returns true if the task can be polled.
    #[must_use]
    pub fn is_runnable(&self) -> bool {
        matches!(&self.state, TaskState::Created | TaskState::Running) || self.state.can_be_polled()
    }

    /// Requests cancellation of this task.
    ///
    /// Returns true if the request was new (not already pending).
    /// This also updates the shared `CxInner` to notify the user code.
    pub fn request_cancel(&mut self, reason: CancelReason) -> bool {
        // Need to get current budget from somewhere.
        // If we removed `budget` field, we should get it from `CxInner` or use default?
        // `request_cancel_with_budget` takes explicit budget.
        // `request_cancel` assumes a default cleanup budget?
        // Usually `reason.cleanup_budget()`.
        let budget = reason.cleanup_budget();
        self.request_cancel_with_budget(reason, budget)
    }

    /// Requests cancellation with an explicit cleanup budget.
    pub fn request_cancel_with_budget(
        &mut self,
        reason: CancelReason,
        cleanup_budget: Budget,
    ) -> bool {
        if self.state.is_terminal() {
            return false;
        }

        // Update shared state first
        if let Some(inner) = &self.cx_inner {
            if let Ok(mut guard) = inner.write() {
                guard.cancel_requested = true;
                // We might also want to update the budget in CxInner to the cleanup budget?
                // Or maybe cleanup budget is separate?
                // Typically cleanup runs with a *fresh* budget or remaining budget?
                // The task description says "Budget for bounded cleanup".
                // If we replace the budget in CxInner, user code sees it.
                // Yes, that's the point.
                guard.budget = cleanup_budget;
            }
        }

        match &mut self.state {
            TaskState::CancelRequested {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            } => {
                existing_reason.strengthen(&reason);
                *existing_budget = existing_budget.combine(cleanup_budget);
                false
            }
            TaskState::Cancelling {
                reason: existing_reason,
                cleanup_budget: b,
            }
            | TaskState::Finalizing {
                reason: existing_reason,
                cleanup_budget: b,
            } => {
                existing_reason.strengthen(&reason);
                *b = b.combine(cleanup_budget);
                false
            }
            TaskState::Created | TaskState::Running => {
                self.state = TaskState::CancelRequested {
                    reason,
                    cleanup_budget,
                };
                true
            }
            TaskState::Completed(_) => false,
        }
    }

    /// Marks the task as running (Created → Running).
    ///
    /// Returns true if the state changed.
    pub fn start_running(&mut self) -> bool {
        match self.state {
            TaskState::Created => {
                self.state = TaskState::Running;
                true
            }
            _ => false,
        }
    }

    /// Completes the task with the given outcome.
    ///
    /// Returns true if the state changed.
    pub fn complete(&mut self, outcome: TaskOutcome) -> bool {
        if self.state.is_terminal() {
            return false;
        }
        self.state = TaskState::Completed(outcome);
        true
    }

    /// Adds a waiter for this task's completion.
    pub fn add_waiter(&mut self, waiter: TaskId) {
        if !self.waiters.contains(&waiter) {
            self.waiters.push(waiter);
        }
    }

    /// Acknowledges cancellation, transitioning from `CancelRequested` to `Cancelling`.
    ///
    /// This is called when `checkpoint()` observes cancellation with mask_depth == 0.
    /// Returns the `CancelReason` if the transition occurred, `None` otherwise.
    ///
    /// # State Transition
    /// ```text
    /// CancelRequested { reason, cleanup_budget } → Cancelling { reason, cleanup_budget }
    /// ```
    pub fn acknowledge_cancel(&mut self) -> Option<CancelReason> {
        match &self.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            } => {
                let reason = reason.clone();
                let budget = *cleanup_budget;
                self.state = TaskState::Cancelling {
                    reason: reason.clone(),
                    cleanup_budget: budget,
                };
                Some(reason)
            }
            _ => None,
        }
    }

    /// Transitions from `Cancelling` to `Finalizing` after cleanup code completes.
    ///
    /// Returns `true` if the transition occurred.
    ///
    /// # State Transition
    /// ```text
    /// Cancelling { reason, cleanup_budget } → Finalizing { reason, cleanup_budget }
    /// ```
    pub fn cleanup_done(&mut self) -> bool {
        match &self.state {
            TaskState::Cancelling {
                reason,
                cleanup_budget,
            } => {
                let reason = reason.clone();
                let budget = *cleanup_budget;
                self.state = TaskState::Finalizing {
                    reason,
                    cleanup_budget: budget,
                };
                true
            }
            _ => false,
        }
    }

    /// Transitions from `Finalizing` to `Completed(Cancelled)` after finalizers complete.
    ///
    /// Returns `true` if the transition occurred.
    ///
    /// # State Transition
    /// ```text
    /// Finalizing { .. } → Completed(Cancelled(reason))
    /// ```
    pub fn finalize_done(&mut self) -> bool {
        let TaskState::Finalizing { reason, .. } = &self.state else {
            return false;
        };
        let reason = reason.clone();
        self.state = TaskState::Completed(Outcome::Cancelled(reason));
        true
    }

    /// Returns the cancel reason if the task is being cancelled.
    ///
    /// This returns `Some` for `CancelRequested`, `Cancelling`, and `Finalizing` states.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<&CancelReason> {
        match &self.state {
            TaskState::CancelRequested { reason, .. }
            | TaskState::Cancelling { reason, .. }
            | TaskState::Finalizing { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// Returns the cleanup budget if the task is being cancelled.
    #[must_use]
    pub fn cleanup_budget(&self) -> Option<Budget> {
        match &self.state {
            TaskState::CancelRequested { cleanup_budget, .. }
            | TaskState::Cancelling { cleanup_budget, .. }
            | TaskState::Finalizing { cleanup_budget, .. } => Some(*cleanup_budget),
            _ => None,
        }
    }

    /// Decrements the mask depth, returning the new value.
    ///
    /// Returns `None` if already at zero.
    ///
    /// This now accesses the shared `CxInner`.
    pub fn decrement_mask(&mut self) -> Option<u32> {
        if let Some(inner) = &self.cx_inner {
            if let Ok(mut guard) = inner.write() {
                if guard.mask_depth > 0 {
                    guard.mask_depth -= 1;
                    return Some(guard.mask_depth);
                }
            }
        }
        None
    }

    /// Increments the mask depth, returning the new value.
    pub fn increment_mask(&mut self) -> u32 {
        if let Some(inner) = &self.cx_inner {
            if let Ok(mut guard) = inner.write() {
                guard.mask_depth += 1;
                return guard.mask_depth;
            }
        }
        0 // Fallback if no inner (shouldn't happen in running task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, ErrorKind};
    use crate::util::ArenaIndex;

    fn task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 0))
    }

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn cancel_before_first_poll_enters_cancel_requested() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(matches!(t.state, TaskState::Created));
        assert!(t.request_cancel(CancelReason::timeout()));
        match &t.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget: _,
            } => {
                assert_eq!(reason.kind, crate::types::CancelKind::Timeout);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
    }

    #[test]
    fn cancel_strengthens_idempotently_when_already_cancel_requested() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(t.request_cancel(CancelReason::timeout()));
        assert!(!t.request_cancel(CancelReason::shutdown()));
        match &t.state {
            TaskState::CancelRequested { reason, .. } => {
                assert_eq!(reason.kind, crate::types::CancelKind::Shutdown);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
    }

    #[test]
    fn completed_is_absorbing() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(t.complete(Outcome::Ok(())));
        assert!(!t.request_cancel(CancelReason::timeout()));
        assert!(t.state.is_terminal());
        match &t.state {
            TaskState::Completed(outcome) => assert!(matches!(outcome, Outcome::Ok(()))),
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn can_be_polled_matches_state() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(!t.state.can_be_polled());
        assert!(t.start_running());
        assert!(t.state.can_be_polled());

        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
        assert!(t.state.can_be_polled());
    }

    #[test]
    fn complete_with_error_outcome() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let err = Error::new(ErrorKind::User);
        assert!(t.complete(Outcome::Err(err)));
        assert!(t.state.is_terminal());
    }

    #[test]
    fn acknowledge_cancel_transitions_to_cancelling() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());

        let reason = t.acknowledge_cancel();
        assert!(reason.is_some());
        assert_eq!(reason.unwrap().kind, crate::types::CancelKind::Timeout);
        assert!(matches!(
            t.state,
            TaskState::Cancelling {
                reason: CancelReason {
                    kind: crate::types::CancelKind::Timeout,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn acknowledge_cancel_fails_for_wrong_state() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(t.acknowledge_cancel().is_none());

        // Move to Running
        t.start_running();
        assert!(t.acknowledge_cancel().is_none());
    }

    #[test]
    fn cleanup_done_transitions_to_finalizing() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        assert!(matches!(t.state, TaskState::Cancelling { .. }));
        assert!(t.cleanup_done());
        assert!(matches!(t.state, TaskState::Finalizing { .. }));
    }

    #[test]
    fn cleanup_done_fails_for_wrong_state() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(!t.cleanup_done());

        let _ = t.request_cancel(CancelReason::timeout());
        // Still in CancelRequested, not Cancelling
        assert!(!t.cleanup_done());
    }

    #[test]
    fn finalize_done_transitions_to_completed_cancelled() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        assert!(matches!(t.state, TaskState::Finalizing { .. }));
        assert!(t.finalize_done());
        assert!(t.state.is_terminal());
        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                assert_eq!(reason.kind, crate::types::CancelKind::Timeout);
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }
    }

    #[test]
    fn full_cancellation_protocol_flow() {
        // Complete flow: Created → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(matches!(t.state, TaskState::Created));

        // Step 1: Request cancellation
        assert!(t.request_cancel(CancelReason::user("stop")));
        assert!(matches!(t.state, TaskState::CancelRequested { .. }));
        assert!(t.state.is_cancelling());

        // Step 2: Acknowledge cancellation (checkpoint with mask=0)
        let reason = t.acknowledge_cancel().expect("should acknowledge");
        assert_eq!(reason.kind, crate::types::CancelKind::User);
        assert!(matches!(t.state, TaskState::Cancelling { .. }));

        // Step 3: Cleanup completes
        assert!(t.cleanup_done());
        assert!(matches!(t.state, TaskState::Finalizing { .. }));

        // Step 4: Finalizers complete
        assert!(t.finalize_done());
        assert!(t.state.is_terminal());
        assert!(matches!(
            t.state,
            TaskState::Completed(Outcome::Cancelled(_))
        ));
    }

    #[test]
    fn masking_operations() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        // Need to set inner for mask operations to work
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner);

        assert_eq!(t.increment_mask(), 1);
        assert_eq!(t.increment_mask(), 2);

        assert_eq!(t.decrement_mask(), Some(1));
        assert_eq!(t.decrement_mask(), Some(0));

        // Can't go below zero
        assert_eq!(t.decrement_mask(), None);
    }

    #[test]
    fn cleanup_budget_accessor() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        assert!(t.cleanup_budget().is_none());

        let _ = t.request_cancel_with_budget(
            CancelReason::timeout(),
            Budget::new().with_poll_quota(500),
        );
        let budget = t.cleanup_budget().expect("should have cleanup budget");
        assert_eq!(budget.poll_quota, 500);
    }

    #[test]
    fn request_cancel_updates_shared_cx() {
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner.clone());

        assert!(!inner.read().unwrap().cancel_requested);

        t.request_cancel(CancelReason::timeout());

        assert!(inner.read().unwrap().cancel_requested);
        assert!(matches!(t.state, TaskState::CancelRequested { .. }));
    }
}
