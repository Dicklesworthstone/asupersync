//! Region record for the runtime.
//!
//! A region owns tasks and child regions, forming a tree structure.
//! When a region closes, it waits for all children to complete.

use crate::record::finalizer::{Finalizer, FinalizerStack};
use crate::types::{Budget, CancelReason, RegionId, TaskId};

/// The state of a region in its lifecycle.
///
/// State machine:
/// ```text
/// Open → Closing → Draining → Finalizing → Closed
///   │                            │
///   └─────────────────────────────┘ (skip Draining if no children)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    /// Region is open and accepting work.
    Open,
    /// Region body completed, beginning close sequence.
    /// No more spawns allowed; about to cancel children.
    Closing,
    /// Cancel issued to children, waiting for all to complete.
    /// Cancelled tasks get scheduled with priority (cancel lane).
    Draining,
    /// Children done, running region finalizers (LIFO order).
    Finalizing,
    /// Terminal state with aggregated outcome.
    Closed,
}

impl RegionState {
    /// Returns true if the region is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the region can accept new work.
    #[must_use]
    pub const fn can_spawn(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns true if the region is draining (waiting for children to complete).
    #[must_use]
    pub const fn is_draining(self) -> bool {
        matches!(self, Self::Draining)
    }

    /// Returns true if the region is in a closing phase (any of Closing, Draining, Finalizing).
    #[must_use]
    pub const fn is_closing(self) -> bool {
        matches!(self, Self::Closing | Self::Draining | Self::Finalizing)
    }
}

/// Internal record for a region in the runtime.
#[derive(Debug)]
pub struct RegionRecord {
    /// Unique identifier for this region.
    pub id: RegionId,
    /// Parent region (None for root).
    pub parent: Option<RegionId>,
    /// Current state.
    pub state: RegionState,
    /// Budget for this region.
    pub budget: Budget,
    /// Child regions.
    pub children: Vec<RegionId>,
    /// Tasks owned by this region.
    pub tasks: Vec<TaskId>,
    /// Pending finalizers (cleanup handlers to run after children complete).
    /// Stored as a stack and executed in LIFO order.
    pub finalizers: FinalizerStack,
    /// Cancellation reason if close was due to cancellation.
    pub cancel_reason: Option<CancelReason>,
}

impl RegionRecord {
    /// Creates a new region record.
    #[must_use]
    pub fn new(id: RegionId, parent: Option<RegionId>, budget: Budget) -> Self {
        Self {
            id,
            parent,
            state: RegionState::Open,
            budget,
            children: Vec::new(),
            tasks: Vec::new(),
            finalizers: FinalizerStack::new(),
            cancel_reason: None,
        }
    }

    /// Returns true if the region has any live children or tasks.
    #[must_use]
    pub fn has_live_work(&self) -> bool {
        !self.children.is_empty() || !self.tasks.is_empty()
    }

    /// Adds a child region.
    pub fn add_child(&mut self, child: RegionId) {
        if !self.children.contains(&child) {
            self.children.push(child);
        }
    }

    /// Removes a child region.
    pub fn remove_child(&mut self, child: RegionId) {
        self.children.retain(|&c| c != child);
    }

    /// Adds a task to this region.
    pub fn add_task(&mut self, task: TaskId) {
        if !self.tasks.contains(&task) {
            self.tasks.push(task);
        }
    }

    /// Removes a task from this region.
    pub fn remove_task(&mut self, task: TaskId) {
        self.tasks.retain(|&t| t != task);
    }

    /// Adds a finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and will be executed
    /// in reverse registration order during the Finalizing phase.
    pub fn add_finalizer(&mut self, finalizer: Finalizer) {
        self.finalizers.push(finalizer);
    }

    /// Pops the next finalizer to run (LIFO order).
    ///
    /// Returns `None` when all finalizers have been executed.
    pub fn pop_finalizer(&mut self) -> Option<Finalizer> {
        self.finalizers.pop()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    pub fn finalizer_count(&self) -> usize {
        self.finalizers.len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    pub fn finalizers_empty(&self) -> bool {
        self.finalizers.is_empty()
    }

    /// Begins the closing process.
    ///
    /// Returns true if the state changed.
    pub fn begin_close(&mut self, reason: Option<CancelReason>) -> bool {
        if self.state == RegionState::Open {
            self.state = RegionState::Closing;
            self.cancel_reason = reason;
            true
        } else {
            false
        }
    }

    /// Transitions from Closing to Draining.
    ///
    /// Called after cancellation has been issued to all children.
    /// Returns true if the state changed.
    pub fn begin_drain(&mut self) -> bool {
        if self.state == RegionState::Closing {
            self.state = RegionState::Draining;
            true
        } else {
            false
        }
    }

    /// Transitions from Draining to Finalizing (or Closing to Finalizing if no children).
    ///
    /// Called when all children have completed.
    /// Returns true if the state changed.
    pub fn begin_finalize(&mut self) -> bool {
        if matches!(self.state, RegionState::Closing | RegionState::Draining) {
            self.state = RegionState::Finalizing;
            true
        } else {
            false
        }
    }

    /// Transitions to Closed.
    ///
    /// Called when all finalizers have run and obligations resolved.
    /// Returns true if the state changed.
    pub fn complete_close(&mut self) -> bool {
        if self.state == RegionState::Finalizing {
            self.state = RegionState::Closed;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn region_state_predicates() {
        assert!(RegionState::Open.can_spawn());
        assert!(!RegionState::Closing.can_spawn());
        assert!(!RegionState::Draining.can_spawn());
        assert!(!RegionState::Finalizing.can_spawn());
        assert!(!RegionState::Closed.can_spawn());

        assert!(!RegionState::Open.is_terminal());
        assert!(!RegionState::Closing.is_terminal());
        assert!(!RegionState::Draining.is_terminal());
        assert!(!RegionState::Finalizing.is_terminal());
        assert!(RegionState::Closed.is_terminal());

        assert!(!RegionState::Open.is_draining());
        assert!(!RegionState::Closing.is_draining());
        assert!(RegionState::Draining.is_draining());
        assert!(!RegionState::Finalizing.is_draining());
        assert!(!RegionState::Closed.is_draining());

        assert!(!RegionState::Open.is_closing());
        assert!(RegionState::Closing.is_closing());
        assert!(RegionState::Draining.is_closing());
        assert!(RegionState::Finalizing.is_closing());
        assert!(!RegionState::Closed.is_closing());
    }

    #[test]
    fn region_lifecycle_with_children() {
        // Open → Closing → Draining → Finalizing → Closed
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert_eq!(region.state, RegionState::Open);

        assert!(region.begin_close(None));
        assert_eq!(region.state, RegionState::Closing);

        // Can't go backwards
        assert!(!region.begin_close(None));

        assert!(region.begin_drain());
        assert_eq!(region.state, RegionState::Draining);

        // Can't drain again
        assert!(!region.begin_drain());

        assert!(region.begin_finalize());
        assert_eq!(region.state, RegionState::Finalizing);

        assert!(region.complete_close());
        assert_eq!(region.state, RegionState::Closed);

        // Closed is absorbing
        assert!(!region.complete_close());
    }

    #[test]
    fn region_lifecycle_without_children() {
        // Open → Closing → Finalizing → Closed (skip Draining)
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.begin_close(None));
        assert_eq!(region.state, RegionState::Closing);

        // Can skip Draining and go directly to Finalizing if no children
        assert!(region.begin_finalize());
        assert_eq!(region.state, RegionState::Finalizing);

        assert!(region.complete_close());
        assert_eq!(region.state, RegionState::Closed);
    }

    #[test]
    fn begin_close_with_reason() {
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());
        let reason = CancelReason::user("test shutdown");

        assert!(region.begin_close(Some(reason.clone())));
        assert_eq!(region.cancel_reason, Some(reason));
    }

    #[test]
    fn invalid_state_transitions_are_rejected() {
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());

        // Can't drain from Open
        assert!(!region.begin_drain());
        assert_eq!(region.state, RegionState::Open);

        // Can't finalize from Open
        assert!(!region.begin_finalize());
        assert_eq!(region.state, RegionState::Open);

        // Can't complete_close from Open
        assert!(!region.complete_close());
        assert_eq!(region.state, RegionState::Open);

        // Move to Draining
        region.begin_close(None);
        region.begin_drain();

        // Can't close from Draining
        assert!(!region.complete_close());
        assert_eq!(region.state, RegionState::Draining);
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn finalizer_registration() {
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.finalizers_empty());
        assert_eq!(region.finalizer_count(), 0);

        // Add a sync finalizer
        region.add_finalizer(Finalizer::Sync(Box::new(|| {})));
        assert!(!region.finalizers_empty());
        assert_eq!(region.finalizer_count(), 1);

        // Add another finalizer
        region.add_finalizer(Finalizer::Async(Box::pin(async {})));
        assert_eq!(region.finalizer_count(), 2);
    }

    #[test]
    fn finalizer_lifo_order() {
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());

        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        // Add finalizers: 1, 2, 3
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o1.lock().unwrap().push(1);
        })));
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o2.lock().unwrap().push(2);
        })));
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o3.lock().unwrap().push(3);
        })));

        // Pop and execute in LIFO order
        while let Some(finalizer) = region.pop_finalizer() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        assert_eq!(*order.lock().unwrap(), vec![3, 2, 1]);
    }

    #[test]
    fn finalizer_pop_returns_none_when_empty() {
        let mut region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.pop_finalizer().is_none());

        // Add and remove
        region.add_finalizer(Finalizer::Sync(Box::new(|| {})));
        assert!(region.pop_finalizer().is_some());
        assert!(region.pop_finalizer().is_none());
    }
}
