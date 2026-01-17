//! Region record for the runtime.
//!
//! A region owns tasks and child regions, forming a tree structure.
//! When a region closes, it waits for all children to complete.

use crate::record::finalizer::{Finalizer, FinalizerStack};
use crate::types::{Budget, CancelReason, RegionId, TaskId};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;

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
    /// Returns the numeric encoding for this state.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Closing => 1,
            Self::Draining => 2,
            Self::Finalizing => 3,
            Self::Closed => 4,
        }
    }

    /// Decodes a numeric state value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Open),
            1 => Some(Self::Closing),
            2 => Some(Self::Draining),
            3 => Some(Self::Finalizing),
            4 => Some(Self::Closed),
            _ => None,
        }
    }

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

    /// Returns true if the region can accept new tasks or children.
    ///
    /// This is true for Open (normal execution) and Finalizing (cleanup).
    /// It is false for Closing and Draining phases.
    #[must_use]
    pub const fn can_accept_work(self) -> bool {
        matches!(self, Self::Open | Self::Finalizing)
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

/// Atomic region state wrapper for thread-safe state transitions.
#[derive(Debug)]
pub struct AtomicRegionState {
    inner: AtomicU8,
}

impl AtomicRegionState {
    /// Creates a new atomic state.
    #[must_use]
    pub fn new(state: RegionState) -> Self {
        Self {
            inner: AtomicU8::new(state.as_u8()),
        }
    }

    /// Loads the current state.
    #[must_use]
    pub fn load(&self) -> RegionState {
        RegionState::from_u8(self.inner.load(Ordering::Acquire)).expect("invalid region state")
    }

    /// Stores the given state.
    pub fn store(&self, state: RegionState) {
        self.inner.store(state.as_u8(), Ordering::Release);
    }

    /// Atomically transitions from `from` to `to`.
    pub fn transition(&self, from: RegionState, to: RegionState) -> bool {
        self.inner
            .compare_exchange(
                from.as_u8(),
                to.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[derive(Debug)]
struct RegionInner {
    budget: Budget,
    children: Vec<RegionId>,
    tasks: Vec<TaskId>,
    finalizers: FinalizerStack,
    cancel_reason: Option<CancelReason>,
}

/// Internal record for a region in the runtime.
#[derive(Debug)]
pub struct RegionRecord {
    /// Unique identifier for this region.
    pub id: RegionId,
    /// Parent region (None for root).
    pub parent: Option<RegionId>,
    /// Current state (atomic for concurrent access).
    state: AtomicRegionState,
    /// Inner mutable state (guarded by a lock).
    inner: RwLock<RegionInner>,
}

impl RegionRecord {
    /// Creates a new region record.
    #[must_use]
    pub fn new(id: RegionId, parent: Option<RegionId>, budget: Budget) -> Self {
        Self {
            id,
            parent,
            state: AtomicRegionState::new(RegionState::Open),
            inner: RwLock::new(RegionInner {
                budget,
                children: Vec::new(),
                tasks: Vec::new(),
                finalizers: FinalizerStack::new(),
                cancel_reason: None,
            }),
        }
    }

    /// Returns the current region state.
    #[must_use]
    pub fn state(&self) -> RegionState {
        self.state.load()
    }

    /// Returns the region budget.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().expect("lock poisoned").budget
    }

    /// Returns the current cancel reason, if any.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        self.inner
            .read()
            .expect("lock poisoned")
            .cancel_reason
            .clone()
    }

    /// Strengthens or sets the cancel reason.
    pub fn strengthen_cancel_reason(&self, reason: CancelReason) {
        let mut inner = self.inner.write().expect("lock poisoned");
        if let Some(existing) = &mut inner.cancel_reason {
            existing.strengthen(&reason);
        } else {
            inner.cancel_reason = Some(reason);
        }
    }

    /// Returns a snapshot of child region IDs.
    #[must_use]
    pub fn child_ids(&self) -> Vec<RegionId> {
        self.inner.read().expect("lock poisoned").children.clone()
    }

    /// Returns a snapshot of task IDs.
    #[must_use]
    pub fn task_ids(&self) -> Vec<TaskId> {
        self.inner.read().expect("lock poisoned").tasks.clone()
    }

    /// Returns true if the region has any live children or tasks.
    #[must_use]
    pub fn has_live_work(&self) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        !inner.children.is_empty() || !inner.tasks.is_empty()
    }

    /// Adds a child region.
    ///
    /// Returns `true` if the child was added, `false` if the region is not accepting work.
    pub fn add_child(&self, child: RegionId) -> bool {
        // Optimistic check (atomic)
        if !self.state.load().can_accept_work() {
            return false;
        }

        let mut inner = self.inner.write().expect("lock poisoned");

        // Double check under lock (though state is atomic, consistency matters)
        if !self.state.load().can_accept_work() {
            return false;
        }

        if !inner.children.contains(&child) {
            inner.children.push(child);
        }
        true
    }

    /// Removes a child region.
    pub fn remove_child(&self, child: RegionId) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.children.retain(|&c| c != child);
    }

    /// Adds a task to this region.
    ///
    /// Returns `true` if the task was added, `false` if the region is not accepting work.
    pub fn add_task(&self, task: TaskId) -> bool {
        // Optimistic check
        if !self.state.load().can_accept_work() {
            return false;
        }

        let mut inner = self.inner.write().expect("lock poisoned");

        // Double check
        if !self.state.load().can_accept_work() {
            return false;
        }

        if !inner.tasks.contains(&task) {
            inner.tasks.push(task);
        }
        true
    }

    /// Removes a task from this region.
    pub fn remove_task(&self, task: TaskId) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.tasks.retain(|&t| t != task);
    }

    /// Adds a finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and will be executed
    /// in reverse registration order during the Finalizing phase.
    pub fn add_finalizer(&self, finalizer: Finalizer) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.finalizers.push(finalizer);
    }

    /// Pops the next finalizer to run (LIFO order).
    ///
    /// Returns `None` when all finalizers have been executed.
    pub fn pop_finalizer(&self) -> Option<Finalizer> {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.finalizers.pop()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    pub fn finalizer_count(&self) -> usize {
        self.inner.read().expect("lock poisoned").finalizers.len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    pub fn finalizers_empty(&self) -> bool {
        self.inner
            .read()
            .expect("lock poisoned")
            .finalizers
            .is_empty()
    }

    /// Begins the closing process.
    ///
    /// Returns true if the state changed.
    pub fn begin_close(&self, reason: Option<CancelReason>) -> bool {
        if self
            .state
            .transition(RegionState::Open, RegionState::Closing)
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.cancel_reason = reason;
            true
        } else {
            false
        }
    }

    /// Transitions from Closing to Draining.
    ///
    /// Called after cancellation has been issued to all children.
    /// Returns true if the state changed.
    pub fn begin_drain(&self) -> bool {
        self.state
            .transition(RegionState::Closing, RegionState::Draining)
    }

    /// Transitions from Draining to Finalizing (or Closing to Finalizing if no children).
    ///
    /// Called when all children have completed.
    /// Returns true if the state changed.
    pub fn begin_finalize(&self) -> bool {
        if self
            .state
            .transition(RegionState::Closing, RegionState::Finalizing)
        {
            return true;
        }
        self.state
            .transition(RegionState::Draining, RegionState::Finalizing)
    }

    /// Transitions to Closed.
    ///
    /// Called when all finalizers have run and obligations resolved.
    /// Returns true if the state changed.
    pub fn complete_close(&self) -> bool {
        self.state
            .transition(RegionState::Finalizing, RegionState::Closed)
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
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert_eq!(region.state(), RegionState::Open);

        assert!(region.begin_close(None));
        assert_eq!(region.state(), RegionState::Closing);

        // Can't go backwards
        assert!(!region.begin_close(None));

        assert!(region.begin_drain());
        assert_eq!(region.state(), RegionState::Draining);

        // Can't drain again
        assert!(!region.begin_drain());

        assert!(region.begin_finalize());
        assert_eq!(region.state(), RegionState::Finalizing);

        assert!(region.complete_close());
        assert_eq!(region.state(), RegionState::Closed);

        // Closed is absorbing
        assert!(!region.complete_close());
    }

    #[test]
    fn region_lifecycle_without_children() {
        // Open → Closing → Finalizing → Closed (skip Draining)
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.begin_close(None));
        assert_eq!(region.state(), RegionState::Closing);

        // Can skip Draining and go directly to Finalizing if no children
        assert!(region.begin_finalize());
        assert_eq!(region.state(), RegionState::Finalizing);

        assert!(region.complete_close());
        assert_eq!(region.state(), RegionState::Closed);
    }

    #[test]
    fn begin_close_with_reason() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        let reason = CancelReason::user("test shutdown");

        assert!(region.begin_close(Some(reason.clone())));
        assert_eq!(region.cancel_reason(), Some(reason));
    }

    #[test]
    fn invalid_state_transitions_are_rejected() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        // Can't drain from Open
        assert!(!region.begin_drain());
        assert_eq!(region.state(), RegionState::Open);

        // Can't finalize from Open
        assert!(!region.begin_finalize());
        assert_eq!(region.state(), RegionState::Open);

        // Can't complete_close from Open
        assert!(!region.complete_close());
        assert_eq!(region.state(), RegionState::Open);

        // Move to Draining
        region.begin_close(None);
        region.begin_drain();

        // Can't close from Draining
        assert!(!region.complete_close());
        assert_eq!(region.state(), RegionState::Draining);
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn finalizer_registration() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

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
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

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
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.pop_finalizer().is_none());

        // Add and remove
        region.add_finalizer(Finalizer::Sync(Box::new(|| {})));
        assert!(region.pop_finalizer().is_some());
        assert!(region.pop_finalizer().is_none());
    }
}
