//! Global runtime state.
//!
//! The runtime state Σ contains all live entities:
//! - Regions (ownership tree)
//! - Tasks (units of execution)
//! - Obligations (resources to be resolved)
//! - Current time

use crate::record::finalizer::Finalizer;
use crate::record::{ObligationRecord, RegionRecord, TaskRecord};
use crate::trace::TraceBuffer;
use crate::types::policy::PolicyAction;
use crate::types::{Budget, CancelReason, Outcome, Policy, RegionId, TaskId, Time};
use crate::util::Arena;
use std::future::Future;

/// The global runtime state.
///
/// This is the "Σ" from the formal semantics:
/// `Σ = ⟨R, T, O, τ_now⟩`
#[derive(Debug)]
pub struct RuntimeState {
    /// All region records.
    pub regions: Arena<RegionRecord>,
    /// All task records.
    pub tasks: Arena<TaskRecord>,
    /// All obligation records.
    pub obligations: Arena<ObligationRecord>,
    /// Current logical time.
    pub now: Time,
    /// The root region.
    pub root_region: Option<RegionId>,
    /// Trace buffer for events.
    pub trace: TraceBuffer,
    /// Next trace sequence number.
    pub trace_seq: u64,
}

impl RuntimeState {
    /// Creates a new empty runtime state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Arena::new(),
            tasks: Arena::new(),
            obligations: Arena::new(),
            now: Time::ZERO,
            root_region: None,
            trace: TraceBuffer::new(4096),
            trace_seq: 0,
        }
    }

    /// Creates a root region and returns its ID.
    pub fn create_root_region(&mut self, budget: Budget) -> RegionId {
        let idx = self.regions.insert(RegionRecord::new(
            RegionId::from_arena(crate::util::ArenaIndex::new(0, 0)), // placeholder
            None,
            budget,
        ));
        let id = RegionId::from_arena(idx);

        // Update the record with the correct ID
        if let Some(record) = self.regions.get_mut(idx) {
            record.id = id;
        }

        self.root_region = Some(id);
        id
    }

    /// Returns the next trace sequence number and increments it.
    pub fn next_trace_seq(&mut self) -> u64 {
        let seq = self.trace_seq;
        self.trace_seq += 1;
        seq
    }

    /// Counts live tasks.
    #[must_use]
    pub fn live_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    /// Counts live regions.
    #[must_use]
    pub fn live_region_count(&self) -> usize {
        self.regions
            .iter()
            .filter(|(_, r)| !r.state.is_terminal())
            .count()
    }

    /// Counts pending obligations.
    #[must_use]
    pub fn pending_obligation_count(&self) -> usize {
        self.obligations
            .iter()
            .filter(|(_, o)| o.is_pending())
            .count()
    }

    /// Returns true if the runtime is quiescent (no live work).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.live_task_count() == 0 && self.pending_obligation_count() == 0
    }

    /// Applies the region policy when a child reaches a terminal outcome.
    ///
    /// This is the core hook for fail-fast behavior: the policy decides whether
    /// siblings should be cancelled.
    pub fn apply_policy_on_child_outcome<P: Policy<Error = crate::error::Error>>(
        &mut self,
        region: RegionId,
        child: TaskId,
        outcome: &Outcome<(), crate::error::Error>,
        policy: &P,
    ) -> PolicyAction {
        let action = policy.on_child_outcome(child, outcome);
        if let PolicyAction::CancelSiblings(reason) = &action {
            self.cancel_sibling_tasks(region, child, reason);
        }
        action
    }

    fn cancel_sibling_tasks(&mut self, region: RegionId, child: TaskId, reason: &CancelReason) {
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return;
        };

        for &task_id in &region_record.tasks {
            if task_id == child {
                continue;
            }
            let Some(task_record) = self.tasks.get_mut(task_id.arena_index()) else {
                continue;
            };
            task_record.request_cancel(reason.clone());
        }
    }

    /// Requests cancellation for a region and all its descendants.
    ///
    /// This implements the CANCEL-REQUEST transition from the formal semantics.
    /// Cancellation propagates down the region tree:
    /// - The target region's cancel_reason is set/strengthened
    /// - All descendant regions are marked with `ParentCancelled`
    /// - All tasks in affected regions are moved to `CancelRequested` state
    ///
    /// Returns a list of (TaskId, priority) pairs for tasks that should be
    /// moved to the cancel lane. The caller is responsible for updating the
    /// scheduler.
    ///
    /// # Arguments
    /// * `region_id` - The region to cancel
    /// * `reason` - The reason for cancellation
    ///
    /// # Example
    /// ```ignore
    /// let tasks_to_schedule = state.cancel_request(region, CancelReason::timeout());
    /// for (task_id, priority) in tasks_to_schedule {
    ///     scheduler.move_to_cancel_lane(task_id, priority);
    /// }
    /// ```
    pub fn cancel_request(
        &mut self,
        region_id: RegionId,
        reason: &CancelReason,
    ) -> Vec<(TaskId, u8)> {
        let mut tasks_to_cancel = Vec::new();
        let cleanup_budget = reason.cleanup_budget();

        // Collect all regions to cancel (target + descendants)
        let regions_to_cancel = self.collect_region_and_descendants(region_id);

        // First pass: mark regions with cancellation reason
        for &rid in &regions_to_cancel {
            if let Some(region) = self.regions.get_mut(rid.arena_index()) {
                // Strengthen or set the cancel reason
                // Use ParentCancelled for descendants, original reason for target
                let region_reason = if rid == region_id {
                    reason.clone()
                } else {
                    CancelReason::parent_cancelled()
                };

                match &mut region.cancel_reason {
                    Some(existing) => {
                        existing.strengthen(&region_reason);
                    }
                    None => {
                        region.cancel_reason = Some(region_reason);
                    }
                }
            }
        }

        // Second pass: mark tasks for cancellation
        for &rid in &regions_to_cancel {
            // Need to get tasks list first to avoid borrow conflict
            let task_ids: Vec<TaskId> = self
                .regions
                .get(rid.arena_index())
                .map(|r| r.tasks.clone())
                .unwrap_or_default();

            for task_id in task_ids {
                if let Some(task) = self.tasks.get_mut(task_id.arena_index()) {
                    // Use the reason's cleanup budget
                    let task_reason = if rid == region_id {
                        reason.clone()
                    } else {
                        CancelReason::parent_cancelled()
                    };

                    let task_budget = task_reason.cleanup_budget();
                    if task.request_cancel_with_budget(task_reason, task_budget) {
                        // Task was newly cancelled, add to list
                        tasks_to_cancel.push((task_id, cleanup_budget.priority));
                    } else if task.state.is_cancelling() {
                        // Task already cancelling, but still needs scheduling priority
                        tasks_to_cancel.push((task_id, cleanup_budget.priority));
                    }
                }
            }
        }

        tasks_to_cancel
    }

    /// Collects a region and all its descendants (recursive).
    ///
    /// Returns a Vec containing the region and all nested child regions.
    fn collect_region_and_descendants(&self, region_id: RegionId) -> Vec<RegionId> {
        let mut result = vec![region_id];
        let mut stack = vec![region_id];

        while let Some(rid) = stack.pop() {
            if let Some(region) = self.regions.get(rid.arena_index()) {
                for &child_id in &region.children {
                    result.push(child_id);
                    stack.push(child_id);
                }
            }
        }

        result
    }

    /// Checks if a region can transition to finalization.
    ///
    /// A region can finalize when all its tasks and child regions have completed.
    /// Returns `true` if the region has no live work remaining.
    #[must_use]
    pub fn can_region_finalize(&self, region_id: RegionId) -> bool {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Check all tasks are terminal
        let all_tasks_done = region.tasks.iter().all(|&task_id| {
            self.tasks
                .get(task_id.arena_index())
                .is_none_or(|t| t.state.is_terminal())
        });

        // Check all child regions are closed
        let all_children_closed = region.children.iter().all(|&child_id| {
            self.regions
                .get(child_id.arena_index())
                .is_none_or(|r| r.state.is_terminal())
        });

        all_tasks_done && all_children_closed
    }

    /// Notifies that a task has completed.
    ///
    /// This checks if the owning region can advance its state.
    /// Returns the task's waiters that should be woken.
    pub fn task_completed(&mut self, task_id: TaskId) -> Vec<TaskId> {
        let Some(task) = self.tasks.get(task_id.arena_index()) else {
            return Vec::new();
        };

        // Return the waiters for the completed task
        task.waiters.clone()
    }

    // =========================================================================
    // Finalizer Registration
    // =========================================================================

    /// Registers a synchronous finalizer for a region.
    ///
    /// Finalizers are stored in LIFO order and run when the region transitions
    /// to the Finalizing state, after all children have completed.
    ///
    /// # Arguments
    /// * `region_id` - The region to register the finalizer with
    /// * `f` - The synchronous cleanup function
    ///
    /// # Returns
    /// `true` if the finalizer was registered, `false` if the region doesn't exist
    /// or is not in a state that accepts finalizers.
    pub fn register_sync_finalizer<F>(&mut self, region_id: RegionId, f: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        let Some(region) = self.regions.get_mut(region_id.arena_index()) else {
            return false;
        };

        // Only allow registration while region is Open
        if !region.state.can_spawn() {
            return false;
        }

        region.add_finalizer(Finalizer::Sync(Box::new(f)));
        true
    }

    /// Registers an asynchronous finalizer for a region.
    ///
    /// Async finalizers run under a cancel mask to prevent interruption.
    /// They are driven to completion with a bounded budget.
    ///
    /// # Arguments
    /// * `region_id` - The region to register the finalizer with
    /// * `future` - The async cleanup future
    ///
    /// # Returns
    /// `true` if the finalizer was registered, `false` if the region doesn't exist
    /// or is not in a state that accepts finalizers.
    pub fn register_async_finalizer<F>(&mut self, region_id: RegionId, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(region) = self.regions.get_mut(region_id.arena_index()) else {
            return false;
        };

        // Only allow registration while region is Open
        if !region.state.can_spawn() {
            return false;
        }

        region.add_finalizer(Finalizer::Async(Box::pin(future)));
        true
    }

    /// Pops the next finalizer from a region's finalizer stack.
    ///
    /// This is called during the Finalizing phase to get the next cleanup
    /// handler to run. Finalizers are returned in LIFO order.
    ///
    /// # Returns
    /// The next finalizer to run, or `None` if all finalizers have been executed.
    pub fn pop_region_finalizer(&mut self, region_id: RegionId) -> Option<Finalizer> {
        let region = self.regions.get_mut(region_id.arena_index())?;
        region.pop_finalizer()
    }

    /// Returns the number of pending finalizers for a region.
    #[must_use]
    pub fn region_finalizer_count(&self, region_id: RegionId) -> usize {
        self.regions
            .get(region_id.arena_index())
            .map_or(0, RegionRecord::finalizer_count)
    }

    /// Returns true if a region has no pending finalizers.
    #[must_use]
    pub fn region_finalizers_empty(&self, region_id: RegionId) -> bool {
        self.regions
            .get(region_id.arena_index())
            .is_none_or(RegionRecord::finalizers_empty)
    }

    /// Runs all synchronous finalizers for a region.
    ///
    /// This method pops and executes sync finalizers in LIFO order.
    /// Async finalizers are skipped and must be handled separately by the
    /// scheduler (they need to be polled to completion).
    ///
    /// # Returns
    /// A vector of async finalizers that need to be scheduled.
    pub fn run_sync_finalizers(&mut self, region_id: RegionId) -> Vec<Finalizer> {
        let mut async_finalizers = Vec::new();

        loop {
            let Some(finalizer) = self.pop_region_finalizer(region_id) else {
                break;
            };

            match finalizer {
                Finalizer::Sync(f) => {
                    // Run synchronously
                    f();
                    // Trace event would be recorded here in full implementation
                }
                Finalizer::Async(_) => {
                    // Collect for scheduler to handle
                    async_finalizers.push(finalizer);
                }
            }
        }

        async_finalizers
    }

    /// Checks if a region can complete its close sequence.
    ///
    /// A region can complete close when:
    /// 1. It's in the Finalizing state
    /// 2. All finalizers have been executed
    /// 3. All obligations are resolved
    ///
    /// # Returns
    /// `true` if the region can transition to Closed state.
    #[must_use]
    pub fn can_region_complete_close(&self, region_id: RegionId) -> bool {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Must be in Finalizing state
        if region.state != crate::record::region::RegionState::Finalizing {
            return false;
        }

        // All finalizers must be done
        if !region.finalizers_empty() {
            return false;
        }

        // All obligations must be resolved (to be implemented with obligation tracking)
        // For now, we assume obligations are resolved if we got to this point
        true
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::task::TaskState;
    use crate::types::CancelKind;
    use crate::util::ArenaIndex;

    fn insert_task(state: &mut RuntimeState, region: RegionId) -> TaskId {
        let idx = state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        state.tasks.get_mut(idx).expect("task missing").id = id;
        state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .add_task(id);
        id
    }

    #[test]
    fn empty_state_is_quiescent() {
        let state = RuntimeState::new();
        assert!(state.is_quiescent());
    }

    #[test]
    fn create_root_region() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        assert!(state.root_region.is_some());
        assert_eq!(state.root_region, Some(root));
        assert_eq!(state.live_region_count(), 1);
    }

    #[test]
    fn policy_can_cancel_siblings() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib1 = insert_task(&mut state, region);
        let sib2 = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let action = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        assert_eq!(
            action,
            PolicyAction::CancelSiblings(CancelReason::sibling_failed())
        );

        for sib in [sib1, sib2] {
            let record = state.tasks.get(sib.arena_index()).expect("sib missing");
            match &record.state {
                TaskState::CancelRequested { reason, .. } => {
                    assert_eq!(reason.kind, CancelKind::FailFast);
                }
                other => panic!("expected CancelRequested, got {other:?}"),
            }
        }
        let child_record = state.tasks.get(child.arena_index()).expect("child missing");
        assert!(matches!(child_record.state, TaskState::Created));
    }

    #[test]
    fn policy_does_not_cancel_siblings_on_cancelled_child() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let action = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        assert_eq!(action, PolicyAction::Continue);
        let sib_record = state.tasks.get(sib.arena_index()).expect("sib missing");
        assert!(matches!(sib_record.state, TaskState::Created));
    }

    fn create_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
        let idx = state.regions.insert(RegionRecord::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            Some(parent),
            Budget::INFINITE,
        ));
        let id = RegionId::from_arena(idx);
        state.regions.get_mut(idx).expect("region missing").id = id;
        state
            .regions
            .get_mut(parent.arena_index())
            .expect("parent missing")
            .add_child(id);
        id
    }

    #[test]
    fn cancel_request_marks_region() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let _tasks = state.cancel_request(region, &CancelReason::timeout());

        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        assert!(region_record.cancel_reason.is_some());
        assert_eq!(
            region_record.cancel_reason.as_ref().unwrap().kind,
            CancelKind::Timeout
        );
    }

    #[test]
    fn cancel_request_marks_tasks() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task1 = insert_task(&mut state, region);
        let task2 = insert_task(&mut state, region);

        let tasks_to_schedule = state.cancel_request(region, &CancelReason::timeout());

        // Both tasks should be returned for scheduling
        assert_eq!(tasks_to_schedule.len(), 2);
        let task_ids: Vec<_> = tasks_to_schedule.iter().map(|(id, _)| *id).collect();
        assert!(task_ids.contains(&task1));
        assert!(task_ids.contains(&task2));

        // Tasks should be in CancelRequested state
        for (task_id, _) in tasks_to_schedule {
            let task = state
                .tasks
                .get(task_id.arena_index())
                .expect("task missing");
            assert!(matches!(task.state, TaskState::CancelRequested { .. }));
        }
    }

    #[test]
    fn cancel_request_propagates_to_descendants() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);
        let grandchild_task = insert_task(&mut state, grandchild);

        let tasks_to_schedule = state.cancel_request(root, &CancelReason::user("stop"));

        // All 3 tasks should be scheduled
        assert_eq!(tasks_to_schedule.len(), 3);

        // Root region gets original reason
        let root_record = state.regions.get(root.arena_index()).expect("root missing");
        assert_eq!(
            root_record.cancel_reason.as_ref().unwrap().kind,
            CancelKind::User
        );

        // Descendants get ParentCancelled
        let child_record = state
            .regions
            .get(child.arena_index())
            .expect("child missing");
        assert_eq!(
            child_record.cancel_reason.as_ref().unwrap().kind,
            CancelKind::ParentCancelled
        );

        let grandchild_record = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild missing");
        assert_eq!(
            grandchild_record.cancel_reason.as_ref().unwrap().kind,
            CancelKind::ParentCancelled
        );

        // Root task gets User reason, descendants get ParentCancelled
        let root_task_record = state
            .tasks
            .get(root_task.arena_index())
            .expect("task missing");
        match &root_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                assert_eq!(reason.kind, CancelKind::User);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        let child_task_record = state
            .tasks
            .get(child_task.arena_index())
            .expect("task missing");
        match &child_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                assert_eq!(reason.kind, CancelKind::ParentCancelled);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        let grandchild_task_record = state
            .tasks
            .get(grandchild_task.arena_index())
            .expect("task missing");
        match &grandchild_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                assert_eq!(reason.kind, CancelKind::ParentCancelled);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
    }

    #[test]
    fn cancel_request_strengthens_existing_reason() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // First cancel with User
        let _ = state.cancel_request(region, &CancelReason::user("stop"));

        // Second cancel with Shutdown (higher severity)
        let _ = state.cancel_request(region, &CancelReason::shutdown());

        // Region should have Shutdown reason
        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        assert_eq!(
            region_record.cancel_reason.as_ref().unwrap().kind,
            CancelKind::Shutdown
        );

        // Task should have Shutdown reason
        let task_record = state.tasks.get(task.arena_index()).expect("task missing");
        match &task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                assert_eq!(reason.kind, CancelKind::Shutdown);
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
    }

    #[test]
    fn can_region_finalize_with_all_tasks_done() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Not finalizable while task is live
        assert!(!state.can_region_finalize(region));

        // Complete the task
        state
            .tasks
            .get_mut(task.arena_index())
            .expect("task missing")
            .complete(Outcome::Ok(()));

        // Now region can finalize
        assert!(state.can_region_finalize(region));
    }

    #[test]
    fn can_region_finalize_requires_child_regions_closed() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);

        // Child region is Open, so root cannot finalize
        assert!(!state.can_region_finalize(root));

        // Close the child region
        let child_record = state
            .regions
            .get_mut(child.arena_index())
            .expect("child missing");
        child_record.begin_close(None);
        child_record.begin_finalize();
        child_record.complete_close();

        // Now root can finalize
        assert!(state.can_region_finalize(root));
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn register_sync_finalizer() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        assert!(state.region_finalizers_empty(region));
        assert_eq!(state.region_finalizer_count(region), 0);

        // Register a sync finalizer
        assert!(state.register_sync_finalizer(region, || {}));

        assert!(!state.region_finalizers_empty(region));
        assert_eq!(state.region_finalizer_count(region), 1);
    }

    #[test]
    fn register_async_finalizer() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        assert!(state.register_async_finalizer(region, async {}));
        assert_eq!(state.region_finalizer_count(region), 1);
    }

    #[test]
    fn register_finalizer_fails_when_region_not_open() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Close the region
        state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .begin_close(None);

        // Registration should fail
        assert!(!state.register_sync_finalizer(region, || {}));
        assert!(!state.register_async_finalizer(region, async {}));
    }

    #[test]
    fn register_finalizer_fails_for_nonexistent_region() {
        let mut state = RuntimeState::new();
        let fake_region = RegionId::from_arena(ArenaIndex::new(999, 0));

        assert!(!state.register_sync_finalizer(fake_region, || {}));
        assert!(!state.register_async_finalizer(fake_region, async {}));
    }

    #[test]
    fn pop_region_finalizer_lifo() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        // Register finalizers: 1, 2, 3
        state.register_sync_finalizer(region, move || o1.lock().unwrap().push(1));
        state.register_sync_finalizer(region, move || o2.lock().unwrap().push(2));
        state.register_sync_finalizer(region, move || o3.lock().unwrap().push(3));

        // Pop and execute in LIFO order
        while let Some(finalizer) = state.pop_region_finalizer(region) {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        assert_eq!(*order.lock().unwrap(), vec![3, 2, 1]);
    }

    #[test]
    fn run_sync_finalizers_executes_and_returns_async() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let sync_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sync_called_clone = sync_called.clone();

        // Register mix of sync and async finalizers
        state.register_sync_finalizer(region, move || {
            sync_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        state.register_async_finalizer(region, async {});
        state.register_sync_finalizer(region, || {}); // Another sync

        let async_finalizers = state.run_sync_finalizers(region);

        // Sync finalizers should have been called
        assert!(sync_called.load(std::sync::atomic::Ordering::SeqCst));

        // One async finalizer should be returned
        assert_eq!(async_finalizers.len(), 1);
        assert!(matches!(async_finalizers[0], Finalizer::Async(_)));

        // All finalizers should be cleared from region
        assert!(state.region_finalizers_empty(region));
    }

    #[test]
    fn can_region_complete_close_requires_finalizing_state() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Must be in Finalizing state
        assert!(!state.can_region_complete_close(region));

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Now it can complete (no finalizers)
        assert!(state.can_region_complete_close(region));
    }

    #[test]
    fn can_region_complete_close_checks_finalizers() {
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Add finalizer while open
        state.register_sync_finalizer(region, || {});

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Can't complete while finalizers pending
        assert!(!state.can_region_complete_close(region));

        // Run the finalizers
        let _ = state.run_sync_finalizers(region);

        // Now can complete
        assert!(state.can_region_complete_close(region));
    }
}
