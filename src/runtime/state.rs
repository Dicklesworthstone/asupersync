//! Global runtime state.
//!
//! The runtime state Σ contains all live entities:
//! - Regions (ownership tree)
//! - Tasks (units of execution)
//! - Obligations (resources to be resolved)
//! - Current time

use crate::error::{Error, ErrorKind};
use crate::record::finalizer::Finalizer;
use crate::record::{
    ObligationAbortReason, ObligationKind, ObligationRecord, RegionRecord, TaskRecord,
};
use crate::runtime::io_driver::{IoDriver, IoDriverHandle};
use crate::runtime::reactor::Reactor;
use crate::runtime::stored_task::StoredTask;
use crate::trace::{TraceBuffer, TraceEvent};
use crate::tracing_compat::{debug, debug_span, trace, trace_span};
use crate::types::policy::PolicyAction;
use crate::types::{Budget, CancelReason, ObligationId, Outcome, Policy, RegionId, TaskId, Time};
use crate::util::Arena;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

/// Errors that can occur when spawning a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    /// The target region does not exist.
    RegionNotFound(RegionId),
    /// The target region is closed or draining and cannot accept new tasks.
    RegionClosed(RegionId),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "region not found: {id:?}"),
            Self::RegionClosed(id) => write!(f, "region closed: {id:?}"),
        }
    }
}

impl std::error::Error for SpawnError {}

#[derive(Debug, Clone, Copy)]
struct CancelRegionNode {
    id: RegionId,
    parent: Option<RegionId>,
    depth: usize,
}

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
    /// Stored futures for polling.
    ///
    /// Maps task IDs to their pollable futures. When a task is created via
    /// `spawn()`, its wrapped future is stored here for the executor to poll.
    pub(crate) stored_futures: HashMap<TaskId, StoredTask>,
    /// I/O driver for reactor integration.
    ///
    /// When present, the runtime can wait on I/O events via the reactor.
    /// When `None`, the runtime operates in pure Lab mode without real I/O.
    io_driver: Option<IoDriverHandle>,
}

impl RuntimeState {
    /// Creates a new empty runtime state without a reactor.
    ///
    /// This is equivalent to [`without_reactor()`](Self::without_reactor) and creates
    /// a runtime suitable for Lab mode or pure computation without I/O.
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
            stored_futures: HashMap::new(),
            io_driver: None,
        }
    }

    /// Creates a runtime state with a real reactor for production use.
    ///
    /// The provided reactor will be wrapped in an [`IoDriver`] to handle
    /// waker dispatch. Use this constructor when you need real I/O support.
    ///
    /// # Arguments
    ///
    /// * `reactor` - The platform-specific reactor (e.g., `EpollReactor` on Linux)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::{RuntimeState, EpollReactor};
    /// use std::sync::Arc;
    ///
    /// let reactor = Arc::new(EpollReactor::new()?);
    /// let state = RuntimeState::with_reactor(reactor);
    /// ```
    #[must_use]
    pub fn with_reactor(reactor: Arc<dyn Reactor>) -> Self {
        Self {
            regions: Arena::new(),
            tasks: Arena::new(),
            obligations: Arena::new(),
            now: Time::ZERO,
            root_region: None,
            trace: TraceBuffer::new(4096),
            trace_seq: 0,
            stored_futures: HashMap::new(),
            io_driver: Some(IoDriverHandle::new(reactor)),
        }
    }

    /// Creates a runtime state without a reactor (Lab mode).
    ///
    /// Use this for deterministic testing or pure computation without I/O.
    /// This is equivalent to [`new()`](Self::new).
    #[must_use]
    pub fn without_reactor() -> Self {
        Self::new()
    }

    /// Returns a reference to the I/O driver handle, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    #[must_use]
    pub fn io_driver(&self) -> Option<&IoDriverHandle> {
        self.io_driver.as_ref()
    }

    /// Returns a locked guard to the I/O driver, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    pub fn io_driver_mut(&self) -> Option<std::sync::MutexGuard<'_, IoDriver>> {
        self.io_driver.as_ref().map(IoDriverHandle::lock)
    }

    /// Returns a cloned handle to the I/O driver, if present.
    ///
    /// Returns `None` if the runtime was created without a reactor.
    #[must_use]
    pub fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.io_driver.clone()
    }

    /// Returns `true` if this runtime has an I/O driver.
    #[must_use]
    pub fn has_io_driver(&self) -> bool {
        self.io_driver.is_some()
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

    /// Creates a task and stores its future for polling.
    ///
    /// This is the core spawn primitive. It:
    /// 1. Creates a TaskRecord in the specified region
    /// 2. Wraps the future to send its result through a oneshot channel
    /// 3. Stores the wrapped future for the executor to poll
    /// 4. Returns a TaskHandle for awaiting the result
    ///
    /// # Arguments
    /// * `region` - The region that will own this task
    /// * `budget` - The budget for this task
    /// * `future` - The future to execute
    ///
    /// # Returns
    /// A Result containing `(TaskId, TaskHandle)` on success, or `SpawnError` on failure.
    ///
    /// # Example
    /// ```ignore
    /// let (task_id, handle) = state.create_task(region, budget, async { 42 })?;
    /// // Later: scheduler.schedule(task_id);
    /// // Even later: let result = handle.join(cx)?;
    /// ```
    pub fn create_task<F, T>(
        &mut self,
        region: RegionId,
        budget: Budget,
        future: F,
    ) -> Result<(TaskId, crate::runtime::TaskHandle<T>), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use crate::channel::oneshot;
        use crate::runtime::task_handle::JoinError;

        // Create oneshot channel for the result
        let (result_tx, result_rx) = oneshot::channel::<Result<T, JoinError>>();

        // Create the TaskRecord
        let idx = self.tasks.insert(TaskRecord::new(
            TaskId::from_arena(crate::util::ArenaIndex::new(0, 0)), // placeholder
            region,
            budget,
        ));
        let task_id = TaskId::from_arena(idx);

        // Update the record with the correct ID
        if let Some(record) = self.tasks.get_mut(idx) {
            record.id = task_id;
        }

        // Add task to the region's task list
        if let Some(region_record) = self.regions.get(region.arena_index()) {
            if !region_record.add_task(task_id) {
                // Rollback task creation
                self.tasks.remove(idx);
                return Err(SpawnError::RegionClosed(region));
            }
        } else {
            // Rollback task creation
            self.tasks.remove(idx);
            return Err(SpawnError::RegionNotFound(region));
        }

        // Create the task's capability context
        let cx = crate::cx::Cx::new_with_observability(
            region,
            task_id,
            budget,
            None,
            self.io_driver_handle(),
        );
        let cx_weak = std::sync::Arc::downgrade(&cx.inner);

        // Link the shared state to the TaskRecord
        if let Some(record) = self.tasks.get_mut(idx) {
            record.set_cx_inner(cx.inner.clone());
            record.set_cx(cx.clone());
        }

        // Wrap the future to send the result through the channel
        let wrapped_future = async move {
            let result = future.await;
            // Send the result - ignore error if TaskHandle was dropped
            let _ = result_tx.send(&cx, Ok::<_, JoinError>(result));
        };

        // Store the wrapped future
        self.stored_futures
            .insert(task_id, StoredTask::new(wrapped_future));

        // Trace task creation
        debug!(
            task_id = ?task_id,
            region_id = ?region,
            initial_state = "Created",
            poll_quota = budget.poll_quota,
            "task created via RuntimeState::create_task"
        );

        // Create the TaskHandle
        let handle = crate::runtime::TaskHandle::new(task_id, result_rx, cx_weak);

        Ok((task_id, handle))
    }

    /// Creates and registers an obligation for the given task and region.
    ///
    /// This records the obligation in the registry and emits a trace event.
    pub fn create_obligation(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        description: Option<String>,
    ) -> ObligationId {
        let reserved_at = self.now;
        let idx = if let Some(desc) = description {
            self.obligations.insert(ObligationRecord::with_description(
                ObligationId::from_arena(crate::util::ArenaIndex::new(0, 0)),
                kind,
                holder,
                region,
                reserved_at,
                desc,
            ))
        } else {
            self.obligations.insert(ObligationRecord::new(
                ObligationId::from_arena(crate::util::ArenaIndex::new(0, 0)),
                kind,
                holder,
                region,
                reserved_at,
            ))
        };
        let obligation_id = ObligationId::from_arena(idx);
        if let Some(record) = self.obligations.get_mut(idx) {
            record.id = obligation_id;
        }

        let _span = crate::tracing_compat::debug_span!(
            "obligation_reserve",
            obligation_id = ?obligation_id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region
        );
        crate::tracing_compat::debug!(
            obligation_id = ?obligation_id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            "obligation reserved"
        );

        let seq = self.next_trace_seq();
        self.trace.push(TraceEvent::obligation_reserve(
            seq,
            self.now,
            obligation_id,
            holder,
            region,
            kind,
        ));

        obligation_id
    }

    /// Marks an obligation as committed and emits a trace event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    pub fn commit_obligation(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        // Extract data first to avoid borrow conflicts with self.next_trace_seq()
        let (duration, id, holder, region, kind) = {
            let record = self
                .obligations
                .get_mut(obligation.arena_index())
                .ok_or_else(|| {
                    Error::new(ErrorKind::ObligationAlreadyResolved)
                        .with_message("obligation not found")
                })?;

            if !record.is_pending() {
                return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
            }

            let duration = record.commit(self.now);
            (
                duration,
                record.id,
                record.holder,
                record.region,
                record.kind,
            )
        };

        let _span = crate::tracing_compat::debug_span!(
            "obligation_commit",
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration
        );
        crate::tracing_compat::debug!(
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration,
            "obligation committed"
        );

        let seq = self.next_trace_seq();
        self.trace.push(TraceEvent::obligation_commit(
            seq, self.now, id, holder, region, kind, duration,
        ));

        Ok(duration)
    }

    /// Marks an obligation as aborted and emits a trace event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    pub fn abort_obligation(
        &mut self,
        obligation: ObligationId,
        reason: ObligationAbortReason,
    ) -> Result<u64, Error> {
        // Extract data first to avoid borrow conflicts with self.next_trace_seq()
        let (duration, id, holder, region, kind) = {
            let record = self
                .obligations
                .get_mut(obligation.arena_index())
                .ok_or_else(|| {
                    Error::new(ErrorKind::ObligationAlreadyResolved)
                        .with_message("obligation not found")
                })?;

            if !record.is_pending() {
                return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
            }

            let duration = record.abort(self.now, reason);
            (
                duration,
                record.id,
                record.holder,
                record.region,
                record.kind,
            )
        };

        let _span = crate::tracing_compat::debug_span!(
            "obligation_abort",
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration,
            abort_reason = %reason
        );
        crate::tracing_compat::debug!(
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration,
            abort_reason = %reason,
            "obligation aborted"
        );

        let seq = self.next_trace_seq();
        self.trace.push(TraceEvent::obligation_abort(
            seq, self.now, id, holder, region, kind, duration, reason,
        ));

        Ok(duration)
    }

    /// Marks an obligation as leaked and emits a trace + error event.
    ///
    /// Returns the duration the obligation was held (nanoseconds).
    pub fn mark_obligation_leaked(&mut self, obligation: ObligationId) -> Result<u64, Error> {
        // Extract data first to avoid borrow conflicts with self.next_trace_seq()
        let (duration, id, holder, region, kind) = {
            let record = self
                .obligations
                .get_mut(obligation.arena_index())
                .ok_or_else(|| {
                    Error::new(ErrorKind::ObligationAlreadyResolved)
                        .with_message("obligation not found")
                })?;

            if !record.is_pending() {
                return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
            }

            let duration = record.mark_leaked(self.now);
            (
                duration,
                record.id,
                record.holder,
                record.region,
                record.kind,
            )
        };

        let _span = crate::tracing_compat::error_span!(
            "obligation_leak",
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration
        );

        let seq = self.next_trace_seq();
        self.trace.push(TraceEvent::obligation_leak(
            seq, self.now, id, holder, region, kind, duration,
        ));
        crate::tracing_compat::error!(
            obligation_id = ?id,
            kind = ?kind,
            holder_task = ?holder,
            region_id = ?region,
            duration_ns = duration,
            "obligation leaked"
        );

        Ok(duration)
    }

    /// Gets a mutable reference to a stored future for polling.
    ///
    /// Returns `None` if no future is stored for this task.
    pub fn get_stored_future(&mut self, task_id: TaskId) -> Option<&mut StoredTask> {
        self.stored_futures.get_mut(&task_id)
    }

    /// Removes and returns a stored future.
    ///
    /// Called when a task completes to clean up the future storage.
    pub fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        self.stored_futures.remove(&task_id)
    }

    /// Stores a spawned task's future for execution.
    ///
    /// This is called after `Scope::spawn` to register the `StoredTask` with
    /// the runtime. The task must already have a `TaskRecord` created via spawn.
    ///
    /// # Arguments
    /// * `task_id` - The ID of the task (from the TaskHandle)
    /// * `stored` - The StoredTask containing the wrapped future
    ///
    /// # Example
    /// ```ignore
    /// let (handle, stored) = scope.spawn(&mut state, &cx, |_| async { 42 })?;
    /// state.store_spawned_task(handle.task_id(), stored);
    /// // Now the executor can poll the task
    /// ```
    pub fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        self.stored_futures.insert(task_id, stored);
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
            .filter(|(_, r)| !r.state().is_terminal())
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
    ///
    /// A runtime is quiescent when:
    /// - No live tasks are running
    /// - No pending obligations exist
    /// - No I/O sources are registered (if I/O driver is present)
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let no_tasks = self.live_task_count() == 0;
        let no_obligations = self.pending_obligation_count() == 0;
        let no_io = self.io_driver.as_ref().is_none_or(IoDriverHandle::is_empty);
        no_tasks && no_obligations && no_io
    }

    /// Applies the region policy when a child reaches a terminal outcome.
    ///
    /// This is the core hook for fail-fast behavior: the policy decides whether
    /// siblings should be cancelled.
    ///
    /// Returns the policy action taken and a list of tasks that need to be
    /// moved to the cancel lane in the scheduler.
    pub fn apply_policy_on_child_outcome<P: Policy<Error = crate::error::Error>>(
        &mut self,
        region: RegionId,
        child: TaskId,
        outcome: &Outcome<(), crate::error::Error>,
        policy: &P,
    ) -> (PolicyAction, Vec<(TaskId, u8)>) {
        let action = policy.on_child_outcome(child, outcome);
        let tasks_to_schedule = if let PolicyAction::CancelSiblings(reason) = &action {
            self.cancel_sibling_tasks(region, child, reason)
        } else {
            Vec::new()
        };
        (action, tasks_to_schedule)
    }

    fn cancel_sibling_tasks(
        &mut self,
        region: RegionId,
        child: TaskId,
        reason: &CancelReason,
    ) -> Vec<(TaskId, u8)> {
        let mut tasks_to_cancel = Vec::new();
        let Some(region_record) = self.regions.get(region.arena_index()) else {
            return tasks_to_cancel;
        };

        for task_id in region_record.task_ids() {
            if task_id == child {
                continue;
            }
            let Some(task_record) = self.tasks.get_mut(task_id.arena_index()) else {
                continue;
            };

            let budget = reason.cleanup_budget();
            if task_record.request_cancel_with_budget(reason.clone(), budget) {
                tasks_to_cancel.push((task_id, budget.priority));
            } else if task_record.state.is_cancelling() {
                tasks_to_cancel.push((task_id, budget.priority));
            }
        }
        tasks_to_cancel
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
    /// * `source_task` - The task that initiated cancellation, if known
    ///
    /// # Example
    /// ```ignore
    /// let tasks_to_schedule = state.cancel_request(region, &CancelReason::timeout(), None);
    /// for (task_id, priority) in tasks_to_schedule {
    ///     scheduler.move_to_cancel_lane(task_id, priority);
    /// }
    /// ```
    pub fn cancel_request(
        &mut self,
        region_id: RegionId,
        reason: &CancelReason,
        _source_task: Option<TaskId>,
    ) -> Vec<(TaskId, u8)> {
        let mut tasks_to_cancel = Vec::new();
        let cleanup_budget = reason.cleanup_budget();
        let root_span = debug_span!(
            "cancel_request",
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = cleanup_budget.poll_quota,
            cleanup_priority = cleanup_budget.priority,
            source_task = ?_source_task
        );
        let _root_guard = root_span.enter();

        debug!(
            target_region = ?region_id,
            cancel_kind = ?reason.kind,
            cancel_message = ?reason.message,
            cleanup_poll_quota = cleanup_budget.poll_quota,
            cleanup_priority = cleanup_budget.priority,
            source_task = ?_source_task,
            "cancel request initiated"
        );

        // Collect all regions to cancel (target + descendants) with depth information
        let regions_to_cancel = self.collect_region_and_descendants_with_depth(region_id);

        // First pass: mark regions with cancellation reason and transition to Closing
        for node in &regions_to_cancel {
            let rid = node.id;
            let region_reason = if rid == region_id {
                reason.clone()
            } else {
                CancelReason::parent_cancelled()
            };

            if let Some(_parent) = node.parent {
                let span = trace_span!(
                    "cancel_propagate_region",
                    from_region = ?_parent,
                    to_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind
                );
                span.follows_from(&root_span);
                let _guard = span.enter();
                trace!(
                    from_region = ?_parent,
                    to_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    "cancel propagated to region"
                );
            } else {
                trace!(
                    target_region = ?rid,
                    depth = node.depth,
                    cancel_kind = ?region_reason.kind,
                    "cancel target region"
                );
            }

            if let Some(region) = self.regions.get(rid.arena_index()) {
                // Use ParentCancelled for descendants, original reason for target
                // Try to transition to Closing with the reason.
                // If already Closing/Draining/etc., strengthen the reason instead.
                if !region.begin_close(Some(region_reason.clone())) {
                    region.strengthen_cancel_reason(region_reason);
                }
            }
        }

        // Second pass: mark tasks for cancellation
        for node in &regions_to_cancel {
            let rid = node.id;
            // Need to get tasks list first to avoid borrow conflict
            let task_ids: Vec<TaskId> = self
                .regions
                .get(rid.arena_index())
                .map(RegionRecord::task_ids)
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
                    let newly_cancelled = task.request_cancel_with_budget(task_reason, task_budget);
                    let already_cancelling = task.state.is_cancelling();
                    let span = trace_span!(
                        "cancel_propagate_task",
                        from_region = ?rid,
                        to_task = ?task_id,
                        depth = node.depth,
                        cancel_kind = ?task.cancel_reason().map(|r| r.kind)
                    );
                    span.follows_from(&root_span);
                    let _guard = span.enter();
                    trace!(
                        from_region = ?rid,
                        to_task = ?task_id,
                        depth = node.depth,
                        newly_cancelled,
                        already_cancelling,
                        cleanup_poll_quota = task_budget.poll_quota,
                        cleanup_priority = task_budget.priority,
                        "cancel propagated to task"
                    );

                    if newly_cancelled {
                        // Task was newly cancelled, add to list
                        tasks_to_cancel.push((task_id, cleanup_budget.priority));
                    } else if already_cancelling {
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
    fn collect_region_and_descendants_with_depth(
        &self,
        region_id: RegionId,
    ) -> Vec<CancelRegionNode> {
        let mut result = Vec::new();
        let mut stack = vec![(region_id, None, 0usize)];

        while let Some((rid, parent, depth)) = stack.pop() {
            result.push(CancelRegionNode {
                id: rid,
                parent,
                depth,
            });

            if let Some(region) = self.regions.get(rid.arena_index()) {
                for child_id in region.child_ids() {
                    stack.push((child_id, Some(rid), depth + 1));
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
        let all_tasks_done = region.task_ids().iter().all(|&task_id| {
            self.tasks
                .get(task_id.arena_index())
                .is_none_or(|t| t.state.is_terminal())
        });

        // Check all child regions are closed
        let all_children_closed = region.child_ids().iter().all(|&child_id| {
            self.regions
                .get(child_id.arena_index())
                .is_none_or(|r| r.state().is_terminal())
        });

        all_tasks_done && all_children_closed
    }

    /// Notifies that a task has completed.
    ///
    /// This checks if the owning region can advance its state.
    /// Returns the task's waiters that should be woken.
    pub fn task_completed(&mut self, task_id: TaskId) -> Vec<TaskId> {
        // Remove the task record to prevent memory leaks
        let Some(task) = self.tasks.remove(task_id.arena_index()) else {
            trace!(
                task_id = ?task_id,
                "task_completed called for unknown task"
            );
            return Vec::new();
        };

        // Get the owning region and the waiters before we mutate
        let owner = task.owner;
        let waiters = task.waiters.clone();
        let _waiter_count = waiters.len();

        // Trace task completion
        let _outcome_kind = match &task.state {
            crate::record::task::TaskState::Completed(outcome) => match outcome {
                Outcome::Ok(()) => "Ok",
                Outcome::Err(_) => "Err",
                Outcome::Cancelled(_) => "Cancelled",
                Outcome::Panicked(_) => "Panicked",
            },
            _ => "Unknown",
        };
        debug!(
            task_id = ?task_id,
            region_id = ?owner,
            outcome_kind = _outcome_kind,
            waiter_count = _waiter_count,
            "task cleanup from runtime state"
        );

        // Remove task from owning region to prevent memory leak
        if let Some(region) = self.regions.get(owner.arena_index()) {
            region.remove_task(task_id);
        }

        // Return the waiters for the completed task
        waiters
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
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Only allow registration while region is Open
        if !region.state().can_spawn() {
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
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Only allow registration while region is Open
        if !region.state().can_spawn() {
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
        let region = self.regions.get(region_id.arena_index())?;
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
    /// 3. All tasks (including those spawned by finalizers) are terminal
    /// 4. All obligations are resolved
    ///
    /// # Returns
    /// `true` if the region can transition to Closed state.
    #[must_use]
    pub fn can_region_complete_close(&self, region_id: RegionId) -> bool {
        let Some(region) = self.regions.get(region_id.arena_index()) else {
            return false;
        };

        // Must be in Finalizing state
        if region.state() != crate::record::region::RegionState::Finalizing {
            return false;
        }

        // All finalizers must be done
        if !region.finalizers_empty() {
            return false;
        }

        // All tasks must be terminal (including any spawned by finalizers)
        let all_tasks_done = region.task_ids().iter().all(|&task_id| {
            self.tasks
                .get(task_id.arena_index())
                .is_none_or(|t| t.state.is_terminal())
        });

        if !all_tasks_done {
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
    use crate::test_utils::init_test_logging;
    use crate::types::CancelKind;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn insert_task(state: &mut RuntimeState, region: RegionId) -> TaskId {
        let idx = state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        state.tasks.get_mut(idx).expect("task missing").id = id;
        let added = state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .add_task(id);
        crate::assert_with_log!(added, "task added to region", true, added);
        id
    }

    #[test]
    fn can_region_complete_close_checks_running_finalizer_tasks() {
        init_test("can_region_complete_close_checks_running_finalizer_tasks");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Manually transition to Finalizing (simulating finalizer execution)
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Add a running task (representing an async finalizer)
        let task = insert_task(&mut state, region);
        state
            .tasks
            .get_mut(task.arena_index())
            .expect("task")
            .start_running();

        // Should NOT be able to close because a task is running
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close with running task",
            false,
            can_close
        );

        // Complete the task
        state
            .tasks
            .get_mut(task.arena_index())
            .expect("task")
            .complete(Outcome::Ok(()));

        // Now should be able to close
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close after task completes", true, can_close);
        crate::test_complete!("can_region_complete_close_checks_running_finalizer_tasks");
    }

    #[test]
    fn empty_state_is_quiescent() {
        init_test("empty_state_is_quiescent");
        let state = RuntimeState::new();
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "state quiescent", true, quiescent);
        crate::test_complete!("empty_state_is_quiescent");
    }

    #[test]
    fn create_root_region() {
        init_test("create_root_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        crate::assert_with_log!(
            state.root_region.is_some(),
            "root region set",
            true,
            state.root_region.is_some()
        );
        crate::assert_with_log!(
            state.root_region == Some(root),
            "root id matches",
            Some(root),
            state.root_region
        );
        crate::assert_with_log!(
            state.live_region_count() == 1,
            "live region count",
            1usize,
            state.live_region_count()
        );
        crate::test_complete!("create_root_region");
    }

    #[test]
    fn policy_can_cancel_siblings() {
        init_test("policy_can_cancel_siblings");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib1 = insert_task(&mut state, region);
        let sib2 = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let (action, tasks) = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        let expected_action = PolicyAction::CancelSiblings(CancelReason::sibling_failed());
        crate::assert_with_log!(
            action == expected_action,
            "cancel siblings action",
            expected_action,
            action
        );
        crate::assert_with_log!(tasks.len() == 2, "tasks len", 2usize, tasks.len());

        for sib in [sib1, sib2] {
            let record = state.tasks.get(sib.arena_index()).expect("sib missing");
            match &record.state {
                TaskState::CancelRequested { reason, .. } => {
                    crate::assert_with_log!(
                        reason.kind == CancelKind::FailFast,
                        "cancel reason kind",
                        CancelKind::FailFast,
                        reason.kind
                    );
                }
                other => panic!("expected CancelRequested, got {other:?}"),
            }
        }
        let child_record = state.tasks.get(child.arena_index()).expect("child missing");
        let is_created = matches!(child_record.state, TaskState::Created);
        crate::assert_with_log!(is_created, "child remains created", true, is_created);
        crate::test_complete!("policy_can_cancel_siblings");
    }

    #[test]
    fn policy_does_not_cancel_siblings_on_cancelled_child() {
        init_test("policy_does_not_cancel_siblings_on_cancelled_child");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let child = insert_task(&mut state, region);
        let sib = insert_task(&mut state, region);

        let policy = crate::types::policy::FailFast;
        let outcome = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let (action, _) = state.apply_policy_on_child_outcome(region, child, &outcome, &policy);

        crate::assert_with_log!(
            action == PolicyAction::Continue,
            "action continue",
            PolicyAction::Continue,
            action
        );
        let sib_record = state.tasks.get(sib.arena_index()).expect("sib missing");
        let is_created = matches!(sib_record.state, TaskState::Created);
        crate::assert_with_log!(is_created, "sibling remains created", true, is_created);
        crate::test_complete!("policy_does_not_cancel_siblings_on_cancelled_child");
    }

    fn create_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
        let idx = state.regions.insert(RegionRecord::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            Some(parent),
            Budget::INFINITE,
        ));
        let id = RegionId::from_arena(idx);
        state.regions.get_mut(idx).expect("region missing").id = id;
        let added = state
            .regions
            .get_mut(parent.arena_index())
            .expect("parent missing")
            .add_child(id);
        crate::assert_with_log!(added, "child added to parent", true, added);
        id
    }

    #[test]
    fn cancel_request_marks_region() {
        init_test("cancel_request_marks_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let _tasks = state.cancel_request(region, &CancelReason::timeout(), None);

        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        let cancel_reason = region_record.cancel_reason();
        crate::assert_with_log!(
            cancel_reason.is_some(),
            "cancel reason set",
            true,
            cancel_reason.is_some()
        );
        let kind = cancel_reason.as_ref().unwrap().kind;
        crate::assert_with_log!(
            kind == CancelKind::Timeout,
            "cancel kind timeout",
            CancelKind::Timeout,
            kind
        );
        crate::test_complete!("cancel_request_marks_region");
    }

    #[test]
    fn cancel_request_marks_tasks() {
        init_test("cancel_request_marks_tasks");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task1 = insert_task(&mut state, region);
        let task2 = insert_task(&mut state, region);

        let tasks_to_schedule = state.cancel_request(region, &CancelReason::timeout(), None);

        // Both tasks should be returned for scheduling
        crate::assert_with_log!(
            tasks_to_schedule.len() == 2,
            "tasks scheduled",
            2usize,
            tasks_to_schedule.len()
        );
        let task_ids: Vec<_> = tasks_to_schedule.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            task_ids.contains(&task2),
            "contains task2",
            true,
            task_ids.contains(&task2)
        );

        // Tasks should be in CancelRequested state
        for (task_id, _) in tasks_to_schedule {
            let task = state
                .tasks
                .get(task_id.arena_index())
                .expect("task missing");
            let is_cancel_requested = matches!(task.state, TaskState::CancelRequested { .. });
            crate::assert_with_log!(
                is_cancel_requested,
                "task cancel requested",
                true,
                is_cancel_requested
            );
        }
        crate::test_complete!("cancel_request_marks_tasks");
    }

    #[test]
    fn cancel_request_propagates_to_descendants() {
        init_test("cancel_request_propagates_to_descendants");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);
        let grandchild = create_child_region(&mut state, child);

        let root_task = insert_task(&mut state, root);
        let child_task = insert_task(&mut state, child);
        let grandchild_task = insert_task(&mut state, grandchild);

        let tasks_to_schedule = state.cancel_request(root, &CancelReason::user("stop"), None);

        // All 3 tasks should be scheduled
        crate::assert_with_log!(
            tasks_to_schedule.len() == 3,
            "tasks scheduled",
            3usize,
            tasks_to_schedule.len()
        );

        // Root region gets original reason
        let root_record = state.regions.get(root.arena_index()).expect("root missing");
        let root_kind = root_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            root_kind == CancelKind::User,
            "root cancel kind",
            CancelKind::User,
            root_kind
        );

        // Descendants get ParentCancelled
        let child_record = state
            .regions
            .get(child.arena_index())
            .expect("child missing");
        let child_kind = child_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            child_kind == CancelKind::ParentCancelled,
            "child cancel kind",
            CancelKind::ParentCancelled,
            child_kind
        );

        let grandchild_record = state
            .regions
            .get(grandchild.arena_index())
            .expect("grandchild missing");
        let grandchild_kind = grandchild_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            grandchild_kind == CancelKind::ParentCancelled,
            "grandchild cancel kind",
            CancelKind::ParentCancelled,
            grandchild_kind
        );

        // Root task gets User reason, descendants get ParentCancelled
        let root_task_record = state
            .tasks
            .get(root_task.arena_index())
            .expect("task missing");
        match &root_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == CancelKind::User,
                    "root task cancel kind",
                    CancelKind::User,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        let child_task_record = state
            .tasks
            .get(child_task.arena_index())
            .expect("task missing");
        match &child_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == CancelKind::ParentCancelled,
                    "child task cancel kind",
                    CancelKind::ParentCancelled,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }

        let grandchild_task_record = state
            .tasks
            .get(grandchild_task.arena_index())
            .expect("task missing");
        match &grandchild_task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == CancelKind::ParentCancelled,
                    "grandchild task cancel kind",
                    CancelKind::ParentCancelled,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_request_propagates_to_descendants");
    }

    #[test]
    fn cancel_request_strengthens_existing_reason() {
        init_test("cancel_request_strengthens_existing_reason");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // First cancel with User
        let _ = state.cancel_request(region, &CancelReason::user("stop"), None);

        // Second cancel with Shutdown (higher severity)
        let _ = state.cancel_request(region, &CancelReason::shutdown(), None);

        // Region should have Shutdown reason
        let region_record = state
            .regions
            .get(region.arena_index())
            .expect("region missing");
        let region_kind = region_record.cancel_reason().as_ref().unwrap().kind;
        crate::assert_with_log!(
            region_kind == CancelKind::Shutdown,
            "region cancel kind",
            CancelKind::Shutdown,
            region_kind
        );

        // Task should have Shutdown reason
        let task_record = state.tasks.get(task.arena_index()).expect("task missing");
        match &task_record.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == CancelKind::Shutdown,
                    "task cancel kind",
                    CancelKind::Shutdown,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_request_strengthens_existing_reason");
    }

    #[test]
    fn can_region_finalize_with_all_tasks_done() {
        init_test("can_region_finalize_with_all_tasks_done");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task = insert_task(&mut state, region);

        // Not finalizable while task is live
        let can_finalize = state.can_region_finalize(region);
        crate::assert_with_log!(
            !can_finalize,
            "cannot finalize with live task",
            false,
            can_finalize
        );

        // Complete the task
        state
            .tasks
            .get_mut(task.arena_index())
            .expect("task missing")
            .complete(Outcome::Ok(()));

        // Now region can finalize
        let can_finalize = state.can_region_finalize(region);
        crate::assert_with_log!(can_finalize, "can finalize", true, can_finalize);
        crate::test_complete!("can_region_finalize_with_all_tasks_done");
    }

    #[test]
    fn can_region_finalize_requires_child_regions_closed() {
        init_test("can_region_finalize_requires_child_regions_closed");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut state, root);

        // Child region is Open, so root cannot finalize
        let can_finalize = state.can_region_finalize(root);
        crate::assert_with_log!(
            !can_finalize,
            "cannot finalize with open child",
            false,
            can_finalize
        );

        // Close the child region
        let child_record = state
            .regions
            .get_mut(child.arena_index())
            .expect("child missing");
        child_record.begin_close(None);
        child_record.begin_finalize();
        child_record.complete_close();

        // Now root can finalize
        let can_finalize = state.can_region_finalize(root);
        crate::assert_with_log!(can_finalize, "can finalize", true, can_finalize);
        crate::test_complete!("can_region_finalize_requires_child_regions_closed");
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn register_sync_finalizer() {
        init_test("register_sync_finalizer");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        crate::assert_with_log!(
            state.region_finalizers_empty(region),
            "finalizers empty",
            true,
            state.region_finalizers_empty(region)
        );
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 0,
            "finalizer count",
            0usize,
            state.region_finalizer_count(region)
        );

        // Register a sync finalizer
        let registered = state.register_sync_finalizer(region, || {});
        crate::assert_with_log!(registered, "register sync finalizer", true, registered);

        crate::assert_with_log!(
            !state.region_finalizers_empty(region),
            "finalizers not empty",
            false,
            state.region_finalizers_empty(region)
        );
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 1,
            "finalizer count",
            1usize,
            state.region_finalizer_count(region)
        );
        crate::test_complete!("register_sync_finalizer");
    }

    #[test]
    fn register_async_finalizer() {
        init_test("register_async_finalizer");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        let registered = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(registered, "register async finalizer", true, registered);
        crate::assert_with_log!(
            state.region_finalizer_count(region) == 1,
            "finalizer count",
            1usize,
            state.region_finalizer_count(region)
        );
        crate::test_complete!("register_async_finalizer");
    }

    #[test]
    fn register_finalizer_fails_when_region_not_open() {
        init_test("register_finalizer_fails_when_region_not_open");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Close the region
        state
            .regions
            .get_mut(region.arena_index())
            .expect("region missing")
            .begin_close(None);

        // Registration should fail
        let sync_ok = state.register_sync_finalizer(region, || {});
        let async_ok = state.register_async_finalizer(region, async {});
        crate::assert_with_log!(!sync_ok, "sync finalizer rejected", false, sync_ok);
        crate::assert_with_log!(!async_ok, "async finalizer rejected", false, async_ok);
        crate::test_complete!("register_finalizer_fails_when_region_not_open");
    }

    #[test]
    fn register_finalizer_fails_for_nonexistent_region() {
        init_test("register_finalizer_fails_for_nonexistent_region");
        let mut state = RuntimeState::new();
        let fake_region = RegionId::from_arena(ArenaIndex::new(999, 0));

        let sync_ok = state.register_sync_finalizer(fake_region, || {});
        let async_ok = state.register_async_finalizer(fake_region, async {});
        crate::assert_with_log!(!sync_ok, "sync finalizer rejected", false, sync_ok);
        crate::assert_with_log!(!async_ok, "async finalizer rejected", false, async_ok);
        crate::test_complete!("register_finalizer_fails_for_nonexistent_region");
    }

    #[test]
    fn pop_region_finalizer_lifo() {
        init_test("pop_region_finalizer_lifo");
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
        let observed = order.lock().unwrap().clone();
        crate::assert_with_log!(
            observed == vec![3, 2, 1],
            "finalizer order",
            vec![3, 2, 1],
            observed
        );
        crate::test_complete!("pop_region_finalizer_lifo");
    }

    #[test]
    fn run_sync_finalizers_executes_and_returns_async() {
        init_test("run_sync_finalizers_executes_and_returns_async");
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
        let sync_flag = sync_called.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(sync_flag, "sync finalizer called", true, sync_flag);

        // One async finalizer should be returned
        crate::assert_with_log!(
            async_finalizers.len() == 1,
            "async finalizers len",
            1usize,
            async_finalizers.len()
        );
        let is_async = matches!(async_finalizers[0], Finalizer::Async(_));
        crate::assert_with_log!(is_async, "async finalizer returned", true, is_async);

        // All finalizers should be cleared from region
        let empty = state.region_finalizers_empty(region);
        crate::assert_with_log!(empty, "finalizers cleared", true, empty);
        crate::test_complete!("run_sync_finalizers_executes_and_returns_async");
    }

    #[test]
    fn can_region_complete_close_requires_finalizing_state() {
        init_test("can_region_complete_close_requires_finalizing_state");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Must be in Finalizing state
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close when not finalizing",
            false,
            can_close
        );

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Now it can complete (no finalizers)
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close", true, can_close);
        crate::test_complete!("can_region_complete_close_requires_finalizing_state");
    }

    #[test]
    fn can_region_complete_close_checks_finalizers() {
        init_test("can_region_complete_close_checks_finalizers");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Add finalizer while open
        state.register_sync_finalizer(region, || {});

        // Transition to Finalizing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);
        region_record.begin_finalize();

        // Can't complete while finalizers pending
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(
            !can_close,
            "cannot close with pending finalizers",
            false,
            can_close
        );

        // Run the finalizers
        let _ = state.run_sync_finalizers(region);

        // Now can complete
        let can_close = state.can_region_complete_close(region);
        crate::assert_with_log!(can_close, "can close", true, can_close);
        crate::test_complete!("can_region_complete_close_checks_finalizers");
    }

    #[test]
    fn task_completed_removes_task_from_region() {
        init_test("task_completed_removes_task_from_region");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Insert some tasks
        let task1 = insert_task(&mut state, region);
        let task2 = insert_task(&mut state, region);
        let task3 = insert_task(&mut state, region);

        // Verify all tasks are in the region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let task_ids = region_record.task_ids();
        crate::assert_with_log!(task_ids.len() == 3, "task count", 3usize, task_ids.len());
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            task_ids.contains(&task2),
            "contains task2",
            true,
            task_ids.contains(&task2)
        );
        crate::assert_with_log!(
            task_ids.contains(&task3),
            "contains task3",
            true,
            task_ids.contains(&task3)
        );

        // Complete task2 (transition to Completed state first)
        state
            .tasks
            .get_mut(task2.arena_index())
            .expect("task2")
            .complete(Outcome::Ok(()));

        // Call task_completed to notify the runtime
        let waiters = state.task_completed(task2);
        crate::assert_with_log!(waiters.is_empty(), "no waiters", true, waiters.is_empty()); // No waiters registered

        // Verify task2 is removed from the region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let task_ids = region_record.task_ids();
        crate::assert_with_log!(task_ids.len() == 2, "task count", 2usize, task_ids.len());
        crate::assert_with_log!(
            task_ids.contains(&task1),
            "contains task1",
            true,
            task_ids.contains(&task1)
        );
        crate::assert_with_log!(
            !task_ids.contains(&task2),
            "task2 removed",
            false,
            task_ids.contains(&task2)
        );
        crate::assert_with_log!(
            task_ids.contains(&task3),
            "contains task3",
            true,
            task_ids.contains(&task3)
        );

        // Verify task2 is removed from the state
        let removed = state.tasks.get(task2.arena_index()).is_none();
        crate::assert_with_log!(removed, "task2 removed from state", true, removed);

        // Complete remaining tasks
        state
            .tasks
            .get_mut(task1.arena_index())
            .expect("task1")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task1);

        state
            .tasks
            .get_mut(task3.arena_index())
            .expect("task3")
            .complete(Outcome::Ok(()));
        let _ = state.task_completed(task3);

        // Verify all tasks removed from region
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let empty = region_record.task_ids().is_empty();
        crate::assert_with_log!(empty, "region tasks empty", true, empty);
        crate::test_complete!("task_completed_removes_task_from_region");
    }

    #[test]
    fn cancel_request_should_prevent_new_spawns() {
        init_test("cancel_request_should_prevent_new_spawns");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);

        // Request cancellation
        let _ = state.cancel_request(region, &CancelReason::user("stop"), None);

        // Verify state transition
        let region_record = state.regions.get(region.arena_index()).expect("region");
        let region_state = region_record.state();
        crate::assert_with_log!(
            region_state == crate::record::region::RegionState::Closing,
            "region closing",
            crate::record::region::RegionState::Closing,
            region_state
        );

        // Verify spawning is rejected with error (not panic)
        let result = state.create_task(region, Budget::INFINITE, async { 42 });
        let rejected = matches!(result, Err(SpawnError::RegionClosed(_)));
        crate::assert_with_log!(rejected, "spawn rejected", true, rejected);
        crate::test_complete!("cancel_request_should_prevent_new_spawns");
    }

    // =========================================================================
    // IoDriver Integration Tests
    // =========================================================================

    #[test]
    fn new_creates_state_without_io_driver() {
        init_test("new_creates_state_without_io_driver");
        let state = RuntimeState::new();
        crate::assert_with_log!(
            !state.has_io_driver(),
            "no io driver",
            false,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_none(),
            "io driver none",
            true,
            state.io_driver().is_none()
        );
        crate::test_complete!("new_creates_state_without_io_driver");
    }

    #[test]
    fn without_reactor_creates_state_without_io_driver() {
        init_test("without_reactor_creates_state_without_io_driver");
        let state = RuntimeState::without_reactor();
        crate::assert_with_log!(
            !state.has_io_driver(),
            "no io driver",
            false,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_none(),
            "io driver none",
            true,
            state.io_driver().is_none()
        );
        crate::test_complete!("without_reactor_creates_state_without_io_driver");
    }

    #[test]
    fn with_reactor_creates_state_with_io_driver() {
        init_test("with_reactor_creates_state_with_io_driver");
        use crate::runtime::reactor::LabReactor;
        use std::sync::Arc;

        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        crate::assert_with_log!(
            state.has_io_driver(),
            "has io driver",
            true,
            state.has_io_driver()
        );
        crate::assert_with_log!(
            state.io_driver().is_some(),
            "io driver some",
            true,
            state.io_driver().is_some()
        );

        // Verify the driver is functional
        let driver = state.io_driver().unwrap();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.waker_count() == 0,
            "waker count",
            0usize,
            driver.waker_count()
        );
        crate::test_complete!("with_reactor_creates_state_with_io_driver");
    }

    #[test]
    fn io_driver_mut_allows_modification() {
        init_test("io_driver_mut_allows_modification");
        use crate::runtime::reactor::LabReactor;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        struct TestWaker(AtomicBool);
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        // Mutably access driver to register a waker
        let waker_state = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_state);
        {
            let mut driver = state.io_driver_mut().unwrap();
            let _key = driver.register_waker(waker);
        }

        // Verify registration
        let waker_count = state.io_driver().unwrap().waker_count();
        crate::assert_with_log!(waker_count == 1, "waker count", 1usize, waker_count);
        let empty = state.io_driver().unwrap().is_empty();
        crate::assert_with_log!(!empty, "driver not empty", false, empty);
        crate::test_complete!("io_driver_mut_allows_modification");
    }

    #[test]
    fn is_quiescent_considers_io_driver() {
        init_test("is_quiescent_considers_io_driver");
        use crate::runtime::reactor::LabReactor;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        struct TestWaker(AtomicBool);
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let reactor = Arc::new(LabReactor::new());
        let state = RuntimeState::with_reactor(reactor);

        // Initially quiescent (no tasks, no I/O registrations)
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "initial quiescent", true, quiescent);

        // Register a waker
        let waker_state = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_state);
        let key = {
            let mut driver = state.io_driver_mut().unwrap();
            driver.register_waker(waker)
        };

        // No longer quiescent due to I/O registration
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(!quiescent, "not quiescent", false, quiescent);

        // Deregister
        {
            let mut driver = state.io_driver_mut().unwrap();
            driver.deregister_waker(key);
        }

        // Quiescent again
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent again", true, quiescent);
        crate::test_complete!("is_quiescent_considers_io_driver");
    }

    #[test]
    fn is_quiescent_without_io_driver_ignores_io() {
        init_test("is_quiescent_without_io_driver_ignores_io");
        let state = RuntimeState::new();

        // Quiescent without I/O driver
        let quiescent = state.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
        crate::test_complete!("is_quiescent_without_io_driver_ignores_io");
    }

    /// Integration test with real epoll reactor.
    #[cfg(target_os = "linux")]
    mod epoll_integration {
        use super::*;
        use crate::runtime::reactor::{EpollReactor, Interest};
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};
        use std::time::Duration;

        struct FlagWaker(AtomicBool);
        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        #[test]
        fn runtime_state_with_epoll_reactor() {
            super::init_test("runtime_state_with_epoll_reactor");
            let reactor = Arc::new(EpollReactor::new().expect("create reactor"));
            let state = RuntimeState::with_reactor(reactor);

            crate::assert_with_log!(
                state.has_io_driver(),
                "has io driver",
                true,
                state.has_io_driver()
            );
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(quiescent, "quiescent", true, quiescent);

            // Create a socket pair
            let (sock_read, mut sock_write) = UnixStream::pair().expect("socket pair");

            // Register with the driver
            let waker_state = Arc::new(FlagWaker(AtomicBool::new(false)));
            let waker = Waker::from(waker_state.clone());

            let token = {
                let mut driver = state.io_driver_mut().unwrap();
                driver
                    .register(&sock_read, Interest::READABLE, waker)
                    .expect("register")
            };

            // Not quiescent due to I/O registration
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(!quiescent, "not quiescent", false, quiescent);

            // Make socket readable
            sock_write.write_all(b"hello").expect("write");

            // Turn the driver to dispatch waker
            let count = {
                let mut driver = state.io_driver_mut().unwrap();
                driver.turn(Some(Duration::from_millis(100))).expect("turn")
            };

            crate::assert_with_log!(count >= 1, "event count", true, count >= 1);
            let flag = waker_state.0.load(Ordering::SeqCst);
            crate::assert_with_log!(flag, "waker fired", true, flag);

            // Deregister and verify quiescence
            {
                let mut driver = state.io_driver_mut().unwrap();
                driver.deregister(token).expect("deregister");
            }
            let quiescent = state.is_quiescent();
            crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
            crate::test_complete!("runtime_state_with_epoll_reactor");
        }
    }
}
