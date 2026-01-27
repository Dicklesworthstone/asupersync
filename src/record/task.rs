//! Task record for the runtime.
//!
//! A task is a unit of concurrent execution owned by a region.
//! This module defines the internal record structure for tracking task state.

use crate::cx::Cx;
use crate::tracing_compat::{debug, trace};
use crate::types::{Budget, CancelReason, CxInner, Outcome, RegionId, TaskId, Time};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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

/// Coarse-grained task phase for cross-thread reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskPhase {
    /// Task created but not yet running.
    Created = 0,
    /// Task currently running.
    Running = 1,
    /// Cancellation requested but not yet acknowledged.
    CancelRequested = 2,
    /// Task running cancellation cleanup.
    Cancelling = 3,
    /// Task running finalizers after cleanup.
    Finalizing = 4,
    /// Task completed (terminal).
    Completed = 5,
}

/// Atomic task phase cell for cross-thread state checks.
#[derive(Debug)]
pub struct TaskPhaseCell {
    inner: AtomicU8,
}

impl TaskPhaseCell {
    /// Creates a new cell initialized to the given phase.
    #[must_use]
    pub fn new(phase: TaskPhase) -> Self {
        Self {
            inner: AtomicU8::new(phase as u8),
        }
    }

    /// Loads the current phase.
    #[must_use]
    pub fn load(&self) -> TaskPhase {
        match self.inner.load(Ordering::Acquire) {
            0 => TaskPhase::Created,
            1 => TaskPhase::Running,
            2 => TaskPhase::CancelRequested,
            3 => TaskPhase::Cancelling,
            4 => TaskPhase::Finalizing,
            _ => TaskPhase::Completed,
        }
    }

    /// Stores the new phase.
    pub fn store(&self, phase: TaskPhase) {
        self.inner.store(phase as u8, Ordering::Release);
    }
}

/// Cross-thread wake dedup state for a task.
#[derive(Debug, Default)]
pub struct TaskWakeState {
    notified: AtomicBool,
}

impl TaskWakeState {
    /// Creates a new wake state with no pending notification.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a pending wake and returns true if this is the first notification.
    pub fn notify(&self) -> bool {
        !self.notified.swap(true, Ordering::AcqRel)
    }

    /// Clears the pending wake flag.
    pub fn clear(&self) {
        self.notified.store(false, Ordering::Release);
    }

    /// Returns true if a wake is pending.
    #[must_use]
    pub fn is_notified(&self) -> bool {
        self.notified.load(Ordering::Acquire)
    }
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
    /// Cross-thread lifecycle phase (atomic snapshot).
    pub phase: TaskPhaseCell,
    /// Cross-thread wake dedup state for this task.
    pub wake_state: Arc<TaskWakeState>,
    /// Shared capability context state.
    ///
    /// This is shared with the `Cx` held by the user code.
    /// It is `None` only during initial construction or testing if not provided.
    pub cx_inner: Option<Arc<RwLock<CxInner>>>,
    /// Full capability context for this task.
    ///
    /// This allows the runtime to set a current task context while polling.
    pub cx: Option<Cx>,
    /// Logical time when the task was created.
    pub created_at: Time,

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
        Self::new_with_time(id, owner, budget, Time::ZERO)
    }

    /// Creates a new task record with an explicit creation time.
    #[must_use]
    pub fn new_with_time(id: TaskId, owner: RegionId, budget: Budget, created_at: Time) -> Self {
        Self {
            id,
            owner,
            state: TaskState::Created,
            phase: TaskPhaseCell::new(TaskPhase::Created),
            wake_state: Arc::new(TaskWakeState::new()),
            cx_inner: None, // Must be set via set_cx_inner or similar
            cx: None,
            created_at,
            polls_remaining: budget.poll_quota,
            last_polled_step: 0,
            waiters: Vec::new(),
        }
    }

    /// Returns the logical time when the task was created.
    #[must_use]
    pub const fn created_at(&self) -> Time {
        self.created_at
    }

    /// Sets the shared CxInner.
    pub fn set_cx_inner(&mut self, inner: Arc<RwLock<CxInner>>) {
        self.cx_inner = Some(inner);
    }

    /// Sets the full Cx for this task.
    pub fn set_cx(&mut self, cx: Cx) {
        self.cx = Some(cx);
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

    /// Returns a string name for the current state (for tracing).
    #[must_use]
    pub fn state_name(&self) -> &'static str {
        match &self.state {
            TaskState::Created => "Created",
            TaskState::Running => "Running",
            TaskState::CancelRequested { .. } => "CancelRequested",
            TaskState::Cancelling { .. } => "Cancelling",
            TaskState::Finalizing { .. } => "Finalizing",
            TaskState::Completed(_) => "Completed",
        }
    }

    /// Returns the atomic lifecycle phase for this task.
    #[must_use]
    pub fn phase(&self) -> TaskPhase {
        self.phase.load()
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
    #[allow(clippy::too_many_lines)]
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
                // Budget update is deferred to acknowledge_cancel to prevent
                // pre-empting the cancellation check with a budget exhaustion error.
            }
        }

        let mut updated_reason_for_inner = None;

        let result = match &mut self.state {
            TaskState::CancelRequested {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            } => {
                self.phase.store(TaskPhase::CancelRequested);
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    cancel_kind = ?reason.kind,
                    "cancel reason strengthened (already CancelRequested)"
                );
                existing_reason.strengthen(&reason);
                *existing_budget = existing_budget.combine(cleanup_budget);
                updated_reason_for_inner = Some(existing_reason.clone());
                false
            }
            TaskState::Cancelling {
                reason: existing_reason,
                cleanup_budget: b,
            } => {
                self.phase.store(TaskPhase::Cancelling);
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    cancel_kind = ?reason.kind,
                    "cancel reason strengthened (in cleanup)"
                );
                existing_reason.strengthen(&reason);
                let new_budget = b.combine(cleanup_budget);
                *b = new_budget;
                updated_reason_for_inner = Some(existing_reason.clone());

                // Update shared state so user code sees tighter budget immediately
                if let Some(inner) = &self.cx_inner {
                    if let Ok(mut guard) = inner.write() {
                        guard.budget = new_budget;
                        guard.budget_baseline = new_budget;
                    }
                }
                // Also update polls_remaining to respect tighter quota
                self.polls_remaining = self.polls_remaining.min(new_budget.poll_quota);

                false
            }
            TaskState::Finalizing {
                reason: existing_reason,
                cleanup_budget: b,
            } => {
                self.phase.store(TaskPhase::Finalizing);
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    cancel_kind = ?reason.kind,
                    "cancel reason strengthened (in cleanup)"
                );
                existing_reason.strengthen(&reason);
                let new_budget = b.combine(cleanup_budget);
                *b = new_budget;
                updated_reason_for_inner = Some(existing_reason.clone());

                // Update shared state so user code sees tighter budget immediately
                if let Some(inner) = &self.cx_inner {
                    if let Ok(mut guard) = inner.write() {
                        guard.budget = new_budget;
                        guard.budget_baseline = new_budget;
                    }
                }
                // Also update polls_remaining to respect tighter quota
                self.polls_remaining = self.polls_remaining.min(new_budget.poll_quota);

                false
            }
            TaskState::Created | TaskState::Running => {
                let _old_state = self.state_name();
                let requested_reason = reason.clone();
                debug!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = _old_state,
                    new_state = "CancelRequested",
                    cancel_kind = ?reason.kind,
                    cleanup_poll_quota = cleanup_budget.poll_quota,
                    "task cancel requested"
                );
                self.state = TaskState::CancelRequested {
                    reason,
                    cleanup_budget,
                };
                self.phase.store(TaskPhase::CancelRequested);
                updated_reason_for_inner = Some(requested_reason);
                true
            }
            TaskState::Completed(_) => false,
        };
        if let Some(reason) = updated_reason_for_inner {
            if let Some(inner) = &self.cx_inner {
                if let Ok(mut guard) = inner.write() {
                    guard.cancel_reason = Some(reason);
                }
            }
        }
        result
    }

    /// Marks the task as running (Created → Running).
    ///
    /// Returns true if the state changed.
    pub fn start_running(&mut self) -> bool {
        match self.state {
            TaskState::Created => {
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = "Created",
                    new_state = "Running",
                    "task state transition"
                );
                self.state = TaskState::Running;
                self.phase.store(TaskPhase::Running);
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
        let _old_state = self.state_name();
        let _outcome_kind = match &outcome {
            Outcome::Ok(()) => "Ok",
            Outcome::Err(_) => "Err",
            Outcome::Cancelled(_) => "Cancelled",
            Outcome::Panicked(_) => "Panicked",
        };
        debug!(
            task_id = ?self.id,
            region_id = ?self.owner,
            old_state = _old_state,
            new_state = "Completed",
            outcome_kind = _outcome_kind,
            "task completed"
        );
        self.state = TaskState::Completed(outcome);
        self.phase.store(TaskPhase::Completed);
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

                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = "CancelRequested",
                    new_state = "Cancelling",
                    cancel_kind = ?reason.kind,
                    cleanup_poll_quota = budget.poll_quota,
                    cleanup_priority = budget.priority,
                    "task acknowledged cancellation"
                );

                // Apply cleanup budget now that we are entering cleanup phase
                if let Some(inner) = &self.cx_inner {
                    if let Ok(mut guard) = inner.write() {
                        guard.budget = budget;
                        guard.budget_baseline = budget;
                    }
                }
                self.polls_remaining = budget.poll_quota;

                self.state = TaskState::Cancelling {
                    reason: reason.clone(),
                    cleanup_budget: budget,
                };
                self.phase.store(TaskPhase::Cancelling);
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
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = "Cancelling",
                    new_state = "Finalizing",
                    cancel_kind = ?reason.kind,
                    finalizer_budget_poll_quota = budget.poll_quota,
                    finalizer_budget_priority = budget.priority,
                    "task cleanup done, entering finalization"
                );
                self.state = TaskState::Finalizing {
                    reason,
                    cleanup_budget: budget,
                };
                self.phase.store(TaskPhase::Finalizing);
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
        let TaskState::Finalizing {
            reason,
            cleanup_budget,
        } = &self.state
        else {
            return false;
        };
        let reason = reason.clone();
        let budget = *cleanup_budget;
        debug!(
            task_id = ?self.id,
            region_id = ?self.owner,
            old_state = "Finalizing",
            new_state = "Completed",
            outcome_kind = "Cancelled",
            cancel_kind = ?reason.kind,
            finalizer_budget_poll_quota = budget.poll_quota,
            finalizer_budget_priority = budget.priority,
            "task finalization done"
        );
        self.state = TaskState::Completed(Outcome::Cancelled(reason));
        self.phase.store(TaskPhase::Completed);
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
    use std::sync::atomic::AtomicUsize;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 0))
    }

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn task_phase_transitions_are_atomic() {
        init_test("task_phase_transitions_are_atomic");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        crate::assert_with_log!(
            t.phase() == TaskPhase::Created,
            "phase created",
            TaskPhase::Created,
            t.phase()
        );

        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Running,
            "phase running",
            TaskPhase::Running,
            t.phase()
        );

        let requested = t.request_cancel(CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        crate::assert_with_log!(
            t.phase() == TaskPhase::CancelRequested,
            "phase cancel requested",
            TaskPhase::CancelRequested,
            t.phase()
        );

        let ack = t.acknowledge_cancel();
        crate::assert_with_log!(ack.is_some(), "acknowledge_cancel", true, ack.is_some());
        crate::assert_with_log!(
            t.phase() == TaskPhase::Cancelling,
            "phase cancelling",
            TaskPhase::Cancelling,
            t.phase()
        );

        let cleaned = t.cleanup_done();
        crate::assert_with_log!(cleaned, "cleanup_done", true, cleaned);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Finalizing,
            "phase finalizing",
            TaskPhase::Finalizing,
            t.phase()
        );

        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Completed,
            "phase completed",
            TaskPhase::Completed,
            t.phase()
        );

        crate::test_complete!("task_phase_transitions_are_atomic");
    }

    #[test]
    fn wake_state_dedups_across_threads() {
        init_test("wake_state_dedups_across_threads");
        let state = Arc::new(TaskWakeState::new());
        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let state = Arc::clone(&state);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if state.notify() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }

        let count = successes.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "single notify wins", 1usize, count);
        let notified = state.is_notified();
        crate::assert_with_log!(notified, "notified true", true, notified);
        state.clear();
        let cleared = state.is_notified();
        crate::assert_with_log!(!cleared, "notified cleared", false, cleared);
        crate::test_complete!("wake_state_dedups_across_threads");
    }

    #[test]
    fn cancel_before_first_poll_enters_cancel_requested() {
        init_test("cancel_before_first_poll_enters_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);
        let requested = t.request_cancel(CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        match &t.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget: _,
            } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_before_first_poll_enters_cancel_requested");
    }

    #[test]
    fn cancel_strengthens_idempotently_when_already_cancel_requested() {
        init_test("cancel_strengthens_idempotently_when_already_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let first = t.request_cancel(CancelReason::timeout());
        crate::assert_with_log!(first, "first cancel", true, first);
        let second = t.request_cancel(CancelReason::shutdown());
        crate::assert_with_log!(!second, "second cancel false", false, second);
        match &t.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Shutdown,
                    "reason kind",
                    crate::types::CancelKind::Shutdown,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_strengthens_idempotently_when_already_cancel_requested");
    }

    #[test]
    fn completed_is_absorbing() {
        init_test("completed_is_absorbing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let requested = t.request_cancel(CancelReason::timeout());
        crate::assert_with_log!(!requested, "request_cancel false", false, requested);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(outcome) => {
                let ok = matches!(outcome, Outcome::Ok(()));
                crate::assert_with_log!(ok, "outcome ok", true, ok);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        crate::test_complete!("completed_is_absorbing");
    }

    #[test]
    fn can_be_polled_matches_state() {
        init_test("can_be_polled_matches_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(!can_poll, "not pollable", false, can_poll);
        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable", true, can_poll);

        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable after cancel", true, can_poll);
        crate::test_complete!("can_be_polled_matches_state");
    }

    #[test]
    fn complete_with_error_outcome() {
        init_test("complete_with_error_outcome");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let err = Error::new(ErrorKind::User);
        let completed = t.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        crate::test_complete!("complete_with_error_outcome");
    }

    #[test]
    fn acknowledge_cancel_transitions_to_cancelling() {
        init_test("acknowledge_cancel_transitions_to_cancelling");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());

        let reason = t.acknowledge_cancel();
        let has_reason = reason.is_some();
        crate::assert_with_log!(has_reason, "reason present", true, has_reason);
        let kind = reason.unwrap().kind;
        crate::assert_with_log!(
            kind == crate::types::CancelKind::Timeout,
            "reason kind",
            crate::types::CancelKind::Timeout,
            kind
        );
        let cancelling = matches!(
            t.state,
            TaskState::Cancelling {
                reason: CancelReason {
                    kind: crate::types::CancelKind::Timeout,
                    ..
                },
                ..
            }
        );
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        crate::test_complete!("acknowledge_cancel_transitions_to_cancelling");
    }

    #[test]
    fn acknowledge_cancel_fails_for_wrong_state() {
        init_test("acknowledge_cancel_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in created", true, none);

        // Move to Running
        t.start_running();
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in running", true, none);
        crate::test_complete!("acknowledge_cancel_fails_for_wrong_state");
    }

    #[test]
    fn cleanup_done_transitions_to_finalizing() {
        init_test("cleanup_done_transitions_to_finalizing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        crate::test_complete!("cleanup_done_transitions_to_finalizing");
    }

    #[test]
    fn cleanup_done_fails_for_wrong_state() {
        init_test("cleanup_done_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);

        let _ = t.request_cancel(CancelReason::timeout());
        // Still in CancelRequested, not Cancelling
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);
        crate::test_complete!("cleanup_done_fails_for_wrong_state");
    }

    #[test]
    fn finalize_done_transitions_to_completed_cancelled() {
        init_test("finalize_done_transitions_to_completed_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.request_cancel(CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }
        crate::test_complete!("finalize_done_transitions_to_completed_cancelled");
    }

    #[test]
    fn full_cancellation_protocol_flow() {
        init_test("full_cancellation_protocol_flow");
        // Complete flow: Created → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);

        // Step 1: Request cancellation
        let requested = t.request_cancel(CancelReason::user("stop"));
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        let cancelling = t.state.is_cancelling();
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 2: Acknowledge cancellation (checkpoint with mask=0)
        let reason = t.acknowledge_cancel().expect("should acknowledge");
        crate::assert_with_log!(
            reason.kind == crate::types::CancelKind::User,
            "reason kind",
            crate::types::CancelKind::User,
            reason.kind
        );
        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 3: Cleanup completes
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);

        // Step 4: Finalizers complete
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);
        crate::test_complete!("full_cancellation_protocol_flow");
    }

    #[test]
    fn masking_operations() {
        init_test("masking_operations");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        // Need to set inner for mask operations to work
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner);

        let mask1 = t.increment_mask();
        crate::assert_with_log!(mask1 == 1, "mask 1", 1, mask1);
        let mask2 = t.increment_mask();
        crate::assert_with_log!(mask2 == 2, "mask 2", 2, mask2);

        let dec1 = t.decrement_mask();
        crate::assert_with_log!(dec1 == Some(1), "dec 1", Some(1), dec1);
        let dec0 = t.decrement_mask();
        crate::assert_with_log!(dec0 == Some(0), "dec 0", Some(0), dec0);

        // Can't go below zero
        let dec_none = t.decrement_mask();
        crate::assert_with_log!(dec_none.is_none(), "dec none", true, dec_none.is_none());
        crate::test_complete!("masking_operations");
    }

    #[test]
    fn cleanup_budget_accessor() {
        init_test("cleanup_budget_accessor");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.cleanup_budget().is_none();
        crate::assert_with_log!(none, "no budget", true, none);

        let _ = t.request_cancel_with_budget(
            CancelReason::timeout(),
            Budget::new().with_poll_quota(500),
        );
        let budget = t.cleanup_budget().expect("should have cleanup budget");
        crate::assert_with_log!(
            budget.poll_quota == 500,
            "poll_quota",
            500,
            budget.poll_quota
        );
        crate::test_complete!("cleanup_budget_accessor");
    }

    #[test]
    fn request_cancel_updates_shared_cx() {
        init_test("request_cancel_updates_shared_cx");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner.clone());

        let cancel_requested = inner.read().unwrap().cancel_requested;
        crate::assert_with_log!(
            !cancel_requested,
            "cancel_requested false",
            false,
            cancel_requested
        );
        let cancel_reason_none = inner.read().unwrap().cancel_reason.is_none();
        crate::assert_with_log!(
            cancel_reason_none,
            "cancel_reason none",
            true,
            cancel_reason_none
        );

        t.request_cancel(CancelReason::timeout());

        let cancel_requested = inner.read().unwrap().cancel_requested;
        crate::assert_with_log!(
            cancel_requested,
            "cancel_requested true",
            true,
            cancel_requested
        );
        let cancel_reason = inner.read().unwrap().cancel_reason.clone();
        crate::assert_with_log!(
            cancel_reason == Some(CancelReason::timeout()),
            "cancel_reason",
            Some(CancelReason::timeout()),
            cancel_reason
        );
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        crate::test_complete!("request_cancel_updates_shared_cx");
    }
}
