//! Cancellation protocol oracle for verifying the cancellation invariant.
//!
//! This oracle verifies invariant #3: Cancellation is a protocol.
//! Tasks must transition through request → drain → finalize in a bounded way.
//!
//! Additionally, this oracle verifies **INV-CANCEL-PROPAGATES**:
//! When a region is cancelled, all its descendant regions also have cancel set.
//!
//! # The Protocol
//!
//! Valid cancellation transitions for a task:
//! ```text
//! Created/Running → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
//! ```
//!
//! Key properties:
//! - Cancellation is idempotent (repeated requests strengthen but don't break protocol)
//! - Mask deferral is bounded (eventually checkpoint must acknowledge)
//! - Cleanup budgets are respected
//! - Cancel propagates downward through the region tree
//!
//! # Usage
//!
//! ```rust,ignore
//! use asupersync::lab::oracle::cancellation_protocol::CancellationProtocolOracle;
//!
//! let mut oracle = CancellationProtocolOracle::new();
//!
//! // Record events as they occur
//! oracle.on_region_create(region, parent);
//! oracle.on_task_create(task, region);
//! oracle.on_cancel_request(task, reason, time);
//! oracle.on_transition(task, from, to, time);
//! oracle.on_region_cancel(region, reason, time);
//!
//! // Verify invariants
//! oracle.check()?;
//! ```

use crate::record::task::TaskState;
use crate::types::{CancelKind, CancelReason, RegionId, TaskId, Time};
use std::collections::HashMap;
use std::fmt;

/// A violation of the cancellation protocol invariant.
#[derive(Debug, Clone)]
pub enum CancellationProtocolViolation {
    /// Task skipped a required state in the cancellation sequence.
    SkippedState {
        /// The task that skipped a state.
        task: TaskId,
        /// The state the task was in.
        from: TaskStateKind,
        /// The state the task transitioned to (illegally).
        to: TaskStateKind,
        /// When this occurred.
        time: Time,
    },

    /// Task was cancelled but not acknowledged within expected bounds.
    CancelNotAcknowledged {
        /// The task that was not acknowledged.
        task: TaskId,
        /// When the cancel was requested.
        requested_at: Time,
        /// Number of polls that have occurred since request.
        polls_since_request: u32,
    },

    /// Task was cancelled but never completed.
    CancelNotCompleted {
        /// The task that didn't complete.
        task: TaskId,
        /// The state the task is stuck in.
        stuck_state: TaskStateKind,
        /// When the cancel was requested.
        requested_at: Time,
    },

    /// Cancel propagation violated: parent cancelled but child was not.
    CancelNotPropagated {
        /// The parent region that was cancelled.
        parent: RegionId,
        /// The child region that was NOT cancelled.
        uncancelled_child: RegionId,
    },

    /// Non-monotonic cancel reason (reason got weaker instead of stronger).
    NonMonotonicCancel {
        /// The task with non-monotonic cancel.
        task: TaskId,
        /// The cancel kind before.
        before: CancelKind,
        /// The cancel kind after (should be >= before).
        after: CancelKind,
    },

    /// Cancel was acknowledged while the task was in a masked section.
    ///
    /// The cancellation protocol requires that cancel acknowledgement is
    /// deferred while `mask_depth > 0`. A task transitioning to `Cancelling`
    /// while masked violates **INV-MASK-DEFER**.
    CancelAckWhileMasked {
        /// The task that acknowledged cancel while masked.
        task: TaskId,
        /// The mask depth at the time of acknowledgement.
        mask_depth: u32,
        /// When this occurred.
        time: Time,
    },

    /// Mask depth exceeded the compile-time bound (`MAX_MASK_DEPTH`).
    ///
    /// Violates **INV-MASK-BOUNDED**: a task's mask depth must be finite
    /// and bounded to guarantee that cancellation cannot be deferred
    /// indefinitely.
    MaskDepthExceeded {
        /// The task that exceeded the mask depth bound.
        task: TaskId,
        /// The actual mask depth reached.
        depth: u32,
        /// The maximum allowed depth.
        max: u32,
        /// When this occurred.
        time: Time,
    },
}

impl fmt::Display for CancellationProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SkippedState {
                task,
                from,
                to,
                time,
            } => {
                write!(
                    f,
                    "Task {task} skipped state: {from:?} -> {to:?} at {time} \
                     (expected intermediate states)"
                )
            }
            Self::CancelNotAcknowledged {
                task,
                requested_at,
                polls_since_request,
            } => {
                write!(
                    f,
                    "Task {task} cancel requested at {requested_at} but not acknowledged \
                     after {polls_since_request} polls"
                )
            }
            Self::CancelNotCompleted {
                task,
                stuck_state,
                requested_at,
            } => {
                write!(
                    f,
                    "Task {task} cancel requested at {requested_at} but stuck in {stuck_state:?}"
                )
            }
            Self::CancelNotPropagated {
                parent,
                uncancelled_child,
            } => {
                write!(
                    f,
                    "Cancel not propagated: parent {parent} cancelled but child \
                     {uncancelled_child} not cancelled"
                )
            }
            Self::NonMonotonicCancel {
                task,
                before,
                after,
            } => {
                write!(
                    f,
                    "Task {task} cancel reason got weaker: {before:?} -> {after:?}"
                )
            }
            Self::CancelAckWhileMasked {
                task,
                mask_depth,
                time,
            } => {
                write!(
                    f,
                    "Task {task} acknowledged cancel while masked (depth={mask_depth}) at {time}"
                )
            }
            Self::MaskDepthExceeded {
                task,
                depth,
                max,
                time,
            } => {
                write!(
                    f,
                    "Task {task} mask depth {depth} exceeded maximum {max} at {time}"
                )
            }
        }
    }
}

impl std::error::Error for CancellationProtocolViolation {}

/// Simplified task state kind for tracking transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskStateKind {
    /// Initial state.
    Created,
    /// Task is running normally.
    Running,
    /// Cancel has been requested but not acknowledged.
    CancelRequested,
    /// Task has acknowledged cancel and is running cleanup.
    Cancelling,
    /// Cleanup done, running finalizers.
    Finalizing,
    /// Task completed with Ok result.
    CompletedOk,
    /// Task completed with error.
    CompletedErr,
    /// Task completed due to cancellation.
    CompletedCancelled,
    /// Task completed due to panic.
    CompletedPanicked,
}

impl TaskStateKind {
    /// Converts from the full TaskState enum.
    #[must_use]
    pub fn from_task_state(state: &TaskState) -> Self {
        match state {
            TaskState::Created => Self::Created,
            TaskState::Running => Self::Running,
            TaskState::CancelRequested { .. } => Self::CancelRequested,
            TaskState::Cancelling { .. } => Self::Cancelling,
            TaskState::Finalizing { .. } => Self::Finalizing,
            TaskState::Completed(outcome) => match outcome {
                crate::types::Outcome::Ok(()) => Self::CompletedOk,
                crate::types::Outcome::Err(_) => Self::CompletedErr,
                crate::types::Outcome::Cancelled(_) => Self::CompletedCancelled,
                crate::types::Outcome::Panicked(_) => Self::CompletedPanicked,
            },
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CompletedOk
                | Self::CompletedErr
                | Self::CompletedCancelled
                | Self::CompletedPanicked
        )
    }

    /// Returns true if this state is part of the cancellation sequence.
    #[must_use]
    pub const fn is_cancel_sequence(self) -> bool {
        matches!(
            self,
            Self::CancelRequested | Self::Cancelling | Self::Finalizing | Self::CompletedCancelled
        )
    }
}

/// Record of a cancel request event.
#[derive(Debug, Clone)]
struct CancelRequestRecord {
    /// When the cancel was requested.
    requested_at: Time,
    /// The cancel reason.
    reason: CancelReason,
    /// Number of polls since the request.
    polls_since: u32,
    /// Whether the cancel has been acknowledged.
    acknowledged: bool,
}

/// Record of a task's state for protocol verification.
#[derive(Debug, Clone)]
struct TaskProtocolRecord {
    /// Current state of the task.
    current_state: TaskStateKind,
    /// Cancel request if any.
    cancel_request: Option<CancelRequestRecord>,
    /// History of state transitions for debugging.
    transitions: Vec<(TaskStateKind, TaskStateKind, Time)>,
    /// Current mask depth (0 = unmasked).
    mask_depth: u32,
}

impl TaskProtocolRecord {
    fn new() -> Self {
        Self {
            current_state: TaskStateKind::Created,
            cancel_request: None,
            transitions: Vec::new(),
            mask_depth: 0,
        }
    }
}

/// Oracle for verifying the cancellation protocol invariant.
///
/// This oracle tracks:
/// - Task state transitions
/// - Cancel requests and acknowledgements
/// - Region tree structure for propagation checking
/// - Region cancel status
#[derive(Debug, Default)]
pub struct CancellationProtocolOracle {
    /// Per-task protocol records.
    tasks: HashMap<TaskId, TaskProtocolRecord>,
    /// Map from region to its parent.
    region_parents: HashMap<RegionId, Option<RegionId>>,
    /// Map from region to its children.
    region_children: HashMap<RegionId, Vec<RegionId>>,
    /// Regions that have been cancelled.
    cancelled_regions: HashMap<RegionId, CancelReason>,
    /// Map from task to owning region.
    task_regions: HashMap<TaskId, RegionId>,
    /// Detected violations.
    violations: Vec<CancellationProtocolViolation>,
}

impl CancellationProtocolOracle {
    /// Creates a new cancellation protocol oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a region creation event.
    pub fn on_region_create(&mut self, region: RegionId, parent: Option<RegionId>) {
        self.region_parents.insert(region, parent);
        self.region_children.entry(region).or_default();

        if let Some(p) = parent {
            self.region_children.entry(p).or_default().push(region);
        }
    }

    /// Records a task creation event.
    pub fn on_task_create(&mut self, task: TaskId, region: RegionId) {
        self.tasks.insert(task, TaskProtocolRecord::new());
        self.task_regions.insert(task, region);
    }

    /// Records a cancel request on a task.
    pub fn on_cancel_request(&mut self, task: TaskId, reason: CancelReason, time: Time) {
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);

        if let Some(ref mut existing) = record.cancel_request {
            // Check monotonicity: new reason should be >= existing reason
            if reason.kind < existing.reason.kind {
                self.violations
                    .push(CancellationProtocolViolation::NonMonotonicCancel {
                        task,
                        before: existing.reason.kind,
                        after: reason.kind,
                    });
            }
            // Strengthen the reason
            existing.reason.strengthen(&reason);
        } else {
            record.cancel_request = Some(CancelRequestRecord {
                requested_at: time,
                reason,
                polls_since: 0,
                acknowledged: false,
            });
        }
    }

    /// Records a cancel acknowledgement (checkpoint with mask=0).
    pub fn on_cancel_ack(&mut self, task: TaskId, _time: Time) {
        if let Some(record) = self.tasks.get_mut(&task) {
            if let Some(ref mut cancel) = record.cancel_request {
                cancel.acknowledged = true;
            }
        }
    }

    /// Records a poll event for a task (for tracking acknowledgement timing).
    pub fn on_task_poll(&mut self, task: TaskId) {
        if let Some(record) = self.tasks.get_mut(&task) {
            if let Some(ref mut cancel) = record.cancel_request {
                if !cancel.acknowledged {
                    cancel.polls_since += 1;
                }
            }
        }
    }

    /// Records a mask section entry for a task.
    ///
    /// Tracks the current mask depth so the oracle can verify that cancel
    /// acknowledgement is deferred while masked (**INV-MASK-DEFER**) and
    /// that mask depth never exceeds the compile-time bound (**INV-MASK-BOUNDED**).
    pub fn on_mask_enter(&mut self, task: TaskId, time: Time) {
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        record.mask_depth += 1;

        if record.mask_depth > crate::types::MAX_MASK_DEPTH {
            self.violations
                .push(CancellationProtocolViolation::MaskDepthExceeded {
                    task,
                    depth: record.mask_depth,
                    max: crate::types::MAX_MASK_DEPTH,
                    time,
                });
        }
    }

    /// Records a mask section exit for a task.
    pub fn on_mask_exit(&mut self, task: TaskId, _time: Time) {
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        record.mask_depth = record.mask_depth.saturating_sub(1);
    }

    /// Records a task state transition.
    ///
    /// This validates that the transition follows the cancellation protocol.
    pub fn on_transition(&mut self, task: TaskId, from: &TaskState, to: &TaskState, time: Time) {
        let from_kind = TaskStateKind::from_task_state(from);
        let to_kind = TaskStateKind::from_task_state(to);

        // Validate the transition first (before borrowing self.tasks mutably)
        let violation = Self::validate_transition_static(task, from_kind, to_kind, time);
        if let Some(v) = violation {
            self.violations.push(v);
        }

        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        record.transitions.push((from_kind, to_kind, time));
        record.current_state = to_kind;

        // If transitioning to Cancelling, mark as acknowledged and check mask state
        if to_kind == TaskStateKind::Cancelling {
            if record.mask_depth > 0 {
                self.violations
                    .push(CancellationProtocolViolation::CancelAckWhileMasked {
                        task,
                        mask_depth: record.mask_depth,
                        time,
                    });
            }
            if let Some(ref mut cancel) = record.cancel_request {
                cancel.acknowledged = true;
            }
        }
    }

    /// Records a region cancel event.
    ///
    /// This also checks that all descendants are cancelled (INV-CANCEL-PROPAGATES).
    pub fn on_region_cancel(&mut self, region: RegionId, reason: CancelReason, _time: Time) {
        self.cancelled_regions.insert(region, reason);
    }

    /// Records a region close event.
    ///
    /// The cancellation protocol oracle does not currently enforce close
    /// semantics directly; this hook exists for symmetry with other oracles
    /// and for conformance tests that model region close events.
    pub fn on_region_close(&mut self, _region: RegionId, _time: Time) {}

    /// Validates a single state transition (static version for borrow checker).
    fn validate_transition_static(
        task: TaskId,
        from: TaskStateKind,
        to: TaskStateKind,
        time: Time,
    ) -> Option<CancellationProtocolViolation> {
        // Define valid transitions (nested patterns for clippy)
        let is_valid = matches!(
            (from, to),
            // From Created: can go to Running or CancelRequested
            (TaskStateKind::Created, TaskStateKind::Running | TaskStateKind::CancelRequested)
                // From Running: can complete normally or start cancellation
                | (
                    TaskStateKind::Running,
                    TaskStateKind::CompletedOk
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                        | TaskStateKind::CancelRequested
                )
                // From CancelRequested: can strengthen or move to Cancelling
                | (
                    TaskStateKind::CancelRequested,
                    TaskStateKind::CancelRequested | TaskStateKind::Cancelling
                )
                // From Cancelling: can finalize or error/panic during cleanup
                | (
                    TaskStateKind::Cancelling,
                    TaskStateKind::Finalizing
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                )
                // From Finalizing: can complete cancelled or error/panic
                | (
                    TaskStateKind::Finalizing,
                    TaskStateKind::CompletedCancelled
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                )
        ) || from == to; // Same state (no-op)

        if is_valid {
            None
        } else {
            Some(CancellationProtocolViolation::SkippedState {
                task,
                from,
                to,
                time,
            })
        }
    }

    /// Verifies cancel propagation for all cancelled regions.
    fn check_cancel_propagation(&self) -> Result<(), CancellationProtocolViolation> {
        let mut regions: Vec<RegionId> = self.cancelled_regions.keys().copied().collect();
        regions.sort();
        for region in regions {
            self.verify_descendants_cancelled(region)?;
        }
        Ok(())
    }

    /// Recursively verifies that all descendants of a cancelled region are also cancelled.
    fn verify_descendants_cancelled(
        &self,
        region: RegionId,
    ) -> Result<(), CancellationProtocolViolation> {
        if let Some(children) = self.region_children.get(&region) {
            let mut ordered = children.clone();
            ordered.sort();
            for child in ordered {
                if !self.cancelled_regions.contains_key(&child) {
                    return Err(CancellationProtocolViolation::CancelNotPropagated {
                        parent: region,
                        uncancelled_child: child,
                    });
                }
                self.verify_descendants_cancelled(child)?;
            }
        }
        Ok(())
    }

    /// Checks for cancelled tasks that haven't completed.
    fn check_cancelled_tasks_completed(&self) -> Vec<CancellationProtocolViolation> {
        let mut violations = Vec::new();

        let mut tasks: Vec<TaskId> = self.tasks.keys().copied().collect();
        tasks.sort();
        for task in tasks {
            let Some(record) = self.tasks.get(&task) else {
                continue;
            };
            if let Some(ref cancel) = record.cancel_request {
                if !record.current_state.is_terminal() {
                    violations.push(CancellationProtocolViolation::CancelNotCompleted {
                        task,
                        stuck_state: record.current_state,
                        requested_at: cancel.requested_at,
                    });
                }
            }
        }

        violations
    }

    /// Checks all invariants and returns the first violation, if any.
    ///
    /// # Errors
    ///
    /// Returns `Err(CancellationProtocolViolation)` if the cancellation protocol
    /// was violated.
    pub fn check(&self) -> Result<(), CancellationProtocolViolation> {
        // Return any accumulated violations first
        if let Some(v) = self.violations.first() {
            return Err(v.clone());
        }

        // Check cancel propagation
        self.check_cancel_propagation()?;

        // Check that cancelled tasks completed
        let task_violations = self.check_cancelled_tasks_completed();
        if let Some(v) = task_violations.first() {
            return Err(v.clone());
        }

        Ok(())
    }

    /// Returns all violations detected so far.
    #[must_use]
    pub fn all_violations(&self) -> Vec<CancellationProtocolViolation> {
        let mut all = self.violations.clone();

        // Add propagation violations
        let mut regions: Vec<RegionId> = self.cancelled_regions.keys().copied().collect();
        regions.sort();
        for region in regions {
            if let Err(v) = self.verify_descendants_cancelled(region) {
                all.push(v);
            }
        }

        // Add completion violations
        all.extend(self.check_cancelled_tasks_completed());

        all
    }

    /// Returns the set of regions that have been cancelled.
    #[must_use]
    pub fn cancelled_regions(&self) -> &HashMap<RegionId, CancelReason> {
        &self.cancelled_regions
    }

    /// Returns the current state of a task, if tracked.
    #[must_use]
    pub fn task_state(&self, task: TaskId) -> Option<TaskStateKind> {
        self.tasks.get(&task).map(|r| r.current_state)
    }

    /// Returns true if a task has an active cancel request.
    #[must_use]
    pub fn has_cancel_request(&self, task: TaskId) -> bool {
        self.tasks
            .get(&task)
            .is_some_and(|r| r.cancel_request.is_some())
    }

    /// Returns the number of tracked regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.region_parents.len()
    }

    /// Returns the number of cancelled regions.
    #[must_use]
    pub fn cancel_count(&self) -> usize {
        self.cancelled_regions.len()
    }

    /// Returns the current mask depth of a task, if tracked.
    #[must_use]
    pub fn task_mask_depth(&self, task: TaskId) -> Option<u32> {
        self.tasks.get(&task).map(|r| r.mask_depth)
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.tasks.clear();
        self.region_parents.clear();
        self.region_children.clear();
        self.cancelled_regions.clear();
        self.task_regions.clear();
        self.violations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, Outcome};
    use crate::util::ArenaIndex;

    fn task_id(idx: usize) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(idx as u32, 0))
    }

    fn region_id(idx: usize) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(idx as u32, 0))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn empty_oracle_passes() {
        init_test("empty_oracle_passes");
        let oracle = CancellationProtocolOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("empty_oracle_passes");
    }

    #[test]
    fn valid_normal_lifecycle_passes() {
        init_test("valid_normal_lifecycle_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Created -> Running -> CompletedOk
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::Completed(Outcome::Ok(())),
            Time::from_nanos(1000),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("valid_normal_lifecycle_passes");
    }

    #[test]
    fn valid_cancellation_protocol_passes() {
        init_test("valid_cancellation_protocol_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Created -> Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Running -> CancelRequested
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // CancelRequested -> Cancelling
        oracle.on_cancel_ack(task, Time::from_nanos(200));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        // Cancelling -> Finalizing
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );

        // Finalizing -> CompletedCancelled
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(400),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("valid_cancellation_protocol_passes");
    }

    #[test]
    fn cancel_before_first_poll_passes() {
        init_test("cancel_before_first_poll_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Created -> CancelRequested (cancel before first poll)
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(50));
        oracle.on_transition(
            task,
            &TaskState::Created,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(50),
        );

        // Continue through protocol
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(300),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_before_first_poll_passes");
    }

    #[test]
    fn skipped_state_detected() {
        init_test("skipped_state_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // _reason unused here - test verifies skipped state detection doesn't need cancel request
        let _reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;
        let reason = CancelReason::timeout();

        // Running -> Finalizing (skipping CancelRequested and Cancelling!)
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::Finalizing {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let skipped = matches!(
            violation,
            CancellationProtocolViolation::SkippedState { .. }
        );
        crate::assert_with_log!(skipped, "skipped state", true, skipped);
        crate::test_complete!("skipped_state_detected");
    }

    #[test]
    fn cancel_strengthening_is_valid() {
        init_test("cancel_strengthening_is_valid");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let cleanup_budget = Budget::INFINITE;

        // First cancel request with User reason
        let reason1 = CancelReason::user("stop");
        oracle.on_cancel_request(task, reason1.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason1,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Second cancel request with stronger reason (Shutdown)
        let reason2 = CancelReason::shutdown();
        oracle.on_cancel_request(task, reason2.clone(), Time::from_nanos(150));
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: CancelReason::user("stop"),
                cleanup_budget,
            },
            &TaskState::CancelRequested {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(150),
        );

        // No violations for strengthening
        let empty = oracle.violations.is_empty();
        crate::assert_with_log!(empty, "violations empty", true, empty);

        // Complete the cancellation
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason2.clone(),
                cleanup_budget,
            },
            Time::from_nanos(300),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason2.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason2)),
            Time::from_nanos(400),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_strengthening_is_valid");
    }

    #[test]
    fn cancel_propagation_violation_detected() {
        init_test("cancel_propagation_violation_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let parent = region_id(0);
        let child = region_id(1);

        oracle.on_region_create(parent, None);
        oracle.on_region_create(child, Some(parent));

        // Cancel parent but NOT child
        oracle.on_region_cancel(parent, CancelReason::timeout(), Time::from_nanos(100));
        // Note: child is NOT cancelled

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let not_propagated = matches!(
            violation,
            CancellationProtocolViolation::CancelNotPropagated { .. }
        );
        crate::assert_with_log!(
            not_propagated,
            "cancel not propagated",
            true,
            not_propagated
        );
        crate::test_complete!("cancel_propagation_violation_detected");
    }

    #[test]
    fn cancel_propagation_valid_when_all_descendants_cancelled() {
        init_test("cancel_propagation_valid_when_all_descendants_cancelled");
        let mut oracle = CancellationProtocolOracle::new();
        let root = region_id(0);
        let child1 = region_id(1);
        let child2 = region_id(2);
        let grandchild = region_id(3);

        oracle.on_region_create(root, None);
        oracle.on_region_create(child1, Some(root));
        oracle.on_region_create(child2, Some(root));
        oracle.on_region_create(grandchild, Some(child1));

        // Cancel all from root down
        oracle.on_region_cancel(root, CancelReason::shutdown(), Time::from_nanos(100));
        oracle.on_region_cancel(
            child1,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );
        oracle.on_region_cancel(
            child2,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );
        oracle.on_region_cancel(
            grandchild,
            CancelReason::parent_cancelled(),
            Time::from_nanos(100),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_propagation_valid_when_all_descendants_cancelled");
    }

    #[test]
    fn cancelled_task_not_completed_detected() {
        init_test("cancelled_task_not_completed_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Start cancellation but don't complete
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Task is stuck in CancelRequested
        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let not_completed = matches!(
            violation,
            CancellationProtocolViolation::CancelNotCompleted { .. }
        );
        crate::assert_with_log!(not_completed, "cancel not completed", true, not_completed);
        crate::test_complete!("cancelled_task_not_completed_detected");
    }

    #[test]
    fn error_during_cleanup_is_valid() {
        init_test("error_during_cleanup_is_valid");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Start cancellation
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );

        // Error during cleanup (valid)
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: CancelReason::timeout(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Err(crate::error::Error::new(
                crate::error::ErrorKind::User,
            ))),
            Time::from_nanos(300),
        );

        // This should pass - error during cleanup is allowed
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("error_during_cleanup_is_valid");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);
        oracle.on_cancel_request(task, CancelReason::timeout(), Time::ZERO);

        let has_request = oracle.has_cancel_request(task);
        crate::assert_with_log!(has_request, "has cancel request", true, has_request);

        oracle.reset();

        let has_request = oracle.has_cancel_request(task);
        crate::assert_with_log!(!has_request, "cancel request cleared", false, has_request);
        let tasks_empty = oracle.tasks.is_empty();
        crate::assert_with_log!(tasks_empty, "tasks empty", true, tasks_empty);
        let parents_empty = oracle.region_parents.is_empty();
        crate::assert_with_log!(parents_empty, "parents empty", true, parents_empty);
        let cancelled_empty = oracle.cancelled_regions.is_empty();
        crate::assert_with_log!(cancelled_empty, "cancelled empty", true, cancelled_empty);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn task_state_tracking() {
        init_test("task_state_tracking");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let created = oracle.task_state(task);
        crate::assert_with_log!(
            created == Some(TaskStateKind::Created),
            "task state created",
            Some(TaskStateKind::Created),
            created
        );

        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        let running = oracle.task_state(task);
        crate::assert_with_log!(
            running == Some(TaskStateKind::Running),
            "task state running",
            Some(TaskStateKind::Running),
            running
        );
        crate::test_complete!("task_state_tracking");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let v = CancellationProtocolViolation::SkippedState {
            task: task_id(0),
            from: TaskStateKind::Running,
            to: TaskStateKind::Finalizing,
            time: Time::from_nanos(100),
        };

        let display = format!("{v}");
        let has_skipped = display.contains("skipped state");
        crate::assert_with_log!(has_skipped, "contains skipped", true, has_skipped);
        let has_running = display.contains("Running");
        crate::assert_with_log!(has_running, "contains Running", true, has_running);
        let has_finalizing = display.contains("Finalizing");
        crate::assert_with_log!(has_finalizing, "contains Finalizing", true, has_finalizing);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn mask_depth_exceeded_detected() {
        init_test("mask_depth_exceeded_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Push mask depth past MAX_MASK_DEPTH
        for i in 0..=crate::types::MAX_MASK_DEPTH {
            oracle.on_mask_enter(task, Time::from_nanos(u64::from(i)));
        }

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let exceeded = matches!(
            violation,
            CancellationProtocolViolation::MaskDepthExceeded { .. }
        );
        crate::assert_with_log!(exceeded, "mask depth exceeded", true, exceeded);
        crate::test_complete!("mask_depth_exceeded_detected");
    }

    #[test]
    fn mask_within_bounds_passes() {
        init_test("mask_within_bounds_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        // Enter and exit mask 3 times (within bounds)
        for i in 0..3 {
            oracle.on_mask_enter(task, Time::from_nanos(i * 2));
            oracle.on_mask_exit(task, Time::from_nanos(i * 2 + 1));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("mask_within_bounds_passes");
    }

    #[test]
    fn cancel_ack_while_masked_detected() {
        init_test("cancel_ack_while_masked_detected");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Enter masked section
        oracle.on_mask_enter(task, Time::from_nanos(50));

        // Cancel while masked
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );

        // Acknowledge cancel while STILL masked (violation!)
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason,
                cleanup_budget,
            },
            Time::from_nanos(150),
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        let ack_masked = matches!(
            violation,
            CancellationProtocolViolation::CancelAckWhileMasked { .. }
        );
        crate::assert_with_log!(ack_masked, "cancel ack while masked", true, ack_masked);
        crate::test_complete!("cancel_ack_while_masked_detected");
    }

    #[test]
    fn cancel_ack_after_unmask_passes() {
        init_test("cancel_ack_after_unmask_passes");
        let mut oracle = CancellationProtocolOracle::new();
        let task = task_id(0);
        let region = region_id(0);

        oracle.on_region_create(region, None);
        oracle.on_task_create(task, region);

        let reason = CancelReason::timeout();
        let cleanup_budget = Budget::INFINITE;

        // Running
        oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);

        // Enter and exit masked section
        oracle.on_mask_enter(task, Time::from_nanos(50));
        oracle.on_mask_exit(task, Time::from_nanos(80));

        // Cancel and ack while unmasked (valid)
        oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
        oracle.on_transition(
            task,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(100),
        );
        oracle.on_transition(
            task,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(150),
        );
        oracle.on_transition(
            task,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            Time::from_nanos(200),
        );
        oracle.on_transition(
            task,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            Time::from_nanos(300),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("cancel_ack_after_unmask_passes");
    }

    #[test]
    fn mask_depth_violation_display() {
        init_test("mask_depth_violation_display");
        let v = CancellationProtocolViolation::MaskDepthExceeded {
            task: task_id(0),
            depth: 65,
            max: 64,
            time: Time::from_nanos(100),
        };
        let display = format!("{v}");
        let has_depth = display.contains("65");
        crate::assert_with_log!(has_depth, "contains depth", true, has_depth);
        let has_max = display.contains("64");
        crate::assert_with_log!(has_max, "contains max", true, has_max);
        crate::test_complete!("mask_depth_violation_display");
    }

    #[test]
    fn cancel_ack_masked_violation_display() {
        init_test("cancel_ack_masked_violation_display");
        let v = CancellationProtocolViolation::CancelAckWhileMasked {
            task: task_id(0),
            mask_depth: 2,
            time: Time::from_nanos(100),
        };
        let display = format!("{v}");
        let has_masked = display.contains("masked");
        crate::assert_with_log!(has_masked, "contains masked", true, has_masked);
        let has_depth = display.contains("depth=2");
        crate::assert_with_log!(has_depth, "contains depth", true, has_depth);
        crate::test_complete!("cancel_ack_masked_violation_display");
    }
}
