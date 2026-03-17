//! I/O operation obligation handle.
//!
//! `IoOp` models the two-phase I/O obligation lifecycle:
//! - submit: reserve an obligation
//! - complete: commit the obligation
//! - cancel/abort: abort the obligation
//!
//! This ensures in-flight I/O participates in region quiescence.

use crate::error::{Error, ErrorKind};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::state::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId};

/// Handle for a submitted I/O operation obligation.
#[derive(Debug)]
#[must_use = "IoOp must be completed, cancelled, aborted, or explicitly disarmed with into_raw()"]
pub struct IoOp {
    obligation: ObligationId,
    resolved: bool,
}

impl IoOp {
    /// Submit a new I/O operation obligation.
    #[allow(clippy::result_large_err)]
    pub fn submit(
        state: &mut RuntimeState,
        holder: TaskId,
        region: RegionId,
        description: Option<String>,
    ) -> Result<Self, Error> {
        let obligation =
            state.create_obligation(ObligationKind::IoOp, holder, region, description)?;
        Ok(Self {
            obligation,
            resolved: false,
        })
    }

    /// Returns the underlying obligation id.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.obligation
    }

    /// Returns whether this handle has already been resolved or disarmed.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.resolved
    }

    /// Explicitly disarm the drop guard and return the raw obligation id.
    ///
    /// This escape hatch is for runtime-owned I/O that intentionally outlives
    /// the handle value, and for tests that need to model an external leak.
    #[must_use]
    pub fn into_raw(mut self) -> ObligationId {
        self.resolved = true;
        self.obligation
    }

    /// Completes the I/O operation, committing the obligation.
    #[allow(clippy::result_large_err)]
    pub fn complete(&mut self, state: &mut RuntimeState) -> Result<u64, Error> {
        self.resolve_with(state, RuntimeState::commit_obligation)
    }

    /// Cancels the I/O operation, aborting the obligation with `Cancel`.
    #[allow(clippy::result_large_err)]
    pub fn cancel(&mut self, state: &mut RuntimeState) -> Result<u64, Error> {
        self.resolve_with(state, |state, obligation| {
            state.abort_obligation(obligation, ObligationAbortReason::Cancel)
        })
    }

    /// Aborts the I/O operation with an explicit reason.
    #[allow(clippy::result_large_err)]
    pub fn abort(
        &mut self,
        state: &mut RuntimeState,
        reason: ObligationAbortReason,
    ) -> Result<u64, Error> {
        self.resolve_with(state, |state, obligation| {
            state.abort_obligation(obligation, reason)
        })
    }

    #[allow(clippy::result_large_err)]
    fn resolve_with(
        &mut self,
        state: &mut RuntimeState,
        resolve: impl FnOnce(&mut RuntimeState, ObligationId) -> Result<u64, Error>,
    ) -> Result<u64, Error> {
        if self.resolved {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved)
                .with_message("I/O obligation handle already resolved"));
        }

        match resolve(state, self.obligation) {
            Ok(duration) => {
                self.resolved = true;
                Ok(duration)
            }
            Err(err) => {
                if err.kind() == ErrorKind::ObligationAlreadyResolved {
                    self.resolved = true;
                }
                Err(err)
            }
        }
    }
}

impl Drop for IoOp {
    fn drop(&mut self) {
        if !self.resolved {
            if std::thread::panicking() {
                return;
            }
            panic!(
                "I/O obligation {:?} was dropped without completion, cancellation, abort, or explicit into_raw() handoff",
                self.obligation
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ObligationAbortReason, ObligationState};
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::{Budget, Time};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn create_task(state: &mut RuntimeState, region: RegionId) -> TaskId {
        let (task_id, _handle) = state
            .create_task(region, Budget::INFINITE, async {})
            .expect("task create");
        task_id
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn io_op_submit_complete_emits_trace() {
        init_test("io_op_submit_complete_emits_trace");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        state.now = Time::from_nanos(10);
        let mut op = IoOp::submit(&mut state, task_id, root, Some("io submit".to_string()))
            .expect("submit io op");
        let obligation_id = op.id();

        state.now = Time::from_nanos(25);
        let duration = op.complete(&mut state).expect("complete io op");
        crate::assert_with_log!(duration == 15, "duration", 15, duration);

        let reserve_event = state
            .trace
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationReserve)
            .expect("reserve event");
        match &reserve_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region: event_region,
                kind,
                state: ob_state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(
                    *obligation == obligation_id,
                    "obligation",
                    obligation_id,
                    *obligation
                );
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*event_region == root, "region", root, *event_region);
                crate::assert_with_log!(
                    *kind == ObligationKind::IoOp,
                    "kind",
                    ObligationKind::IoOp,
                    *kind
                );
                crate::assert_with_log!(
                    *ob_state == ObligationState::Reserved,
                    "state",
                    ObligationState::Reserved,
                    *ob_state
                );
                crate::assert_with_log!(
                    duration_ns.is_none(),
                    "duration none",
                    true,
                    duration_ns.is_none()
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort none",
                    true,
                    abort_reason.is_none()
                );
            }
            other => unreachable!("unexpected reserve data: {other:?}"),
        }

        let commit_event = state
            .trace
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region: event_region,
                kind,
                state: ob_state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(
                    *obligation == obligation_id,
                    "obligation",
                    obligation_id,
                    *obligation
                );
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*event_region == root, "region", root, *event_region);
                crate::assert_with_log!(
                    *kind == ObligationKind::IoOp,
                    "kind",
                    ObligationKind::IoOp,
                    *kind
                );
                crate::assert_with_log!(
                    *ob_state == ObligationState::Committed,
                    "state",
                    ObligationState::Committed,
                    *ob_state
                );
                crate::assert_with_log!(
                    *duration_ns == Some(15),
                    "duration",
                    Some(15),
                    *duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort none",
                    true,
                    abort_reason.is_none()
                );
            }
            other => unreachable!("unexpected commit data: {other:?}"),
        }
        crate::test_complete!("io_op_submit_complete_emits_trace");
    }

    #[test]
    fn io_op_cancel_emits_trace() {
        init_test("io_op_cancel_emits_trace");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        state.now = Time::from_nanos(100);
        let mut op = IoOp::submit(&mut state, task_id, root, None).expect("submit io op");
        let obligation_id = op.id();

        state.now = Time::from_nanos(130);
        let duration = op.cancel(&mut state).expect("cancel io op");
        crate::assert_with_log!(duration == 30, "duration", 30, duration);

        let abort_event = state
            .trace
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region: event_region,
                kind,
                state: ob_state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(
                    *obligation == obligation_id,
                    "obligation",
                    obligation_id,
                    *obligation
                );
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*event_region == root, "region", root, *event_region);
                crate::assert_with_log!(
                    *kind == ObligationKind::IoOp,
                    "kind",
                    ObligationKind::IoOp,
                    *kind
                );
                crate::assert_with_log!(
                    *ob_state == ObligationState::Aborted,
                    "state",
                    ObligationState::Aborted,
                    *ob_state
                );
                crate::assert_with_log!(
                    *duration_ns == Some(30),
                    "duration",
                    Some(30),
                    *duration_ns
                );
                crate::assert_with_log!(
                    *abort_reason == Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    Some(ObligationAbortReason::Cancel),
                    *abort_reason
                );
            }
            other => unreachable!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("io_op_cancel_emits_trace");
    }

    #[test]
    fn io_op_debug_format() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        let op = IoOp::submit(&mut state, task_id, root, None).expect("submit");
        let dbg = format!("{op:?}");
        assert!(dbg.contains("IoOp"), "{dbg}");
        let obligation_id = op.into_raw();
        let _ = state.abort_obligation(obligation_id, ObligationAbortReason::Cancel);
    }

    #[test]
    fn io_op_id_accessor() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        let mut op = IoOp::submit(&mut state, task_id, root, None).expect("submit");
        let id = op.id();
        // Id should be deterministic (first obligation)
        let _ = format!("{id:?}");
        op.complete(&mut state).expect("complete");
    }

    #[test]
    fn io_op_abort_with_explicit_reason() {
        init_test("io_op_abort_with_explicit_reason");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        state.now = Time::from_nanos(50);
        let mut op =
            IoOp::submit(&mut state, task_id, root, Some("explicit abort".into())).expect("submit");

        state.now = Time::from_nanos(80);
        let duration = op
            .abort(&mut state, ObligationAbortReason::Explicit)
            .expect("abort");
        crate::assert_with_log!(duration == 30, "abort duration", 30, duration);

        let abort_event = state
            .trace
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation { abort_reason, .. } => {
                crate::assert_with_log!(
                    *abort_reason == Some(ObligationAbortReason::Explicit),
                    "abort reason",
                    Some(ObligationAbortReason::Explicit),
                    *abort_reason
                );
            }
            other => unreachable!("unexpected data: {other:?}"),
        }
        crate::test_complete!("io_op_abort_with_explicit_reason");
    }

    #[test]
    fn io_op_submit_no_description() {
        init_test("io_op_submit_no_description");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        state.now = Time::from_nanos(0);
        let mut op = IoOp::submit(&mut state, task_id, root, None).expect("submit without desc");
        state.now = Time::from_nanos(5);
        let duration = op.complete(&mut state).expect("complete");
        crate::assert_with_log!(duration == 5, "duration no desc", 5, duration);
        crate::test_complete!("io_op_submit_no_description");
    }

    #[test]
    #[should_panic(expected = "I/O obligation")]
    fn dropping_unresolved_io_op_panics() {
        init_test("dropping_unresolved_io_op_panics");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        let _op =
            IoOp::submit(&mut state, task_id, root, Some("drop leak".into())).expect("submit");
    }

    #[test]
    fn into_raw_disarms_drop_guard_and_preserves_pending_obligation() {
        init_test("into_raw_disarms_drop_guard_and_preserves_pending_obligation");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        let op =
            IoOp::submit(&mut state, task_id, root, Some("raw handoff".into())).expect("submit");
        let obligation_id = op.into_raw();

        crate::assert_with_log!(
            state.pending_obligation_count() == 1,
            "obligation remains pending after raw handoff",
            1usize,
            state.pending_obligation_count()
        );

        let duration = state
            .abort_obligation(obligation_id, ObligationAbortReason::Cancel)
            .expect("abort raw obligation");
        crate::assert_with_log!(duration == 0, "duration", 0, duration);
        crate::test_complete!("into_raw_disarms_drop_guard_and_preserves_pending_obligation");
    }

    #[test]
    fn already_resolved_state_disarms_io_op_handle() {
        init_test("already_resolved_state_disarms_io_op_handle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, root);

        let mut op = IoOp::submit(&mut state, task_id, root, Some("external resolve".into()))
            .expect("submit");
        let obligation_id = op.id();
        state
            .abort_obligation(obligation_id, ObligationAbortReason::Cancel)
            .expect("external abort");

        let err = op
            .cancel(&mut state)
            .expect_err("second resolution should fail");
        crate::assert_with_log!(
            err.kind() == ErrorKind::ObligationAlreadyResolved,
            "already resolved error",
            ErrorKind::ObligationAlreadyResolved,
            err.kind()
        );
        crate::assert_with_log!(op.is_resolved(), "handle disarmed", true, op.is_resolved());
        crate::test_complete!("already_resolved_state_disarms_io_op_handle");
    }
}
