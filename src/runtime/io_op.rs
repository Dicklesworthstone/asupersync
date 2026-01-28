//! I/O operation obligation handle.
//!
//! `IoOp` models the two-phase I/O obligation lifecycle:
//! - submit: reserve an obligation
//! - complete: commit the obligation
//! - cancel/abort: abort the obligation
//!
//! This ensures in-flight I/O participates in region quiescence.

use crate::error::Error;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::state::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId};

/// Handle for a submitted I/O operation obligation.
#[derive(Debug)]
#[must_use = "IoOp must be completed or cancelled"]
pub struct IoOp {
    obligation: ObligationId,
}

impl IoOp {
    /// Submit a new I/O operation obligation.
    pub fn submit(
        state: &mut RuntimeState,
        holder: TaskId,
        region: RegionId,
        description: Option<String>,
    ) -> Result<Self, Error> {
        let obligation =
            state.create_obligation(ObligationKind::IoOp, holder, region, description)?;
        Ok(Self { obligation })
    }

    /// Returns the underlying obligation id.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.obligation
    }

    /// Completes the I/O operation, committing the obligation.
    pub fn complete(self, state: &mut RuntimeState) -> Result<u64, Error> {
        state.commit_obligation(self.obligation)
    }

    /// Cancels the I/O operation, aborting the obligation with `Cancel`.
    pub fn cancel(self, state: &mut RuntimeState) -> Result<u64, Error> {
        state.abort_obligation(self.obligation, ObligationAbortReason::Cancel)
    }

    /// Aborts the I/O operation with an explicit reason.
    pub fn abort(
        self,
        state: &mut RuntimeState,
        reason: ObligationAbortReason,
    ) -> Result<u64, Error> {
        state.abort_obligation(self.obligation, reason)
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
    fn io_op_submit_complete_emits_trace() {
        init_test("io_op_submit_complete_emits_trace");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, region);

        state.now = Time::from_nanos(10);
        let op = IoOp::submit(
            &mut state,
            task_id,
            region,
            Some("io submit".to_string()),
        )
        .expect("submit io op");
        let obligation_id = op.id();

        state.now = Time::from_nanos(25);
        let duration = op.complete(&mut state).expect("complete io op");
        crate::assert_with_log!(duration == 15, "duration", 15, duration);

        let reserve_event = state
            .trace
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationReserve)
            .expect("reserve event");
        match &reserve_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
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
                crate::assert_with_log!(*region == region, "region", region, *region);
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
            other => panic!("unexpected reserve data: {other:?}"),
        }

        let commit_event = state
            .trace
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
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
                crate::assert_with_log!(*region == region, "region", region, *region);
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
                    duration_ns == &Some(15),
                    "duration",
                    &Some(15),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort none",
                    true,
                    abort_reason.is_none()
                );
            }
            other => panic!("unexpected commit data: {other:?}"),
        }
        crate::test_complete!("io_op_submit_complete_emits_trace");
    }

    #[test]
    fn io_op_cancel_emits_trace() {
        init_test("io_op_cancel_emits_trace");
        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let task_id = create_task(&mut state, region);

        state.now = Time::from_nanos(100);
        let op = IoOp::submit(&mut state, task_id, region, None).expect("submit io op");
        let obligation_id = op.id();

        state.now = Time::from_nanos(130);
        let duration = op.cancel(&mut state).expect("cancel io op");
        crate::assert_with_log!(duration == 30, "duration", 30, duration);

        let abort_event = state
            .trace
            .iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
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
                crate::assert_with_log!(*region == region, "region", region, *region);
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
                    duration_ns == &Some(30),
                    "duration",
                    &Some(30),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason == &Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    &Some(ObligationAbortReason::Cancel),
                    abort_reason
                );
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("io_op_cancel_emits_trace");
    }
}
