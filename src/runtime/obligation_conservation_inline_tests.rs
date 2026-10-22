use super::*;
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::{ObligationAbortReason, RegionState, SourceLocation};
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::obligation_table::ObligationCreateArgs;
use crate::runtime::state::RuntimeState;
use crate::types::{Budget, Time};
use crate::util::ArenaIndex;

fn holder(runtime: &mut LabRuntime, region: RegionId) -> (TaskId, Cx) {
    let (task, _join) = runtime
        .state
        .create_task(region, Budget::INFINITE, std::future::pending::<()>())
        .unwrap();
    let cx = runtime.state.task(task).unwrap().cx.clone().unwrap();
    (task, cx)
}

fn checked_runtime() -> (LabRuntime, RegionId, TaskId, Cx) {
    let mut runtime = LabRuntime::new(LabConfig::new(0xD152));
    runtime
        .state
        .set_obligation_leak_response(ObligationLeakResponse::Silent);
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task, cx) = holder(&mut runtime, region);
    (runtime, region, task, cx)
}

#[test]
fn queued_reserve_defers_but_decided_terminal_reconciles_before_application() {
    let (mut runtime, region, task, cx) = checked_runtime();
    let token = cx
        .try_register_obligation_checked(ObligationKind::SendPermit, task)
        .unwrap()
        .unwrap();
    let queued = runtime.state.check_obligation_conservation();
    assert!(queued.violation.is_none());
    assert_eq!(queued.deferred_regions, vec![region]);
    assert!(
        !queued.is_verified(),
        "queued credit must never be a proved zero"
    );

    assert_eq!(runtime.state.drain_obligation_posts(1), 1);
    assert!(
        runtime
            .state
            .obligation_conservation_report()
            .unwrap()
            .is_verified()
    );
    assert!(token.commit());
    assert_eq!(
        runtime.state.region(region).unwrap().pending_obligations(),
        0
    );
    assert_eq!(runtime.state.pending_obligation_count(), 1);
    assert_eq!(
        runtime
            .state
            .region(region)
            .unwrap()
            .unapplied_obligation_count(),
        1
    );
    assert!(runtime.state.check_obligation_conservation().is_verified());

    assert_eq!(runtime.state.drain_obligation_posts(1), 1);
    assert!(
        runtime
            .state
            .obligation_conservation_report()
            .unwrap()
            .is_verified()
    );
    assert_eq!(runtime.state.pending_obligation_count(), 0);
    assert_eq!(
        runtime
            .state
            .region(region)
            .unwrap()
            .unapplied_obligation_count(),
        0
    );
}

#[test]
fn queued_credit_cannot_verify_zero_after_its_region_row_disappears() {
    let (mut runtime, region, task, cx) = checked_runtime();
    let token = cx
        .try_register_obligation_checked(ObligationKind::SendPermit, task)
        .unwrap()
        .unwrap();
    // Plant loss of the only region before its accepted Reserve is projected.
    // There is no remaining arena or region row from which to recover its id.
    runtime.state.regions.remove(region.arena_index()).unwrap();
    let report = runtime.state.check_obligation_conservation();
    assert!(report.pending_ownership_projection);
    assert_eq!(report.checked_regions, 0);
    assert!(report.deferred_regions.is_empty());
    assert!(
        !report.is_verified(),
        "an unlocated queued credit is never proved zero"
    );
    assert!(token.abort(ObligationAbortReason::Explicit));
}

#[test]
fn chained_handoffs_defer_until_the_last_owner_is_projected() {
    let (mut runtime, root, task, cx) = checked_runtime();
    let child = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .unwrap();
    let (_, destination) = holder(&mut runtime, child);
    let (last_holder, last_destination) = holder(&mut runtime, child);
    let token = cx
        .try_register_obligation_checked(ObligationKind::Lease, task)
        .unwrap()
        .unwrap()
        .try_transfer(&destination)
        .unwrap()
        .try_transfer(&last_destination)
        .unwrap();

    // Reserve, cross-region handoff, same-region handoff are three separately
    // applied receipts. Both intermediate projections are legitimate.
    for _ in 0..2 {
        assert_eq!(runtime.state.drain_obligation_posts(1), 1);
        let report = runtime.state.obligation_conservation_report().unwrap();
        assert!(report.violation.is_none());
        assert!(!report.deferred_regions.is_empty());
    }
    assert_eq!(runtime.state.drain_obligation_posts(1), 1);
    assert!(
        runtime
            .state
            .obligation_conservation_report()
            .unwrap()
            .is_verified()
    );
    let (_, record) = runtime
        .state
        .obligations_iter()
        .find(|(_, record)| record.is_pending())
        .unwrap();
    assert_eq!((record.region, record.holder), (child, last_holder));
    assert!(token.abort(ObligationAbortReason::Explicit));
    assert!(runtime.state.check_obligation_conservation().is_verified());
    runtime.state.drain_obligation_posts(64);
    assert!(
        runtime
            .state
            .obligation_conservation_report()
            .unwrap()
            .is_verified()
    );
}

#[test]
fn independent_region_drift_is_latched_and_fails_the_lab_report() {
    let mut runtime = LabRuntime::new(LabConfig::new(0xD153));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    // Plant a credit without an arena record. A self-balancing mailbox counter
    // would miss this disagreement in the region admission state.
    runtime
        .state
        .region(region)
        .unwrap()
        .try_reserve_obligation()
        .unwrap();
    let fault = runtime
        .state
        .check_obligation_conservation()
        .violation
        .unwrap();
    assert_eq!(fault.region, region);
    assert_eq!(
        fault.issue,
        ObligationConservationIssue::LiveCountMismatch {
            expected: 0,
            observed: 1,
        }
    );
    runtime.state.region(region).unwrap().resolve_obligation();
    assert_eq!(
        runtime.state.check_obligation_conservation().violation,
        Some(fault)
    );
    let report = runtime.report();
    assert!(
        report
            .invariant_violations
            .iter()
            .any(|failure| { failure.contains("obligation projection invariant") })
    );
    assert!(!report.lab_test_passed());
}

#[test]
fn close_uses_arena_marking_even_when_region_counts_claim_zero() {
    let mut state = RuntimeState::new();
    state.enable_obligation_conservation_checks();
    let region = state.create_root_region(Budget::INFINITE);
    // Plant the historical failure shape directly: an actual Reserved record
    // exists while the independent region accounting says it is empty.
    let obligation = state.obligations.create(ObligationCreateArgs {
        kind: ObligationKind::IoOp,
        holder: TaskId::from_arena(ArenaIndex::new(7, 3)),
        region,
        now: Time::ZERO,
        description: None,
        acquired_at: SourceLocation::unknown(),
        acquire_backtrace: None,
    });
    let record = state.region(region).unwrap();
    assert_eq!(record.pending_obligations(), 0);
    assert!(record.begin_close(None));
    assert!(record.begin_finalize());
    state.advance_region_state(region);

    assert_eq!(
        state.region(region).unwrap().state(),
        RegionState::Finalizing
    );
    assert!(!state.region_was_closed(region));
    let fault = state
        .obligation_conservation_report()
        .unwrap()
        .violation
        .unwrap();
    assert_eq!(
        fault.checkpoint,
        ObligationConservationCheckpoint::RegionClose
    );
    assert_eq!(fault.obligation, Some(obligation));
    assert_eq!(fault.kind, Some(ObligationKind::IoOp));
    assert_eq!(fault.issue, ObligationConservationIssue::PendingAtClose);
}

#[test]
fn exact_holder_generation_disagreement_is_detected() {
    let (mut runtime, region, task, cx) = checked_runtime();
    let token = cx
        .try_register_obligation_checked(ObligationKind::Ack, task)
        .unwrap()
        .unwrap();
    runtime.state.drain_obligation_posts(1);
    let id = runtime.state.obligations_iter().next().unwrap().1.id;
    let index = task.arena_index();
    runtime.state.obligation_mut(id).unwrap().holder =
        TaskId::from_arena(ArenaIndex::new(index.index(), index.generation() + 1));
    let fault = runtime
        .state
        .check_obligation_conservation()
        .violation
        .unwrap();
    assert_eq!(fault.obligation, Some(id));
    assert_eq!(
        fault.issue,
        ObligationConservationIssue::CreditBindingMismatch {
            credit_holder: task,
            credit_region: region,
        }
    );
    // Restore ownership so token cleanup does not add an unrelated defect.
    runtime.state.obligation_mut(id).unwrap().holder = task;
    assert!(token.abort(ObligationAbortReason::Explicit));
    runtime.state.drain_obligation_posts(64);
}

#[test]
fn an_admitted_credit_cannot_disappear_with_its_arena_record() {
    let (mut runtime, _, task, cx) = checked_runtime();
    let token = cx
        .try_register_obligation_checked(ObligationKind::Transaction, task)
        .unwrap()
        .unwrap();
    runtime.state.drain_obligation_posts(1);
    let id = runtime.state.obligations_iter().next().unwrap().1.id;
    runtime.state.obligations.remove(id.arena_index()).unwrap();
    let fault = runtime
        .state
        .check_obligation_conservation()
        .violation
        .unwrap();
    assert_eq!(fault.obligation, Some(id));
    assert_eq!(
        fault.issue,
        ObligationConservationIssue::MissingPendingRecord
    );
    // Resolution may queue, but cannot retroactively make the missing record a
    // verified conservation result; the fault remains latched.
    assert!(token.abort(ObligationAbortReason::Explicit));
}

#[test]
fn native_state_checks_are_opt_in_and_direct_obligations_reconcile() {
    let mut state = RuntimeState::new();
    assert!(state.obligation_conservation_report().is_none());
    let region = state.create_root_region(Budget::INFINITE);
    let (task, _join) = state
        .create_task(region, Budget::INFINITE, std::future::pending::<()>())
        .unwrap();
    let id = state
        .create_obligation(ObligationKind::SemaphorePermit, task, region, None)
        .unwrap();
    state.enable_obligation_conservation_checks();
    assert!(
        state
            .obligation_conservation_report()
            .unwrap()
            .is_verified()
    );
    state.commit_obligation(id).unwrap();
    assert!(state.check_obligation_conservation().is_verified());
}

#[test]
fn sharded_inspection_and_close_use_the_authoritative_obligation_arena() {
    use crate::runtime::sharded_state::{ShardedConfig, ShardedState};
    use crate::trace::distributed::LogicalClockMode;

    let mut state = RuntimeState::new();
    let shards = Arc::new(ShardedState::new(
        state.trace_handle(),
        Arc::clone(&state.metrics),
        ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: Default::default(),
            entropy_source: state.entropy_source(),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Silent,
            leak_escalation: None,
            observability: None,
        },
    ));
    state.install_shard_tables(Arc::clone(&shards));
    state.enable_obligation_conservation_checks();
    let region = state.create_root_region(Budget::INFINITE);
    state
        .region(region)
        .unwrap()
        .try_reserve_obligation()
        .unwrap();
    let id = shards
        .obligations
        .lock()
        .unwrap()
        .create(ObligationCreateArgs {
            kind: ObligationKind::Lease,
            holder: TaskId::from_arena(ArenaIndex::new(4, 2)),
            region,
            now: Time::ZERO,
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
    assert!(
        state.obligations.is_empty(),
        "the embedded table is intentionally empty"
    );
    assert!(state.check_obligation_conservation().is_verified());

    let record = state.region(region).unwrap();
    record.resolve_obligation();
    assert!(record.begin_close(None));
    assert!(record.begin_finalize());
    state.advance_region_state(region);
    assert_eq!(
        state.region(region).unwrap().state(),
        RegionState::Finalizing
    );
    let fault = state
        .obligation_conservation_report()
        .unwrap()
        .violation
        .unwrap();
    assert_eq!(fault.obligation, Some(id));
    assert_eq!(fault.issue, ObligationConservationIssue::PendingAtClose);
}
