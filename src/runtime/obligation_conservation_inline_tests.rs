use super::*;
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::RegionState;
use crate::record::{ObligationAbortReason, SourceLocation};
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::obligation_table::{ObligationCreateArgs, ObligationTable};
use crate::runtime::state::RuntimeState;
use crate::types::{Budget, Time};
use crate::util::ArenaIndex;

fn lifetime_args(region: RegionId, kind: ObligationKind) -> ObligationCreateArgs {
    ObligationCreateArgs {
        kind,
        holder: TaskId::from_arena(ArenaIndex::new(7, 3)),
        region,
        now: Time::ZERO,
        description: None,
        acquired_at: SourceLocation::unknown(),
        acquire_backtrace: None,
    }
}

fn lifetime_counts(table: &ObligationTable, kind: ObligationKind) -> ObligationLifetimeCounts {
    let (report, fault) = table
        .inspect_lifetime(ObligationConservationCheckpoint::Inspection)
        .unwrap();
    assert!(fault.is_none(), "{fault:?}");
    report
        .by_kind
        .iter()
        .find(|entry| entry.kind == kind)
        .unwrap()
        .counts
}

#[test]
fn lifetime_history_survives_retention_and_finalized_region_retirement() {
    let mut table = ObligationTable::new();
    table.enable_lifetime_checks();
    let region = RegionId::from_arena(ArenaIndex::new(2, 5));
    let kind = ObligationKind::SendPermit;
    let first = table.create(lifetime_args(region, kind));
    table.commit(first, Time::ZERO).unwrap();
    for _ in 1..5000 {
        let id = table.create(lifetime_args(region, kind));
        table.commit(id, Time::ZERO).unwrap();
    }
    assert!(
        table.get(first.arena_index()).is_none(),
        "the regression must cross the resolved-record retention boundary"
    );
    let aborted = table.create(lifetime_args(region, kind));
    table
        .abort(aborted, Time::ZERO, ObligationAbortReason::Explicit)
        .unwrap();
    let leaked = table.create(lifetime_args(region, kind));
    table.mark_leaked(leaked, Time::ZERO).unwrap();
    let counts = lifetime_counts(&table, kind);
    assert_eq!(counts.reserved, 5002);
    assert_eq!(counts.committed, 5000);
    assert_eq!(counts.aborted, 1);
    assert_eq!(counts.leaked, 1);
    assert_eq!(counts.live, 0);
    assert!(counts.is_balanced());
    table.mark_region_finalized(region);
    let (retired, fault) = table
        .inspect_lifetime(ObligationConservationCheckpoint::Inspection)
        .unwrap();
    assert!(fault.is_none());
    assert_eq!(retired.retained_region_kinds, 0);
    assert_eq!(lifetime_counts(&table, kind), counts);
}

#[test]
fn lifetime_enablement_uses_a_baseline_and_never_resets_the_epoch() {
    let mut table = ObligationTable::new();
    let region = RegionId::from_arena(ArenaIndex::new(2, 5));
    let kind = ObligationKind::Ack;
    let historical = table.create(lifetime_args(region, kind));
    table.commit(historical, Time::ZERO).unwrap();
    let existing = table.create(lifetime_args(region, kind));
    assert!(
        table
            .inspect_lifetime(ObligationConservationCheckpoint::Inspection)
            .is_none()
    );
    table.enable_lifetime_checks();
    let created = table.create(lifetime_args(region, kind));
    table.commit(created, Time::ZERO).unwrap();
    assert!(table.commit(created, Time::ZERO).is_err());
    table.enable_lifetime_checks();
    let counts = lifetime_counts(&table, kind);
    assert_eq!(counts.baseline_live, 1);
    assert_eq!(counts.reserved, 1);
    assert_eq!(counts.committed, 1);
    assert_eq!(counts.live, 1);
    table
        .abort(existing, Time::ZERO, ObligationAbortReason::Explicit)
        .unwrap();
    assert!(lifetime_counts(&table, kind).is_balanced());
}

#[test]
fn lifetime_transfer_distinguishes_reused_region_generations() {
    let mut table = ObligationTable::new();
    table.enable_lifetime_checks();
    let source = RegionId::from_arena(ArenaIndex::new(3, 4));
    let destination = RegionId::from_arena(ArenaIndex::new(3, 5));
    let holder = TaskId::from_arena(ArenaIndex::new(7, 3));
    let kind = ObligationKind::Lease;
    let id = table.create(lifetime_args(source, kind));
    table.rebind_pending(id, holder, source).unwrap();
    assert_eq!(lifetime_counts(&table, kind).transferred_in, 0);
    table.rebind_pending(id, holder, destination).unwrap();
    assert!(table.lifetime_violation_at_close(source).is_none());
    table.mark_region_finalized(source);
    let counts = lifetime_counts(&table, kind);
    assert_eq!(counts.reserved, 1);
    assert_eq!(counts.transferred_out, 1);
    assert_eq!(counts.transferred_in, 1);
    assert_eq!(counts.live, 1);
    table.commit(id, Time::ZERO).unwrap();
    table.mark_region_finalized(destination);
    assert!(lifetime_counts(&table, kind).is_balanced());
}

#[test]
fn erased_record_and_erased_region_credit_cannot_jointly_hide_a_lost_obligation() {
    let mut state = RuntimeState::new();
    state.enable_obligation_conservation_checks();
    let region = state.create_root_region(Budget::INFINITE);
    state
        .region(region)
        .unwrap()
        .try_reserve_obligation()
        .unwrap();
    let id = state
        .obligations
        .create(lifetime_args(region, ObligationKind::IoOp));
    assert!(state.check_obligation_conservation().is_verified());
    // Both current projections now claim empty. Only independent historical
    // reservation accounting can distinguish this from a legitimate terminal.
    state.obligations.remove(id.arena_index()).unwrap();
    state.region(region).unwrap().resolve_obligation();
    let fault = state.check_obligation_conservation().violation.unwrap();
    assert_eq!(fault.region, region);
    assert_eq!(fault.obligation, Some(id));
    assert_eq!(fault.kind, Some(ObligationKind::IoOp));
    let ObligationConservationIssue::LifetimeCountMismatch {
        counts,
        last_transition,
    } = fault.issue
    else {
        panic!("expected lifetime disagreement");
    };
    assert_eq!(counts.reserved, 1);
    assert_eq!(counts.live, 0);
    assert_eq!(
        last_transition,
        Some(ObligationLifetimeTransition::RemovePending)
    );
    let record = state.region(region).unwrap();
    assert!(record.begin_close(None));
    assert!(record.begin_finalize());
    state.advance_region_state(region);
    assert_eq!(
        state.region(region).unwrap().state(),
        RegionState::Finalizing
    );
    assert!(!state.region_was_closed(region));
}

#[test]
fn lifetime_arithmetic_overflow_is_never_a_verified_balance() {
    let counts = ObligationLifetimeCounts {
        baseline_live: u128::MAX,
        reserved: 1,
        ..ObligationLifetimeCounts::default()
    };
    assert!(!counts.is_balanced());
    let region = RegionId::from_arena(ArenaIndex::new(2, 5));
    let id = ObligationId::from_arena(ArenaIndex::new(1, 1));
    let kind = ObligationKind::Transaction;
    let mut ledger = ObligationLifetimeLedger::default();
    ledger
        .by_region
        .entry((region, kind))
        .or_default()
        .counts
        .reserved = u128::MAX;
    ledger.note(id, region, kind, ObligationLifetimeTransition::Reserve);
    let fault = ledger
        .check(
            &BTreeMap::new(),
            ObligationConservationCheckpoint::Inspection,
            None,
        )
        .unwrap();
    assert_eq!(
        fault.issue,
        ObligationConservationIssue::LifetimeCounterOverflow {
            transition: ObligationLifetimeTransition::Reserve
        }
    );
}

#[test]
fn aggregate_sum_overflow_stays_latched_and_prevents_other_regions_closing() {
    let first = RegionId::from_arena(ArenaIndex::new(2, 5));
    let second = RegionId::from_arena(ArenaIndex::new(3, 5));
    let unrelated = RegionId::from_arena(ArenaIndex::new(4, 5));
    let id = ObligationId::from_arena(ArenaIndex::new(1, 1));
    let kind = ObligationKind::Ack;
    let mut ledger = ObligationLifetimeLedger::default();
    let historic = ObligationLifetimeCounts {
        baseline_live: u128::MAX,
        aborted: u128::MAX,
        ..ObligationLifetimeCounts::default()
    };
    assert!(historic.is_balanced());
    ledger.by_region.entry((first, kind)).or_default().counts = historic;
    ledger.totals.insert(kind, historic);
    // No individual counter overflows. The aggregate baseline + new reserve
    // sum does, while each region can still balance independently.
    ledger.note(id, second, kind, ObligationLifetimeTransition::Reserve);
    ledger.note(id, second, kind, ObligationLifetimeTransition::Commit);
    assert!(
        ledger
            .by_region
            .get(&(first, kind))
            .unwrap()
            .counts
            .is_balanced()
    );
    assert!(
        ledger
            .by_region
            .get(&(second, kind))
            .unwrap()
            .counts
            .is_balanced()
    );
    let fault = ledger
        .check(
            &BTreeMap::new(),
            ObligationConservationCheckpoint::RegionClose,
            Some(unrelated),
        )
        .unwrap();
    assert_eq!(fault.region, second);
    assert_eq!(
        fault.issue,
        ObligationConservationIssue::LifetimeCounterOverflow {
            transition: ObligationLifetimeTransition::Reserve
        }
    );
}

#[test]
fn lifetime_counts_low_level_reserved_insertions() {
    let mut table = ObligationTable::new();
    table.enable_lifetime_checks();
    let region = RegionId::from_arena(ArenaIndex::new(8, 2));
    let holder = TaskId::from_arena(ArenaIndex::new(7, 3));
    let kind = ObligationKind::IoOp;
    let first = table.insert(ObligationRecord::new(
        ObligationId::from_arena(ArenaIndex::new(99, 1)),
        kind,
        holder,
        region,
        Time::ZERO,
    ));
    let second = table.insert_with(|index| {
        ObligationRecord::new(
            ObligationId::from_arena(index),
            kind,
            holder,
            region,
            Time::ZERO,
        )
    });
    let counts = lifetime_counts(&table, kind);
    assert_eq!(counts.reserved, 2);
    assert_eq!(counts.live, 2);
    table
        .commit(ObligationId::from_arena(first), Time::ZERO)
        .unwrap();
    table
        .abort(
            ObligationId::from_arena(second),
            Time::ZERO,
            ObligationAbortReason::Explicit,
        )
        .unwrap();
    assert!(lifetime_counts(&table, kind).is_balanced());
}

#[test]
fn lifetime_conservation_holds_across_thousands_of_mixed_transitions() {
    let mut table = ObligationTable::new();
    table.enable_lifetime_checks();
    let regions = [
        RegionId::from_arena(ArenaIndex::new(1, 2)),
        RegionId::from_arena(ArenaIndex::new(1, 3)),
        RegionId::from_arena(ArenaIndex::new(2, 1)),
    ];
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
        ObligationKind::SemaphorePermit,
        ObligationKind::Transaction,
    ];
    let holder = TaskId::from_arena(ArenaIndex::new(7, 3));
    let mut live = Vec::new();
    let mut seed = 0xD152_u64;
    for step in 0..4096 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        if live.is_empty() || seed & 3 == 0 {
            let region = regions[step % regions.len()];
            live.push(table.create(lifetime_args(region, kinds[step % kinds.len()])));
        } else {
            let index = usize::try_from(seed % u64::try_from(live.len()).unwrap()).unwrap();
            let id = live[index];
            match (seed >> 32) % 4 {
                0 => {
                    table
                        .rebind_pending(id, holder, regions[step % regions.len()])
                        .unwrap();
                }
                1 => {
                    table.commit(id, Time::ZERO).unwrap();
                    live.swap_remove(index);
                }
                2 => {
                    table
                        .abort(id, Time::ZERO, ObligationAbortReason::Explicit)
                        .unwrap();
                    live.swap_remove(index);
                }
                _ => {
                    table.mark_leaked(id, Time::ZERO).unwrap();
                    live.swap_remove(index);
                }
            }
        }
        let (report, fault) = table
            .inspect_lifetime(ObligationConservationCheckpoint::Inspection)
            .unwrap();
        assert!(fault.is_none(), "step={step}: {fault:?}");
        assert!(
            report
                .by_kind
                .iter()
                .all(|entry| entry.counts.is_balanced())
        );
        assert_eq!(
            report
                .by_kind
                .iter()
                .map(|entry| entry.counts.live)
                .sum::<u128>(),
            u128::try_from(live.len()).unwrap()
        );
    }
}

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

    for enable_before_install in [false, true] {
        let mut state = RuntimeState::new();
        if enable_before_install {
            state.enable_obligation_conservation_checks();
        }
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
        if !enable_before_install {
            state.enable_obligation_conservation_checks();
        }
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
        let report = state.check_obligation_conservation();
        assert!(report.is_verified());
        let counts = report.lifetime.unwrap().by_kind[0].counts;
        assert_eq!(counts.reserved, 1);
        assert_eq!(counts.live, 1);

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
}
