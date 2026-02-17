//! Comprehensive cross-cutting E2E test suite.
//!
//! Unlike the per-subsystem E2E tests (sync_e2e, io_e2e, time_e2e, etc.),
//! these tests exercise multiple subsystems simultaneously to verify that
//! the runtime's invariants hold under realistic cross-cutting scenarios:
//!
//! - Multi-level structured concurrency (nested regions with budgets)
//! - Combinator composition (join/race/timeout/quorum interacting)
//! - Obligation lifecycle across combinator boundaries
//! - Cancellation cascade through deep region trees
//! - Budget enforcement with cascading propagation
//! - Deterministic replay of complex multi-task scenarios
//! - Stress tests with many concurrent tasks using varied combinators
//! - Full lifecycle including finalizer execution order

#[macro_use]
mod common;

use asupersync::combinator::{
    first_ok_outcomes, first_ok_to_result, hedge_outcomes, hedge_to_result, join2_outcomes,
    join_all_to_result, make_join_all_result, make_race_all_result, pipeline2_outcomes,
    pipeline_to_result, quorum_outcomes, race2_to_result, HedgeWinner, RaceWinner,
};
use asupersync::lab::oracle::{CancellationProtocolOracle, OracleSuite};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::runtime::yield_now;
use asupersync::types::{
    Budget, CancelKind, CancelReason, ObligationId, Outcome, PanicPayload, RegionId, TaskId, Time,
};
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// 1. Combinator composition: join wrapping race
// ============================================================================

/// join(race(a, b), race(c, d)) should produce worst-of(first-of(a,b), first-of(c,d))
#[test]
fn e2e_join_of_races_composition() {
    init_test("e2e_join_of_races_composition");

    test_section!("both-ok");
    {
        // Race where first (Ok) wins
        let left_val = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Ok(1),
            Outcome::Err("slow"),
        )
        .expect("left race should pick Ok");
        let right_val = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Ok(2),
            Outcome::Err("slower"),
        )
        .expect("right race should pick Ok");

        let (join_result, _, _): (Outcome<(i32, i32), &str>, _, _) =
            join2_outcomes(Outcome::Ok(left_val), Outcome::Ok(right_val));
        assert_outcome_ok!(join_result, (1, 2));
    }

    test_section!("one-race-fails");
    {
        // Both arms of left race fail → left race fails
        let left_res = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Err("fail"),
            Outcome::Err("also fail"),
        );
        // Right race: Ok wins
        let right_res = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Ok(99),
            Outcome::Err("backup"),
        );

        assert!(left_res.is_err(), "left race should fail");
        assert!(right_res.is_ok(), "right race should succeed");

        // join(Err, Ok) → Err (worst severity)
        let (join_result, _, _): (Outcome<(i32, i32), &str>, _, _) =
            join2_outcomes(Outcome::Err("fail"), Outcome::Ok(right_res.unwrap()));
        assert_outcome_err!(join_result);
    }

    test_complete!("e2e_join_of_races_composition");
}

// ============================================================================
// 2. Combinator composition: race wrapping joins
// ============================================================================

/// race(join_all(slow_group), fast_single) → fast_single wins
#[test]
fn e2e_race_of_join_groups() {
    init_test("e2e_race_of_join_groups");

    test_section!("fast-single-wins");
    {
        // Simulate: join_all of [Ok, Ok, Cancelled] (slow group, worst = Cancelled)
        let slow_group: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let join_result = make_join_all_result(slow_group);
        let slow_result = join_all_to_result(join_result);
        assert!(slow_result.is_err(), "slow group has cancellation");

        // Race: second (fast single Ok) wins
        let race_result = make_race_all_result(
            1, // winner_index = 1 (the fast single)
            vec![Outcome::<i32, &str>::Err("group_failed"), Outcome::Ok(42)],
        );
        let winner = race_result;
        assert_eq!(winner.unwrap(), 42, "fast single should win the race");
    }

    test_complete!("e2e_race_of_join_groups");
}

// ============================================================================
// 3. Pipeline → quorum composition
// ============================================================================

/// Pipeline stages feed into quorum: pipeline produces N outputs, quorum needs M
#[test]
fn e2e_pipeline_feeds_quorum() {
    init_test("e2e_pipeline_feeds_quorum");

    test_section!("pipeline-all-ok-quorum-met");
    {
        let stage1: Outcome<i32, &str> = Outcome::Ok(10);
        let stage2: Outcome<i32, &str> = Outcome::Ok(20);
        let pipeline_result = pipeline2_outcomes(stage1, Some(stage2));
        let pipeline_val = pipeline_to_result(pipeline_result).expect("pipeline should complete");

        // Feed pipeline output to quorum as one of several results
        let quorum_inputs: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(pipeline_val),
            Outcome::Ok(99),
            Outcome::Err("fail"),
        ];
        let quorum_result = quorum_outcomes(2, quorum_inputs);

        assert_with_log!(
            quorum_result.quorum_met,
            "quorum should be met with 2/3 Ok",
            true,
            quorum_result.quorum_met
        );
        assert_eq!(quorum_result.success_count(), 2);
    }

    test_section!("pipeline-fails-quorum-misses");
    {
        let stage1: Outcome<i32, &str> = Outcome::Ok(10);
        let stage2: Outcome<i32, &str> = Outcome::Err("stage2 fail");
        let pipeline_result = pipeline2_outcomes(stage1, Some(stage2));
        assert!(
            pipeline_to_result(pipeline_result).is_err(),
            "pipeline should fail at stage 2"
        );

        // Only 1 Ok out of 3 needed for quorum of 2
        let quorum_inputs: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("pipeline_fail"),
            Outcome::Ok(99),
            Outcome::Err("other"),
        ];
        let quorum_result = quorum_outcomes(2, quorum_inputs);

        assert_with_log!(
            !quorum_result.quorum_met,
            "quorum should NOT be met with 1/3 Ok",
            false,
            quorum_result.quorum_met
        );
    }

    test_complete!("e2e_pipeline_feeds_quorum");
}

// ============================================================================
// 4. Hedge + first_ok fallback chain
// ============================================================================

/// Hedge primary is slow → backup wins, then first_ok tries hedge result first
#[test]
fn e2e_hedge_with_first_ok_fallback() {
    init_test("e2e_hedge_with_first_ok_fallback");

    test_section!("backup-wins");
    {
        // Simulate: primary failed, backup spawned and won
        let primary: Outcome<i32, &str> = Outcome::Err("slow primary");
        let backup: Outcome<i32, &str> = Outcome::Ok(42);
        let hedge_result = hedge_outcomes(primary, true, Some(backup), Some(HedgeWinner::Backup));
        let hedge_val = hedge_to_result(hedge_result);
        assert_eq!(hedge_val.unwrap(), 42, "backup should win");
    }

    test_section!("first-ok-chain");
    {
        // first_ok tries: [hedge_fail, fallback_1, fallback_2]
        let attempt_1: Outcome<i32, &str> = Outcome::Err("hedge failed");
        let attempt_2: Outcome<i32, &str> = Outcome::Err("fallback 1 failed");
        let attempt_3: Outcome<i32, &str> = Outcome::Ok(77);

        let first_ok_result = first_ok_outcomes(vec![attempt_1, attempt_2, attempt_3]);
        let val = first_ok_to_result(first_ok_result).expect("first_ok should find attempt 3");
        assert_eq!(val, 77);
    }

    test_section!("all-fail");
    {
        let attempts: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("a"), Outcome::Err("b"), Outcome::Err("c")];
        let result = first_ok_outcomes(attempts);
        assert!(
            result.success.is_none(),
            "no success when all attempts fail"
        );
        assert_eq!(result.failures.len(), 3, "all 3 failures recorded");
    }

    test_complete!("e2e_hedge_with_first_ok_fallback");
}

// ============================================================================
// 5. Multi-level region tree with cascading cancellation (oracle-driven)
// ============================================================================

/// Cancel root → verify all children and grandchildren properly drained
#[test]
fn e2e_cascading_cancel_deep_region_tree() {
    init_test("e2e_cascading_cancel_deep_region_tree");
    let mut suite = OracleSuite::new();

    // Build 3-level region tree: root → [child_a, child_b] → [grandchild]
    let root = region(0);
    let child_a = region(1);
    let child_b = region(2);
    let grandchild = region(3);

    let worker_a = task(1);
    let worker_b = task(2);
    let worker_gc = task(3);

    test_section!("create-tree");
    suite.region_tree.on_region_create(root, None, t(0));
    suite
        .region_tree
        .on_region_create(child_a, Some(root), t(1));
    suite
        .region_tree
        .on_region_create(child_b, Some(root), t(2));
    suite
        .region_tree
        .on_region_create(grandchild, Some(child_a), t(3));

    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child_a, Some(root));
    suite.quiescence.on_region_create(child_b, Some(root));
    suite.quiescence.on_region_create(grandchild, Some(child_a));

    test_section!("spawn-tasks");
    suite.task_leak.on_spawn(worker_a, child_a, t(10));
    suite.task_leak.on_spawn(worker_b, child_b, t(10));
    suite.task_leak.on_spawn(worker_gc, grandchild, t(10));
    suite.quiescence.on_spawn(worker_a, child_a);
    suite.quiescence.on_spawn(worker_b, child_b);
    suite.quiescence.on_spawn(worker_gc, grandchild);

    test_section!("cancel-root");
    let reason = CancelReason::user("shutdown");
    suite
        .cancellation_protocol
        .on_region_cancel(root, reason, t(50));

    test_section!("drain-and-complete");
    // All tasks complete (cancelled)
    suite.task_leak.on_complete(worker_gc, t(60));
    suite.quiescence.on_task_complete(worker_gc);
    suite.task_leak.on_complete(worker_a, t(65));
    suite.quiescence.on_task_complete(worker_a);
    suite.task_leak.on_complete(worker_b, t(70));
    suite.quiescence.on_task_complete(worker_b);

    test_section!("close-regions-bottom-up");
    suite.quiescence.on_region_close(grandchild, t(75));
    suite.task_leak.on_region_close(grandchild, t(75));
    suite.quiescence.on_region_close(child_a, t(80));
    suite.task_leak.on_region_close(child_a, t(80));
    suite.quiescence.on_region_close(child_b, t(85));
    suite.task_leak.on_region_close(child_b, t(85));
    suite.quiescence.on_region_close(root, t(90));
    suite.task_leak.on_region_close(root, t(90));

    test_section!("verify");
    let violations = suite.check_all(t(100));
    assert_with_log!(
        violations.is_empty(),
        "no violations after cascading cancel",
        "empty",
        violations
    );
    test_complete!("e2e_cascading_cancel_deep_region_tree");
}

// ============================================================================
// 6. Obligation lifecycle through combinator boundary
// ============================================================================

/// Reserve obligation → use across join → commit on success, abort on failure
#[test]
fn e2e_obligation_across_join_boundary() {
    init_test("e2e_obligation_across_join_boundary");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker_1 = task(1);
    let worker_2 = task(2);
    let ob_1 = obligation(0);
    let ob_2 = obligation(1);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);
    suite.task_leak.on_spawn(worker_1, root, t(5));
    suite.task_leak.on_spawn(worker_2, root, t(5));
    suite.quiescence.on_spawn(worker_1, root);
    suite.quiescence.on_spawn(worker_2, root);

    test_section!("reserve-obligations");
    suite
        .obligation_leak
        .on_create(ob_1, ObligationKind::SendPermit, worker_1, root);
    suite
        .obligation_leak
        .on_create(ob_2, ObligationKind::SendPermit, worker_2, root);

    test_section!("join-both-succeed");
    suite
        .obligation_leak
        .on_resolve(ob_1, ObligationState::Committed);
    suite
        .obligation_leak
        .on_resolve(ob_2, ObligationState::Committed);

    suite.task_leak.on_complete(worker_1, t(30));
    suite.task_leak.on_complete(worker_2, t(30));
    suite.quiescence.on_task_complete(worker_1);
    suite.quiescence.on_task_complete(worker_2);

    suite.quiescence.on_region_close(root, t(40));
    suite.task_leak.on_region_close(root, t(40));

    let violations = suite.check_all(t(50));
    assert_with_log!(
        violations.is_empty(),
        "no leaks when both obligations committed",
        "empty",
        violations
    );
    test_complete!("e2e_obligation_across_join_boundary");
}

/// When one arm of a join is cancelled, its obligation must be aborted
#[test]
fn e2e_obligation_abort_on_join_partial_cancel() {
    init_test("e2e_obligation_abort_on_join_partial_cancel");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let child_a = region(1);
    let child_b = region(2);
    let worker_a = task(1);
    let worker_b = task(2);
    let ob_a = obligation(0);
    let ob_b = obligation(1);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite
        .region_tree
        .on_region_create(child_a, Some(root), t(1));
    suite
        .region_tree
        .on_region_create(child_b, Some(root), t(1));
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child_a, Some(root));
    suite.quiescence.on_region_create(child_b, Some(root));

    suite.task_leak.on_spawn(worker_a, child_a, t(5));
    suite.task_leak.on_spawn(worker_b, child_b, t(5));
    suite.quiescence.on_spawn(worker_a, child_a);
    suite.quiescence.on_spawn(worker_b, child_b);

    suite
        .obligation_leak
        .on_create(ob_a, ObligationKind::SendPermit, worker_a, child_a);
    suite
        .obligation_leak
        .on_create(ob_b, ObligationKind::SendPermit, worker_b, child_b);

    test_section!("cancel-child-b");
    let reason = CancelReason::timeout();
    suite
        .cancellation_protocol
        .on_region_cancel(child_b, reason, t(20));

    // Worker A commits normally
    suite
        .obligation_leak
        .on_resolve(ob_a, ObligationState::Committed);
    suite.task_leak.on_complete(worker_a, t(25));
    suite.quiescence.on_task_complete(worker_a);

    // Worker B aborts due to cancellation
    suite
        .obligation_leak
        .on_resolve(ob_b, ObligationState::Aborted);
    suite.task_leak.on_complete(worker_b, t(30));
    suite.quiescence.on_task_complete(worker_b);

    test_section!("close");
    suite.quiescence.on_region_close(child_a, t(35));
    suite.task_leak.on_region_close(child_a, t(35));
    suite.quiescence.on_region_close(child_b, t(40));
    suite.task_leak.on_region_close(child_b, t(40));
    suite.quiescence.on_region_close(root, t(45));
    suite.task_leak.on_region_close(root, t(45));

    let violations = suite.check_all(t(50));
    assert_with_log!(
        violations.is_empty(),
        "no leaks when cancelled arm aborts obligation",
        "empty",
        violations
    );
    test_complete!("e2e_obligation_abort_on_join_partial_cancel");
}

// ============================================================================
// 7. Budget enforcement through region tree
// ============================================================================

/// Budget limits propagate; exhaustion triggers proper cancel protocol
#[test]
fn e2e_budget_enforcement_cancel_protocol() {
    init_test("e2e_budget_enforcement_cancel_protocol");

    test_section!("exhaustion-triggers-cancel");
    {
        let mut oracle = CancellationProtocolOracle::new();
        let root = region(0);
        let child = region(1);
        let worker = task(1);

        oracle.on_region_create(root, None);
        oracle.on_region_create(child, Some(root));
        oracle.on_task_create(worker, child);
        oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(0));

        // Budget exhausted at t=100 → cancel child region
        let reason = CancelReason::deadline().with_message("budget exhausted");
        oracle.on_region_cancel(child, reason.clone(), t(100));
        oracle.on_cancel_request(worker, reason.clone(), t(100));

        // Task drains and completes
        let cleanup = Budget::MINIMAL;
        let cancel_requested = TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        };
        let cancelling = TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        };
        let finalizing = TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        };
        let completed = TaskState::Completed(Outcome::Cancelled(reason));
        oracle.on_transition(worker, &TaskState::Running, &cancel_requested, t(110));
        oracle.on_transition(worker, &cancel_requested, &cancelling, t(115));
        oracle.on_transition(worker, &cancelling, &finalizing, t(120));
        oracle.on_transition(worker, &finalizing, &completed, t(130));

        let violations = oracle.check();
        assert_with_log!(
            violations.is_ok(),
            "budget exhaustion properly cancels",
            "ok",
            violations
        );
    }

    test_complete!("e2e_budget_enforcement_cancel_protocol");
}

// ============================================================================
// 8. Deterministic replay of multi-task scenario
// ============================================================================

/// Run identical lab config twice → verify identical step counts
#[test]
fn e2e_deterministic_replay_multi_task() {
    init_test("e2e_deterministic_replay_multi_task");

    let seed: u64 = 0xCAFE_BABE;
    let task_count: usize = 5;
    let yields_per_task: usize = 3;

    test_section!("run-1");
    let steps_1 = {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicUsize::new(0));

        for _ in 0..task_count {
            let completed = Arc::clone(&completed);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for _ in 0..yields_per_task {
                        yield_now().await;
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
        assert_eq!(
            completed.load(Ordering::SeqCst),
            task_count,
            "all tasks completed"
        );
        runtime.steps()
    };

    test_section!("run-2");
    let steps_2 = {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicUsize::new(0));

        for _ in 0..task_count {
            let completed = Arc::clone(&completed);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for _ in 0..yields_per_task {
                        yield_now().await;
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
        assert_eq!(
            completed.load(Ordering::SeqCst),
            task_count,
            "all tasks completed"
        );
        runtime.steps()
    };

    test_section!("verify-determinism");
    assert_with_log!(
        steps_1 == steps_2,
        "same seed produces same step count",
        steps_1,
        steps_2
    );
    test_complete!(
        "e2e_deterministic_replay_multi_task",
        steps = steps_1,
        seed = seed
    );
}

// ============================================================================
// 9. Severity lattice across nested combinators
// ============================================================================

/// Verify severity ordering: Ok < Err < Cancelled < Panicked across compositions
#[test]
fn e2e_severity_lattice_nested_combinators() {
    init_test("e2e_severity_lattice_nested_combinators");

    test_section!("join-severity-escalation");
    {
        // join(Ok, Err) → Err (worst of the two)
        let (result, _sev_a, _sev_b): (Outcome<(i32, i32), &str>, _, _) =
            join2_outcomes(Outcome::Ok(1), Outcome::Err("fail"));
        assert_outcome_err!(result);
    }

    test_section!("join-cancelled-beats-err");
    {
        let (result, _, _): (Outcome<(i32, i32), &str>, _, _) = join2_outcomes(
            Outcome::Err("fail"),
            Outcome::Cancelled(CancelReason::timeout()),
        );
        assert_outcome_cancelled!(result);
    }

    test_section!("join-panicked-beats-all");
    {
        let (result, _, _): (Outcome<(i32, i32), &str>, _, _) = join2_outcomes(
            Outcome::Cancelled(CancelReason::user("cancel")),
            Outcome::Panicked(PanicPayload::new("boom")),
        );
        assert_outcome_panicked!(result);
    }

    test_section!("join-all-severity");
    {
        // join_all with mixed severities → worst wins
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e"), Outcome::Ok(2)];
        let result = make_join_all_result(outcomes);
        let as_result = join_all_to_result(result);
        assert!(as_result.is_err(), "join_all with any Err → Err");
    }

    test_section!("race-takes-first-ok");
    {
        // race picks the winner; if winner is Ok, returns Ok
        let result = make_race_all_result(
            1, // winner_index = 1 (the Ok(42))
            vec![
                Outcome::<i32, &str>::Err("fail1"),
                Outcome::Ok(42),
                Outcome::Panicked(PanicPayload::new("panic")),
            ],
        );
        let val = result.expect("race should pick Ok(42)");
        assert_eq!(val, 42);
    }

    test_complete!("e2e_severity_lattice_nested_combinators");
}

// ============================================================================
// 10. Quorum degeneracies match join/race
// ============================================================================

/// quorum(N,N) ≃ join_all; quorum(1,N) ≃ race_all in outcome selection
#[test]
fn e2e_quorum_degeneracies_match_primitives() {
    init_test("e2e_quorum_degeneracies_match_primitives");

    test_section!("n-of-n-like-join");
    {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let quorum_result = quorum_outcomes(3, outcomes.clone());
        let join_result = make_join_all_result(outcomes);

        // Both should succeed
        assert!(quorum_result.quorum_met, "3-of-3 met");
        assert!(join_all_to_result(join_result).is_ok(), "join_all ok");
    }

    test_section!("n-of-n-fails-like-join");
    {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("fail"), Outcome::Ok(3)];
        let quorum_result = quorum_outcomes(3, outcomes.clone());
        let join_result = make_join_all_result(outcomes);

        // Both should fail
        assert!(!quorum_result.quorum_met, "3-of-3 not met with 1 failure");
        assert!(join_all_to_result(join_result).is_err(), "join_all fails");
    }

    test_section!("1-of-n-like-race");
    {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("a"), Outcome::Ok(42), Outcome::Err("c")];
        let quorum_result = quorum_outcomes(1, outcomes.clone());
        let race_result = make_race_all_result(1, outcomes); // winner_index=1 (Ok(42))

        // Both should succeed
        assert!(quorum_result.quorum_met, "1-of-3 met");
        assert!(race_result.is_ok(), "race_all ok");
    }

    test_section!("0-of-n-always-met");
    {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("a"), Outcome::Err("b"), Outcome::Err("c")];
        let quorum_result = quorum_outcomes(0, outcomes);
        assert!(quorum_result.quorum_met, "0-of-N always succeeds");
    }

    test_complete!("e2e_quorum_degeneracies_match_primitives");
}

// ============================================================================
// 11. Full lifecycle with finalizers (oracle-driven)
// ============================================================================

/// Create → operate → cancel → drain → finalize → close with finalizer ordering
#[test]
fn e2e_full_lifecycle_with_finalizers() {
    init_test("e2e_full_lifecycle_with_finalizers");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);
    let finalizer_task = task(2);

    test_section!("create");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.region_tree.on_region_create(child, Some(root), t(1));
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child, Some(root));

    test_section!("operate");
    suite.task_leak.on_spawn(worker, child, t(10));
    suite.quiescence.on_spawn(worker, child);

    // Register a finalizer
    suite.task_leak.on_spawn(finalizer_task, child, t(15));
    suite.quiescence.on_spawn(finalizer_task, child);

    test_section!("cancel-and-drain");
    let reason = CancelReason::user("shutdown");
    suite
        .cancellation_protocol
        .on_region_cancel(child, reason, t(50));

    // Worker completes
    suite.task_leak.on_complete(worker, t(60));
    suite.quiescence.on_task_complete(worker);

    test_section!("finalize");
    // Finalizer runs after worker completes
    suite.task_leak.on_complete(finalizer_task, t(70));
    suite.quiescence.on_task_complete(finalizer_task);

    test_section!("close");
    suite.quiescence.on_region_close(child, t(80));
    suite.task_leak.on_region_close(child, t(80));
    suite.quiescence.on_region_close(root, t(90));
    suite.task_leak.on_region_close(root, t(90));

    let violations = suite.check_all(t(100));
    assert_with_log!(
        violations.is_empty(),
        "full lifecycle with finalizers is clean",
        "empty",
        violations
    );
    test_complete!("e2e_full_lifecycle_with_finalizers");
}

// ============================================================================
// 12. Stress: many tasks with lab runtime
// ============================================================================

/// Many concurrent tasks completing without leaks
#[test]
fn e2e_stress_many_tasks_lab_no_leaks() {
    init_test("e2e_stress_many_tasks_lab_no_leaks");

    let task_count: usize = 50;
    let mut runtime = LabRuntime::new(LabConfig::new(0xBEEF).max_steps(50_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let completed = Arc::new(AtomicUsize::new(0));

    test_section!("spawn-tasks");
    for i in 0..task_count {
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                // Each task yields a variable number of times
                for _ in 0..(i % 5) {
                    yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    test_section!("run-to-quiescence");
    runtime.run_until_quiescent();

    test_section!("verify");
    let count = completed.load(Ordering::SeqCst);
    assert_with_log!(
        count == task_count,
        "all tasks completed",
        task_count,
        count
    );

    test_complete!("e2e_stress_many_tasks_lab_no_leaks", tasks = task_count);
}

// ============================================================================
// 13. Race semantics: winner selection
// ============================================================================

/// Race semantics with explicit winner selection
#[test]
fn e2e_race_winner_selection() {
    init_test("e2e_race_winner_selection");

    test_section!("first-wins-ok");
    {
        let result = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Ok(42),
            Outcome::Err("loser"),
        );
        assert_eq!(result.unwrap(), 42);
    }

    test_section!("second-wins-ok");
    {
        let result = race2_to_result(
            RaceWinner::Second,
            Outcome::<i32, &str>::Err("loser"),
            Outcome::Ok(7),
        );
        assert_eq!(result.unwrap(), 7);
    }

    test_section!("winner-is-err");
    {
        let result = race2_to_result(
            RaceWinner::First,
            Outcome::<i32, &str>::Err("winner failed"),
            Outcome::Ok(99),
        );
        assert!(result.is_err(), "winner Err propagates even if loser is Ok");
    }

    test_section!("race-all-winner");
    {
        let result = make_race_all_result(
            2, // winner_index = 2
            vec![
                Outcome::<i32, &str>::Err("a"),
                Outcome::Err("b"),
                Outcome::Ok(100),
            ],
        );
        let val = result.expect("winner at index 2 is Ok");
        assert_eq!(val, 100);
    }

    test_complete!("e2e_race_winner_selection");
}

// ============================================================================
// 14. Cross-combinator: pipeline short-circuit + fallback
// ============================================================================

/// Pipeline fails at stage 2 → fallback via first_ok handles gracefully
#[test]
fn e2e_pipeline_shortcircuit_with_fallback() {
    init_test("e2e_pipeline_shortcircuit_with_fallback");

    test_section!("pipeline-fails-midway");
    let pipeline_result = {
        let stage1: Outcome<i32, &str> = Outcome::Ok(10);
        let stage2: Outcome<i32, &str> = Outcome::Err("validation failed");
        pipeline2_outcomes(stage1, Some(stage2))
    };
    let primary_result = pipeline_to_result(pipeline_result);
    assert!(primary_result.is_err(), "pipeline should fail at stage 2");

    test_section!("fallback-via-first-ok");
    {
        let attempt_1: Outcome<i32, &str> = Outcome::Err("pipeline failed");
        let attempt_2: Outcome<i32, &str> = Outcome::Ok(999);

        let result = first_ok_outcomes(vec![attempt_1, attempt_2]);
        let val = first_ok_to_result(result).expect("fallback should succeed");
        assert_eq!(val, 999, "fallback value used after pipeline failure");
    }

    test_complete!("e2e_pipeline_shortcircuit_with_fallback");
}

// ============================================================================
// 15. Determinism across seeds (different seeds → same logical outcome)
// ============================================================================

/// Different seeds can produce different execution orders but same logical outcomes
#[test]
fn e2e_different_seeds_same_logical_outcome() {
    init_test("e2e_different_seeds_same_logical_outcome");

    let task_count: usize = 10;
    let seeds = [42u64, 123, 9999, 0xDEAD];

    let mut all_completed = Vec::new();

    for &seed in &seeds {
        test_section!(&format!("seed-{seed:#x}"));
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicUsize::new(0));

        for _i in 0..task_count {
            let completed = Arc::clone(&completed);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    yield_now().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
        let count = completed.load(Ordering::SeqCst);
        all_completed.push(count);
    }

    test_section!("verify-all-complete");
    for (i, &count) in all_completed.iter().enumerate() {
        assert_with_log!(
            count == task_count,
            &format!("seed {} all completed", seeds[i]),
            task_count,
            count
        );
    }

    test_complete!("e2e_different_seeds_same_logical_outcome");
}

// ============================================================================
// 16. Cancel reason propagation through region hierarchy
// ============================================================================

/// Cancel reason (timeout, user, deadline) propagates correctly
#[test]
fn e2e_cancel_reason_propagation() {
    init_test("e2e_cancel_reason_propagation");

    test_section!("timeout-reason");
    {
        let reason = CancelReason::timeout();
        assert_with_log!(
            reason.kind() == CancelKind::Timeout,
            "timeout kind",
            "Timeout",
            reason.kind()
        );
        let cleanup = reason.cleanup_budget();
        assert_with_log!(
            cleanup.poll_quota > 0,
            "timeout has cleanup budget",
            true,
            cleanup.poll_quota > 0
        );
    }

    test_section!("user-reason");
    {
        let reason = CancelReason::user("user requested");
        assert_with_log!(
            reason.kind() == CancelKind::User,
            "user kind",
            "User",
            reason.kind()
        );
    }

    test_section!("deadline-reason");
    {
        let reason = CancelReason::deadline().with_message("budget exceeded");
        assert_with_log!(
            reason.kind() == CancelKind::Deadline,
            "deadline kind",
            "Deadline",
            reason.kind()
        );
    }

    test_section!("strengthening");
    {
        // Stronger kind overwrites weaker via strengthen()
        let mut timeout_reason = CancelReason::timeout();
        let user_reason = CancelReason::user("explicit");
        let changed = timeout_reason.strengthen(&user_reason);
        // Timeout > User, so strengthen should not change
        assert_with_log!(!changed, "strengthen ignores weaker", false, changed);
        assert_with_log!(
            timeout_reason.kind() == CancelKind::Timeout,
            "strengthened stays Timeout",
            "Timeout",
            timeout_reason.kind()
        );
    }

    test_complete!("e2e_cancel_reason_propagation");
}

// ============================================================================
// 17. Complex scenario: reservation → split → merge
// ============================================================================

/// Simulate: reserve resources, fan-out to workers, merge results
#[test]
fn e2e_fanout_merge_pattern() {
    init_test("e2e_fanout_merge_pattern");

    test_section!("fanout");
    let worker_outcomes: Vec<Outcome<i32, &str>> = (0..5)
        .map(|i| {
            if i == 3 {
                Outcome::Err("worker 3 failed")
            } else {
                Outcome::Ok(i * 10)
            }
        })
        .collect();

    test_section!("merge-via-quorum");
    {
        // Need 3-of-5 for quorum
        let quorum_result = quorum_outcomes(3, worker_outcomes.clone());
        assert_with_log!(
            quorum_result.quorum_met,
            "3-of-5 quorum met (4 ok, 1 fail)",
            true,
            quorum_result.quorum_met
        );
        assert_eq!(quorum_result.success_count(), 4);
        assert_eq!(quorum_result.failure_count(), 1);
    }

    test_section!("merge-via-join-all");
    {
        // join_all requires ALL → fails because worker 3 failed
        let join_result = make_join_all_result(worker_outcomes);
        let as_result = join_all_to_result(join_result);
        assert!(as_result.is_err(), "join_all fails with any error");
    }

    test_complete!("e2e_fanout_merge_pattern");
}

// ============================================================================
// 18. Hedge: primary fast → no backup needed
// ============================================================================

/// When primary is fast, hedge should not use backup
#[test]
fn e2e_hedge_primary_fast_no_backup() {
    init_test("e2e_hedge_primary_fast_no_backup");

    test_section!("primary-only");
    {
        let primary: Outcome<i32, &str> = Outcome::Ok(1);
        // backup_spawned=false, no backup outcome, no winner
        let result = hedge_outcomes(primary, false, None, None);
        let val = hedge_to_result(result).expect("primary-only should succeed");
        assert_eq!(val, 1);
    }

    test_section!("primary-wins-race");
    {
        let primary: Outcome<i32, &str> = Outcome::Ok(1);
        let backup: Outcome<i32, &str> = Outcome::Ok(2);
        // backup_spawned=true, primary won
        let result = hedge_outcomes(primary, true, Some(backup), Some(HedgeWinner::Primary));
        let val = hedge_to_result(result).expect("should succeed");
        assert_eq!(val, 1, "primary should win when it completes first");
    }

    test_complete!("e2e_hedge_primary_fast_no_backup");
}

// ============================================================================
// 19. Multiple obligation kinds in same region
// ============================================================================

#[test]
fn e2e_multiple_obligation_kinds_same_region() {
    init_test("e2e_multiple_obligation_kinds_same_region");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker = task(1);
    let send_ob = obligation(0);
    let ack_ob = obligation(1);
    let lease_ob = obligation(2);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);
    suite.task_leak.on_spawn(worker, root, t(5));
    suite.quiescence.on_spawn(worker, root);

    test_section!("reserve-multiple");
    suite
        .obligation_leak
        .on_create(send_ob, ObligationKind::SendPermit, worker, root);
    suite
        .obligation_leak
        .on_create(ack_ob, ObligationKind::Ack, worker, root);
    suite
        .obligation_leak
        .on_create(lease_ob, ObligationKind::Lease, worker, root);

    test_section!("resolve-all");
    suite
        .obligation_leak
        .on_resolve(send_ob, ObligationState::Committed);
    suite
        .obligation_leak
        .on_resolve(ack_ob, ObligationState::Committed);
    suite
        .obligation_leak
        .on_resolve(lease_ob, ObligationState::Committed);

    suite.task_leak.on_complete(worker, t(30));
    suite.quiescence.on_task_complete(worker);
    suite.quiescence.on_region_close(root, t(40));
    suite.task_leak.on_region_close(root, t(40));

    let violations = suite.check_all(t(50));
    assert_with_log!(
        violations.is_empty(),
        "no leaks with multiple obligation kinds",
        "empty",
        violations
    );
    test_complete!("e2e_multiple_obligation_kinds_same_region");
}

// ============================================================================
// 20. Same-seed determinism via repeated execution
// ============================================================================

#[test]
fn e2e_deterministic_complex_workload() {
    init_test("e2e_deterministic_complex_workload");

    let make_runtime = || {
        let mut runtime = LabRuntime::new(LabConfig::new(0x1234_5678).max_steps(10_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let counter = Arc::new(AtomicUsize::new(0));

        // Spawn tasks with varied behavior
        for i in 0..8usize {
            let counter = Arc::clone(&counter);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    // Different yield patterns per task
                    for _ in 0..=(i % 4) {
                        yield_now().await;
                    }
                    counter.fetch_add(i + 1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
        (runtime.steps(), counter.load(Ordering::SeqCst))
    };

    test_section!("two-runs");
    let (steps_a, sum_a) = make_runtime();
    let (steps_b, sum_b) = make_runtime();

    assert_with_log!(
        steps_a == steps_b,
        "deterministic step count",
        steps_a,
        steps_b
    );
    assert_with_log!(sum_a == sum_b, "deterministic counter sum", sum_a, sum_b);
    // Sum of 1..=8 = 36
    assert_with_log!(sum_a == 36, "all tasks contributed", 36, sum_a);

    test_complete!("e2e_deterministic_complex_workload");
}
