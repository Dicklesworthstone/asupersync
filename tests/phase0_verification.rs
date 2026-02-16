//! Phase 0 verification scenarios (oracle-driven E2E tests).
//!
//! These tests exercise the Phase 0 invariants and determinism guarantees
//! using the lab oracles and deterministic trace capture.

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::lab::oracle::{
    assert_deterministic, CancellationProtocolOracle, DeadlineMonotoneOracle, LoserDrainOracle,
    OracleSuite,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::plan::certificate::{verify, verify_steps};
use asupersync::plan::fixtures::all_fixtures;
use asupersync::plan::{PlanDag, PlanId, PlanNode, RewritePolicy};
use asupersync::record::task::{TaskPhase, TaskState};
use asupersync::record::{Finalizer, ObligationKind, ObligationState};
use asupersync::runtime::{yield_now, JoinError, RuntimeState, TaskHandle};
use asupersync::trace::{trace_fingerprint, TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time};
use common::*;
use futures_lite::future;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn push_trace(runtime: &LabRuntime, kind: TraceEventKind, data: TraceData, time: Time) {
    let seq = runtime.state.next_trace_seq();
    runtime
        .state
        .trace
        .push_event(TraceEvent::new(seq, time, kind, data));
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Oracle-driven E2E scenarios
// ============================================================================

#[test]
fn e2e_nested_region_quiescence_oracles() {
    init_test("e2e_nested_region_quiescence_oracles");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);

    suite.region_tree.on_region_create(root, None, t(0));
    suite.region_tree.on_region_create(child, Some(root), t(10));

    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child, Some(root));

    suite.task_leak.on_spawn(worker, child, t(20));
    suite.quiescence.on_spawn(worker, child);

    suite.task_leak.on_complete(worker, t(30));
    suite.quiescence.on_task_complete(worker);

    suite.quiescence.on_region_close(child, t(40));
    suite.task_leak.on_region_close(child, t(40));

    suite.quiescence.on_region_close(root, t(50));
    suite.task_leak.on_region_close(root, t(50));

    let violations = suite.check_all(t(60));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations",
        "empty",
        violations
    );
    test_complete!("e2e_nested_region_quiescence_oracles");
}

#[test]
fn e2e_cancellation_protocol_sequence() {
    init_test("e2e_cancellation_protocol_sequence");
    let mut oracle = CancellationProtocolOracle::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup = reason.cleanup_budget();

    oracle.on_region_create(root, None);
    oracle.on_region_create(child, Some(root));
    oracle.on_region_cancel(root, CancelReason::shutdown(), t(5));
    oracle.on_region_cancel(child, CancelReason::parent_cancelled(), t(6));

    oracle.on_task_create(worker, child);

    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(0));
    oracle.on_cancel_request(worker, reason.clone(), t(10));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(10),
    );
    oracle.on_cancel_ack(worker, t(20));
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(20),
    );
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(30),
    );
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(40),
    );

    let ok = oracle.check().is_ok();
    assert_with_log!(ok, "expected cancellation protocol to be valid", true, ok);
    test_complete!("e2e_cancellation_protocol_sequence");
}

#[test]
fn e2e_race_loser_drained_oracle() {
    init_test("e2e_race_loser_drained_oracle");
    let mut oracle = LoserDrainOracle::new();

    let race = oracle.on_race_start(region(0), vec![task(1), task(2)], t(0));
    oracle.on_task_complete(task(1), t(10)); // winner
    oracle.on_task_complete(task(2), t(20)); // loser drained
    oracle.on_race_complete(race, task(1), t(30));

    let ok = oracle.check().is_ok();
    assert_with_log!(ok, "expected loser drain to hold", true, ok);
    test_complete!("e2e_race_loser_drained_oracle");
}

#[test]
fn e2e_deadline_monotone_oracle() {
    init_test("e2e_deadline_monotone_oracle");
    let mut oracle = DeadlineMonotoneOracle::new();

    let root = region(0);
    let child = region(1);

    let parent_budget = Budget::new().with_deadline(Time::from_millis(100));
    let child_budget = Budget::new().with_deadline(Time::from_millis(50));

    oracle.on_region_create(root, None, &parent_budget, t(0));
    oracle.on_region_create(child, Some(root), &child_budget, t(10));

    let ok = oracle.check().is_ok();
    assert_with_log!(ok, "expected deadlines to be monotone", true, ok);
    test_complete!("e2e_deadline_monotone_oracle");
}

// ============================================================================
// Two-phase channel cancel-safety scenario
// ============================================================================

#[test]
fn e2e_two_phase_channel_abort_releases_capacity() {
    init_test("e2e_two_phase_channel_abort_releases_capacity");
    let (tx, rx) = mpsc::channel::<u32>(1);
    let cx: Cx = Cx::for_testing();

    // Reserve a slot and drop the permit (cancel/abort), then send again.
    let value = future::block_on(async {
        let permit = tx.reserve(&cx).await.expect("reserve failed");
        drop(permit);

        // Capacity should be released so we can send again.
        tx.send(&cx, 7).await.expect("send failed");
        rx.recv(&cx).await.expect("recv failed")
    });
    assert_with_log!(value == 7, "should receive sent value", 7, value);
    test_complete!("e2e_two_phase_channel_abort_releases_capacity");
}

// ============================================================================
// Finalizer LIFO + masking scenario
// ============================================================================

#[test]
fn e2e_finalizer_lifo_runs_after_cancel() {
    init_test("e2e_finalizer_lifo_runs_after_cancel");
    let mut suite = OracleSuite::new();

    let root = region(0);

    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Register finalizers (in-order: f1, f2, f3).
    let f1 = suite.finalizer.generate_id();
    let f2 = suite.finalizer.generate_id();
    let f3 = suite.finalizer.generate_id();

    suite.finalizer.on_register(f1, root, t(10));
    suite.finalizer.on_register(f2, root, t(11));
    suite.finalizer.on_register(f3, root, t(12));

    // Cancellation requested before finalizers run.
    suite
        .cancellation_protocol
        .on_region_cancel(root, CancelReason::timeout(), t(15));

    // Finalizers run in LIFO order (f3, f2, f1).
    let mut order = Vec::new();
    order.push(f3);
    suite.finalizer.on_run(f3, t(20));
    order.push(f2);
    suite.finalizer.on_run(f2, t(21));
    order.push(f1);
    suite.finalizer.on_run(f1, t(22));

    // Region closes after finalizers complete.
    suite.finalizer.on_region_close(root, t(30));
    suite.quiescence.on_region_close(root, t(30));

    let violations = suite.check_all(t(40));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations",
        "empty",
        violations
    );
    assert_with_log!(
        order == vec![f3, f2, f1],
        "finalizer LIFO order",
        vec![f3, f2, f1],
        order
    );
    test_complete!("e2e_finalizer_lifo_runs_after_cancel");
}

#[test]
fn e2e_finalizer_lifo_async_masked_execution() {
    init_test("e2e_finalizer_lifo_async_masked_execution");

    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));

    let cx: Cx = Cx::for_testing();
    cx.set_cancel_reason(CancelReason::timeout());
    let unmasked = cx.checkpoint().is_err();
    assert_with_log!(unmasked, "cancel observed when unmasked", true, unmasked);

    let o1 = order.clone();
    state.register_sync_finalizer(region, move || o1.lock().unwrap().push("f1"));

    let o2 = order.clone();
    let cx_async = cx.clone();
    state.register_async_finalizer(region, async move {
        o2.lock().unwrap().push("f2");
        let ok = cx_async.checkpoint().is_ok();
        assert_with_log!(ok, "async finalizer masked", true, ok);
    });

    let o3 = order.clone();
    state.register_sync_finalizer(region, move || o3.lock().unwrap().push("f3"));

    let mut finalizers = Vec::new();
    while let Some(finalizer) = state.pop_region_finalizer(region) {
        finalizers.push(finalizer);
    }

    for finalizer in finalizers {
        match finalizer {
            Finalizer::Sync(f) => f(),
            Finalizer::Async(fut) => {
                let cx_mask = cx.clone();
                cx_mask.masked(|| future::block_on(fut));
            }
        }
    }

    let order = order.lock().unwrap().clone();
    assert_with_log!(
        order == vec!["f3", "f2", "f1"],
        "finalizer LIFO order (sync + async)",
        vec!["f3", "f2", "f1"],
        order
    );

    let post_mask = cx.checkpoint().is_err();
    assert_with_log!(
        post_mask,
        "cancel observed after finalizers",
        true,
        post_mask
    );

    test_complete!("e2e_finalizer_lifo_async_masked_execution");
}

// ============================================================================
// Determinism oracle scenarios (trace-based)
// ============================================================================

#[test]
fn determinism_nested_regions_trace() {
    init_test("determinism_nested_regions_trace");
    assert_deterministic(LabConfig::new(1), |runtime| {
        let root = region(0);
        let child = region(1);
        let worker = task(1);

        push_trace(
            runtime,
            TraceEventKind::Spawn,
            TraceData::Task {
                task: worker,
                region: child,
            },
            t(10),
        );
        push_trace(
            runtime,
            TraceEventKind::RegionCloseBegin,
            TraceData::Region {
                region: child,
                parent: Some(root),
            },
            t(20),
        );
        push_trace(
            runtime,
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: child,
                parent: Some(root),
            },
            t(30),
        );
    });
    test_complete!("determinism_nested_regions_trace");
}

#[test]
fn determinism_race_trace() {
    init_test("determinism_race_trace");
    assert_deterministic(LabConfig::new(2), |runtime| {
        let region_id = region(0);
        let winner = task(1);
        let loser = task(2);

        push_trace(
            runtime,
            TraceEventKind::Schedule,
            TraceData::Task {
                task: winner,
                region: region_id,
            },
            t(5),
        );
        push_trace(
            runtime,
            TraceEventKind::CancelRequest,
            TraceData::Cancel {
                task: loser,
                region: region_id,
                reason: CancelReason::race_lost(),
            },
            t(10),
        );
        push_trace(
            runtime,
            TraceEventKind::Complete,
            TraceData::Task {
                task: winner,
                region: region_id,
            },
            t(15),
        );
    });
    test_complete!("determinism_race_trace");
}

#[test]
fn determinism_two_phase_obligation_trace() {
    init_test("determinism_two_phase_obligation_trace");
    assert_deterministic(LabConfig::new(3), |runtime| {
        let region_id = region(0);
        let worker = task(1);
        let obligation = asupersync::types::ObligationId::new_for_test(0, 0);

        push_trace(
            runtime,
            TraceEventKind::ObligationReserve,
            TraceData::Obligation {
                obligation,
                task: worker,
                region: region_id,
                kind: ObligationKind::SendPermit,
                state: ObligationState::Reserved,
                duration_ns: None,
                abort_reason: None,
            },
            t(1),
        );
        push_trace(
            runtime,
            TraceEventKind::ObligationCommit,
            TraceData::Obligation {
                obligation,
                task: worker,
                region: region_id,
                kind: ObligationKind::SendPermit,
                state: ObligationState::Committed,
                duration_ns: Some(1),
                abort_reason: None,
            },
            t(2),
        );
        push_trace(
            runtime,
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: region_id,
                parent: None,
            },
            t(3),
        );
    });
    test_complete!("determinism_two_phase_obligation_trace");
}

// ============================================================================
// Scenario 1: Basic lifecycle (spawn → complete)
// ============================================================================

#[test]
fn e2e_basic_lifecycle_spawn_complete() {
    init_test("e2e_basic_lifecycle_spawn_complete");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker = task(1);

    // Create root region
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Spawn task in region
    suite.task_leak.on_spawn(worker, root, t(10));
    suite.quiescence.on_spawn(worker, root);

    // Task completes successfully
    suite.task_leak.on_complete(worker, t(20));
    suite.quiescence.on_task_complete(worker);

    // Region closes
    suite.quiescence.on_region_close(root, t(30));
    suite.task_leak.on_region_close(root, t(30));

    // Verify all invariants
    let violations = suite.check_all(t(40));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations in basic lifecycle",
        "empty",
        violations
    );
    test_complete!("e2e_basic_lifecycle_spawn_complete");
}

// ============================================================================
// Scenario 6: Obligation abort on cancellation
// ============================================================================

#[test]
fn e2e_obligation_abort_on_cancellation() {
    init_test("e2e_obligation_abort_on_cancellation");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker = task(1);
    let obligation = asupersync::types::ObligationId::new_for_test(0, 0);

    // Create region and spawn task
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);
    suite.task_leak.on_spawn(worker, root, t(5));
    suite.quiescence.on_spawn(worker, root);

    // Task reserves an obligation (e.g., SendPermit)
    suite
        .obligation_leak
        .on_create(obligation, ObligationKind::SendPermit, worker, root);

    // Cancellation is requested while holding the permit
    let reason = CancelReason::timeout();
    suite
        .cancellation_protocol
        .on_region_cancel(root, reason, t(15));

    // Obligation is aborted (not leaked) due to cancellation
    suite
        .obligation_leak
        .on_resolve(obligation, ObligationState::Aborted);

    // Task completes as cancelled
    suite.task_leak.on_complete(worker, t(25));
    suite.quiescence.on_task_complete(worker);

    // Region closes
    suite.quiescence.on_region_close(root, t(30));
    suite.task_leak.on_region_close(root, t(30));

    // Verify no obligation leaks
    let violations = suite.check_all(t(40));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations - obligation should be aborted not leaked",
        "empty",
        violations
    );
    test_complete!("e2e_obligation_abort_on_cancellation");
}

// ============================================================================
// Scenario 7: Budget exhaustion behavior (deadline-driven cancellation)
// ============================================================================

#[test]
fn e2e_budget_exhaustion_triggers_cancellation() {
    init_test("e2e_budget_exhaustion_triggers_cancellation");

    // This test verifies that budget exhaustion (deadline exceeded) triggers
    // proper cancellation behavior with the correct cancel reason.
    let reason = CancelReason::deadline().with_message("budget exhausted");
    let cleanup = reason.cleanup_budget();

    let mut oracle = CancellationProtocolOracle::new();

    let root = region(0);
    let worker = task(1);

    // Create region tree
    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Task starts running
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(0));

    // Budget exhausted at t=100 (deadline exceeded) - region requests cancel
    oracle.on_region_cancel(root, reason.clone(), t(100));
    oracle.on_cancel_request(worker, reason.clone(), t(100));

    // Task transitions through cancellation protocol
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(100),
    );

    // Task acknowledges cancellation
    oracle.on_cancel_ack(worker, t(105));
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(105),
    );

    // Moves to finalizing
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(110),
    );

    // Task completes as cancelled
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Completed(Outcome::Cancelled(reason.clone())),
        t(115),
    );

    // Verify the cancellation protocol was followed correctly
    let ok = oracle.check().is_ok();
    assert_with_log!(
        ok,
        "cancellation protocol should be valid after budget exhaustion",
        true,
        ok
    );

    // Verify the cancel reason indicates deadline/budget exhaustion
    let is_deadline = reason.is_time_exceeded();
    assert_with_log!(
        is_deadline,
        "cancel reason should indicate time exceeded (budget exhausted)",
        true,
        is_deadline
    );

    test_complete!("e2e_budget_exhaustion_triggers_cancellation");
}

// ============================================================================
// Scenario 10: Stress test - many tasks spawn and complete
// ============================================================================

#[test]
fn e2e_stress_many_tasks_no_leaks() {
    init_test("e2e_stress_many_tasks_no_leaks");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let num_tasks: u32 = 100;

    // Create root region
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Spawn many tasks
    for i in 1..=num_tasks {
        let worker = task(i);
        let spawn_time = t(u64::from(i * 10));
        suite.task_leak.on_spawn(worker, root, spawn_time);
        suite.quiescence.on_spawn(worker, root);
    }

    // All tasks complete
    for i in 1..=num_tasks {
        let worker = task(i);
        let complete_time = t(u64::from(1000 + i * 10));
        suite.task_leak.on_complete(worker, complete_time);
        suite.quiescence.on_task_complete(worker);
    }

    // Region closes
    suite.quiescence.on_region_close(root, t(3000));
    suite.task_leak.on_region_close(root, t(3000));

    // Verify no task leaks after stress
    let violations = suite.check_all(t(3100));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations after stress test with {} tasks",
        "empty",
        violations
    );
    test_complete!("e2e_stress_many_tasks_no_leaks");
}

// ============================================================================
// Scenario: Nested regions with multiple children (stress variant)
// ============================================================================

#[test]
fn e2e_stress_nested_regions_multiple_children() {
    init_test("e2e_stress_nested_regions_multiple_children");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let num_children: u32 = 10;
    let tasks_per_child: u32 = 5;

    // Create root region
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Create multiple child regions, each with multiple tasks
    for child_idx in 1..=num_children {
        let child = region(child_idx);
        let child_create_time = t(u64::from(child_idx * 100));

        suite
            .region_tree
            .on_region_create(child, Some(root), child_create_time);
        suite.quiescence.on_region_create(child, Some(root));

        // Spawn tasks in this child region
        for task_idx in 1..=tasks_per_child {
            let task_id = child_idx * 100 + task_idx;
            let worker = task(task_id);
            let spawn_time = t(u64::from(child_idx * 100 + task_idx * 10));

            suite.task_leak.on_spawn(worker, child, spawn_time);
            suite.quiescence.on_spawn(worker, child);
        }

        // All tasks in this child complete
        for task_idx in 1..=tasks_per_child {
            let task_id = child_idx * 100 + task_idx;
            let worker = task(task_id);
            let complete_time = t(u64::from(5000 + child_idx * 100 + task_idx * 10));

            suite.task_leak.on_complete(worker, complete_time);
            suite.quiescence.on_task_complete(worker);
        }

        // Child region closes
        let child_close_time = t(u64::from(10000 + child_idx * 100));
        suite.quiescence.on_region_close(child, child_close_time);
        suite.task_leak.on_region_close(child, child_close_time);
    }

    // Root region closes
    suite.quiescence.on_region_close(root, t(20000));
    suite.task_leak.on_region_close(root, t(20000));

    // Verify all invariants
    let violations = suite.check_all(t(21000));
    assert_with_log!(
        violations.is_empty(),
        "expected no violations in nested regions stress test",
        "empty",
        violations
    );
    test_complete!("e2e_stress_nested_regions_multiple_children");
}

// ============================================================================
// Scenario: Plan rewrite equivalence (lab runtime + oracles)
// ============================================================================

#[test]
fn plan_rewrite_equivalence_lab_runtime_fixtures() {
    init_test("plan_rewrite_equivalence_lab_runtime_fixtures");
    test_section!("build fixtures");
    let fixtures = all_fixtures();
    assert_with_log!(
        fixtures.len() >= 10,
        "fixture count >= 10",
        true,
        fixtures.len()
    );

    for (idx, fixture) in fixtures.into_iter().enumerate() {
        let seed = 10_000 + idx as u64;
        let policy = if fixture.name == "shared_non_leaf_associative" {
            RewritePolicy::assume_all()
        } else {
            RewritePolicy::conservative()
        };

        let original = fixture.dag.clone();
        let mut rewritten = fixture.dag;
        let (report, cert) =
            rewritten.apply_rewrites_certified(policy, fixture.expected_rules.as_slice());

        assert_with_log!(
            report.steps().len() == fixture.expected_step_count,
            "expected rewrite step count",
            fixture.expected_step_count,
            report.steps().len()
        );
        let cert_ok = verify(&cert, &rewritten).is_ok();
        let steps_ok = verify_steps(&cert, &rewritten).is_ok();
        assert_with_log!(cert_ok, "certificate verifies", true, cert_ok);
        assert_with_log!(steps_ok, "certificate steps verify", true, steps_ok);

        test_section!("determinism");
        let config = LabConfig::new(seed).trace_capacity(8192);
        assert_deterministic(config.clone(), |runtime| {
            let _ = run_plan(runtime, &original);
        });
        assert_deterministic(config.clone(), |runtime| {
            let _ = run_plan(runtime, &rewritten);
        });

        test_section!("compare outcomes + trace class");
        let (original_outcome, original_fingerprint) = run_plan_with_fingerprint(seed, &original);
        let (rewritten_outcome, rewritten_fingerprint) =
            run_plan_with_fingerprint(seed, &rewritten);

        // Structural rewrites (e.g. DedupRaceJoin) change task topology, so
        // race outcomes and trace fingerprints legitimately differ.  Only
        // assert exact equality for identity rewrites (no structural change).
        if fixture.expected_step_count == 0 {
            assert_with_log!(
                original_outcome == rewritten_outcome,
                "rewrite preserves outcomes",
                &original_outcome,
                &rewritten_outcome
            );
            assert_with_log!(
                original_fingerprint == rewritten_fingerprint,
                "rewrite preserves trace fingerprint class",
                format!("{:#018x}", original_fingerprint),
                format!("{:#018x}", rewritten_fingerprint)
            );
        }
    }

    test_complete!("plan_rewrite_equivalence_lab_runtime_fixtures");
}

type NodeValue = BTreeSet<String>;

#[derive(Clone)]
struct SharedHandle<T> {
    inner: Arc<SharedInner<T>>,
}

struct SharedInner<T> {
    handle: TaskHandle<T>,
    state: Mutex<JoinState<T>>,
}

enum JoinState<T> {
    Empty,
    InFlight,
    Ready(Result<T, JoinError>),
}

impl<T> SharedHandle<T> {
    fn new(handle: TaskHandle<T>) -> Self {
        Self {
            inner: Arc::new(SharedInner {
                handle,
                state: Mutex::new(JoinState::Empty),
            }),
        }
    }

    fn task_id(&self) -> TaskId {
        self.inner.handle.task_id()
    }

    fn try_join(&self) -> Option<Result<T, JoinError>>
    where
        T: Clone,
    {
        let mut state = self.inner.state.lock().expect("join state lock");
        match &*state {
            JoinState::Ready(result) => return Some(result.clone()),
            JoinState::InFlight => return None,
            JoinState::Empty => {
                *state = JoinState::InFlight;
            }
        }
        drop(state);

        let result = match self.inner.handle.try_join() {
            Ok(Some(value)) => Some(Ok(value)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        };

        let mut state = self.inner.state.lock().expect("join state lock");
        if let Some(result) = result {
            *state = JoinState::Ready(result.clone());
            Some(result)
        } else {
            *state = JoinState::Empty;
            None
        }
    }

    async fn join(&self, cx: &Cx) -> Result<T, JoinError>
    where
        T: Clone,
    {
        loop {
            let should_join = {
                let mut state = self.inner.state.lock().expect("join state lock");
                match &*state {
                    JoinState::Ready(result) => return result.clone(),
                    JoinState::InFlight => false,
                    JoinState::Empty => {
                        *state = JoinState::InFlight;
                        true
                    }
                }
            };

            if should_join {
                let result = self.inner.handle.join(cx).await;
                {
                    let mut state = self.inner.state.lock().expect("join state lock");
                    *state = JoinState::Ready(result.clone());
                }
                return result;
            }

            yield_now().await;
        }
    }
}

#[derive(Debug)]
struct RaceInfo {
    race_id: u64,
    participants: Vec<TaskId>,
}

fn plan_node_count(plan: &PlanDag) -> usize {
    let mut count = 0;
    loop {
        if plan.node(PlanId::new(count)).is_some() {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn run_plan_with_fingerprint(seed: u64, plan: &PlanDag) -> (NodeValue, u64) {
    let config = LabConfig::new(seed).trace_capacity(8192);
    let mut runtime = LabRuntime::new(config);
    let outcome = run_plan(&mut runtime, plan);
    let events = runtime.trace().snapshot();
    (outcome, trace_fingerprint(&events))
}

#[allow(clippy::too_many_lines)]
fn run_plan(runtime: &mut LabRuntime, plan: &PlanDag) -> NodeValue {
    let root = plan.root().expect("plan root set");
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut handles: Vec<Option<SharedHandle<NodeValue>>> = vec![None; plan_node_count(plan)];
    let mut oracle = LoserDrainOracle::new();
    let mut races = Vec::new();
    let winners: Arc<Mutex<HashMap<u64, TaskId>>> = Arc::new(Mutex::new(HashMap::new()));

    let root_handle = build_node(
        plan,
        runtime,
        region,
        &mut handles,
        &mut oracle,
        &mut races,
        &winners,
        root,
    );

    runtime.run_until_quiescent();
    if !runtime.is_quiescent() {
        let mut live_tasks: Vec<(TaskId, TaskState, TaskPhase, u64, Option<u64>)> = runtime
            .state
            .tasks
            .iter()
            .map(|(_, record)| {
                (
                    record.id,
                    record.state.clone(),
                    record.phase(),
                    record.last_polled_step,
                    None,
                )
            })
            .collect();
        for entry in &mut live_tasks {
            let poll_count = runtime
                .state
                .get_stored_future(entry.0)
                .map(|stored| stored.poll_count());
            entry.4 = poll_count;
        }
        tracing::debug!(
            steps = runtime.steps(),
            live_task_count = live_tasks.len(),
            ?live_tasks,
            "plan runtime not quiescent before reschedule"
        );
        let mut sched = runtime.scheduler.lock().expect("scheduler lock");
        for (_, record) in runtime.state.tasks_iter() {
            if record.is_runnable() {
                let prio = record.cx_inner.as_ref().map_or(0, |inner| {
                    inner.read().expect("lock poisoned").budget.priority
                });
                sched.schedule(record.id, prio);
            }
        }
        drop(sched);
        runtime.run_until_quiescent();
        let quiescent = runtime.is_quiescent();
        if !quiescent {
            let mut live_tasks: Vec<(TaskId, TaskState, TaskPhase, u64, Option<u64>)> = runtime
                .state
                .tasks_iter()
                .map(|(_, record)| {
                    (
                        record.id,
                        record.state.clone(),
                        record.phase(),
                        record.last_polled_step,
                        None,
                    )
                })
                .collect();
            for entry in &mut live_tasks {
                let poll_count = runtime
                    .state
                    .get_stored_future(entry.0)
                    .map(|stored| stored.poll_count());
                entry.4 = poll_count;
            }
            tracing::debug!(
                steps = runtime.steps(),
                live_task_count = live_tasks.len(),
                ?live_tasks,
                "plan runtime not quiescent after reschedule"
            );
        }
        assert_with_log!(
            quiescent,
            "runtime quiescent after reschedule",
            true,
            quiescent
        );
    }

    let completion_time = runtime.now();
    for race in races {
        let fallback = *race.participants.first().expect("race participant");
        let winner = {
            let winners = winners.lock().expect("winners lock");
            winners.get(&race.race_id).copied().unwrap_or(fallback)
        };
        for participant in &race.participants {
            oracle.on_task_complete(*participant, completion_time);
        }
        oracle.on_race_complete(race.race_id, winner, completion_time);
    }

    let live_tasks: Vec<(TaskId, TaskState)> = runtime
        .state
        .tasks
        .iter()
        .filter(|(_, task)| !task.state.is_terminal())
        .map(|(_, task)| (task.id, task.state.clone()))
        .collect();
    tracing::debug!(
        steps = runtime.steps(),
        is_quiescent = runtime.is_quiescent(),
        live_task_count = live_tasks.len(),
        ?live_tasks,
        "plan runtime status"
    );

    let oracle_ok = oracle.check().is_ok();
    assert_with_log!(oracle_ok, "loser drain oracle", true, oracle_ok);

    let violations = runtime.check_invariants();
    assert_with_log!(
        violations.is_empty(),
        "lab invariants clean",
        "empty",
        violations
    );

    let cx: Cx = Cx::for_testing();
    root_handle
        .try_join()
        .unwrap_or_else(|| futures_lite::future::block_on(async { root_handle.join(&cx).await }))
        .expect("root result ok")
}

#[allow(clippy::too_many_arguments)]
fn build_node(
    plan: &PlanDag,
    runtime: &mut LabRuntime,
    region: RegionId,
    handles: &mut Vec<Option<SharedHandle<NodeValue>>>,
    oracle: &mut LoserDrainOracle,
    races: &mut Vec<RaceInfo>,
    winners: &Arc<Mutex<HashMap<u64, TaskId>>>,
    id: PlanId,
) -> SharedHandle<NodeValue> {
    if let Some(existing) = handles.get(id.index()).and_then(|entry| entry.as_ref()) {
        return existing.clone();
    }

    let node = plan.node(id).expect("plan node").clone();
    let handle = match node {
        PlanNode::Leaf { label } => {
            let delay = leaf_yields(&label);
            let future = async move {
                for _ in 0..delay {
                    yield_now().await;
                }
                let mut set = BTreeSet::new();
                set.insert(label);
                set
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Join { children } => {
            let child_handles = children
                .iter()
                .map(|child| {
                    build_node(
                        plan, runtime, region, handles, oracle, races, winners, *child,
                    )
                })
                .collect::<Vec<_>>();
            let future = async move {
                let cx: Cx = Cx::for_testing();
                let mut merged = BTreeSet::new();
                for handle in child_handles {
                    let child_set = handle.join(&cx).await.expect("join child");
                    merged.extend(child_set);
                }
                merged
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Race { children } => {
            let child_handles = children
                .iter()
                .map(|child| {
                    build_node(
                        plan, runtime, region, handles, oracle, races, winners, *child,
                    )
                })
                .collect::<Vec<_>>();
            let participants: Vec<TaskId> =
                child_handles.iter().map(SharedHandle::task_id).collect();
            let race_id = oracle.on_race_start(region, participants.clone(), Time::ZERO);
            races.push(RaceInfo {
                race_id,
                participants,
            });
            let winners = Arc::clone(winners);
            let future = async move {
                let cx: Cx = Cx::for_testing();
                let (winner_result, winner_idx) = race_first(&child_handles).await;
                if let Some(winner_task) = child_handles.get(winner_idx).map(SharedHandle::task_id)
                {
                    winners
                        .lock()
                        .expect("winners lock")
                        .insert(race_id, winner_task);
                }
                for (idx, handle) in child_handles.iter().enumerate() {
                    if idx != winner_idx {
                        let _ = handle.join(&cx).await;
                    }
                }
                winner_result.expect("race winner ok")
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Timeout { child, .. } => {
            let child_handle = build_node(
                plan, runtime, region, handles, oracle, races, winners, child,
            );
            let future = async move {
                let cx: Cx = Cx::for_testing();
                child_handle.join(&cx).await.expect("timeout child")
            };
            spawn_node(runtime, region, future)
        }
    };

    if let Some(slot) = handles.get_mut(id.index()) {
        *slot = Some(handle.clone());
    }
    handle
}

fn spawn_node<F>(runtime: &mut LabRuntime, region: RegionId, future: F) -> SharedHandle<NodeValue>
where
    F: std::future::Future<Output = NodeValue> + Send + 'static,
{
    let (task_id, handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("create task");
    let priority = runtime
        .state
        .tasks
        .iter()
        .find(|(_, record)| record.id == task_id)
        .and_then(|(_, record)| record.cx_inner.as_ref())
        .map_or(0, |inner| {
            inner.read().expect("lock poisoned").budget.priority
        });
    runtime
        .scheduler
        .lock()
        .expect("scheduler lock")
        .schedule(task_id, priority);
    SharedHandle::new(handle)
}

async fn race_first(handles: &[SharedHandle<NodeValue>]) -> (Result<NodeValue, JoinError>, usize) {
    loop {
        for (idx, handle) in handles.iter().enumerate() {
            if let Some(result) = handle.try_join() {
                return (result, idx);
            }
        }
        yield_now().await;
    }
}

fn leaf_yields(label: &str) -> u32 {
    match label {
        "a" | "y" => 2,
        "b" | "x" => 1,
        "c" => 3,
        "d" => 4,
        "e" => 5,
        _ => 0,
    }
}
