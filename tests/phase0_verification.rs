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
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn push_trace(runtime: &mut LabRuntime, kind: TraceEventKind, data: TraceData, time: Time) {
    let seq = runtime.state.next_trace_seq();
    runtime
        .state
        .trace
        .push(TraceEvent::new(seq, time, kind, data));
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
    let cx = Cx::for_testing();

    // Reserve a slot and drop the permit (cancel/abort).
    let permit = tx.reserve(&cx).expect("reserve failed");
    drop(permit);

    // Capacity should be released so we can send again.
    tx.send(&cx, 7).expect("send failed");
    let value = rx.recv(&cx).expect("recv failed");
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
    suite.cancellation_protocol.on_region_cancel(root, reason.clone(), t(15));

    // Obligation is aborted (not leaked) due to cancellation
    suite.obligation_leak.on_resolve(obligation, ObligationState::Aborted);

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
// Scenario 10: Stress test - many tasks spawn and complete
// ============================================================================

#[test]
fn e2e_stress_many_tasks_no_leaks() {
    init_test("e2e_stress_many_tasks_no_leaks");
    let mut suite = OracleSuite::new();

    let root = region(0);
    let num_tasks = 100;

    // Create root region
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Spawn many tasks
    for i in 1..=num_tasks {
        let worker = task(i);
        let spawn_time = t((i * 10) as u64);
        suite.task_leak.on_spawn(worker, root, spawn_time);
        suite.quiescence.on_spawn(worker, root);
    }

    // All tasks complete
    for i in 1..=num_tasks {
        let worker = task(i);
        let complete_time = t((1000 + i * 10) as u64);
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
    let num_children = 10;
    let tasks_per_child = 5;

    // Create root region
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);

    // Create multiple child regions, each with multiple tasks
    for child_idx in 1..=num_children {
        let child = region(child_idx);
        let child_create_time = t((child_idx * 100) as u64);

        suite
            .region_tree
            .on_region_create(child, Some(root), child_create_time);
        suite.quiescence.on_region_create(child, Some(root));

        // Spawn tasks in this child region
        for task_idx in 1..=tasks_per_child {
            let task_id = (child_idx * 100 + task_idx) as u32;
            let worker = task(task_id);
            let spawn_time = t((child_idx * 100 + task_idx * 10) as u64);

            suite.task_leak.on_spawn(worker, child, spawn_time);
            suite.quiescence.on_spawn(worker, child);
        }

        // All tasks in this child complete
        for task_idx in 1..=tasks_per_child {
            let task_id = (child_idx * 100 + task_idx) as u32;
            let worker = task(task_id);
            let complete_time = t((5000 + child_idx * 100 + task_idx * 10) as u64);

            suite.task_leak.on_complete(worker, complete_time);
            suite.quiescence.on_task_complete(worker);
        }

        // Child region closes
        let child_close_time = t((10000 + child_idx * 100) as u64);
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
