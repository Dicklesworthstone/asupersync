//! Combined cancellation + obligation invariant tests (bd-38kk).
//!
//! These tests exercise the interaction between cancellation protocol,
//! obligation lifecycle, quiescence, and loser drain invariants using
//! oracle-based verification.
//!
//! # Invariants Under Test
//!
//! 1. Cancellation protocol: request → drain → finalize (Spec 3.1)
//! 2. Region close = quiescence: no live children + all obligations resolved
//! 3. No obligation leaks: permits/acks/leases must be committed or aborted
//! 4. Losers are drained: race losers with obligations are properly cleaned up
//! 5. Combined: OracleSuite detects cross-cutting violations

#[macro_use]
mod common;

use asupersync::lab::oracle::{
    CancellationProtocolOracle, LoserDrainOracle, ObligationLeakOracle, OracleSuite,
    QuiescenceOracle,
};
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::types::{Budget, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Cancellation + Obligation: Obligations aborted on cancel
// ============================================================================

/// When a task is cancelled, any pending obligations it holds must be aborted
/// (not leaked). Verifies that obligation leak oracle is clean after proper abort.
#[test]
fn cancel_with_obligation_abort_is_clean() {
    init_test("cancel_with_obligation_abort_is_clean");

    let mut cancel_oracle = CancellationProtocolOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    // Setup region and task
    cancel_oracle.on_region_create(root, None);
    cancel_oracle.on_task_create(worker, root);

    // Task starts running and acquires an obligation
    cancel_oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    obligation_oracle.on_create(obl, ObligationKind::SendPermit, worker, root);

    // Cancel is requested
    cancel_oracle.on_cancel_request(worker, reason.clone(), t(50));
    cancel_oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );

    // During drain phase, obligation is aborted (proper cleanup)
    cancel_oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(100),
    );
    obligation_oracle.on_resolve(obl, ObligationState::Aborted);

    // Finalize and complete
    cancel_oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(150),
    );
    cancel_oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    // Region closes
    obligation_oracle.on_region_close(root, t(250));

    // Both oracles should be clean
    let cancel_ok = cancel_oracle.check().is_ok();
    assert_with_log!(cancel_ok, "cancel protocol valid", true, cancel_ok);

    let obligation_ok = obligation_oracle.check(t(250)).is_ok();
    assert_with_log!(obligation_ok, "no obligation leaks", true, obligation_ok);

    test_complete!("cancel_with_obligation_abort_is_clean");
}

/// When a task is cancelled but does NOT resolve its obligations,
/// the obligation leak oracle must detect the leak.
#[test]
fn cancel_without_obligation_resolve_detects_leak() {
    init_test("cancel_without_obligation_resolve_detects_leak");

    let mut cancel_oracle = CancellationProtocolOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    cancel_oracle.on_region_create(root, None);
    cancel_oracle.on_task_create(worker, root);

    // Task runs, acquires obligation
    cancel_oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    obligation_oracle.on_create(obl, ObligationKind::Lease, worker, root);

    // Cancel protocol completes, but obligation is NOT resolved
    cancel_oracle.on_cancel_request(worker, reason.clone(), t(50));
    cancel_oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    cancel_oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(100),
    );
    // NOTE: obligation NOT aborted here — this is the bug scenario
    cancel_oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(150),
    );
    cancel_oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    // Region closes with unresolved obligation
    obligation_oracle.on_region_close(root, t(250));

    // Cancel protocol itself is valid
    let cancel_ok = cancel_oracle.check().is_ok();
    assert_with_log!(cancel_ok, "cancel protocol valid", true, cancel_ok);

    // But obligation oracle detects the leak
    let obligation_result = obligation_oracle.check(t(250));
    let is_leak = obligation_result.is_err();
    assert_with_log!(is_leak, "obligation leak detected", true, is_leak);

    if let Err(violation) = obligation_result {
        let leaked_count = violation.leaked.len();
        assert_with_log!(leaked_count == 1, "one obligation leaked", 1, leaked_count);
        let leaked_kind = violation.leaked[0].kind;
        assert_with_log!(
            leaked_kind == ObligationKind::Lease,
            "leaked kind is Lease",
            ObligationKind::Lease,
            leaked_kind
        );
    }

    test_complete!("cancel_without_obligation_resolve_detects_leak");
}

// ============================================================================
// Multiple obligations during cancellation
// ============================================================================

/// Task with multiple obligations: all must be resolved during cancel drain.
#[test]
fn cancel_multiple_obligations_all_resolved() {
    init_test("cancel_multiple_obligations_all_resolved");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl_send = obligation(10);
    let obl_ack = obligation(11);
    let obl_lease = obligation(12);

    // Create three obligations
    obligation_oracle.on_create(obl_send, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_ack, ObligationKind::Ack, worker, root);
    obligation_oracle.on_create(obl_lease, ObligationKind::Lease, worker, root);

    // During cancellation drain, resolve all: commit some, abort others
    obligation_oracle.on_resolve(obl_send, ObligationState::Aborted); // cancel → abort
    obligation_oracle.on_resolve(obl_ack, ObligationState::Aborted); // cancel → abort
    obligation_oracle.on_resolve(obl_lease, ObligationState::Committed); // finish in-progress lease

    // Region close
    obligation_oracle.on_region_close(root, t(200));

    let result = obligation_oracle.check(t(200));
    let ok = result.is_ok();
    assert_with_log!(ok, "all obligations resolved", true, ok);

    test_complete!("cancel_multiple_obligations_all_resolved");
}

/// Task with multiple obligations: partial resolution leaves leaks.
#[test]
fn cancel_partial_obligation_resolution_detects_leak() {
    init_test("cancel_partial_obligation_resolution_detects_leak");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl_send = obligation(10);
    let obl_ack = obligation(11);
    let obl_io = obligation(12);

    obligation_oracle.on_create(obl_send, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_ack, ObligationKind::Ack, worker, root);
    obligation_oracle.on_create(obl_io, ObligationKind::IoOp, worker, root);

    // Only resolve two of three
    obligation_oracle.on_resolve(obl_send, ObligationState::Aborted);
    obligation_oracle.on_resolve(obl_ack, ObligationState::Committed);
    // obl_io NOT resolved

    obligation_oracle.on_region_close(root, t(200));

    let result = obligation_oracle.check(t(200));
    let is_err = result.is_err();
    assert_with_log!(is_err, "leak detected", true, is_err);

    if let Err(violation) = result {
        let leaked_count = violation.leaked.len();
        assert_with_log!(leaked_count == 1, "one leaked", 1, leaked_count);
        let leaked_obl = violation.leaked[0].obligation;
        assert_with_log!(leaked_obl == obl_io, "leaked obl_io", obl_io, leaked_obl);
    }

    test_complete!("cancel_partial_obligation_resolution_detects_leak");
}

// ============================================================================
// Region close + quiescence + obligations
// ============================================================================

/// Region close requires both task completion AND obligation resolution.
/// This test verifies that quiescence and obligation oracles together
/// catch the case where tasks complete but obligations don't.
#[test]
fn region_close_requires_obligation_resolution() {
    init_test("region_close_requires_obligation_resolution");

    let mut quiescence = QuiescenceOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);

    // Setup
    quiescence.on_region_create(root, None);
    quiescence.on_spawn(worker, root);
    obligation_oracle.on_create(obl, ObligationKind::SendPermit, worker, root);

    // Task completes (quiescence satisfied for tasks)
    quiescence.on_task_complete(worker);
    quiescence.on_region_close(root, t(100));

    // Quiescence oracle passes (task completed)
    let quiescence_ok = quiescence.check().is_ok();
    assert_with_log!(quiescence_ok, "quiescence satisfied", true, quiescence_ok);

    // But obligation oracle catches the leak
    obligation_oracle.on_region_close(root, t(100));
    let obligation_result = obligation_oracle.check(t(100));
    let is_leak = obligation_result.is_err();
    assert_with_log!(is_leak, "obligation leak detected", true, is_leak);

    test_complete!("region_close_requires_obligation_resolution");
}

/// Region close with both tasks completed and obligations resolved is clean.
#[test]
fn region_close_clean_with_obligations_resolved() {
    init_test("region_close_clean_with_obligations_resolved");

    let mut quiescence = QuiescenceOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let child = region(1);
    let worker1 = task(1);
    let worker2 = task(2);
    let obl1 = obligation(10);
    let obl2 = obligation(11);

    // Setup nested region with tasks and obligations
    quiescence.on_region_create(root, None);
    quiescence.on_region_create(child, Some(root));
    quiescence.on_spawn(worker1, root);
    quiescence.on_spawn(worker2, child);
    obligation_oracle.on_create(obl1, ObligationKind::Ack, worker1, root);
    obligation_oracle.on_create(obl2, ObligationKind::Lease, worker2, child);

    // Resolve everything properly: inner first, then outer
    obligation_oracle.on_resolve(obl2, ObligationState::Committed);
    quiescence.on_task_complete(worker2);
    quiescence.on_region_close(child, t(50));
    obligation_oracle.on_region_close(child, t(50));

    obligation_oracle.on_resolve(obl1, ObligationState::Committed);
    quiescence.on_task_complete(worker1);
    quiescence.on_region_close(root, t(100));
    obligation_oracle.on_region_close(root, t(100));

    // Both oracles clean
    let quiescence_ok = quiescence.check().is_ok();
    assert_with_log!(quiescence_ok, "quiescence ok", true, quiescence_ok);

    let obligation_ok = obligation_oracle.check(t(100)).is_ok();
    assert_with_log!(obligation_ok, "obligation ok", true, obligation_ok);

    test_complete!("region_close_clean_with_obligations_resolved");
}

// ============================================================================
// Race losers + obligations
// ============================================================================

/// Race loser with obligations: loser drained and obligations aborted.
#[test]
fn race_loser_obligations_aborted_on_drain() {
    init_test("race_loser_obligations_aborted_on_drain");

    let mut loser_drain = LoserDrainOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let winner = task(1);
    let loser = task(2);
    let obl_winner = obligation(10);
    let obl_loser = obligation(11);

    // Both tasks have obligations
    obligation_oracle.on_create(obl_winner, ObligationKind::SendPermit, winner, root);
    obligation_oracle.on_create(obl_loser, ObligationKind::Ack, loser, root);

    // Race starts
    let race_id = loser_drain.on_race_start(root, vec![winner, loser], t(0));

    // Winner completes, committing its obligation
    obligation_oracle.on_resolve(obl_winner, ObligationState::Committed);
    loser_drain.on_task_complete(winner, t(50));

    // Loser is cancelled and drained, aborting its obligation
    obligation_oracle.on_resolve(obl_loser, ObligationState::Aborted);
    loser_drain.on_task_complete(loser, t(80));

    // Race completes
    loser_drain.on_race_complete(race_id, winner, t(100));

    // Region closes
    obligation_oracle.on_region_close(root, t(150));

    // Both oracles clean
    let drain_ok = loser_drain.check().is_ok();
    assert_with_log!(drain_ok, "losers drained", true, drain_ok);

    let obligation_ok = obligation_oracle.check(t(150)).is_ok();
    assert_with_log!(obligation_ok, "no obligation leaks", true, obligation_ok);

    test_complete!("race_loser_obligations_aborted_on_drain");
}

/// Race loser with obligations: loser drained but obligation NOT resolved → leak.
#[test]
fn race_loser_obligation_leak_detected() {
    init_test("race_loser_obligation_leak_detected");

    let mut loser_drain = LoserDrainOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let winner = task(1);
    let loser = task(2);
    let obl_loser = obligation(11);

    // Loser has an obligation
    obligation_oracle.on_create(obl_loser, ObligationKind::IoOp, loser, root);

    let race_id = loser_drain.on_race_start(root, vec![winner, loser], t(0));

    // Winner completes
    loser_drain.on_task_complete(winner, t(50));

    // Loser "completes" (drain finishes) but obligation NOT resolved
    loser_drain.on_task_complete(loser, t(80));

    loser_drain.on_race_complete(race_id, winner, t(100));

    obligation_oracle.on_region_close(root, t(150));

    // Loser drain passes (task completed)
    let drain_ok = loser_drain.check().is_ok();
    assert_with_log!(drain_ok, "losers drained", true, drain_ok);

    // But obligation oracle detects the leak
    let obligation_result = obligation_oracle.check(t(150));
    let is_leak = obligation_result.is_err();
    assert_with_log!(is_leak, "obligation leak detected", true, is_leak);

    test_complete!("race_loser_obligation_leak_detected");
}

/// Three-way race with obligations: all losers drain, all obligations resolved.
#[test]
fn three_way_race_obligations_fully_resolved() {
    init_test("three_way_race_obligations_fully_resolved");

    let mut loser_drain = LoserDrainOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let t1 = task(1);
    let t2 = task(2);
    let t3 = task(3);
    let o1 = obligation(10);
    let o2 = obligation(11);
    let o3 = obligation(12);

    obligation_oracle.on_create(o1, ObligationKind::SendPermit, t1, root);
    obligation_oracle.on_create(o2, ObligationKind::Ack, t2, root);
    obligation_oracle.on_create(o3, ObligationKind::Lease, t3, root);

    let race_id = loser_drain.on_race_start(root, vec![t1, t2, t3], t(0));

    // t2 wins
    obligation_oracle.on_resolve(o2, ObligationState::Committed);
    loser_drain.on_task_complete(t2, t(40));

    // Losers drain with obligation aborts
    obligation_oracle.on_resolve(o1, ObligationState::Aborted);
    loser_drain.on_task_complete(t1, t(60));

    obligation_oracle.on_resolve(o3, ObligationState::Aborted);
    loser_drain.on_task_complete(t3, t(70));

    loser_drain.on_race_complete(race_id, t2, t(100));
    obligation_oracle.on_region_close(root, t(150));

    let drain_ok = loser_drain.check().is_ok();
    assert_with_log!(drain_ok, "all losers drained", true, drain_ok);

    let obligation_ok = obligation_oracle.check(t(150)).is_ok();
    assert_with_log!(
        obligation_ok,
        "all obligations resolved",
        true,
        obligation_ok
    );

    test_complete!("three_way_race_obligations_fully_resolved");
}

// ============================================================================
// Cancel protocol + quiescence combined
// ============================================================================

/// Region with cancelled tasks must still achieve quiescence.
/// Cancelled tasks must complete through the protocol before region closes.
#[test]
fn cancelled_tasks_achieve_quiescence() {
    init_test("cancelled_tasks_achieve_quiescence");

    let mut cancel_oracle = CancellationProtocolOracle::new();
    let mut quiescence = QuiescenceOracle::new();

    let root = region(0);
    let w1 = task(1);
    let w2 = task(2);
    let reason = CancelReason::shutdown();
    let cleanup_budget = Budget::INFINITE;

    cancel_oracle.on_region_create(root, None);
    cancel_oracle.on_task_create(w1, root);
    cancel_oracle.on_task_create(w2, root);
    quiescence.on_region_create(root, None);
    quiescence.on_spawn(w1, root);
    quiescence.on_spawn(w2, root);

    // Both tasks start
    cancel_oracle.on_transition(w1, &TaskState::Created, &TaskState::Running, t(10));
    cancel_oracle.on_transition(w2, &TaskState::Created, &TaskState::Running, t(10));

    // w1 completes normally
    cancel_oracle.on_transition(
        w1,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(50),
    );
    quiescence.on_task_complete(w1);

    // w2 is cancelled and goes through the full protocol
    cancel_oracle.on_cancel_request(w2, reason.clone(), t(60));
    cancel_oracle.on_transition(
        w2,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(60),
    );
    cancel_oracle.on_transition(
        w2,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(80),
    );
    cancel_oracle.on_transition(
        w2,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(90),
    );
    cancel_oracle.on_transition(
        w2,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(100),
    );
    quiescence.on_task_complete(w2);

    // Region closes after both tasks complete
    quiescence.on_region_close(root, t(150));

    let cancel_ok = cancel_oracle.check().is_ok();
    assert_with_log!(cancel_ok, "cancel protocol valid", true, cancel_ok);

    let quiescence_ok = quiescence.check().is_ok();
    assert_with_log!(quiescence_ok, "quiescence achieved", true, quiescence_ok);

    test_complete!("cancelled_tasks_achieve_quiescence");
}

/// Region close before cancelled task completes violates quiescence.
#[test]
fn region_close_before_cancel_completes_violates_quiescence() {
    init_test("region_close_before_cancel_completes_violates_quiescence");

    let mut quiescence = QuiescenceOracle::new();

    let root = region(0);
    let w1 = task(1);

    quiescence.on_region_create(root, None);
    quiescence.on_spawn(w1, root);

    // Task is in cancelling state but hasn't completed yet
    // Region tries to close → violation
    quiescence.on_region_close(root, t(100));

    let result = quiescence.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "quiescence violation", true, is_err);

    if let Err(violation) = result {
        let has_live_task = violation.live_tasks.contains(&w1);
        assert_with_log!(has_live_task, "task still live", true, has_live_task);
    }

    test_complete!("region_close_before_cancel_completes_violates_quiescence");
}

// ============================================================================
// Cancel propagation + nested obligation resolution
// ============================================================================

/// Parent region cancel propagates to children; obligations in child region
/// must be resolved before child region closes.
#[test]
fn cancel_propagation_resolves_child_obligations() {
    init_test("cancel_propagation_resolves_child_obligations");

    let mut cancel_oracle = CancellationProtocolOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();
    let mut quiescence = QuiescenceOracle::new();

    let parent = region(0);
    let child = region(1);
    let child_task = task(1);
    let obl = obligation(10);
    let reason = CancelReason::shutdown();
    let cleanup_budget = Budget::INFINITE;

    // Setup
    cancel_oracle.on_region_create(parent, None);
    cancel_oracle.on_region_create(child, Some(parent));
    cancel_oracle.on_task_create(child_task, child);
    quiescence.on_region_create(parent, None);
    quiescence.on_region_create(child, Some(parent));
    quiescence.on_spawn(child_task, child);
    obligation_oracle.on_create(obl, ObligationKind::SendPermit, child_task, child);

    // Task starts
    cancel_oracle.on_transition(child_task, &TaskState::Created, &TaskState::Running, t(10));

    // Parent cancel propagates to child
    cancel_oracle.on_region_cancel(parent, reason, t(50));
    cancel_oracle.on_region_cancel(child, CancelReason::parent_cancelled(), t(50));

    // Child task goes through cancel protocol
    cancel_oracle.on_cancel_request(child_task, CancelReason::parent_cancelled(), t(55));
    cancel_oracle.on_transition(
        child_task,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        t(55),
    );
    cancel_oracle.on_transition(
        child_task,
        &TaskState::CancelRequested {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        t(70),
    );

    // Obligation aborted during drain
    obligation_oracle.on_resolve(obl, ObligationState::Aborted);

    cancel_oracle.on_transition(
        child_task,
        &TaskState::Cancelling {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        t(80),
    );
    cancel_oracle.on_transition(
        child_task,
        &TaskState::Finalizing {
            reason: CancelReason::parent_cancelled(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(CancelReason::parent_cancelled())),
        t(90),
    );

    // Regions close inner-first
    quiescence.on_task_complete(child_task);
    quiescence.on_region_close(child, t(100));
    obligation_oracle.on_region_close(child, t(100));

    quiescence.on_region_close(parent, t(150));
    obligation_oracle.on_region_close(parent, t(150));

    // All oracles clean
    let cancel_ok = cancel_oracle.check().is_ok();
    assert_with_log!(cancel_ok, "cancel protocol valid", true, cancel_ok);

    let quiescence_ok = quiescence.check().is_ok();
    assert_with_log!(quiescence_ok, "quiescence ok", true, quiescence_ok);

    let obligation_ok = obligation_oracle.check(t(150)).is_ok();
    assert_with_log!(obligation_ok, "no obligation leaks", true, obligation_ok);

    test_complete!("cancel_propagation_resolves_child_obligations");
}

// ============================================================================
// OracleSuite combined scenarios
// ============================================================================

/// Full scenario using OracleSuite: region with tasks, obligations,
/// cancellation, and race — all invariants must hold.
#[test]
#[allow(clippy::too_many_lines)]
fn oracle_suite_combined_cancel_race_obligation() {
    init_test("oracle_suite_combined_cancel_race_obligation");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let race_region = region(1);
    let racer1 = task(1);
    let racer2 = task(2);
    let normal_task = task(3);
    let obl_racer1 = obligation(10);
    let obl_racer2 = obligation(11);
    let obl_normal = obligation(12);
    let cleanup_budget = Budget::INFINITE;

    // Setup regions and tasks
    suite.region_tree.on_region_create(root, None, t(0));
    suite
        .region_tree
        .on_region_create(race_region, Some(root), t(5));

    suite.cancellation_protocol.on_region_create(root, None);
    suite
        .cancellation_protocol
        .on_region_create(race_region, Some(root));
    suite
        .cancellation_protocol
        .on_task_create(racer1, race_region);
    suite
        .cancellation_protocol
        .on_task_create(racer2, race_region);
    suite
        .cancellation_protocol
        .on_task_create(normal_task, root);

    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(race_region, Some(root));
    suite.quiescence.on_spawn(racer1, race_region);
    suite.quiescence.on_spawn(racer2, race_region);
    suite.quiescence.on_spawn(normal_task, root);

    // Create obligations
    suite
        .obligation_leak
        .on_create(obl_racer1, ObligationKind::SendPermit, racer1, race_region);
    suite
        .obligation_leak
        .on_create(obl_racer2, ObligationKind::Ack, racer2, race_region);
    suite
        .obligation_leak
        .on_create(obl_normal, ObligationKind::Lease, normal_task, root);

    // Tasks start running
    suite.cancellation_protocol.on_transition(
        racer1,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );
    suite.cancellation_protocol.on_transition(
        racer2,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );
    suite.cancellation_protocol.on_transition(
        normal_task,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );

    // Race starts
    let race_id = suite
        .loser_drain
        .on_race_start(race_region, vec![racer1, racer2], t(15));

    // racer1 wins
    suite
        .obligation_leak
        .on_resolve(obl_racer1, ObligationState::Committed);
    suite.cancellation_protocol.on_transition(
        racer1,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(40),
    );
    suite.loser_drain.on_task_complete(racer1, t(40));
    suite.quiescence.on_task_complete(racer1);

    // racer2 loses: cancel protocol + obligation abort
    let loser_reason = CancelReason::race_loser();
    suite
        .cancellation_protocol
        .on_cancel_request(racer2, loser_reason.clone(), t(45));
    suite.cancellation_protocol.on_transition(
        racer2,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        t(45),
    );
    suite.cancellation_protocol.on_transition(
        racer2,
        &TaskState::CancelRequested {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    suite
        .obligation_leak
        .on_resolve(obl_racer2, ObligationState::Aborted);
    suite.cancellation_protocol.on_transition(
        racer2,
        &TaskState::Cancelling {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        t(55),
    );
    suite.cancellation_protocol.on_transition(
        racer2,
        &TaskState::Finalizing {
            reason: loser_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(loser_reason)),
        t(60),
    );
    suite.loser_drain.on_task_complete(racer2, t(60));
    suite.quiescence.on_task_complete(racer2);

    // Race completes
    suite.loser_drain.on_race_complete(race_id, racer1, t(65));

    // Close race region
    suite.quiescence.on_region_close(race_region, t(70));
    suite.obligation_leak.on_region_close(race_region, t(70));

    // Normal task completes
    suite
        .obligation_leak
        .on_resolve(obl_normal, ObligationState::Committed);
    suite.cancellation_protocol.on_transition(
        normal_task,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(80),
    );
    suite.quiescence.on_task_complete(normal_task);

    // Close root region
    suite.quiescence.on_region_close(root, t(100));
    suite.obligation_leak.on_region_close(root, t(100));

    // Check all oracles
    let violations = suite.check_all(t(100));
    let clean = violations.is_empty();
    assert_with_log!(clean, "no violations", true, clean);

    if !clean {
        for v in &violations {
            tracing::error!(violation = %v, "VIOLATION");
        }
        panic!("OracleSuite detected {} violations", violations.len());
    }

    test_complete!("oracle_suite_combined_cancel_race_obligation");
}

/// OracleSuite detects obligation leak in combined scenario.
#[test]
fn oracle_suite_detects_obligation_leak_in_combined_scenario() {
    init_test("oracle_suite_detects_obligation_leak_in_combined_scenario");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);

    suite.region_tree.on_region_create(root, None, t(0));
    suite.cancellation_protocol.on_region_create(root, None);
    suite.cancellation_protocol.on_task_create(worker, root);
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_spawn(worker, root);

    // Create obligation
    suite
        .obligation_leak
        .on_create(obl, ObligationKind::SendPermit, worker, root);

    // Task completes normally (but obligation still pending!)
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(50),
    );
    suite.quiescence.on_task_complete(worker);

    // Region closes
    suite.quiescence.on_region_close(root, t(100));
    suite.obligation_leak.on_region_close(root, t(100));

    let violations = suite.check_all(t(100));
    let has_obligation_leak = violations.iter().any(|v| {
        matches!(
            v,
            asupersync::lab::oracle::OracleViolation::ObligationLeak(_)
        )
    });

    assert_with_log!(
        has_obligation_leak,
        "obligation leak detected",
        true,
        has_obligation_leak
    );

    test_complete!("oracle_suite_detects_obligation_leak_in_combined_scenario");
}

// ============================================================================
// Cancel reason severity during obligation drain
// ============================================================================

/// Higher severity cancellation should still respect obligation cleanup.
/// Even shutdown-level cancel must abort obligations cleanly.
#[test]
fn shutdown_cancel_still_resolves_obligations() {
    init_test("shutdown_cancel_still_resolves_obligations");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl1 = obligation(10);
    let obl2 = obligation(11);

    obligation_oracle.on_create(obl1, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl2, ObligationKind::Lease, worker, root);

    // Shutdown cancel: obligations still must be aborted
    obligation_oracle.on_resolve(obl1, ObligationState::Aborted);
    obligation_oracle.on_resolve(obl2, ObligationState::Aborted);

    obligation_oracle.on_region_close(root, t(100));

    let ok = obligation_oracle.check(t(100)).is_ok();
    assert_with_log!(ok, "shutdown cancel obligations clean", true, ok);

    // Verify the cleanup budget for shutdown is tight but sufficient
    let shutdown_budget = CancelReason::shutdown().cleanup_budget();
    let has_polls = shutdown_budget.poll_quota > 0;
    assert_with_log!(has_polls, "shutdown has poll budget", true, has_polls);

    let has_high_priority = shutdown_budget.priority == 255;
    assert_with_log!(
        has_high_priority,
        "shutdown has max priority",
        true,
        has_high_priority
    );

    test_complete!("shutdown_cancel_still_resolves_obligations");
}

// ============================================================================
// Obligation resolution order invariant
// ============================================================================

/// Obligations must be resolvable in any order; no ordering constraint.
/// This verifies the ledger handles interleaved commits and aborts.
#[test]
fn obligation_resolution_order_independent() {
    init_test("obligation_resolution_order_independent");

    let mut oracle1 = ObligationLeakOracle::new();
    let mut oracle2 = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let o_a = obligation(10);
    let o_b = obligation(11);
    let o_c = obligation(12);

    // Setup both oracles identically
    for oracle in [&mut oracle1, &mut oracle2] {
        oracle.on_create(o_a, ObligationKind::SendPermit, worker, root);
        oracle.on_create(o_b, ObligationKind::Ack, worker, root);
        oracle.on_create(o_c, ObligationKind::Lease, worker, root);
    }

    // Oracle 1: resolve in order A, B, C
    oracle1.on_resolve(o_a, ObligationState::Committed);
    oracle1.on_resolve(o_b, ObligationState::Aborted);
    oracle1.on_resolve(o_c, ObligationState::Committed);
    oracle1.on_region_close(root, t(100));

    // Oracle 2: resolve in reverse order C, B, A
    oracle2.on_resolve(o_c, ObligationState::Committed);
    oracle2.on_resolve(o_b, ObligationState::Aborted);
    oracle2.on_resolve(o_a, ObligationState::Committed);
    oracle2.on_region_close(root, t(100));

    // Both should be clean regardless of resolution order
    let ok1 = oracle1.check(t(100)).is_ok();
    assert_with_log!(ok1, "forward order clean", true, ok1);

    let ok2 = oracle2.check(t(100)).is_ok();
    assert_with_log!(ok2, "reverse order clean", true, ok2);

    test_complete!("obligation_resolution_order_independent");
}

// ============================================================================
// Cross-region obligation isolation
// ============================================================================

/// Obligations in different regions are checked independently.
/// A leak in one region should not affect the other.
#[test]
fn obligation_isolation_across_regions() {
    init_test("obligation_isolation_across_regions");

    let mut oracle = ObligationLeakOracle::new();

    let r1 = region(0);
    let r2 = region(1);
    let t1 = task(1);
    let t2 = task(2);
    let o1 = obligation(10);
    let o2 = obligation(11);

    oracle.on_create(o1, ObligationKind::SendPermit, t1, r1);
    oracle.on_create(o2, ObligationKind::Ack, t2, r2);

    // Resolve o1 but not o2
    oracle.on_resolve(o1, ObligationState::Committed);

    // Close only r1 (should be clean)
    oracle.on_region_close(r1, t(100));

    let result = oracle.check(t(100));
    let ok = result.is_ok();
    assert_with_log!(ok, "r1 clean despite r2 pending", true, ok);

    // Now close r2 (should detect leak)
    oracle.on_region_close(r2, t(200));
    let result2 = oracle.check(t(200));
    let is_err = result2.is_err();
    assert_with_log!(is_err, "r2 leak detected", true, is_err);

    test_complete!("obligation_isolation_across_regions");
}
