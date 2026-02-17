#![allow(missing_docs)]
//! Obligation Lifecycle E2E Tests + Logging (bd-275by).
//!
//! End-to-end tests exercising two-phase channels, obligation tokens, and
//! region close with structured tracing. Each scenario validates a specific
//! facet of the obligation lifecycle under the lab runtime.
//!
//! # Scenarios
//!
//! 1. **Reserve/Commit**: Obligation reserved, committed, region closes cleanly
//! 2. **Reserve/Abort**: Obligation reserved, explicitly aborted, no leak
//! 3. **Cancellation mid-reserve**: Task cancelled while holding obligations
//! 4. **Leak detection**: Region close with unresolved obligation → oracle catches it
//! 5. **Multiple obligations**: Mixed commit/abort across obligation kinds
//! 6. **Two-phase channel**: MPSC reserve→send, reserve→abort, reserve→drop
//! 7. **Nested regions**: Obligations in child regions propagate correctly
//! 8. **Concurrent tasks**: Multiple tasks with obligations in same region
//! 9. **Race with obligations**: Loser branch obligations aborted on drain
//!
//! # Cross-references
//!
//!   Oracle-based tests:      tests/cancel_obligation_invariants.rs
//!   Runtime obligation E2E:  tests/runtime_e2e.rs (e2e_obligation_lifecycle)
//!   Leak regression suite:   tests/leak_regression_e2e.rs
//!   Integration E2E:         tests/integration_e2e.rs (e2e_obligation_across_join_boundary)
//!   Channel unit tests:      src/channel/mpsc.rs

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::lab::oracle::{CancellationProtocolOracle, ObligationLeakOracle, OracleSuite};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::test_logging::TestHarness;
use asupersync::types::{
    Budget, CancelKind, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time,
};
use common::*;

// ============================================================================
// Helpers
// ============================================================================

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
// 1. Reserve/Commit: Happy path
// ============================================================================

/// Single obligation: reserve → commit → region close. No leaks.
#[test]
fn obligation_reserve_commit_clean() {
    let mut harness = TestHarness::new("obligation_reserve_commit_clean");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("reserve_and_commit");
    let obl_id = runtime
        .state
        .create_obligation(
            ObligationKind::SendPermit,
            task_id,
            root,
            Some("e2e reserve/commit test".to_string()),
        )
        .expect("create obligation");
    tracing::info!(obligation = ?obl_id, "obligation reserved");

    let commit_result = runtime.state.commit_obligation(obl_id);
    harness.assert_true("commit_succeeded", commit_result.is_ok());
    tracing::info!(hold_ns = ?commit_result, "obligation committed");
    harness.exit_phase();

    harness.enter_phase("quiescence");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "obligation_reserve_commit_clean failed");
}

/// All four obligation kinds: reserve → commit each. No leaks.
#[test]
fn obligation_all_kinds_commit() {
    let mut harness = TestHarness::new("obligation_all_kinds_commit");
    init_test_logging();

    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ];

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("reserve_and_commit_all_kinds");
    for kind in &kinds {
        let obl_id = runtime
            .state
            .create_obligation(*kind, task_id, root, Some(format!("e2e {kind}")))
            .expect("create obligation");
        tracing::info!(obligation = ?obl_id, kind = ?kind, "reserved");

        let commit = runtime.state.commit_obligation(obl_id);
        harness.assert_true(&format!("commit_{kind}"), commit.is_ok());
        tracing::info!(obligation = ?obl_id, kind = ?kind, "committed");
    }
    harness.exit_phase();

    harness.enter_phase("quiescence");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "obligation_all_kinds_commit failed");
}

// ============================================================================
// 2. Reserve/Abort: Explicit abort path
// ============================================================================

/// Single obligation: reserve → abort → region close. No leaks.
#[test]
fn obligation_reserve_abort_clean() {
    let mut harness = TestHarness::new("obligation_reserve_abort_clean");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("reserve_and_abort");
    let obl_id = runtime
        .state
        .create_obligation(
            ObligationKind::Lease,
            task_id,
            root,
            Some("e2e reserve/abort test".to_string()),
        )
        .expect("create obligation");
    tracing::info!(obligation = ?obl_id, "obligation reserved");

    let abort_result = runtime
        .state
        .abort_obligation(obl_id, ObligationAbortReason::Explicit);
    harness.assert_true("abort_succeeded", abort_result.is_ok());
    tracing::info!(obligation = ?obl_id, "obligation aborted explicitly");
    harness.exit_phase();

    harness.enter_phase("quiescence");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "obligation_reserve_abort_clean failed");
}

/// Mixed: some obligations committed, some aborted. All resolved → no leaks.
#[test]
fn obligation_mixed_commit_abort() {
    let mut harness = TestHarness::new("obligation_mixed_commit_abort");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("mixed_resolve");
    let obl_commit = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obl 1");
    let obl_abort = runtime
        .state
        .create_obligation(ObligationKind::Ack, task_id, root, None)
        .expect("create obl 2");
    let obl_commit2 = runtime
        .state
        .create_obligation(ObligationKind::IoOp, task_id, root, None)
        .expect("create obl 3");
    let obl_abort2 = runtime
        .state
        .create_obligation(ObligationKind::Lease, task_id, root, None)
        .expect("create obl 4");

    harness.assert_true(
        "commit_1",
        runtime.state.commit_obligation(obl_commit).is_ok(),
    );
    harness.assert_true(
        "abort_1",
        runtime
            .state
            .abort_obligation(obl_abort, ObligationAbortReason::Explicit)
            .is_ok(),
    );
    harness.assert_true(
        "commit_2",
        runtime.state.commit_obligation(obl_commit2).is_ok(),
    );
    harness.assert_true(
        "abort_2",
        runtime
            .state
            .abort_obligation(obl_abort2, ObligationAbortReason::Cancel)
            .is_ok(),
    );
    tracing::info!("all four obligations resolved (2 commit, 2 abort)");
    harness.exit_phase();

    harness.enter_phase("quiescence");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "obligation_mixed_commit_abort failed");
}

// ============================================================================
// 3. Cancellation mid-reserve (oracle-based)
// ============================================================================

/// Task holding an obligation is cancelled. During drain, obligation is aborted.
/// Oracle validates protocol correctness and no leaks.
#[test]
fn obligation_cancel_during_hold_oracle() {
    init_test("obligation_cancel_during_hold_oracle");

    let mut cancel_oracle = CancellationProtocolOracle::new();
    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);
    let obl_ack = obligation(11);

    // Setup
    cancel_oracle.on_region_create(root, None);
    cancel_oracle.on_task_create(worker, root);
    cancel_oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Task acquires two obligations
    obligation_oracle.on_create(obl, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_ack, ObligationKind::Ack, worker, root);
    tracing::info!("two obligations acquired");

    // Cancel requested
    let reason = CancelReason::user("parent shutdown");
    let cleanup_budget = Budget::INFINITE;
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

    // Drain phase: obligations resolved
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
    obligation_oracle.on_resolve(obl_ack, ObligationState::Aborted);
    tracing::info!("both obligations aborted during drain");

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

    // Region close
    obligation_oracle.on_region_close(root, t(250));

    let cancel_ok = cancel_oracle.check().is_ok();
    assert_with_log!(cancel_ok, "cancel protocol valid", true, cancel_ok);

    let obligation_ok = obligation_oracle.check(t(250)).is_ok();
    assert_with_log!(obligation_ok, "no obligation leaks", true, obligation_ok);

    test_complete!("obligation_cancel_during_hold_oracle");
}

/// Cancellation with mixed resolution: one committed before cancel, one aborted during drain.
#[test]
fn obligation_partial_commit_then_cancel() {
    init_test("obligation_partial_commit_then_cancel");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl_early = obligation(20);
    let obl_late = obligation(21);

    // Task acquires two obligations
    obligation_oracle.on_create(obl_early, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_late, ObligationKind::Lease, worker, root);

    // First obligation committed before cancel
    obligation_oracle.on_resolve(obl_early, ObligationState::Committed);
    tracing::info!("first obligation committed before cancel");

    // Cancel arrives: second obligation aborted during drain
    obligation_oracle.on_resolve(obl_late, ObligationState::Aborted);
    tracing::info!("second obligation aborted during drain");

    obligation_oracle.on_region_close(root, t(300));

    let result = obligation_oracle.check(t(300));
    assert_with_log!(
        result.is_ok(),
        "no leaks with partial commit",
        true,
        result.is_ok()
    );

    test_complete!("obligation_partial_commit_then_cancel");
}

// ============================================================================
// 4. Leak detection: oracle catches unresolved obligations
// ============================================================================

/// Region close with one unresolved obligation → oracle detects leak.
#[test]
fn obligation_leak_detected_on_region_close() {
    init_test("obligation_leak_detected_on_region_close");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);
    let obl_ok = obligation(30);
    let obl_leaked = obligation(31);

    // Two obligations acquired
    obligation_oracle.on_create(obl_ok, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_leaked, ObligationKind::IoOp, worker, root);

    // Only the first is resolved
    obligation_oracle.on_resolve(obl_ok, ObligationState::Committed);
    tracing::info!("first obligation committed, second left unresolved");

    // Region closes
    obligation_oracle.on_region_close(root, t(500));

    let result = obligation_oracle.check(t(500));
    let is_leak = result.is_err();
    assert_with_log!(is_leak, "leak detected", true, is_leak);

    if let Err(violation) = result {
        let leaked_count = violation.leaked.len();
        assert_with_log!(leaked_count == 1, "exactly one leak", 1, leaked_count);
        let leaked_kind = violation.leaked[0].kind;
        assert_with_log!(
            leaked_kind == ObligationKind::IoOp,
            "leaked kind is IoOp",
            ObligationKind::IoOp,
            leaked_kind
        );
        tracing::info!(
            leaked = ?violation.leaked,
            "oracle correctly identified leaked obligation"
        );
    }

    test_complete!("obligation_leak_detected_on_region_close");
}

/// Multiple obligations leaked in the same region → oracle reports all.
#[test]
fn obligation_multiple_leaks_detected() {
    init_test("obligation_multiple_leaks_detected");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker = task(1);

    let obl_a = obligation(40);
    let obl_b = obligation(41);
    let obl_c = obligation(42);

    obligation_oracle.on_create(obl_a, ObligationKind::SendPermit, worker, root);
    obligation_oracle.on_create(obl_b, ObligationKind::Lease, worker, root);
    obligation_oracle.on_create(obl_c, ObligationKind::Ack, worker, root);

    // None resolved
    obligation_oracle.on_region_close(root, t(100));

    let result = obligation_oracle.check(t(100));
    let is_leak = result.is_err();
    assert_with_log!(is_leak, "leaks detected", true, is_leak);

    if let Err(violation) = result {
        let leaked_count = violation.leaked.len();
        assert_with_log!(leaked_count == 3, "three leaks", 3, leaked_count);
        tracing::info!(
            count = leaked_count,
            "oracle correctly identified all leaked obligations"
        );
    }

    test_complete!("obligation_multiple_leaks_detected");
}

// ============================================================================
// 5. Two-phase channel: MPSC reserve/send/abort/drop
// ============================================================================

/// MPSC channel: reserve permit → send value → receiver gets it.
#[test]
fn channel_reserve_send_receive() {
    let mut harness = TestHarness::new("channel_reserve_send_receive");
    init_test_logging();

    harness.enter_phase("setup");
    let (tx, rx) = mpsc::channel::<u64>(4);
    let cx = Cx::for_testing();
    harness.exit_phase();

    harness.enter_phase("reserve_and_send");
    run_test(|| async {
        let permit = tx.reserve(&cx).await.expect("reserve");
        permit.send(42);
        tracing::info!("value sent via permit");

        let received = rx.try_recv().expect("receive");
        assert_eq!(received, 42, "received value matches sent");
        tracing::info!(received, "value received correctly");
    });
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "channel_reserve_send_receive failed");
}

/// MPSC channel: reserve permit → explicit abort → capacity reclaimed.
#[test]
fn channel_reserve_abort_reclaims_capacity() {
    let mut harness = TestHarness::new("channel_reserve_abort_reclaims_capacity");
    init_test_logging();

    harness.enter_phase("setup");
    let (tx, _rx) = mpsc::channel::<u64>(1); // capacity=1
    let cx = Cx::for_testing();
    harness.exit_phase();

    harness.enter_phase("reserve_abort_reserve_again");
    run_test(|| async {
        // Reserve the sole slot
        let permit = tx.reserve(&cx).await.expect("first reserve");
        tracing::info!("first permit acquired");

        // try_reserve should fail (capacity exhausted)
        let try_result = tx.try_reserve();
        harness.assert_true("capacity_full", try_result.is_err());
        tracing::info!("try_reserve correctly reports full");

        // Abort: capacity should be reclaimed
        permit.abort();
        tracing::info!("permit aborted, capacity reclaimed");

        // Now try_reserve should succeed
        let permit2 = tx.try_reserve().expect("reserve after abort");
        tracing::info!("second reserve succeeded after abort");
        permit2.send(99);
    });
    harness.exit_phase();

    let summary = harness.finish();
    assert!(
        summary.passed,
        "channel_reserve_abort_reclaims_capacity failed"
    );
}

/// MPSC channel: permit dropped without send/abort → implicit abort (RAII).
#[test]
fn channel_permit_drop_implicit_abort() {
    let mut harness = TestHarness::new("channel_permit_drop_implicit_abort");
    init_test_logging();

    harness.enter_phase("setup");
    let (tx, _rx) = mpsc::channel::<u64>(1);
    let cx = Cx::for_testing();
    harness.exit_phase();

    harness.enter_phase("implicit_abort_via_drop");
    run_test(|| async {
        {
            let _permit = tx.reserve(&cx).await.expect("reserve");
            tracing::info!("permit acquired, will be dropped");
            // permit drops here without send() or abort()
        }
        tracing::info!("permit dropped (implicit abort)");

        // Capacity should be reclaimed after drop
        let permit2 = tx.try_reserve().expect("reserve after implicit abort");
        tracing::info!("second reserve succeeded after implicit abort");
        permit2.send(77);
    });
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "channel_permit_drop_implicit_abort failed");
}

/// MPSC channel: receiver dropped → reserve returns Disconnected.
#[test]
fn channel_receiver_dropped_reserve_fails() {
    let mut harness = TestHarness::new("channel_receiver_dropped_reserve_fails");
    init_test_logging();

    harness.enter_phase("receiver_drop");
    let (tx, rx) = mpsc::channel::<u64>(4);
    drop(rx);
    tracing::info!("receiver dropped");
    harness.exit_phase();

    harness.enter_phase("reserve_after_disconnect");
    let result = tx.try_reserve();
    let is_disconnected = matches!(result, Err(mpsc::SendError::Disconnected(())));
    harness.assert_true("disconnected_error", is_disconnected);
    tracing::info!("try_reserve correctly returns Disconnected");
    harness.exit_phase();

    let summary = harness.finish();
    assert!(
        summary.passed,
        "channel_receiver_dropped_reserve_fails failed"
    );
}

/// MPSC channel: send to closed receiver via permit → value silently dropped.
#[test]
fn channel_send_to_closed_receiver() {
    let mut harness = TestHarness::new("channel_send_to_closed_receiver");
    init_test_logging();

    harness.enter_phase("setup");
    let (tx, rx) = mpsc::channel::<u64>(4);
    let cx = Cx::for_testing();
    harness.exit_phase();

    harness.enter_phase("reserve_then_close_then_send");
    run_test(|| async {
        let permit = tx.reserve(&cx).await.expect("reserve before close");
        tracing::info!("permit acquired");
        drop(rx);
        tracing::info!("receiver dropped after reserve");
        // Send should not panic even though receiver is gone
        permit.send(123);
        tracing::info!("send completed (value dropped since receiver gone)");
    });
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed, "channel_send_to_closed_receiver failed");
}

// ============================================================================
// 6. Nested regions: obligations in child regions
// ============================================================================

/// Obligation in a child region: both regions close cleanly after commit.
#[test]
fn obligation_nested_region_commit() {
    init_test("obligation_nested_region_commit");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);
    let obl = obligation(50);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.region_tree.on_region_create(child, Some(root), t(5));
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child, Some(root));
    suite.task_leak.on_spawn(worker, child, t(10));
    suite.quiescence.on_spawn(worker, child);

    test_section!("reserve_and_commit");
    suite
        .obligation_leak
        .on_create(obl, ObligationKind::SendPermit, worker, child);
    tracing::info!("obligation reserved in child region");

    suite
        .obligation_leak
        .on_resolve(obl, ObligationState::Committed);
    tracing::info!("obligation committed in child region");

    test_section!("close_hierarchy");
    suite.task_leak.on_complete(worker, t(50));
    suite.quiescence.on_task_complete(worker);
    suite.quiescence.on_region_close(child, t(60));
    suite.task_leak.on_region_close(child, t(60));
    suite.quiescence.on_region_close(root, t(70));
    suite.task_leak.on_region_close(root, t(70));

    let violations = suite.check_all(t(80));
    assert_with_log!(
        violations.is_empty(),
        "no violations with nested obligation commit",
        "empty",
        violations
    );

    test_complete!("obligation_nested_region_commit");
}

/// Obligation in child region: parent cancels, child obligation aborted.
#[test]
fn obligation_nested_region_parent_cancel() {
    init_test("obligation_nested_region_parent_cancel");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let child = region(1);
    let worker = task(1);
    let obl = obligation(55);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.region_tree.on_region_create(child, Some(root), t(5));
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(child, Some(root));
    suite.task_leak.on_spawn(worker, child, t(10));
    suite.quiescence.on_spawn(worker, child);

    suite
        .obligation_leak
        .on_create(obl, ObligationKind::Lease, worker, child);
    tracing::info!("obligation reserved in child region");

    test_section!("parent_cancel");
    let reason = CancelReason::new(CancelKind::Shutdown);
    suite
        .cancellation_protocol
        .on_region_cancel(child, reason, t(30));

    // Obligation aborted during drain
    suite
        .obligation_leak
        .on_resolve(obl, ObligationState::Aborted);
    tracing::info!("child obligation aborted due to parent cancel");

    test_section!("close_hierarchy");
    suite.task_leak.on_complete(worker, t(50));
    suite.quiescence.on_task_complete(worker);
    suite.quiescence.on_region_close(child, t(60));
    suite.task_leak.on_region_close(child, t(60));
    suite.quiescence.on_region_close(root, t(70));
    suite.task_leak.on_region_close(root, t(70));

    let violations = suite.check_all(t(80));
    assert_with_log!(
        violations.is_empty(),
        "no violations after parent cancel",
        "empty",
        violations
    );

    test_complete!("obligation_nested_region_parent_cancel");
}

// ============================================================================
// 7. Concurrent tasks: multiple tasks with obligations in same region
// ============================================================================

/// Two tasks in the same region each hold obligations. Both commit. No leaks.
#[test]
fn obligation_concurrent_tasks_both_commit() {
    init_test("obligation_concurrent_tasks_both_commit");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let worker_a = task(1);
    let worker_b = task(2);
    let obl_a = obligation(60);
    let obl_b = obligation(61);

    test_section!("setup");
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);
    suite.task_leak.on_spawn(worker_a, root, t(5));
    suite.task_leak.on_spawn(worker_b, root, t(5));
    suite.quiescence.on_spawn(worker_a, root);
    suite.quiescence.on_spawn(worker_b, root);

    test_section!("reserve_obligations");
    suite
        .obligation_leak
        .on_create(obl_a, ObligationKind::SendPermit, worker_a, root);
    suite
        .obligation_leak
        .on_create(obl_b, ObligationKind::Ack, worker_b, root);
    tracing::info!("both tasks hold obligations");

    test_section!("commit_both");
    suite
        .obligation_leak
        .on_resolve(obl_a, ObligationState::Committed);
    suite
        .obligation_leak
        .on_resolve(obl_b, ObligationState::Committed);
    tracing::info!("both obligations committed");

    test_section!("close");
    suite.task_leak.on_complete(worker_a, t(30));
    suite.task_leak.on_complete(worker_b, t(35));
    suite.quiescence.on_task_complete(worker_a);
    suite.quiescence.on_task_complete(worker_b);
    suite.quiescence.on_region_close(root, t(40));
    suite.task_leak.on_region_close(root, t(40));

    let violations = suite.check_all(t(50));
    assert_with_log!(
        violations.is_empty(),
        "no violations with concurrent commits",
        "empty",
        violations
    );

    test_complete!("obligation_concurrent_tasks_both_commit");
}

/// Two tasks in same region: one commits, other leaks → oracle catches it.
#[test]
fn obligation_concurrent_one_leaks() {
    init_test("obligation_concurrent_one_leaks");

    let mut obligation_oracle = ObligationLeakOracle::new();

    let root = region(0);
    let worker_a = task(1);
    let worker_b = task(2);
    let obl_a = obligation(70);
    let obl_b = obligation(71);

    obligation_oracle.on_create(obl_a, ObligationKind::SendPermit, worker_a, root);
    obligation_oracle.on_create(obl_b, ObligationKind::Lease, worker_b, root);

    // Only worker_a resolves
    obligation_oracle.on_resolve(obl_a, ObligationState::Committed);
    tracing::info!("worker_a committed, worker_b unresolved");

    obligation_oracle.on_region_close(root, t(100));

    let result = obligation_oracle.check(t(100));
    let is_leak = result.is_err();
    assert_with_log!(is_leak, "leak from worker_b detected", true, is_leak);

    if let Err(violation) = result {
        let leaked = &violation.leaked;
        assert_with_log!(leaked.len() == 1, "one leak", 1, leaked.len());
        assert_with_log!(
            leaked[0].kind == ObligationKind::Lease,
            "leaked kind is Lease",
            ObligationKind::Lease,
            leaked[0].kind
        );
    }

    test_complete!("obligation_concurrent_one_leaks");
}

// ============================================================================
// 8. Race with obligations: loser branch obligations aborted
// ============================================================================

/// Race: two branches with obligations. Winner commits, loser aborts.
#[test]
fn obligation_race_winner_commits_loser_aborts() {
    init_test("obligation_race_winner_commits_loser_aborts");

    let mut suite = OracleSuite::new();

    let root = region(0);
    let branch_a = region(1);
    let branch_b = region(2);
    let worker_a = task(1);
    let worker_b = task(2);
    let obl_a = obligation(80);
    let obl_b = obligation(81);

    test_section!("setup_race");
    suite.region_tree.on_region_create(root, None, t(0));
    suite
        .region_tree
        .on_region_create(branch_a, Some(root), t(1));
    suite
        .region_tree
        .on_region_create(branch_b, Some(root), t(1));
    suite.quiescence.on_region_create(root, None);
    suite.quiescence.on_region_create(branch_a, Some(root));
    suite.quiescence.on_region_create(branch_b, Some(root));

    suite.task_leak.on_spawn(worker_a, branch_a, t(5));
    suite.task_leak.on_spawn(worker_b, branch_b, t(5));
    suite.quiescence.on_spawn(worker_a, branch_a);
    suite.quiescence.on_spawn(worker_b, branch_b);

    suite
        .obligation_leak
        .on_create(obl_a, ObligationKind::SendPermit, worker_a, branch_a);
    suite
        .obligation_leak
        .on_create(obl_b, ObligationKind::SendPermit, worker_b, branch_b);
    tracing::info!("both race branches hold obligations");

    test_section!("race_result_a_wins");
    // Branch A wins: commit
    suite
        .obligation_leak
        .on_resolve(obl_a, ObligationState::Committed);
    suite.task_leak.on_complete(worker_a, t(20));
    suite.quiescence.on_task_complete(worker_a);
    tracing::info!("branch A wins, obligation committed");

    // Branch B loses: cancel + abort
    let reason = CancelReason::race_lost();
    suite
        .cancellation_protocol
        .on_region_cancel(branch_b, reason, t(25));
    suite
        .obligation_leak
        .on_resolve(obl_b, ObligationState::Aborted);
    suite.task_leak.on_complete(worker_b, t(30));
    suite.quiescence.on_task_complete(worker_b);
    tracing::info!("branch B loses, obligation aborted");

    test_section!("close_hierarchy");
    suite.quiescence.on_region_close(branch_a, t(35));
    suite.task_leak.on_region_close(branch_a, t(35));
    suite.quiescence.on_region_close(branch_b, t(40));
    suite.task_leak.on_region_close(branch_b, t(40));
    suite.quiescence.on_region_close(root, t(45));
    suite.task_leak.on_region_close(root, t(45));

    let violations = suite.check_all(t(50));
    assert_with_log!(
        violations.is_empty(),
        "no violations in race scenario",
        "empty",
        violations
    );

    test_complete!("obligation_race_winner_commits_loser_aborts");
}

// ============================================================================
// 9. Runtime-level: obligation lifecycle with actual runtime state
// ============================================================================

/// Runtime: create multiple obligations, abort all on cancel, verify quiescence.
#[test]
fn obligation_runtime_cancel_aborts_all() {
    let mut harness = TestHarness::new("obligation_runtime_cancel_aborts_all");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0xBEEF));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("create_obligations");
    let obls: Vec<ObligationId> = (0..5)
        .map(|i| {
            let kind = match i % 4 {
                0 => ObligationKind::SendPermit,
                1 => ObligationKind::Ack,
                2 => ObligationKind::Lease,
                _ => ObligationKind::IoOp,
            };
            runtime
                .state
                .create_obligation(kind, task_id, root, Some(format!("obl-{i}")))
                .expect("create obligation")
        })
        .collect();
    tracing::info!(count = obls.len(), "obligations created");
    harness.exit_phase();

    harness.enter_phase("abort_all");
    for obl in &obls {
        let result = runtime
            .state
            .abort_obligation(*obl, ObligationAbortReason::Cancel);
        harness.assert_true(&format!("abort_{obl:?}"), result.is_ok());
    }
    tracing::info!("all obligations aborted");
    harness.exit_phase();

    harness.enter_phase("quiescence");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    harness.enter_phase("verify_double_resolve_fails");
    for obl in &obls {
        let double_commit = runtime.state.commit_obligation(*obl);
        harness.assert_true(
            &format!("double_commit_fails_{obl:?}"),
            double_commit.is_err(),
        );
        let double_abort = runtime
            .state
            .abort_obligation(*obl, ObligationAbortReason::Explicit);
        harness.assert_true(
            &format!("double_abort_fails_{obl:?}"),
            double_abort.is_err(),
        );
    }
    tracing::info!("double-resolve correctly rejected for all obligations");
    harness.exit_phase();

    let summary = harness.finish();
    assert!(
        summary.passed,
        "obligation_runtime_cancel_aborts_all failed"
    );
}

/// Runtime: obligation commit timing is recorded.
#[test]
fn obligation_commit_records_hold_duration() {
    let mut harness = TestHarness::new("obligation_commit_records_hold_duration");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("reserve_advance_commit");
    let obl = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obligation");

    // Advance virtual time
    runtime.state.now = Time::from_nanos(1_000_000);

    let hold_ns = runtime.state.commit_obligation(obl).expect("commit");
    tracing::info!(hold_ns, "obligation committed with hold duration");
    harness.assert_true("hold_duration_positive", hold_ns > 0);
    harness.exit_phase();

    let summary = harness.finish();
    assert!(
        summary.passed,
        "obligation_commit_records_hold_duration failed"
    );
}
