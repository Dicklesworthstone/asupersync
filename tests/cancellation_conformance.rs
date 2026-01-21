//! Cancellation protocol conformance tests.
//!
//! These tests verify the cancellation protocol invariants as specified in
//! asupersync_v4_formal_semantics.md. They cover request, drain, and finalize
//! phases using oracle-based verification.
//!
//! # The Cancellation Protocol
//!
//! Valid transitions: Created/Running -> CancelRequested -> Cancelling -> Finalizing -> CompletedCancelled
//!
//! # Spec References
//!
//! - Spec 3.1: Cancellation protocol overview
//! - Spec 3.1.1: Cancel request phase
//! - Spec 3.1.2: Drain phase (cleanup)
//! - Spec 3.1.3: Finalize phase
//! - Spec 3.2: Cancellation propagation (INV-CANCEL-PROPAGATES)
//! - Spec 3.3: Cancel reason attribution and strengthening
//! - Spec 3.4: Nested cancellation semantics

#[macro_use]
mod common;

use asupersync::lab::oracle::{
    CancellationProtocolOracle, CancellationProtocolViolation, OracleSuite, TaskStateKind,
};
use asupersync::record::task::TaskState;
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

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Cancel Request Phase Tests (Spec 3.1.1)
// ============================================================================

/// Validates: Spec 3.1.1 - "Cancel request can be issued to a running task"
#[test]
fn cancel_request_on_running_task() {
    init_test("cancel_request_on_running_task");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    // Setup
    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Task starts running
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Cancel request
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );

    // Complete the protocol
    oracle.on_transition(
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
    oracle.on_transition(
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
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "cancel request valid", true, ok);

    test_complete!("cancel_request_on_running_task");
}

/// Validates: Spec 3.1.1 - "Cancel can be requested before first poll"
#[test]
fn cancel_request_before_first_poll() {
    init_test("cancel_request_before_first_poll");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::user("stop");
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Cancel before running (from Created state)
    oracle.on_cancel_request(worker, reason.clone(), t(10));
    oracle.on_transition(
        worker,
        &TaskState::Created,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(10),
    );

    // Complete the protocol
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(100),
    );
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(150),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "cancel before first poll valid", true, ok);

    test_complete!("cancel_request_before_first_poll");
}

/// Validates: Spec 3.1.1 - "Skipping CancelRequested state is a violation"
#[test]
fn cancel_skipping_request_state_detected() {
    init_test("cancel_skipping_request_state_detected");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Task starts running
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Invalid: Running -> Cancelling (skipping CancelRequested)
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::Cancelling {
            reason,
            cleanup_budget,
        },
        t(50),
    );

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "skipped state detected", true, is_err);

    if let Err(violation) = result {
        let is_skipped = matches!(
            violation,
            CancellationProtocolViolation::SkippedState { .. }
        );
        assert_with_log!(is_skipped, "violation is SkippedState", true, is_skipped);
    }

    test_complete!("cancel_skipping_request_state_detected");
}

// ============================================================================
// Drain Phase Tests (Spec 3.1.2)
// ============================================================================

/// Validates: Spec 3.1.2 - "Task enters Cancelling state after acknowledging cancel"
#[test]
fn cancel_drain_phase_entered() {
    init_test("cancel_drain_phase_entered");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Start and request cancel
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );

    // Acknowledge and enter drain phase
    oracle.on_cancel_ack(worker, t(100));
    oracle.on_transition(
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

    // Verify state
    let state = oracle.task_state(worker);
    let is_cancelling = state == Some(TaskStateKind::Cancelling);
    assert_with_log!(
        is_cancelling,
        "task in Cancelling state",
        true,
        is_cancelling
    );

    // Complete the protocol
    oracle.on_transition(
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
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "drain phase valid", true, ok);

    test_complete!("cancel_drain_phase_entered");
}

/// Validates: Spec 3.1.2 - "Error during cleanup is valid"
#[test]
fn cancel_error_during_drain_valid() {
    init_test("cancel_error_during_drain_valid");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Start, cancel, and enter drain
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason,
            cleanup_budget,
        },
        t(100),
    );

    // Error during cleanup (valid transition)
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: CancelReason::timeout(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Err(asupersync::error::Error::new(
            asupersync::error::ErrorKind::User,
        ))),
        t(150),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "error during drain valid", true, ok);

    test_complete!("cancel_error_during_drain_valid");
}

// ============================================================================
// Finalize Phase Tests (Spec 3.1.3)
// ============================================================================

/// Validates: Spec 3.1.3 - "Task enters Finalizing state after drain"
#[test]
fn cancel_finalize_phase_entered() {
    init_test("cancel_finalize_phase_entered");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Complete request and drain phases
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    oracle.on_transition(
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

    // Enter finalize phase
    oracle.on_transition(
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

    let state = oracle.task_state(worker);
    let is_finalizing = state == Some(TaskStateKind::Finalizing);
    assert_with_log!(
        is_finalizing,
        "task in Finalizing state",
        true,
        is_finalizing
    );

    // Complete
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "finalize phase valid", true, ok);

    test_complete!("cancel_finalize_phase_entered");
}

/// Validates: Spec 3.1.3 - "Skipping Finalizing state is a violation"
#[test]
fn cancel_skipping_finalize_detected() {
    init_test("cancel_skipping_finalize_detected");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Complete request and drain phases
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    oracle.on_transition(
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

    // Invalid: Cancelling -> CompletedCancelled (skipping Finalizing)
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(150),
    );

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "skipped finalize detected", true, is_err);

    test_complete!("cancel_skipping_finalize_detected");
}

/// Validates: Spec 3.1.3 - "Cancelled task must complete"
#[test]
fn cancel_task_must_complete() {
    init_test("cancel_task_must_complete");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Cancel but don't complete
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason,
            cleanup_budget,
        },
        t(50),
    );

    // Task stuck in CancelRequested
    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "incomplete cancel detected", true, is_err);

    if let Err(violation) = result {
        let is_not_completed = matches!(
            violation,
            CancellationProtocolViolation::CancelNotCompleted { .. }
        );
        assert_with_log!(
            is_not_completed,
            "violation is CancelNotCompleted",
            true,
            is_not_completed
        );
    }

    test_complete!("cancel_task_must_complete");
}

// ============================================================================
// Cancel Propagation Tests (Spec 3.2)
// ============================================================================

/// Validates: Spec 3.2 - "Cancel propagates to child regions"
#[test]
fn cancel_propagates_to_children() {
    init_test("cancel_propagates_to_children");

    let mut oracle = CancellationProtocolOracle::new();
    let parent = region(0);
    let child = region(1);

    oracle.on_region_create(parent, None);
    oracle.on_region_create(child, Some(parent));

    // Cancel parent AND child (proper propagation)
    oracle.on_region_cancel(parent, CancelReason::shutdown(), t(100));
    oracle.on_region_cancel(child, CancelReason::parent_cancelled(), t(100));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "cancel propagation valid", true, ok);

    test_complete!("cancel_propagates_to_children");
}

/// Validates: Spec 3.2 - "Missing propagation is a violation"
#[test]
fn cancel_missing_propagation_detected() {
    init_test("cancel_missing_propagation_detected");

    let mut oracle = CancellationProtocolOracle::new();
    let parent = region(0);
    let child = region(1);

    oracle.on_region_create(parent, None);
    oracle.on_region_create(child, Some(parent));

    // Cancel parent but NOT child (violation)
    oracle.on_region_cancel(parent, CancelReason::shutdown(), t(100));

    let result = oracle.check();
    let is_err = result.is_err();
    assert_with_log!(is_err, "missing propagation detected", true, is_err);

    if let Err(violation) = result {
        let is_not_propagated = matches!(
            violation,
            CancellationProtocolViolation::CancelNotPropagated { .. }
        );
        assert_with_log!(
            is_not_propagated,
            "violation is CancelNotPropagated",
            true,
            is_not_propagated
        );
    }

    test_complete!("cancel_missing_propagation_detected");
}

/// Validates: Spec 3.2 - "Cancel propagates through deep region tree"
#[test]
fn cancel_propagates_deeply() {
    init_test("cancel_propagates_deeply");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let child = region(1);
    let grandchild = region(2);
    let great_grandchild = region(3);

    oracle.on_region_create(root, None);
    oracle.on_region_create(child, Some(root));
    oracle.on_region_create(grandchild, Some(child));
    oracle.on_region_create(great_grandchild, Some(grandchild));

    // Cancel all from root down
    oracle.on_region_cancel(root, CancelReason::shutdown(), t(100));
    oracle.on_region_cancel(child, CancelReason::parent_cancelled(), t(100));
    oracle.on_region_cancel(grandchild, CancelReason::parent_cancelled(), t(100));
    oracle.on_region_cancel(great_grandchild, CancelReason::parent_cancelled(), t(100));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "deep propagation valid", true, ok);

    test_complete!("cancel_propagates_deeply");
}

// ============================================================================
// Cancel Reason Attribution Tests (Spec 3.3)
// ============================================================================

/// Validates: Spec 3.3 - "Cancel reason is attributed correctly"
#[test]
fn cancel_reason_attribution() {
    init_test("cancel_reason_attribution");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Task with timeout cancellation
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_cancel_request(worker, reason.clone(), t(50));

    let has_request = oracle.has_cancel_request(worker);
    assert_with_log!(has_request, "cancel request recorded", true, has_request);

    // Complete the protocol
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    oracle.on_transition(
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
    oracle.on_transition(
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
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "reason attribution valid", true, ok);

    test_complete!("cancel_reason_attribution");
}

/// Validates: Spec 3.3 - "Cancel reason can be strengthened"
#[test]
fn cancel_reason_strengthening() {
    init_test("cancel_reason_strengthening");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // First cancel with User reason
    let reason1 = CancelReason::user("stop");
    oracle.on_cancel_request(worker, reason1.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason1,
            cleanup_budget,
        },
        t(50),
    );

    // Strengthen with Shutdown reason
    let reason2 = CancelReason::shutdown();
    oracle.on_cancel_request(worker, reason2.clone(), t(60));
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: CancelReason::user("stop"),
            cleanup_budget,
        },
        &TaskState::CancelRequested {
            reason: reason2.clone(),
            cleanup_budget,
        },
        t(60),
    );

    // Complete with strengthened reason
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason2.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason2.clone(),
            cleanup_budget,
        },
        t(100),
    );
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason2.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason2.clone(),
            cleanup_budget,
        },
        t(150),
    );
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason2.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason2)),
        t(200),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "reason strengthening valid", true, ok);

    test_complete!("cancel_reason_strengthening");
}

// ============================================================================
// Nested Cancellation Tests (Spec 3.4)
// ============================================================================

/// Validates: Spec 3.4 - "Cancelling middle region doesn't affect parent"
#[test]
fn cancel_nested_only_affects_descendants() {
    init_test("cancel_nested_only_affects_descendants");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let middle = region(1);
    let leaf = region(2);

    oracle.on_region_create(root, None);
    oracle.on_region_create(middle, Some(root));
    oracle.on_region_create(leaf, Some(middle));

    // Cancel middle and leaf (root NOT cancelled)
    oracle.on_region_cancel(middle, CancelReason::user("stop"), t(100));
    oracle.on_region_cancel(leaf, CancelReason::parent_cancelled(), t(100));

    // Root should NOT be in cancelled_regions
    let cancelled = oracle.cancelled_regions();
    let root_not_cancelled = !cancelled.contains_key(&root);
    assert_with_log!(
        root_not_cancelled,
        "root not cancelled",
        true,
        root_not_cancelled
    );

    let middle_cancelled = cancelled.contains_key(&middle);
    assert_with_log!(middle_cancelled, "middle cancelled", true, middle_cancelled);

    let leaf_cancelled = cancelled.contains_key(&leaf);
    assert_with_log!(leaf_cancelled, "leaf cancelled", true, leaf_cancelled);

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "nested cancel valid", true, ok);

    test_complete!("cancel_nested_only_affects_descendants");
}

/// Validates: Spec 3.4 - "Multiple siblings can be cancelled independently"
#[test]
fn cancel_sibling_regions_independent() {
    init_test("cancel_sibling_regions_independent");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let sibling1 = region(1);
    let sibling2 = region(2);
    let sibling3 = region(3);

    oracle.on_region_create(root, None);
    oracle.on_region_create(sibling1, Some(root));
    oracle.on_region_create(sibling2, Some(root));
    oracle.on_region_create(sibling3, Some(root));

    // Cancel only sibling2 (not root, not siblings 1 or 3)
    oracle.on_region_cancel(sibling2, CancelReason::timeout(), t(100));

    let cancelled = oracle.cancelled_regions();
    let only_sibling2 = cancelled.len() == 1 && cancelled.contains_key(&sibling2);
    assert_with_log!(
        only_sibling2,
        "only sibling2 cancelled",
        true,
        only_sibling2
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "sibling cancel valid", true, ok);

    test_complete!("cancel_sibling_regions_independent");
}

// ============================================================================
// Complete Protocol Tests
// ============================================================================

/// Validates: Complete cancellation protocol flow
#[test]
fn cancel_complete_protocol_flow() {
    init_test("cancel_complete_protocol_flow");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Complete flow: Created -> Running -> CancelRequested -> Cancelling -> Finalizing -> CompletedCancelled
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Verify Running state
    let state1 = oracle.task_state(worker);
    assert_with_log!(
        state1 == Some(TaskStateKind::Running),
        "task running",
        Some(TaskStateKind::Running),
        state1
    );

    oracle.on_cancel_request(worker, reason.clone(), t(50));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );

    // Verify CancelRequested state
    let state2 = oracle.task_state(worker);
    assert_with_log!(
        state2 == Some(TaskStateKind::CancelRequested),
        "task cancel requested",
        Some(TaskStateKind::CancelRequested),
        state2
    );

    oracle.on_transition(
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

    // Verify Cancelling state
    let state3 = oracle.task_state(worker);
    assert_with_log!(
        state3 == Some(TaskStateKind::Cancelling),
        "task cancelling",
        Some(TaskStateKind::Cancelling),
        state3
    );

    oracle.on_transition(
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

    // Verify Finalizing state
    let state4 = oracle.task_state(worker);
    assert_with_log!(
        state4 == Some(TaskStateKind::Finalizing),
        "task finalizing",
        Some(TaskStateKind::Finalizing),
        state4
    );

    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    // Verify CompletedCancelled state
    let state5 = oracle.task_state(worker);
    assert_with_log!(
        state5 == Some(TaskStateKind::CompletedCancelled),
        "task completed cancelled",
        Some(TaskStateKind::CompletedCancelled),
        state5
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "complete protocol valid", true, ok);

    test_complete!("cancel_complete_protocol_flow");
}

/// Validates: Normal completion (not cancelled) is still valid
#[test]
fn cancel_normal_completion_valid() {
    init_test("cancel_normal_completion_valid");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);

    // Normal flow without cancellation
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(100),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "normal completion valid", true, ok);

    test_complete!("cancel_normal_completion_valid");
}

/// Validates: OracleSuite includes cancellation protocol
#[test]
fn oracle_suite_checks_cancellation_protocol() {
    init_test("oracle_suite_checks_cancellation_protocol");

    let mut suite = OracleSuite::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;

    // Setup via OracleSuite's cancellation_protocol oracle
    suite.cancellation_protocol.on_region_create(root, None);
    suite.cancellation_protocol.on_task_create(worker, root);

    // Valid cancellation flow
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );
    suite
        .cancellation_protocol
        .on_cancel_request(worker, reason.clone(), t(50));
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        t(50),
    );
    suite.cancellation_protocol.on_transition(
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
    suite.cancellation_protocol.on_transition(
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
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    let violations = suite.check_all(t(200));
    let empty = violations.is_empty();
    assert_with_log!(empty, "no violations", true, empty);

    test_complete!("oracle_suite_checks_cancellation_protocol");
}

/// Validates: Oracle reset clears all state
#[test]
fn cancel_oracle_reset() {
    init_test("cancel_oracle_reset");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_cancel_request(worker, CancelReason::timeout(), t(50));

    let has_request = oracle.has_cancel_request(worker);
    assert_with_log!(has_request, "cancel request exists", true, has_request);

    oracle.reset();

    let has_request_after = oracle.has_cancel_request(worker);
    assert_with_log!(
        !has_request_after,
        "cancel request cleared",
        false,
        has_request_after
    );

    let state = oracle.task_state(worker);
    assert_with_log!(state.is_none(), "task state cleared", true, state.is_none());

    let cancelled = oracle.cancelled_regions();
    assert_with_log!(
        cancelled.is_empty(),
        "cancelled regions cleared",
        true,
        cancelled.is_empty()
    );

    test_complete!("cancel_oracle_reset");
}
