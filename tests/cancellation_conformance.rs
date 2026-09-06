#![allow(warnings)]
#![allow(clippy::all)]
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

// Actual runtime journeys are separate from the historical oracle transition
// fixtures above. In particular, no on_* oracle calls manufacture their evidence.
#[deny(warnings)]
mod stock_responsiveness_runtime {
    use asupersync::cancel::{
        FiniteResponsiveness, ResponsivenessGoal, ResponsivenessQuery, ResponsivenessRefusal,
        ResponsivenessRegistry, ResponsivenessUnit,
    };
    use asupersync::channel::{broadcast, mpsc, oneshot, session, watch};
    use asupersync::cx::Cx;
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::sync::{Barrier, Mutex, Notify, OnceCell, RwLock, Semaphore};
    use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::{Budget, CancelKind, CancelReason, RegionId, TaskId};
    use std::future::{Future, poll_fn};
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Weak};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    type OwnedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
    type TraceSnapshot = Box<dyn Fn() -> Vec<TraceEvent> + Send + Sync>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Case {
        Checkpoint,
        MpscReserve,
        MpscReceive,
        Oneshot,
        Broadcast,
        Watch,
        TrackedReserve,
        Mutex,
        RwLock,
        Semaphore,
        ZeroSemaphore,
        Pool,
        OnceCell,
        Barrier,
        Sleep,
        Copy,
        CopyBuf,
        CopyBidirectional,
        Tcp,
        Udp,
    }

    const CASES: [Case; 20] = [
        Case::Checkpoint,
        Case::MpscReserve,
        Case::MpscReceive,
        Case::Oneshot,
        Case::Broadcast,
        Case::Watch,
        Case::TrackedReserve,
        Case::Mutex,
        Case::RwLock,
        Case::Semaphore,
        Case::ZeroSemaphore,
        Case::Pool,
        Case::OnceCell,
        Case::Barrier,
        Case::Sleep,
        Case::Copy,
        Case::CopyBuf,
        Case::CopyBidirectional,
        Case::Tcp,
        Case::Udp,
    ];

    impl Case {
        fn id(self) -> &'static str {
            match self {
                Self::Checkpoint => "cx.checkpoint",
                Self::MpscReserve => "mpsc.reserve",
                Self::MpscReceive => "mpsc.receive",
                Self::Oneshot => "oneshot.receive",
                Self::Broadcast => "broadcast.receive",
                Self::Watch => "watch.changed",
                Self::TrackedReserve => "session.reserve",
                Self::Mutex => "mutex.lock",
                Self::RwLock => "rwlock.acquire",
                Self::Semaphore => "semaphore.acquire",
                Self::ZeroSemaphore => "semaphore.zero",
                Self::Pool => "pool.capacity-wait",
                Self::OnceCell => "once-cell.wait",
                Self::Barrier => "barrier.wait",
                Self::Sleep => "sleep.cancel",
                Self::Copy => "io.copy",
                Self::CopyBuf => "io.copy-buf",
                Self::CopyBidirectional => "io.copy-bidirectional",
                Self::Tcp => "net.tcp-wait",
                Self::Udp => "net.udp-wait",
            }
        }

        fn immediate(self) -> bool {
            matches!(self, Self::Checkpoint | Self::ZeroSemaphore)
        }

        fn socket(self) -> bool {
            matches!(self, Self::Tcp | Self::Udp)
        }
    }

    #[derive(Default)]
    struct Probe {
        identity: parking_lot::Mutex<Option<(TaskId, RegionId)>>,
        context: parking_lot::Mutex<Option<Cx>>,
        pending: AtomicBool,
        returned: AtomicBool,
        cleanup_pending: AtomicBool,
        cleanup_done: AtomicBool,
        polls: AtomicU64,
        cancelled_polls: AtomicU64,
        checkpoints: AtomicU64,
        forwarded_wakes: AtomicU64,
        operation_waker: parking_lot::Mutex<Option<Waker>>,
        changed: Notify,
        start: Notify,
        cleanup: Notify,
    }

    struct OperationWake {
        runtime: Waker,
        probe: Weak<Probe>,
    }

    impl Wake for OperationWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            if let Some(probe) = self.probe.upgrade() {
                probe.forwarded_wakes.fetch_add(1, Ordering::SeqCst);
            }
            self.runtime.wake_by_ref();
        }
    }

    fn returned_bound(cx: &Cx, case: Case) -> FiniteResponsiveness {
        ResponsivenessRegistry::lookup(case.id())
            .unwrap()
            .bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(cx, CancelKind::User),
            )
            .expect("actual task's unmasked named phase has a conditional bound")
    }

    // Counts calls to the named operation Future::poll, not scheduler turns or
    // CPU cost. The real runtime waker is forwarded, never replaced by a noop.
    async fn measured<F: Future>(
        cx: &Cx,
        probe: &Arc<Probe>,
        future: F,
        parked_resource: impl Fn(),
    ) -> F::Output {
        let mut future = std::pin::pin!(future);
        poll_fn(|context| {
            probe.polls.fetch_add(1, Ordering::SeqCst);
            let cancelled = cx.is_cancel_requested();
            if cancelled {
                probe.cancelled_polls.fetch_add(1, Ordering::SeqCst);
            }
            let before = cx.checkpoint_state().checkpoint_count;
            let waker = Waker::from(Arc::new(OperationWake {
                runtime: context.waker().clone(),
                probe: Arc::downgrade(probe),
            }));
            *probe.operation_waker.lock() = Some(waker.clone());
            let result = future.as_mut().poll(&mut Context::from_waker(&waker));
            if cancelled {
                probe.checkpoints.fetch_add(
                    cx.checkpoint_state().checkpoint_count - before,
                    Ordering::SeqCst,
                );
            }
            if result.is_pending() {
                parked_resource();
                probe.pending.store(true, Ordering::SeqCst);
            }
            probe.changed.notify_one();
            result
        })
        .await
    }

    async fn until(probe: &Probe, predicate: impl Fn() -> bool) {
        loop {
            let notified = probe.changed.notified();
            if predicate() {
                return;
            }
            notified.await;
        }
    }

    fn complete_count(trace: &[TraceEvent], identity: (TaskId, RegionId)) -> usize {
        trace
            .iter()
            .filter(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(event.data, TraceData::Task { task, region }
                    if (task, region) == identity)
            })
            .count()
    }

    // An actual byte provider with one available byte followed by a real Notify
    // registration. It intentionally has no cancellation checkpoint. This tests
    // Copy's checkpoint, rather than inheriting cancellation from its reader.
    // This is controlled provider progress in both runtimes, not OS I/O delivery.
    struct GatedIo {
        first: Option<u8>,
        input: OwnedFuture<()>,
        gate: Arc<Notify>,
        written: Vec<u8>,
    }

    impl GatedIo {
        fn new(byte: u8) -> Self {
            Self::with_gate(byte, Arc::new(Notify::new()))
        }

        fn with_gate(byte: u8, gate: Arc<Notify>) -> Self {
            let input_gate = Arc::clone(&gate);
            Self {
                first: Some(byte),
                input: Box::pin(async move { input_gate.notified().await }),
                gate,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for GatedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buffer.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Some(byte) = self.first.take() {
                buffer.put_slice(&[byte]);
                return Poll::Ready(Ok(()));
            }
            self.input.as_mut().poll(context).map(Ok)
        }
    }

    impl AsyncWrite for GatedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn operation(cx: &Cx, probe: &Arc<Probe>, case: Case) -> &'static str {
        match case {
            Case::Checkpoint => {
                let before = cx.checkpoint_state().checkpoint_count;
                assert!(cx.checkpoint().unwrap_err().is_cancelled());
                probe.checkpoints.store(
                    cx.checkpoint_state().checkpoint_count - before,
                    Ordering::SeqCst,
                );
                "checkpoint_cancelled"
            }
            Case::MpscReserve | Case::TrackedReserve => {
                let (sender, mut receiver) = mpsc::channel::<u8>(1);
                sender.try_send(7).unwrap();
                let tracked = session::TrackedSender::new(sender.clone());
                if case == Case::MpscReserve {
                    assert!(matches!(
                        measured(cx, probe, sender.reserve_checked(cx), || {
                            assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1);
                        })
                        .await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                } else {
                    assert!(matches!(
                        measured(cx, probe, tracked.reserve_checked(cx), || {
                            assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1);
                        })
                        .await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                }
                let snapshot = sender.telemetry_snapshot(1);
                assert_eq!(snapshot.send_waiter_count, 0);
                assert_eq!(snapshot.reserved_uncommitted_obligations, 0);
                assert_eq!(snapshot.queued_messages, 1);
                assert_eq!(receiver.try_recv(), Ok(7));
                "checked_send_cancelled"
            }
            Case::MpscReceive => {
                let (sender, mut receiver) = mpsc::channel::<u8>(1);
                assert_eq!(
                    measured(cx, probe, receiver.recv(cx), || {
                        assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 1);
                    })
                    .await,
                    Err(mpsc::RecvError::Cancelled)
                );
                assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 0);
                sender.try_send(11).unwrap();
                assert_eq!(receiver.try_recv(), Ok(11));
                "mpsc_receive_cancelled"
            }
            Case::Oneshot => {
                let (sender, mut receiver) = oneshot::channel::<u8>();
                assert_eq!(
                    measured(cx, probe, receiver.recv(cx), || {
                        assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 1);
                    })
                    .await,
                    Err(oneshot::RecvError::Cancelled)
                );
                assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 0);
                "oneshot_receive_cancelled"
            }
            Case::Broadcast => {
                let (sender, mut receiver) = broadcast::channel::<u8>(1);
                assert_eq!(
                    measured(cx, probe, receiver.recv(cx), || {
                        assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 1);
                    })
                    .await,
                    Err(broadcast::RecvError::Cancelled)
                );
                assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 0);
                "broadcast_receive_cancelled"
            }
            Case::Watch => {
                let (sender, mut receiver) = watch::channel(13_u8);
                assert_eq!(
                    measured(cx, probe, receiver.changed(cx), || {
                        assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 1);
                    })
                    .await,
                    Err(watch::RecvError::Cancelled)
                );
                assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 0);
                assert_eq!(*receiver.borrow(), 13);
                "watch_changed_cancelled"
            }
            Case::Mutex => {
                let lock = Arc::new(Mutex::new(17_u8));
                let held = lock.try_lock_owned().unwrap();
                assert!(matches!(
                    measured(cx, probe, lock.lock(cx), || {
                        assert_eq!(lock.waiters(), 1);
                    })
                    .await,
                    Err(asupersync::sync::LockError::Cancelled)
                ));
                assert_eq!(lock.waiters(), 0);
                assert_eq!(*held, 17);
                assert!(lock.try_lock_owned().is_err());
                drop(held);
                assert_eq!(*lock.try_lock_owned().unwrap(), 17);
                "mutex_lock_cancelled"
            }
            Case::RwLock => {
                let lock = RwLock::new(19_u8);
                let held = lock.try_read().unwrap();
                assert!(matches!(
                    measured(cx, probe, lock.write(cx), || {
                        assert!(lock.try_write().is_err());
                    })
                    .await,
                    Err(asupersync::sync::RwLockError::Cancelled)
                ));
                assert_eq!(*held, 19);
                drop(held);
                // Public RwLock has no queue counter. This is real removal of
                // writer preference: the cancelled waiter cannot block readers.
                assert_eq!(*lock.try_read().unwrap(), 19);
                assert_eq!(*lock.try_write().unwrap(), 19);
                "rwlock_write_cancelled"
            }
            Case::Semaphore => {
                let semaphore = Semaphore::new(1);
                let held = semaphore.try_acquire(1).unwrap();
                assert!(matches!(
                    measured(cx, probe, semaphore.acquire_checked(cx, 1), || {
                        assert_eq!(semaphore.telemetry_snapshot(6).waiter_count, 1);
                    })
                    .await,
                    Err(asupersync::sync::semaphore::CheckedAcquireError::Semaphore(
                        asupersync::sync::AcquireError::Cancelled
                    ))
                ));
                assert_eq!(semaphore.telemetry_snapshot(6).waiter_count, 0);
                assert_eq!(semaphore.available_permits(), 0);
                drop(held);
                assert_eq!(semaphore.available_permits(), 1);
                "checked_semaphore_cancelled"
            }
            Case::ZeroSemaphore => {
                let semaphore = Semaphore::new(0);
                let permit = measured(cx, probe, semaphore.acquire_checked(cx, 0), || {
                    panic!("zero acquisition must never park")
                })
                .await
                .unwrap();
                drop(permit);
                assert_eq!(semaphore.telemetry_snapshot(7).waiter_count, 0);
                assert_eq!(semaphore.available_permits(), 0);
                "zero_permits_ready_without_acknowledgement"
            }
            Case::Pool => {
                use asupersync::sync::{CheckedPoolError, GenericPool, PoolConfig, PoolError};
                let pool = GenericPool::new(
                    || std::future::ready(Ok::<_, io::Error>(23_u8)),
                    PoolConfig::with_max_size(1),
                );
                let held = pool.acquire(cx).await.unwrap();
                assert!(matches!(
                    measured(cx, probe, pool.acquire_checked(cx), || {
                        assert_eq!(pool.stats().waiters, 1);
                        assert_eq!(pool.stats().active, 1);
                    })
                    .await,
                    Err(CheckedPoolError::Pool(PoolError::Cancelled))
                ));
                assert_eq!(pool.stats().waiters, 0);
                assert_eq!(pool.stats().active, 1);
                drop(held);
                assert_eq!(pool.stats().active, 0);
                assert_eq!(pool.stats().idle, 1);
                pool.close().await;
                assert_eq!(pool.stats().total, 0);
                "checked_pool_capacity_cancelled"
            }
            Case::OnceCell => {
                let cell = OnceCell::<u8>::new();
                assert_eq!(
                    measured(cx, probe, cell.wait(cx), || {
                        assert_eq!(cell.telemetry_snapshot(8).waiter_count, 1);
                    })
                    .await,
                    Err(asupersync::sync::OnceCellError::Cancelled)
                );
                assert_eq!(cell.telemetry_snapshot(8).waiter_count, 0);
                assert!(!cell.is_initialized());
                cell.set(29).unwrap();
                assert_eq!(cell.get(), Some(&29));
                "once_cell_wait_cancelled"
            }
            Case::Barrier => {
                let barrier = Barrier::new(2);
                assert!(matches!(
                    measured(cx, probe, barrier.wait(cx), || {
                        assert_eq!(barrier.telemetry_snapshot(9).waiter_count, 1);
                        assert_eq!(barrier.telemetry_snapshot(9).occupied_units, 1);
                    })
                    .await,
                    Err(asupersync::sync::barrier::BarrierWaitError::Cancelled)
                ));
                assert_eq!(barrier.telemetry_snapshot(9).waiter_count, 0);
                assert_eq!(barrier.telemetry_snapshot(9).occupied_units, 0);
                "barrier_arrival_cancelled"
            }
            Case::Sleep => {
                let driver = cx.timer_driver().expect("actual runtime timer");
                let baseline = driver.pending_count();
                measured(
                    cx,
                    probe,
                    asupersync::time::sleep(cx.now(), Duration::from_secs(600)),
                    || {
                        assert_eq!(driver.pending_count(), baseline + 1);
                    },
                )
                .await;
                assert_eq!(driver.pending_count(), baseline);
                "sleep_user_cancelled"
            }
            Case::Copy | Case::CopyBuf | Case::CopyBidirectional => {
                let mut source = GatedIo::new(31);
                let gate = Arc::clone(&source.gate);
                if case == Case::CopyBidirectional {
                    let mut peer = GatedIo::new(37);
                    let peer_gate = Arc::clone(&peer.gate);
                    let error = measured(
                        cx,
                        probe,
                        asupersync::io::copy_bidirectional(&mut source, &mut peer),
                        || {
                            assert_eq!(gate.waiter_count(), 1);
                            assert_eq!(peer_gate.waiter_count(), 1);
                        },
                    )
                    .await
                    .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                    assert_eq!(source.written, [37]);
                    assert_eq!(peer.written, [31]);
                    drop(peer);
                    assert_eq!(peer_gate.waiter_count(), 0);
                } else {
                    let mut written = Vec::new();
                    let error = if case == Case::Copy {
                        measured(
                            cx,
                            probe,
                            asupersync::io::copy(&mut source, &mut written),
                            || {
                                assert_eq!(gate.waiter_count(), 1);
                            },
                        )
                        .await
                        .unwrap_err()
                    } else {
                        let mut buffered = asupersync::io::BufReader::new(&mut source);
                        measured(
                            cx,
                            probe,
                            asupersync::io::copy_buf(&mut buffered, &mut written),
                            || {
                                assert_eq!(gate.waiter_count(), 1);
                            },
                        )
                        .await
                        .unwrap_err()
                    };
                    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                    assert_eq!(written, [31]);
                }
                drop(source);
                assert_eq!(gate.waiter_count(), 0);
                "copy_interrupted_after_observable_bytes"
            }
            Case::Tcp => {
                let listener = asupersync::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let error = measured(cx, probe, listener.accept(), || {})
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                "tcp_accept_interrupted"
            }
            Case::Udp => {
                let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                raw.set_nonblocking(true).unwrap();
                let socket = asupersync::net::UdpSocket::from_std(raw).unwrap();
                let mut bytes = [0_u8; 8];
                let error = measured(cx, probe, socket.peek_from(&mut bytes), || {})
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert_eq!(bytes, [0; 8]);
                "udp_peek_interrupted"
            }
        }
    }

    async fn child(cx: Cx, probe: Arc<Probe>, case: Case) -> serde_json::Value {
        *probe.identity.lock() = Some((cx.task_id(), cx.region_id()));
        *probe.context.lock() = Some(cx.clone());
        let bound = returned_bound(&cx, case);
        if case.immediate() {
            // Cancellation is published before the actual synchronous call or
            // zero-sized operation. The setup gate is not that operation.
            let mut start = std::pin::pin!(probe.start.notified());
            poll_fn(|context| {
                let result = start.as_mut().poll(context);
                if result.is_pending() {
                    assert_eq!(probe.start.waiter_count(), 1);
                    probe.pending.store(true, Ordering::SeqCst);
                    probe.changed.notify_one();
                }
                result
            })
            .await;
        }
        let result = operation(&cx, &probe, case).await;
        probe.operation_waker.lock().take();
        let observed = if case == Case::Checkpoint {
            probe.checkpoints.load(Ordering::SeqCst)
        } else {
            probe.cancelled_polls.load(Ordering::SeqCst)
        };
        assert_eq!(
            observed, 1,
            "exact one delivered post-cancel operation boundary"
        );
        bound.check_observed(observed, true).unwrap();
        if case == Case::ZeroSemaphore {
            assert_eq!(probe.checkpoints.load(Ordering::SeqCst), 0);
        } else {
            assert!(probe.checkpoints.load(Ordering::SeqCst) > 0);
        }
        let reason = cx
            .cancel_reason()
            .expect("actual attributed task cancellation");
        assert_eq!(reason.kind, CancelKind::User);
        assert_eq!(
            reason.message.as_deref(),
            Some("responsiveness runtime boundary")
        );
        // Acknowledge outside the measured boundary as well, so an immediate
        // Ready-wins result can retain the subsequent cleanup receipt legally.
        assert!(cx.checkpoint().unwrap_err().is_cancelled());
        probe.returned.store(true, Ordering::SeqCst);
        let mut cleanup = std::pin::pin!(probe.cleanup.notified());
        poll_fn(|context| {
            let result = cleanup.as_mut().poll(context);
            if result.is_pending() {
                assert_eq!(probe.cleanup.waiter_count(), 1);
                probe.cleanup_pending.store(true, Ordering::SeqCst);
                probe.changed.notify_one();
            }
            result
        })
        .await;
        probe.cleanup_done.store(true, Ordering::SeqCst);
        serde_json::json!({
            "entry":case.id(), "task":cx.task_id(), "region":cx.region_id(),
            "unit":if bound.unit() == ResponsivenessUnit::CheckpointCalls {"checkpoint_calls"} else {"operation_polls"},
            "bound":bound.steps(), "observed":observed,
            "operation_polls":probe.polls.load(Ordering::SeqCst),
            "post_cancel_checkpoints":probe.checkpoints.load(Ordering::SeqCst),
            "forwarded_operation_wakes":probe.forwarded_wakes.load(Ordering::SeqCst),
            "operation_was_parked":!case.immediate(), "setup_gate_only":case.immediate(),
            "result":result,"actual_cancel_reason":reason,
            "cleanup_crossed_pending":true,"cleanup_completed":true,
            "unit_scope":"conditional delivered operation boundaries, not wall time or scheduler cost",
            "premises":ResponsivenessRegistry::lookup(case.id()).unwrap().contract()
        })
    }

    async fn journey(cx: &Cx, trace: &TraceSnapshot, case: Case) -> serde_json::Value {
        let probe = Arc::new(Probe::default());
        let child_probe = Arc::clone(&probe);
        let mut handle = cx
            .spawn(move |child_cx| -> OwnedFuture<serde_json::Value> {
                Box::pin(child(child_cx, child_probe, case))
            })
            .unwrap();
        until(&probe, || probe.pending.load(Ordering::SeqCst)).await;
        let identity = probe.identity.lock().expect("actual child Cx identity");
        assert_eq!(complete_count(&trace(), identity), 0);
        assert!(!probe.returned.load(Ordering::SeqCst));
        handle.abort_with_reason(CancelReason::user("responsiveness runtime boundary"));
        if case.immediate() {
            until(&probe, || {
                probe.context.lock().as_ref().unwrap().is_cancel_requested()
            })
            .await;
            assert!(probe.start.notify_one());
        }
        until(&probe, || probe.cleanup_pending.load(Ordering::SeqCst)).await;
        assert!(probe.returned.load(Ordering::SeqCst));
        for _ in 0..3 {
            assert_eq!(probe.cleanup.waiter_count(), 1);
            assert!(!probe.cleanup_done.load(Ordering::SeqCst));
            assert_eq!(complete_count(&trace(), identity), 0);
            assert_eq!(
                ResponsivenessRegistry::lookup(case.id()).unwrap().bound(
                    ResponsivenessGoal::OwnerQuiescent,
                    ResponsivenessQuery::for_cx(cx, CancelKind::User),
                ),
                Err(ResponsivenessRefusal::OwnerProgress)
            );
            let pending =
                poll_fn(|context| Poll::Ready(handle.poll_join(context).is_pending())).await;
            assert!(
                pending,
                "actual retained child cannot be accepted as drained"
            );
            asupersync::runtime::yield_now().await;
        }
        assert!(probe.cleanup.notify_one());
        let receipt = poll_fn(|context| handle.poll_join(context)).await.unwrap();
        assert!(probe.cleanup_done.load(Ordering::SeqCst));
        assert_eq!(probe.cleanup.waiter_count(), 0);
        assert_eq!(probe.start.waiter_count(), 0);
        wait_for_complete(trace, identity).await;
        receipt
    }

    async fn wait_for_complete(trace: &TraceSnapshot, identity: (TaskId, RegionId)) {
        let deadline = Instant::now();
        while complete_count(&trace(), identity) == 0 {
            assert!(
                deadline.elapsed() < Duration::from_secs(10),
                "joined task must publish its actual Complete"
            );
            asupersync::runtime::yield_now().await;
        }
        assert_eq!(complete_count(&trace(), identity), 1);
    }

    async fn withheld_progress(
        cx: &Cx,
        trace: &TraceSnapshot,
        generic_read: bool,
    ) -> serde_json::Value {
        let probe = Arc::new(Probe::default());
        let release = Arc::new(Notify::new());
        let child_probe = Arc::clone(&probe);
        let child_release = Arc::clone(&release);
        let mut handle = cx.spawn(move |child_cx| -> OwnedFuture<serde_json::Value> {
            Box::pin(async move {
                let probe = child_probe;
                *probe.identity.lock() = Some((child_cx.task_id(), child_cx.region_id()));
                let public_name = if generic_read { "io::AsyncReadExt::read" } else { "sync::Notify::notified" };
                assert_eq!(ResponsivenessRegistry::lookup(public_name).unwrap().bound(
                    ResponsivenessGoal::OperationReturned,
                    ResponsivenessQuery::for_cx(&child_cx, CancelKind::User),
                ), Err(ResponsivenessRefusal::ExternalProgress));
                if generic_read {
                    use asupersync::io::AsyncReadExt;
                    let mut source = GatedIo::with_gate(41, Arc::clone(&child_release));
                    let mut bytes = [0_u8; 1];
                    assert_eq!(source.read(&mut bytes).await.unwrap(), 1);
                    assert_eq!(bytes, [41]);
                    let received = measured(&child_cx, &probe, source.read(&mut bytes), || {
                        assert_eq!(child_release.waiter_count(), 1);
                    }).await.unwrap();
                    assert_eq!(received, 0, "only actual provider release produces EOF");
                    assert_eq!(bytes, [41]);
                } else {
                    measured(&child_cx, &probe, child_release.notified(), || {
                        assert_eq!(child_release.waiter_count(), 1);
                    }).await;
                }
                probe.operation_waker.lock().take();
                assert_eq!(probe.checkpoints.load(Ordering::SeqCst), 0,
                    "the actual unbounded wait has no hidden cancellation checkpoint");
                probe.returned.store(true, Ordering::SeqCst);
                assert!(child_cx.checkpoint().unwrap_err().is_cancelled());
                serde_json::json!({
                    "control":if generic_read {"generic_read_withheld_provider"} else {"notify_withheld_delivery"},
                    "task":child_cx.task_id(),"region":child_cx.region_id(),
                    "public_operation":public_name,"classification":"ExternalProgress",
                    "post_cancel_operation_polls":probe.cancelled_polls.load(Ordering::SeqCst),
                    "post_cancel_operation_checkpoints":probe.checkpoints.load(Ordering::SeqCst),
                    "forwarded_operation_wakes":probe.forwarded_wakes.load(Ordering::SeqCst),
                    "planted_finite_label_refused":"GoalNotObserved",
                    "real_release_completed":true,"remaining_waiters":child_release.waiter_count()
                })
            })
        }).unwrap();
        until(&probe, || probe.pending.load(Ordering::SeqCst)).await;
        let identity = probe.identity.lock().unwrap();
        handle.abort_with_reason(CancelReason::user("withheld provider control"));
        until(&probe, || probe.cancelled_polls.load(Ordering::SeqCst) > 0).await;
        let planted = returned_bound(
            cx,
            if generic_read {
                Case::Copy
            } else {
                Case::Mutex
            },
        );
        for turn in 0..3 {
            let actual_polls = probe.cancelled_polls.load(Ordering::SeqCst);
            assert_eq!(
                planted.check_observed(actual_polls, probe.returned.load(Ordering::SeqCst)),
                Err(ResponsivenessRefusal::GoalNotObserved)
            );
            assert_eq!(release.waiter_count(), 1);
            assert_eq!(complete_count(&trace(), identity), 0);
            assert!(poll_fn(|context| Poll::Ready(handle.poll_join(context).is_pending())).await);
            if turn < 2 {
                let waker = probe.operation_waker.lock().as_ref().unwrap().clone();
                waker.wake();
                until(&probe, || {
                    probe.cancelled_polls.load(Ordering::SeqCst) > actual_polls
                })
                .await;
            }
        }
        assert!(release.notify_one());
        let row = poll_fn(|context| handle.poll_join(context)).await.unwrap();
        assert!(probe.returned.load(Ordering::SeqCst));
        assert!(probe.cancelled_polls.load(Ordering::SeqCst) >= 4);
        assert!(probe.forwarded_wakes.load(Ordering::SeqCst) >= 3);
        assert_eq!(release.waiter_count(), 0);
        wait_for_complete(trace, identity).await;
        row
    }

    fn nested_masks<R>(cx: &Cx, depth: u32, action: &mut impl FnMut() -> R) -> R {
        if depth == 0 {
            action()
        } else {
            cx.masked(|| nested_masks(cx, depth - 1, action))
        }
    }

    async fn masked_wait(cx: &Cx, trace: &TraceSnapshot, depth: u32) -> serde_json::Value {
        let probe = Arc::new(Probe::default());
        let child_probe = Arc::clone(&probe);
        let mut handle = cx
            .spawn(move |child_cx| -> OwnedFuture<serde_json::Value> {
                Box::pin(async move {
                    let probe = child_probe;
                    *probe.identity.lock() = Some((child_cx.task_id(), child_cx.region_id()));
                    let mutex = Arc::new(Mutex::new(43_u8));
                    let held = mutex.try_lock_owned().unwrap();
                    let mut operation = Box::pin(mutex.lock(&child_cx));
                    let before = child_cx.checkpoint_state().checkpoint_count;
                    // Stop this control phase after the actual cancelled, masked
                    // poll. The original lock future and waiter remain owned below;
                    // this Ready is not reported as lock completion.
                    poll_fn(|context| {
                        let cancelled = child_cx.is_cancel_requested();
                        nested_masks(&child_cx, depth, &mut || {
                            let query = ResponsivenessQuery::for_cx(&child_cx, CancelKind::User);
                            assert_eq!(
                                ResponsivenessRegistry::lookup("mutex.lock")
                                    .unwrap()
                                    .bound(ResponsivenessGoal::OperationReturned, query),
                                Err(ResponsivenessRefusal::Masked { depth })
                            );
                            if depth == 64 {
                                assert_eq!(
                                    query.with_additional_masks(1).unwrap_err(),
                                    ResponsivenessRefusal::MaskDepthExceeded {
                                        depth: 65,
                                        maximum: 64
                                    }
                                );
                            }
                            assert!(operation.as_mut().poll(context).is_pending());
                            assert_eq!(mutex.waiters(), 1);
                        });
                        probe.pending.store(true, Ordering::SeqCst);
                        if cancelled {
                            probe.cancelled_polls.fetch_add(1, Ordering::SeqCst);
                        }
                        probe.changed.notify_one();
                        if cancelled {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    let masked_checkpoints = child_cx.checkpoint_state().checkpoint_count - before;
                    assert!(
                        masked_checkpoints > 0,
                        "real masked checkpoints were reached"
                    );
                    probe.start.notified().await;
                    assert_eq!(mutex.waiters(), 1);
                    assert_eq!(*held, 43);
                    probe.cancelled_polls.store(0, Ordering::SeqCst);
                    assert!(matches!(
                        measured(&child_cx, &probe, operation.as_mut(), || {
                            panic!("released mask must expose cancellation on this poll")
                        })
                        .await,
                        Err(asupersync::sync::LockError::Cancelled)
                    ));
                    drop(operation);
                    probe.operation_waker.lock().take();
                    assert_eq!(probe.cancelled_polls.load(Ordering::SeqCst), 1);
                    returned_bound(&child_cx, Case::Mutex)
                        .check_observed(1, true)
                        .unwrap();
                    assert_eq!(mutex.waiters(), 0);
                    drop(held);
                    assert_eq!(*mutex.try_lock_owned().unwrap(), 43);
                    probe.returned.store(true, Ordering::SeqCst);
                    serde_json::json!({
                        "control":"actual_masked_lock","depth":depth,
                        "task":child_cx.task_id(),"region":child_cx.region_id(),
                        "masked_checkpoints":masked_checkpoints,"masked_result":"Pending",
                        "finite_query_refusal":"Masked","after_unmask_polls":1,
                        "actual_result":"LockError::Cancelled","waiters":0
                    })
                })
            })
            .unwrap();
        until(&probe, || probe.pending.load(Ordering::SeqCst)).await;
        let identity = probe.identity.lock().unwrap();
        handle.abort_with_reason(CancelReason::user("actual nested mask boundary"));
        until(&probe, || probe.cancelled_polls.load(Ordering::SeqCst) == 1).await;
        // The real guard has unwound, but the original Pending operation is
        // retained without another poll until this owned observation releases it.
        assert_eq!(
            returned_bound(cx, Case::Mutex)
                .check_observed(1, probe.returned.load(Ordering::SeqCst)),
            Err(ResponsivenessRefusal::GoalNotObserved)
        );
        assert_eq!(complete_count(&trace(), identity), 0);
        assert!(poll_fn(|context| Poll::Ready(handle.poll_join(context).is_pending())).await);
        probe.start.notify_one();
        let row = poll_fn(|context| handle.poll_join(context)).await.unwrap();
        assert_eq!(probe.start.waiter_count(), 0);
        wait_for_complete(trace, identity).await;
        row
    }

    async fn budget_composition(cx: &Cx, trace: &TraceSnapshot) -> serde_json::Value {
        let probe = Arc::new(Probe::default());
        let child_probe = Arc::clone(&probe);
        let mut handle = cx.spawn(move |child_cx| -> OwnedFuture<serde_json::Value> {
            Box::pin(async move {
                let probe = child_probe;
                *probe.identity.lock() = Some((child_cx.task_id(), child_cx.region_id()));
                *probe.context.lock() = Some(child_cx.clone());
                let mut gate = std::pin::pin!(probe.start.notified());
                poll_fn(|context| {
                    let result = gate.as_mut().poll(context);
                    probe.pending.store(result.is_pending(), Ordering::SeqCst);
                    probe.changed.notify_one();
                    result
                }).await;
                assert!(child_cx.is_cancel_requested());
                let one = returned_bound(&child_cx, Case::MpscReceive);
                let three = one.checked_repeat(3).unwrap();
                for quota in [2, 3, 4] {
                    let proposal = three.check_poll_budget(Budget::INFINITE.with_poll_quota(quota));
                    if quota == 2 {
                        assert_eq!(proposal, Err(ResponsivenessRefusal::InsufficientPollBudget {required:3, available:2}));
                    } else {
                        assert_eq!(proposal, Ok(three));
                    }
                }
                assert_eq!(one.check_poll_budget(Budget::INFINITE.with_poll_quota(0)),
                    Err(ResponsivenessRefusal::InsufficientPollBudget {required:1, available:0}));
                assert_eq!(one.checked_repeat(0).unwrap().check_poll_budget(Budget::INFINITE.with_poll_quota(0)).unwrap().steps(), 0);
                let largest = one.checked_repeat(u64::MAX).unwrap();
                assert_eq!(largest.checked_then(one), Err(ResponsivenessRefusal::Overflow));
                assert_eq!(largest.checked_repeat(2), Err(ResponsivenessRefusal::Overflow));
                assert_eq!(ResponsivenessRegistry::checked_mask_depth(u32::MAX, 1), Err(ResponsivenessRefusal::Overflow));
                for _ in 0..3 {
                    let (sender, mut receiver) = mpsc::channel::<u8>(1);
                    assert_eq!(measured(&child_cx, &probe, receiver.recv(&child_cx), || {
                        panic!("cancel was published before each real receive")
                    }).await, Err(mpsc::RecvError::Cancelled));
                    assert_eq!(sender.telemetry_snapshot(10).recv_waiter_count, 0);
                    assert_eq!(sender.telemetry_snapshot(10).queued_messages, 0);
                }
                let observed = probe.cancelled_polls.load(Ordering::SeqCst);
                assert_eq!(observed, 3);
                three.check_observed(observed, true).unwrap();
                probe.operation_waker.lock().take();
                serde_json::json!({
                    "control":"actual_three_phase_composition","task":child_cx.task_id(),"region":child_cx.region_id(),
                    "unit":"operation_polls","observed":observed,"typed_results":["Cancelled","Cancelled","Cancelled"],
                    "headroom_below":2,"headroom_at":3,"headroom_above":4,
                    "below_refusal":"InsufficientPollBudget","zero_and_overflow_refused":true,
                    "scope":"proposed poll headroom compared with actual operation calls; no automatic native budget charging"
                })
            })
        }).unwrap();
        until(&probe, || probe.pending.load(Ordering::SeqCst)).await;
        let identity = probe.identity.lock().unwrap();
        handle.abort_with_reason(CancelReason::user("three phase cancellation"));
        until(&probe, || {
            probe.context.lock().as_ref().unwrap().is_cancel_requested()
        })
        .await;
        assert!(probe.start.notify_one());
        let row = poll_fn(|context| handle.poll_join(context)).await.unwrap();
        assert_eq!(probe.start.waiter_count(), 0);
        wait_for_complete(trace, identity).await;
        row
    }

    async fn journeys(cx: Cx, trace: TraceSnapshot, sockets: bool) -> serde_json::Value {
        let mut rows = Vec::new();
        for case in CASES {
            if !case.socket() || sockets {
                rows.push(journey(&cx, &trace, case).await);
            }
        }
        let mut controls = Vec::new();
        for generic_read in [false, true] {
            controls.push(withheld_progress(&cx, &trace, generic_read).await);
        }
        for depth in [1, 64] {
            controls.push(masked_wait(&cx, &trace, depth).await);
        }
        controls.push(budget_composition(&cx, &trace).await);
        let mut explicit_refusals = Vec::new();
        for entry in ResponsivenessRegistry::entries() {
            let result = entry.bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(&cx, CancelKind::User),
            );
            if CASES.iter().any(|case| case.id() == entry.id()) {
                assert!(result.is_ok(), "known finite phase: {}", entry.id());
            } else {
                let refusal = result.expect_err("inventoried unbounded phase must refuse");
                assert_ne!(refusal, ResponsivenessRefusal::UnknownOperation);
                explicit_refusals
                    .push(serde_json::json!({"entry":entry.id(),"refusal":format!("{refusal:?}")}));
            }
        }
        assert_eq!(explicit_refusals.len(), 24);
        serde_json::json!({"journeys":rows,"controls":controls,"explicit_refusals":explicit_refusals})
    }

    #[test]
    fn stock_responsiveness_runtime_seeded_lab_park_cancel_and_drain() {
        for seed in [0x3101, 0x3102, 0x3103] {
            let mut lab = LabRuntime::new(
                LabConfig::new(seed)
                    .max_steps(100_000)
                    .trace_capacity(100_000),
            );
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trace = lab.state.trace_handle();
            let coordinator: OwnedFuture<serde_json::Value> = Box::pin(async move {
                journeys(
                    Cx::current().unwrap(),
                    Box::new(move || trace.snapshot()),
                    false,
                )
                .await
            });
            let (task, mut result) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            let rows = result
                .try_join()
                .unwrap()
                .expect("all actual Lab tasks returned");
            assert_eq!(rows["journeys"].as_array().unwrap().len(), 18);
            assert_eq!(rows["controls"].as_array().unwrap().len(), 5);
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.leak_count(), 0);
            let gateway = lab.state.obligation_gateway().unwrap();
            let mailbox = gateway.mailbox();
            let stats = mailbox.stats();
            assert_eq!(stats.posted, stats.applied);
            assert_eq!(stats.reserved, stats.committed + stats.aborted);
            assert_eq!(mailbox.open_tickets(), 0);
            assert!(mailbox.is_empty());
            assert_eq!(lab.state.region(root).unwrap().pending_obligations(), 0);
            assert_eq!(
                lab.state.region(root).unwrap().unapplied_obligation_count(),
                0
            );
            assert!(
                lab.state.trace_handle().total_pushed()
                    < lab.state.trace_handle().capacity() as u64
            );
            let report = lab.run_until_quiescent_with_report();
            assert!(report.lab_test_passed(), "{report:?}");
            assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
            let effects = lab.state.cancel_request(
                root,
                &CancelReason::user("responsiveness complete"),
                None,
            );
            let (tasks, wakes) = effects.into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ASUPERSYNC_RESPONSIVENESS_RUNTIME {}",
                serde_json::json!({
                    "backend":"lab","seed":seed,"evidence":rows,"live_tasks":0,
                    "pending_obligations":0,"leaks":0,"region_closed":true,
                    "scope":"actual deterministic runtime scheduling; no OS signal or socket delivery"
                })
            );
        }
    }

    #[test]
    fn stock_responsiveness_runtime_native_park_cancel_and_drain() {
        for sharded in [false, true] {
            let (finished, completion) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| native(sharded));
                let _ = finished.send(result);
            });
            let result = completion.recv_timeout(Duration::from_secs(90)).expect(
                "whole native journey watchdog; timeout is not a responsiveness bound or pass",
            );
            worker.join().unwrap();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }
    }

    #[test]
    fn stock_responsiveness_runtime_lab_charges_real_finite_task_budgets() {
        // Three receive phases occupy three actual task polls. Cleanup needs a
        // fourth delivered poll. The Lab charges BEFORE polling; a checkpoint
        // at a remaining quota of zero reports PollQuota rather than reading.
        // Therefore the actual minimum here is four initial task credits, even
        // though the separate operation-only composition above has size three.
        for seed in [0x3101, 0x3102, 0x3103] {
            for initial_quota in [3_u32, 4, 5] {
                let mut lab = LabRuntime::new(
                    LabConfig::new(seed)
                        .max_steps(10_000)
                        .trace_capacity(10_000),
                );
                let root = lab.state.create_root_region(Budget::INFINITE);
                let (sender, mut receiver) = mpsc::channel::<u8>(3);
                for value in [71, 73, 79] {
                    sender.try_send(value).unwrap();
                }
                let semaphore = Arc::new(Semaphore::new(1));
                let cleanup = Arc::new(Notify::new());
                let cleanup_pending = Arc::new(AtomicBool::new(false));
                let delivered = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
                let failure = Arc::new(parking_lot::Mutex::new(None::<CancelReason>));
                let returned_receiver = Arc::new(parking_lot::Mutex::new(None));
                let operation_calls = Arc::new(AtomicU64::new(0));
                let dispatched_quotas = Arc::new(parking_lot::Mutex::new(Vec::<u32>::new()));
                let worker_semaphore = Arc::clone(&semaphore);
                let worker_cleanup = Arc::clone(&cleanup);
                let worker_pending = Arc::clone(&cleanup_pending);
                let worker_delivered = Arc::clone(&delivered);
                let worker_failure = Arc::clone(&failure);
                let worker_receiver = Arc::clone(&returned_receiver);
                let worker_calls = Arc::clone(&operation_calls);
                let mut body: OwnedFuture<()> = Box::pin(async move {
                    let cx = Cx::current().expect("actual finite-budget Lab task");
                    let permit = worker_semaphore.acquire_checked(&cx, 1).await.unwrap();
                    for index in 0..3 {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        match receiver.recv(&cx).await {
                            Ok(value) => worker_delivered.lock().push(value),
                            Err(mpsc::RecvError::Cancelled) => {
                                let reason = cx.cancel_reason().expect("actual budget exhaustion");
                                assert_eq!(reason.kind, CancelKind::PollQuota);
                                *worker_failure.lock() = Some(reason);
                                break;
                            }
                            result => panic!("unexpected real receive result: {result:?}"),
                        }
                        if index < 2 {
                            asupersync::runtime::yield_now().await;
                        }
                    }
                    *worker_receiver.lock() = Some(receiver);
                    let mut wait = std::pin::pin!(worker_cleanup.notified());
                    poll_fn(|context| {
                        let result = wait.as_mut().poll(context);
                        if result.is_pending() {
                            assert_eq!(worker_cleanup.waiter_count(), 1);
                            worker_pending.store(true, Ordering::SeqCst);
                        }
                        result
                    })
                    .await;
                    drop(permit);
                });
                let worker_quotas = Arc::clone(&dispatched_quotas);
                let metered: OwnedFuture<()> = Box::pin(poll_fn(move |context| {
                    // Read what the actual Lab pre-poll charge installed; this
                    // wrapper never mutates the budget or invokes consume_poll.
                    worker_quotas
                        .lock()
                        .push(Cx::current().unwrap().budget().poll_quota);
                    body.as_mut().poll(context)
                }));
                let (task, mut handle) = lab
                    .state
                    .create_task(
                        root,
                        Budget::INFINITE.with_poll_quota(initial_quota),
                        metered,
                    )
                    .unwrap();
                lab.scheduler.lock().schedule(task, 0);
                lab.run_until_idle();
                assert!(cleanup_pending.load(Ordering::SeqCst));
                assert_eq!(cleanup.waiter_count(), 1);
                assert_eq!(semaphore.available_permits(), 0);
                assert_eq!(semaphore.telemetry_snapshot(11).waiter_count, 0);
                assert_eq!(operation_calls.load(Ordering::SeqCst), 3);
                let quotas_before_release = dispatched_quotas.lock().clone();
                assert!(quotas_before_release.len() >= 3);
                assert_eq!(
                    &quotas_before_release[..3],
                    &[initial_quota - 1, initial_quota - 2, initial_quota - 3,]
                );
                let task_before_release = lab.state.task(task).expect("actual held cleanup owner");
                assert_eq!(task_before_release.owner, root);
                assert!(!task_before_release.state.is_terminal());
                assert_eq!(
                    lab.certificate().decisions(),
                    quotas_before_release.len() as u64
                );
                assert_eq!(
                    complete_count(&lab.state.trace_handle().snapshot(), (task, root)),
                    0
                );
                assert!(matches!(handle.try_join(), Ok(None)));
                assert_eq!(
                    lab.state.pending_obligation_count(),
                    1,
                    "actual checked permit remains owned until real cleanup release"
                );
                if initial_quota == 3 {
                    assert_eq!(*delivered.lock(), [71, 73]);
                    assert_eq!(failure.lock().as_ref().unwrap().kind, CancelKind::PollQuota);
                    assert_eq!(sender.telemetry_snapshot(12).queued_messages, 1);
                } else {
                    assert_eq!(*delivered.lock(), [71, 73, 79]);
                    assert!(failure.lock().is_none());
                    assert_eq!(quotas_before_release.len(), 3);
                    assert_eq!(sender.telemetry_snapshot(12).queued_messages, 0);
                }
                assert!(cleanup.notify_one());
                lab.run_until_idle();
                if initial_quota == 3 {
                    let actual_reason = failure.lock().clone().unwrap();
                    assert!(matches!(handle.try_join(),
                        Err(asupersync::runtime::JoinError::Cancelled(reason)) if reason == actual_reason));
                } else {
                    assert!(matches!(handle.try_join(), Ok(Some(()))));
                    assert_eq!(dispatched_quotas.lock().len(), 4);
                }
                let mut receiver = returned_receiver.lock().take().unwrap();
                if initial_quota == 3 {
                    assert_eq!(
                        receiver.try_recv(),
                        Ok(79),
                        "exhaustion cannot consume the remaining value"
                    );
                }
                assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
                assert_eq!(sender.telemetry_snapshot(12).recv_waiter_count, 0);
                assert_eq!(semaphore.available_permits(), 1);
                assert_eq!(cleanup.waiter_count(), 0);
                assert_eq!(lab.state.live_task_count(), 0);
                assert_eq!(
                    lab.certificate().decisions(),
                    dispatched_quotas.lock().len() as u64,
                    "the single admitted task accounts for every real scheduler decision"
                );
                assert_eq!(lab.state.pending_obligation_count(), 0);
                assert_eq!(lab.state.leak_count(), 0);
                assert_eq!(
                    complete_count(&lab.state.trace_handle().snapshot(), (task, root)),
                    1
                );
                let gateway = lab.state.obligation_gateway().unwrap();
                let mailbox = gateway.mailbox();
                let stats = mailbox.stats();
                assert_eq!(stats.posted, stats.applied);
                assert_eq!(stats.reserved, 1);
                assert_eq!(stats.reserved, stats.committed + stats.aborted);
                assert_eq!(mailbox.open_tickets(), 0);
                assert!(mailbox.is_empty());
                let report = lab.run_until_quiescent_with_report();
                assert!(report.lab_test_passed(), "{report:?}");
                assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
                let effects = lab.state.cancel_request(
                    root,
                    &CancelReason::user("finite budget finished"),
                    None,
                );
                let (tasks, wakes) = effects.into_parts();
                assert!(tasks.is_empty());
                wakes.dispatch();
                lab.state.advance_region_state(root);
                assert!(lab.state.region(root).is_none());
                assert!(lab.run_until_quiescent_with_report().lab_test_passed());
                eprintln!(
                    "ASUPERSYNC_RESPONSIVENESS_LAB_BUDGET {}",
                    serde_json::json!({
                        "seed":seed,"task":task,"region":root,"initial_task_poll_quota":initial_quota,
                        "actual_minimum_for_three_reads_and_cleanup":4,
                    "actual_dispatched_remaining_quotas":*dispatched_quotas.lock(),
                    "actual_scheduler_dispatches":lab.certificate().decisions(),
                        "operation_calls":operation_calls.load(Ordering::SeqCst),
                        "delivered":*delivered.lock(),"actual_failure":*failure.lock(),
                        "cleanup_was_pending":true,"checked_permits_before_release":1,
                        "live_tasks":0,"pending_obligations":0,"leaks":0,"region_closed":true,
                        "scope":"actual Lab task poll charging; distinct from operation-only headroom and no native charging claim"
                    })
                );
            }
        }
    }

    fn native(sharded: bool) {
        let runtime = if sharded {
            RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .trace_storage_profile(asupersync::runtime::config::TraceStorageProfile::LargeMemory256G)
        .build()
        .unwrap();
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(
            runtime.config().runtime_state_shape,
            if sharded {
                asupersync::runtime::config::RuntimeStateShape::Sharded
            } else {
                asupersync::runtime::config::RuntimeStateShape::Unified
            }
        );
        let observer = runtime.handle();
        let coordinator: OwnedFuture<serde_json::Value> = Box::pin(async move {
            journeys(
                Cx::current().unwrap(),
                Box::new(move || observer.trace_snapshot().unwrap()),
                true,
            )
            .await
        });
        let rows = runtime.block_on(runtime.handle().spawn(coordinator));
        assert_eq!(rows["journeys"].as_array().unwrap().len(), 20);
        assert_eq!(rows["controls"].as_array().unwrap().len(), 5);
        runtime.block_on(async {
            let started = Instant::now();
            while !runtime.is_quiescent() {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "native ownership did not drain"
                );
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.trace_snapshot().len() < runtime.trace_buffer_capacity());
        assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
        eprintln!(
            "ASUPERSYNC_RESPONSIVENESS_RUNTIME {}",
            serde_json::json!({
                "backend":if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
                "evidence":rows,"live_tasks":0,"leaks":0,"shutdown_completed":true,
                "scope":"actual native parked cancellation and joined cleanup; watchdog is not a mathematical bound"
            })
        );
    }
}
