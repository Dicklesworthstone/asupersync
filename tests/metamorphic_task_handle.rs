#![allow(clippy::all)]
//! Metamorphic Testing: TaskHandle join/cancel/detach interactions
//!
//! Tests the mathematical properties and protocol invariants of TaskHandle
//! operations including join(), abort(), try_join(), and drop semantics.
//! Uses metamorphic relations to verify behavioral consistency under various
//! operation sequences and state transitions.
//!
//! # Core Metamorphic Relations Tested
//!
//! ## MR1: Result Conservation (Equivalence)
//! For successful completion: join() result ≡ try_join() result when ready
//! - Both methods must yield identical values for successful tasks
//! - Error types and payloads must be preserved exactly
//! - Terminal state must be consistent across methods
//!
//! ## MR2: Terminal State Preservation (Invertive)
//! Once terminal_consumed = true: all subsequent operations return PolledAfterCompletion
//! - join() → PolledAfterCompletion for repolls
//! - try_join() → PolledAfterCompletion after consumption
//! - is_finished() behavior must remain consistent
//!
//! ## MR3: Drop-Abort Consistency (Equivalence)
//! drop(join_future) ≡ abort() when task is pending
//! - Dropping join future should cancel task with same reason as explicit abort
//! - Terminal tasks should not be affected by drop-abort
//! - Defused drops should not trigger abort
//!
//! ## MR4: Error Propagation Preservation (Equivalence)
//! Error details preserved across all access methods:
//! - Cancel reasons must be identical between join/try_join/abort
//! - Panic payloads must be preserved exactly
//! - Error timing should not affect error content
//!
//! ## MR5: ID Preservation (Equivalence)
//! task_id() returns constant value regardless of handle state
//! - Task ID must never change during handle lifetime
//! - Operations should not affect ID accessibility
//! - Cloning handle should preserve same task ID
//!
//! ## MR6: Join Future Drop Safety (Conditional Equivalence)
//! drop(join_future) behavior depends on terminal state:
//! - If pending: triggers abort with reason
//! - If ready: no abort triggered (no side effects)
//! - If defused: no abort regardless of state
//!
//! ## MR7: Cancel Reason Strengthening (Additive)
//! Multiple abort() calls strengthen cancel reason:
//! - abort_with_reason(A) + abort_with_reason(B) ≡ strengthen(A, B)
//! - Reason precedence preserved (timeout > user > race_lost)
//! - Final reason contains strongest components
//!
//! ## MR8: Try Join State Consistency (Equivalence)
//! try_join() state transitions match join() state logic:
//! - Ready → Some(result) + terminal_consumed=true
//! - Closed → Cancelled(reason) + terminal_consumed=true
//! - Empty → None + terminal_consumed=false
//! - Consumed → PolledAfterCompletion
//!
//! ## MR9: Finish Status Correlation (Equivalence)
//! is_finished() correlates with operation availability:
//! - is_finished()=true ⟺ try_join() returns immediate result
//! - is_finished()=false ⟺ join() may block
//! - Terminal consumption affects finish status
//!
//! ## MR10: Join Method Independence (Equivalence)
//! join() vs join_with_drop_reason() preserve core semantics:
//! - Success cases yield identical results
//! - Only drop behavior differs (abort reason)
//! - Poll sequences must be equivalent until drop

use proptest::prelude::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::runtime::task_handle::{JoinError, TaskHandle};
use asupersync::types::{Budget, CancelReason, PanicPayload, TaskId};
use asupersync::util::ArenaIndex;

// Test utilities
fn test_cx() -> Cx {
    Cx::new(
        asupersync::RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// Property-based test data generators
prop_compose! {
    fn task_result()
        (success in any::<bool>(),
         value in any::<i32>(),
         cancel_reason_type in 0u8..=3,
         panic_msg in prop::collection::vec(prop::char::any(), 1..=20))
        -> Result<i32, JoinError> {
        if success {
            Ok(value)
        } else {
            let reason = match cancel_reason_type {
                0 => CancelReason::user("test"),
                1 => CancelReason::timeout(),
                2 => CancelReason::race_loser(),
                _ => CancelReason::user("custom"),
            };

            if cancel_reason_type < 3 {
                Err(JoinError::Cancelled(reason))
            } else {
                let msg: String = panic_msg.into_iter().collect();
                Err(JoinError::Panicked(PanicPayload::new(&msg)))
            }
        }
    }
}

prop_compose! {
    fn operation_sequence()
        (operations in prop::collection::vec(operation_type(), 1..=20))
        -> Vec<HandleOperation> {
        operations
    }
}

#[derive(Debug, Clone)]
enum HandleOperation {
    Join,
    TryJoin,
    Abort,
    DropJoin,
    DropJoinWithReason,
    CheckFinished,
    CheckTaskId,
    DefuseDropThenJoin,
}

fn operation_type() -> impl Strategy<Value = HandleOperation> {
    prop_oneof![
        Just(HandleOperation::Join),
        Just(HandleOperation::TryJoin),
        Just(HandleOperation::Abort),
        Just(HandleOperation::DropJoin),
        Just(HandleOperation::DropJoinWithReason),
        Just(HandleOperation::CheckFinished),
        Just(HandleOperation::CheckTaskId),
        Just(HandleOperation::DefuseDropThenJoin),
    ]
}

// ============================================================================
// MR1: Result Conservation (join() ≡ try_join() for ready results)
// ============================================================================

proptest! {
    #[test]
    fn mr1_result_conservation_success(value in any::<i32>()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        // Send success result
        tx.send(&cx, Ok(value)).unwrap();

        // Test join() result
        let mut handle1 = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let join_result = block_on(handle1.join(&cx));

        // Create second handle with same result
        let (tx2, rx2) = oneshot::channel::<Result<i32, JoinError>>();
        tx2.send(&cx, Ok(value)).unwrap();
        let mut handle2 = TaskHandle::new(task_id, rx2, std::sync::Weak::new());

        // Test try_join() result after result is ready
        let try_join_result = handle2.try_join().unwrap();

        // MR1: Both methods must yield identical results for successful tasks
        prop_assert_eq!(join_result, Ok(value), "join() should return original value");
        prop_assert_eq!(
            try_join_result,
            Some(value),
            "try_join() should return original value"
        );
    }

    #[test]
    fn mr1_result_conservation_cancelled(cancel_type in 0u8..=2) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(2, 0));

        let reason = match cancel_type {
            0 => CancelReason::user("test"),
            1 => CancelReason::timeout(),
            _ => CancelReason::race_loser(),
        };

        // Test join() with cancel result
        let (tx1, rx1) = oneshot::channel::<Result<i32, JoinError>>();
        tx1.send(&cx, Err(JoinError::Cancelled(reason.clone()))).unwrap();
        let mut handle1 = TaskHandle::new(task_id, rx1, std::sync::Weak::new());
        let join_result = block_on(handle1.join(&cx));

        // Test try_join() with same cancel result
        let (tx2, rx2) = oneshot::channel::<Result<i32, JoinError>>();
        tx2.send(&cx, Err(JoinError::Cancelled(reason.clone()))).unwrap();
        let mut handle2 = TaskHandle::new(task_id, rx2, std::sync::Weak::new());
        let try_join_result = handle2.try_join();

        // MR1: Both methods must preserve cancel reasons identically
        match (join_result, try_join_result) {
            (Err(JoinError::Cancelled(r1)), Err(JoinError::Cancelled(r2))) => {
                prop_assert_eq!(r1.kind, r2.kind, "Cancel reasons must match between join/try_join");
            },
            _ => prop_assert!(false, "Both methods should return Cancelled error"),
        }
    }

    #[test]
    fn mr1_result_conservation_panicked(panic_msg in prop::collection::vec(prop::char::any(), 1..=10)) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(3, 0));
        let msg: String = panic_msg.into_iter().collect();

        // Test join() with panic result
        let (tx1, rx1) = oneshot::channel::<Result<i32, JoinError>>();
        tx1.send(&cx, Err(JoinError::Panicked(PanicPayload::new(&msg)))).unwrap();
        let mut handle1 = TaskHandle::new(task_id, rx1, std::sync::Weak::new());
        let join_result = block_on(handle1.join(&cx));

        // Test try_join() with same panic result
        let (tx2, rx2) = oneshot::channel::<Result<i32, JoinError>>();
        tx2.send(&cx, Err(JoinError::Panicked(PanicPayload::new(&msg)))).unwrap();
        let mut handle2 = TaskHandle::new(task_id, rx2, std::sync::Weak::new());
        let try_join_result = handle2.try_join();

        // MR1: Both methods must preserve panic payloads identically
        match (join_result, try_join_result) {
            (Err(JoinError::Panicked(p1)), Err(JoinError::Panicked(p2))) => {
                prop_assert_eq!(p1.to_string(), p2.to_string(),
                    "Panic payloads must match between join/try_join");
            },
            _ => prop_assert!(false, "Both methods should return Panicked error"),
        }
    }
}

// ============================================================================
// MR2: Terminal State Preservation (repolls return PolledAfterCompletion)
// ============================================================================

proptest! {
    #[test]
    fn mr2_terminal_state_preservation(result in task_result()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(4, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        // Send result
        tx.send(&cx, result.clone()).unwrap();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // First join should succeed and consume terminal state
        let first_result = block_on(handle.join(&cx));

        // Second try_join should fail with PolledAfterCompletion
        let second_result = handle.try_join();

        // MR2: Once terminal state consumed, all operations return PolledAfterCompletion
        prop_assert!(first_result.is_ok() || matches!(first_result, Err(JoinError::Cancelled(_) | JoinError::Panicked(_))),
            "First join should return result or error, not PolledAfterCompletion");

        prop_assert!(matches!(second_result, Err(JoinError::PolledAfterCompletion)),
            "Second try_join after terminal consumption should return PolledAfterCompletion");
    }

    #[test]
    fn mr2_join_future_repoll_safety(value in any::<i32>()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(5, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        tx.send(&cx, Ok(value)).unwrap();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let mut join_future = Box::pin(handle.join(&cx));

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        // First poll should return result
        let first_poll = join_future.as_mut().poll(&mut poll_cx);

        // Second poll should return PolledAfterCompletion
        let second_poll = join_future.as_mut().poll(&mut poll_cx);

        // MR2: Join future repolls must consistently return PolledAfterCompletion
        prop_assert!(matches!(first_poll, Poll::Ready(Ok(v)) if v == value),
            "First poll should return success result");

        prop_assert!(matches!(second_poll, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "Second poll should return PolledAfterCompletion");
    }
}

// MR3/MR4/MR6/MR7 private-state relations are covered inline in
// `src/runtime/task_handle.rs`, where the crate-private Cx state and
// `defuse_drop_abort()` hook are visible.

// ============================================================================
// MR5: ID Preservation (task_id() immutability)
// ============================================================================

proptest! {
    #[test]
    fn mr5_id_preservation(operations in operation_sequence()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let original_id = handle.task_id();

        // Send a result to make operations meaningful
        tx.send(&cx, Ok(123)).unwrap();

        // Perform various operations
        for operation in operations.iter().take(5) { // Limit operations to avoid terminal consumption conflicts
            match operation {
                HandleOperation::CheckTaskId => {
                    let current_id = handle.task_id();
                    prop_assert_eq!(current_id, original_id, "Task ID must never change");
                },
                HandleOperation::CheckFinished => {
                    let _ = handle.is_finished(); // Should not affect task ID
                    let id_after_check = handle.task_id();
                    prop_assert_eq!(id_after_check, original_id, "is_finished() must not affect task ID");
                },
                HandleOperation::TryJoin => {
                    if handle.try_join().is_ok() {
                        // After successful try_join, ID should still be same
                        let id_after_try_join = handle.task_id();
                        prop_assert_eq!(id_after_try_join, original_id, "try_join() must not affect task ID");
                        break; // Avoid multiple consumptions
                    }
                },
                _ => {
                    // For other operations, just verify ID hasn't changed
                    let id_after_op = handle.task_id();
                    prop_assert_eq!(id_after_op, original_id, "Operations must not affect task ID");
                }
            }
        }

        // MR5: Task ID must remain constant throughout handle lifetime
        let final_id = handle.task_id();
        prop_assert_eq!(final_id, original_id, "Task ID must be immutable across all operations");
    }
}

// ============================================================================
// MR8: Try Join State Consistency
// ============================================================================

proptest! {
    #[test]
    fn mr8_try_join_state_consistency(result in task_result()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Before sending result, try_join should return Ok(None)
        let before_result = handle.try_join();
        prop_assert!(matches!(before_result, Ok(None)), "try_join() should return None when not ready");
        prop_assert!(!handle.is_finished(), "Handle should not be finished before result");

        // Send result
        tx.send(&cx, result.clone()).unwrap();

        // After sending, try_join should return the result
        let after_result = handle.try_join();
        prop_assert!(handle.is_finished(), "Handle should be finished after result consumed");

        // Third try_join should return PolledAfterCompletion
        let third_result = handle.try_join();
        prop_assert!(matches!(third_result, Err(JoinError::PolledAfterCompletion)),
            "try_join() after consumption should return PolledAfterCompletion");

        // MR8: State transitions should be consistent
        match (result, after_result) {
            (Ok(expected), Ok(Some(actual))) => {
                prop_assert_eq!(actual, expected, "Successful result should match");
            },
            (Err(expected_err), Err(actual_err)) => {
                // Error types should match
                match (&expected_err, &actual_err) {
                    (JoinError::Cancelled(e1), JoinError::Cancelled(e2)) => {
                        prop_assert_eq!(e1.kind, e2.kind, "Cancel reasons should match");
                    },
                    (JoinError::Panicked(p1), JoinError::Panicked(p2)) => {
                        prop_assert_eq!(p1.to_string(), p2.to_string(), "Panic payloads should match");
                    },
                    _ => prop_assert!(false, "Error types should match"),
                }
            },
            _ => prop_assert!(false, "Result types should match between send and try_join"),
        }
    }
}

// ============================================================================
// MR9: Finish Status Correlation
// ============================================================================

proptest! {
    #[test]
    fn mr9_finish_status_correlation(send_result in any::<bool>()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(15, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Before sending result
        let before_finished = handle.is_finished();
        let before_try_join = handle.try_join();

        if send_result {
            tx.send(&cx, Ok(42)).unwrap();
        } else {
            drop(tx); // Close channel
        }

        let after_finished = handle.is_finished();
        let after_try_join = handle.try_join();

        // MR9: is_finished() should correlate with try_join() availability
        prop_assert!(!before_finished, "Should not be finished before result/close");
        prop_assert!(matches!(before_try_join, Ok(None)), "try_join should return None when not finished");

        prop_assert!(after_finished, "Should be finished after result/close");
        prop_assert!(!matches!(after_try_join, Ok(None)), "try_join should not return None when finished");
    }
}

// ============================================================================
// MR10: Join Method Independence (core semantics preservation)
// ============================================================================

proptest! {
    #[test]
    fn mr10_join_method_independence(value in any::<i32>(), drop_reason_type in 0u8..=2) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(16, 0));

        let drop_reason = match drop_reason_type {
            0 => CancelReason::user("custom_drop"),
            1 => CancelReason::timeout(),
            _ => CancelReason::race_loser(),
        };

        // Test regular join()
        let (tx1, rx1) = oneshot::channel::<Result<i32, JoinError>>();
        tx1.send(&cx, Ok(value)).unwrap();
        let mut handle1 = TaskHandle::new(task_id, rx1, std::sync::Weak::new());
        let regular_result = block_on(handle1.join(&cx));

        // Test join_with_drop_reason()
        let (tx2, rx2) = oneshot::channel::<Result<i32, JoinError>>();
        tx2.send(&cx, Ok(value)).unwrap();
        let mut handle2 = TaskHandle::new(task_id, rx2, std::sync::Weak::new());
        let drop_reason_result = block_on(handle2.join_with_drop_reason(&cx, drop_reason));

        // MR10: Core join semantics must be identical regardless of drop reason method
        prop_assert_eq!(regular_result.clone(), drop_reason_result,
            "join() and join_with_drop_reason() must yield identical results for successful tasks");

        prop_assert_eq!(regular_result, Ok(value), "Both methods should return the correct value");
    }
}

// ============================================================================
// Compound Metamorphic Relations (Testing multiple invariants together)
// ============================================================================

proptest! {
    #[test]
    fn mr_compound_state_and_result_consistency(value in any::<i32>()) {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(17, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Verify initial state
        let initial_finished = handle.is_finished();
        let initial_id = handle.task_id();
        let initial_try_join = handle.try_join();

        // Send result
        tx.send(&cx, Ok(value)).unwrap();

        // Verify state after result available
        let ready_finished = handle.is_finished();
        let ready_id = handle.task_id();
        let ready_try_join = handle.try_join();

        // Verify state after consumption
        let consumed_finished = handle.is_finished();
        let consumed_id = handle.task_id();
        let consumed_try_join = handle.try_join();

        // Compound invariants: ID preservation + state consistency + result conservation
        prop_assert_eq!(initial_id, ready_id, "Task ID must be preserved during state transitions");
        prop_assert_eq!(ready_id, consumed_id, "Task ID must be preserved after consumption");

        prop_assert!(!initial_finished, "Initially should not be finished");
        prop_assert!(ready_finished, "Should be finished when result ready");
        prop_assert!(consumed_finished, "Should remain finished after consumption");

        prop_assert!(matches!(initial_try_join, Ok(None)), "Initial try_join should return None");
        prop_assert!(matches!(ready_try_join, Ok(Some(v)) if v == value), "Ready try_join should return value");
        prop_assert!(matches!(consumed_try_join, Err(JoinError::PolledAfterCompletion)),
            "Consumed try_join should return PolledAfterCompletion");
    }
}
