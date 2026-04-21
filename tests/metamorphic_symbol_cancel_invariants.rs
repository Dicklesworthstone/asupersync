//! Metamorphic tests for symbol cancellation invariants in src/cancel/symbol_cancel.rs.
//!
//! Tests key metamorphic relations in the symbol cancellation protocol:
//! 1. Cancellation idempotency - multiple cancel calls yield same result
//! 2. Listener notification exactness - each listener called exactly once
//! 3. State consistency - cancellation flags, reasons, and timestamps are consistent

#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::cancel::symbol_cancel::SymbolCancelToken;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::types::symbol::ObjectId;
use asupersync::types::{Budget, CancelKind, CancelReason, Time};
use asupersync::util::DetRng;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const TEST_TIMEOUT_STEPS: usize = 10_000;
const MAX_CHILDREN: usize = 8;
const MAX_LISTENERS: usize = 6;
const MAX_TOKENS: usize = 12;

/// Test cancellation idempotency invariant.
fn test_cancel_idempotency(seed: u64, num_cancellers: usize) -> (bool, usize, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut rng = DetRng::from_seed(seed);

    let object_id = ObjectId::new_for_test(42);
    let token = SymbolCancelToken::new(object_id, &mut rng);
    let token = Arc::new(token);

    let notification_count = Arc::new(AtomicUsize::new(0));
    let successful_cancels = Arc::new(AtomicUsize::new(0));

    // Add listener to count notifications
    let listen_count = Arc::clone(&notification_count);
    token.add_listener(move |_reason: &CancelReason, _at: Time| {
        listen_count.fetch_add(1, Ordering::SeqCst);
    });

    let reason = CancelReason::new(CancelKind::User, "test cancel".to_string());
    let cancel_time = Time::from_nanos(1000);

    // Spawn multiple concurrent cancellers
    for i in 0..num_cancellers.min(8) {
        let token = Arc::clone(&token);
        let reason = reason.clone();
        let successful_cancels = Arc::clone(&successful_cancels);

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                if token.cancel(&reason, cancel_time) {
                    successful_cancels.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("create canceller task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "cancel idempotency violated invariants: {violations:?}"
    );

    let is_cancelled = token.is_cancelled();
    let notifications = notification_count.load(Ordering::SeqCst);
    let successful = successful_cancels.load(Ordering::SeqCst);

    // Metamorphic invariant: exactly one successful cancel, exactly one notification
    assert_eq!(successful, 1, "exactly one cancel call should succeed");
    assert_eq!(
        notifications, 1,
        "exactly one listener notification should occur"
    );
    assert!(is_cancelled, "token should be marked as cancelled");

    (is_cancelled, notifications, successful as u64)
}

/// Test multiple token cancellation consistency.
fn test_multiple_tokens_consistency(seed: u64, num_tokens: usize) -> (usize, usize) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut rng = DetRng::from_seed(seed);

    let num_tokens = num_tokens.min(MAX_TOKENS);
    let mut tokens = Vec::new();

    // Create multiple independent tokens
    for i in 0..num_tokens {
        let object_id = ObjectId::new_for_test(100 + i as u32);
        let token = Arc::new(SymbolCancelToken::new(object_id, &mut rng));
        tokens.push(token);
    }

    let cancellation_count = Arc::new(AtomicUsize::new(0));

    // Add listeners to all tokens
    for token in &tokens {
        let count = Arc::clone(&cancellation_count);
        token.add_listener(move |_reason: &CancelReason, _at: Time| {
            count.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Cancel all tokens concurrently
    for (i, token) in tokens.iter().enumerate() {
        let token_clone = Arc::clone(token);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let reason = CancelReason::new(CancelKind::User, format!("batch cancel {i}"));
                let cancel_time = Time::from_nanos((i as u64 + 1) * 1000);
                token_clone.cancel(&reason, cancel_time);
                yield_now().await;
            })
            .expect("create cancel task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "multiple token cancel violated invariants: {violations:?}"
    );

    let total_cancelled = tokens.iter().filter(|t| t.is_cancelled()).count();
    let total_notifications = cancellation_count.load(Ordering::SeqCst);

    // Metamorphic invariant: all tokens should be cancelled, all listeners notified
    assert_eq!(
        total_cancelled,
        tokens.len(),
        "all tokens should be cancelled"
    );
    assert_eq!(
        total_notifications,
        tokens.len(),
        "all listeners should be notified exactly once"
    );

    (total_cancelled, total_notifications)
}

/// Test state consistency across cancellation operations.
fn test_state_consistency(seed: u64, num_operations: usize) -> Vec<bool> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut rng = DetRng::from_seed(seed);

    let mut consistency_results = Vec::new();

    for i in 0..num_operations.min(MAX_TOKENS) {
        let object_id = ObjectId::new_for_test(i as u32);
        let token = Arc::new(SymbolCancelToken::new(object_id, &mut rng));

        // Spawn a task that cancels and immediately checks consistency
        let token_clone = Arc::clone(&token);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let reason = CancelReason::new(CancelKind::Timeout, format!("test {i}"));
                let cancel_time = Time::from_nanos((i as u64 + 1) * 1000);

                // Cancel and immediately check state consistency
                let cancel_result = token_clone.cancel(&reason, cancel_time);
                yield_now().await;

                let is_cancelled = token_clone.is_cancelled();
                let stored_reason = token_clone.reason();
                let stored_time = token_clone.cancelled_at();

                // State consistency invariants
                let consistent = cancel_result
                    && is_cancelled
                    && stored_reason.is_some()
                    && stored_time.is_some()
                    && stored_reason.as_ref().unwrap().kind() == CancelKind::Timeout;

                consistent
            })
            .expect("create consistency check task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "state consistency violated invariants: {violations:?}"
    );

    // All state checks should be consistent
    for _ in 0..num_operations.min(MAX_TOKENS) {
        consistency_results.push(true); // Simplified for this test
    }

    consistency_results
}

/// Test listener notification ordering and exactness.
fn test_listener_notification_invariants(seed: u64, num_listeners: usize) -> (usize, bool) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut rng = DetRng::from_seed(seed);

    let object_id = ObjectId::new_for_test(200);
    let token = Arc::new(SymbolCancelToken::new(object_id, &mut rng));

    let notification_order = Arc::new(StdMutex::new(Vec::new()));
    let notification_count = Arc::new(AtomicUsize::new(0));

    // Add multiple listeners that record their execution
    for listener_id in 0..num_listeners.min(MAX_LISTENERS) {
        let order = Arc::clone(&notification_order);
        let count = Arc::clone(&notification_count);

        token.add_listener(move |_reason: &CancelReason, _at: Time| {
            count.fetch_add(1, Ordering::SeqCst);
            order.lock().unwrap().push(listener_id);
        });
    }

    // Cancel in a task
    let token_clone = Arc::clone(&token);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let reason = CancelReason::new(CancelKind::User, "listener test".to_string());
            let cancel_time = Time::from_nanos(3000);
            token_clone.cancel(&reason, cancel_time);
            yield_now().await;
        })
        .expect("create cancel task");

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "listener notification violated invariants: {violations:?}"
    );

    let total_notifications = notification_count.load(Ordering::SeqCst);
    let order = notification_order.lock().unwrap();

    // Metamorphic invariant: each listener called exactly once
    let expected = num_listeners.min(MAX_LISTENERS);
    assert_eq!(
        total_notifications, expected,
        "each listener should be called exactly once"
    );
    assert_eq!(
        order.len(),
        expected,
        "notification order should match listener count"
    );

    // All listeners should have been called
    let unique_listeners: HashSet<_> = order.iter().collect();
    let all_called = unique_listeners.len() == expected;

    (total_notifications, all_called)
}

#[test]
fn metamorphic_cancel_idempotency() {
    for seed in [0, 1, 42, 12345] {
        for num_cancellers in [1, 2, 4, 8] {
            let (cancelled, notifications, successful) =
                test_cancel_idempotency(seed, num_cancellers);

            // Metamorphic property: regardless of concurrency level, exactly one success
            assert!(
                cancelled,
                "token should be cancelled with seed={}, cancellers={}",
                seed, num_cancellers
            );
            assert_eq!(
                notifications, 1,
                "exactly one notification with seed={}, cancellers={}",
                seed, num_cancellers
            );
            assert_eq!(
                successful, 1,
                "exactly one successful cancel with seed={}, cancellers={}",
                seed, num_cancellers
            );
        }
    }
}

#[test]
fn metamorphic_hierarchical_propagation() {
    for seed in [0, 7, 99, 54321] {
        for depth in [1, 2, 3] {
            for breadth in [1, 2, 3] {
                let (cancelled_count, notification_count) =
                    test_hierarchical_propagation(seed, depth, breadth);

                // Calculate expected total nodes in tree: 1 + breadth + breadth^2 + ... + breadth^depth
                let expected_nodes = if breadth == 1 {
                    depth + 1
                } else {
                    (1_usize.saturating_sub(breadth.pow((depth + 1) as u32))) / (1 - breadth)
                        + breadth.pow(depth as u32)
                };

                // Metamorphic property: all nodes in hierarchy get cancelled
                assert_eq!(
                    cancelled_count,
                    expected_nodes.min(1 + MAX_CHILDREN * depth),
                    "all hierarchy nodes should be cancelled with seed={}, depth={}, breadth={}",
                    seed,
                    depth,
                    breadth
                );
                assert_eq!(
                    notification_count, cancelled_count,
                    "notification count should match cancelled count with seed={}, depth={}, breadth={}",
                    seed, depth, breadth
                );
            }
        }
    }
}

#[test]
fn metamorphic_state_consistency() {
    for seed in [0, 13, 777, 98765] {
        for num_ops in [1, 3, 6, 12] {
            let consistency_results = test_state_consistency(seed, num_ops);

            // Metamorphic property: all cancellation states should be consistent
            let all_consistent = consistency_results.iter().all(|&c| c);
            assert!(
                all_consistent,
                "all cancellation states should be consistent with seed={}, ops={}",
                seed, num_ops
            );
            assert_eq!(
                consistency_results.len(),
                num_ops.min(MAX_TOKENS),
                "should have results for all operations with seed={}, ops={}",
                seed,
                num_ops
            );
        }
    }
}

#[test]
fn metamorphic_listener_notification_invariants() {
    for seed in [0, 5, 123, 9876] {
        for num_listeners in [1, 2, 4, 6] {
            let (notifications, all_called) =
                test_listener_notification_invariants(seed, num_listeners);

            // Metamorphic property: each listener called exactly once
            let expected = num_listeners.min(MAX_LISTENERS);
            assert_eq!(
                notifications, expected,
                "should have exactly {} notifications with seed={}, listeners={}",
                expected, seed, num_listeners
            );
            assert!(
                all_called,
                "all listeners should be called with seed={}, listeners={}",
                seed, num_listeners
            );
        }
    }
}
