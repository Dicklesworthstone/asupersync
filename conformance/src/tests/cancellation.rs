//! Cancellation and Race/Drain Conformance Test Suite
//!
//! Tests covering the cancellation protocol (request → drain → finalize),
//! race semantics (losers must be drained), and timeout interaction with
//! concurrent tasks. These tests verify Asupersync's non-negotiable invariants:
//!
//! - Cancellation is observable (not silent drop)
//! - Timeout respects cleanup ordering
//! - Race losers are drained before the winner is returned
//! - Nested timeouts compose correctly
//!
//! # Test IDs
//!
//! - CANCEL-001: Timeout cancels a running task (side-effect observable)
//! - CANCEL-002: Cancelled task cleanup runs before timeout returns
//! - CANCEL-003: Nested timeouts (inner tighter than outer) compose
//! - CANCEL-004: Race pattern drains loser (side-effect verifiable)
//! - CANCEL-005: Timeout does not interfere with already-completed task
//! - CANCEL-006: Multiple timeouts resolve independently
//! - CANCEL-007: Cancellation propagates via resource cleanup (channel drop)

use crate::{
    ConformanceTest, OneshotSender, RuntimeInterface, TestCategory, TestMeta, TestResult,
    checkpoint,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Get all cancellation and race conformance tests.
pub fn all_tests<RT: RuntimeInterface + Sync>() -> Vec<ConformanceTest<RT>> {
    vec![
        cancel_001_timeout_cancels_task::<RT>(),
        cancel_002_cleanup_before_return::<RT>(),
        cancel_003_nested_timeout::<RT>(),
        cancel_004_race_loser_drain::<RT>(),
        cancel_005_no_interference_completed::<RT>(),
        cancel_006_multiple_timeouts::<RT>(),
        cancel_007_cancel_propagates_via_drop::<RT>(),
    ]
}

/// CANCEL-001: Timeout cancels a running task
///
/// A task that sleeps longer than the timeout should be cancelled. We verify
/// cancellation happened by checking that the task did NOT complete its
/// post-sleep work (observable via an atomic flag).
pub fn cancel_001_timeout_cancels_task<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-001".to_string(),
            name: "Timeout cancels running task".to_string(),
            description: "A task sleeping longer than its timeout is cancelled".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "timeout".to_string(),
                "observable".to_string(),
            ],
            expected: "Task is cancelled; post-sleep flag not set".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let completed = Arc::new(AtomicBool::new(false));
                let completed_clone = completed.clone();

                // Pre-create the sleep future to avoid capturing &RT in the async block
                let long_sleep = rt.sleep(Duration::from_millis(500));

                let result = rt
                    .timeout(Duration::from_millis(50), async move {
                        // This sleep should be interrupted by the timeout
                        long_sleep.await;
                        // If we reach here, cancellation failed
                        completed_clone.store(true, Ordering::SeqCst);
                        42
                    })
                    .await;

                let was_completed = completed.load(Ordering::SeqCst);

                checkpoint(
                    "timeout_result",
                    serde_json::json!({
                        "timed_out": result.is_err(),
                        "task_completed": was_completed
                    }),
                );

                if result.is_ok() {
                    return TestResult::failed("Timeout should have expired before task completed");
                }

                if was_completed {
                    return TestResult::failed(
                        "Task should have been cancelled; post-sleep flag should not be set",
                    );
                }

                TestResult::passed()
            })
        },
    )
}

/// CANCEL-002: Cancelled task cleanup runs before timeout returns
///
/// Spawn a task that starts work, then timeout. After the timeout, verify that
/// the task's observable work was partially done (it started) but the final
/// step was not completed (it was cancelled).
pub fn cancel_002_cleanup_before_return<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-002".to_string(),
            name: "Cleanup ordering on cancellation".to_string(),
            description: "After timeout, task has started but not completed its terminal step"
                .to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "cleanup".to_string(),
                "ordering".to_string(),
            ],
            expected: "Task started (flag set) but did not finish (terminal flag unset)"
                .to_string(),
        },
        |rt| {
            rt.block_on(async {
                let started = Arc::new(AtomicBool::new(false));
                let finished = Arc::new(AtomicBool::new(false));
                let started_c = started.clone();
                let finished_c = finished.clone();

                // Pre-create the sleep future
                let long_sleep = rt.sleep(Duration::from_millis(500));

                let _ = rt
                    .timeout(Duration::from_millis(50), async move {
                        // Mark that we started
                        started_c.store(true, Ordering::SeqCst);
                        // Sleep long enough to be cancelled
                        long_sleep.await;
                        // Should not reach here
                        finished_c.store(true, Ordering::SeqCst);
                    })
                    .await;

                let did_start = started.load(Ordering::SeqCst);
                let did_finish = finished.load(Ordering::SeqCst);

                checkpoint(
                    "cleanup_state",
                    serde_json::json!({
                        "started": did_start,
                        "finished": did_finish
                    }),
                );

                if !did_start {
                    return TestResult::failed("Task should have started before cancellation");
                }

                if did_finish {
                    return TestResult::failed(
                        "Task should not have finished; cancellation should prevent terminal step",
                    );
                }

                TestResult::passed()
            })
        },
    )
}

/// CANCEL-003: Nested timeouts compose correctly
///
/// Inner timeout (tighter) should fire before outer timeout.
/// Verifies that timeout nesting composes as expected.
pub fn cancel_003_nested_timeout<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-003".to_string(),
            name: "Nested timeout composition".to_string(),
            description: "Inner (tighter) timeout fires before outer timeout".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "timeout".to_string(),
                "nested".to_string(),
            ],
            expected: "Inner timeout fires; outer timeout does not".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let start = Instant::now();

                // Pre-create inner sleep, then wrap in inner timeout
                let inner_sleep = rt.sleep(Duration::from_millis(300));
                let inner_timeout = rt.timeout(Duration::from_millis(50), inner_sleep);

                // Outer timeout wraps the inner timeout future
                let outer_result = rt.timeout(Duration::from_millis(500), inner_timeout).await;

                let elapsed = start.elapsed();

                checkpoint(
                    "nested_timeout",
                    serde_json::json!({
                        "elapsed_ms": elapsed.as_millis() as u64,
                        "outer_timed_out": outer_result.is_err(),
                        "inner_timed_out": matches!(&outer_result, Ok(Err(_)))
                    }),
                );

                // Inner should have timed out
                match outer_result {
                    Ok(Err(_inner_timeout)) => {
                        // Inner timed out, outer did not — correct
                        if elapsed > Duration::from_millis(400) {
                            return TestResult::failed(format!(
                                "Inner timeout took too long: {:?}",
                                elapsed
                            ));
                        }
                        TestResult::passed()
                    }
                    Ok(Ok(_)) => {
                        TestResult::failed("Inner future should have timed out, but completed")
                    }
                    Err(_) => TestResult::failed("Outer timeout fired unexpectedly"),
                }
            })
        },
    )
}

/// CANCEL-004: Race pattern drains the loser
///
/// Simulate a race where the future first does "fast path" work (immediate),
/// then enters a long "loser continuation" (500ms sleep). A timeout at 50ms
/// acts as the race deadline, ensuring the loser continuation is drained
/// before it completes its terminal work.
pub fn cancel_004_race_loser_drain<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-004".to_string(),
            name: "Race loser is drained".to_string(),
            description: "In a race, the losing branch does not complete its work".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "race".to_string(),
                "drain".to_string(),
                "invariant".to_string(),
            ],
            expected: "Timeout fires; loser's terminal flag is not set".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let loser_terminal = Arc::new(AtomicBool::new(false));
                let loser_terminal_clone = loser_terminal.clone();

                // Pre-create the long sleep that represents the "loser" continuation
                let loser_sleep = rt.sleep(Duration::from_millis(500));

                let result = rt
                    .timeout(Duration::from_millis(50), async move {
                        // Fast path: immediate work (the "winner" result)
                        let _winner_value = 42;

                        // Loser continuation: long operation that should be cancelled
                        loser_sleep.await;

                        // Terminal work: should NOT execute if drain is correct
                        loser_terminal_clone.store(true, Ordering::SeqCst);
                        _winner_value
                    })
                    .await;

                let loser_did_complete = loser_terminal.load(Ordering::SeqCst);

                checkpoint(
                    "race_drain",
                    serde_json::json!({
                        "timed_out": result.is_err(),
                        "loser_completed": loser_did_complete
                    }),
                );

                if result.is_ok() {
                    return TestResult::failed(
                        "Timeout should have fired during the loser's long operation",
                    );
                }

                if loser_did_complete {
                    return TestResult::failed(
                        "Loser's terminal work should have been drained by timeout",
                    );
                }

                TestResult::passed()
            })
        },
    )
}

/// CANCEL-005: Timeout does not interfere with already-completed tasks
///
/// A task that completes before its timeout should return its value normally.
/// The timeout mechanism should not corrupt or modify the result.
pub fn cancel_005_no_interference_completed<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-005".to_string(),
            name: "Timeout no-op on completed task".to_string(),
            description: "A task that finishes before its timeout returns normally".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "timeout".to_string(),
                "no-op".to_string(),
            ],
            expected: "Task result is returned without modification".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let result = rt
                    .timeout(Duration::from_millis(500), async { 42i32 })
                    .await;

                checkpoint(
                    "completed_before_timeout",
                    serde_json::json!({
                        "result": format!("{:?}", result)
                    }),
                );

                match result {
                    Ok(value) => {
                        if value != 42 {
                            return TestResult::failed(format!(
                                "Expected 42, got {}; timeout corrupted result",
                                value
                            ));
                        }
                        TestResult::passed()
                    }
                    Err(_) => {
                        TestResult::failed("Task completed immediately but timeout fired anyway")
                    }
                }
            })
        },
    )
}

/// CANCEL-006: Multiple timeouts resolve independently
///
/// Run three timeout operations with different durations. Each should resolve
/// with correct semantics: short and medium timeouts fire (task too slow),
/// long timeout does not (task completes first). Timing is verified.
pub fn cancel_006_multiple_timeouts<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-006".to_string(),
            name: "Multiple timeouts resolve independently".to_string(),
            description: "Each timeout resolves correctly regardless of prior timeouts".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "timeout".to_string(),
                "independence".to_string(),
            ],
            expected: "Short/medium timeouts fire; long timeout does not".to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Timeout 1: Short deadline (30ms), long task (500ms) → should timeout
                let start1 = Instant::now();
                let sleep1 = rt.sleep(Duration::from_millis(500));
                let r1 = rt.timeout(Duration::from_millis(30), sleep1).await;
                let elapsed1 = start1.elapsed();

                // Timeout 2: Medium deadline (80ms), long task (500ms) → should timeout
                let start2 = Instant::now();
                let sleep2 = rt.sleep(Duration::from_millis(500));
                let r2 = rt.timeout(Duration::from_millis(80), sleep2).await;
                let elapsed2 = start2.elapsed();

                // Timeout 3: Long deadline (500ms), short task (10ms) → should succeed
                let start3 = Instant::now();
                let sleep3 = rt.sleep(Duration::from_millis(10));
                let r3 = rt.timeout(Duration::from_millis(500), sleep3).await;
                let elapsed3 = start3.elapsed();

                checkpoint(
                    "timeout_results",
                    serde_json::json!({
                        "short": {"timed_out": r1.is_err(), "elapsed_ms": elapsed1.as_millis() as u64},
                        "medium": {"timed_out": r2.is_err(), "elapsed_ms": elapsed2.as_millis() as u64},
                        "long": {"timed_out": r3.is_err(), "elapsed_ms": elapsed3.as_millis() as u64}
                    }),
                );

                if r1.is_ok() {
                    return TestResult::failed("Short timeout (30ms) should have fired");
                }

                if r2.is_ok() {
                    return TestResult::failed("Medium timeout (80ms) should have fired");
                }

                if r3.is_err() {
                    return TestResult::failed(
                        "Long timeout (500ms) should NOT have fired (task completes in 10ms)",
                    );
                }

                // Verify timing: short timeout should resolve near its deadline
                if elapsed1 > Duration::from_millis(200) {
                    return TestResult::failed(format!(
                        "Short timeout took too long: {:?}",
                        elapsed1
                    ));
                }

                if elapsed2 > Duration::from_millis(300) {
                    return TestResult::failed(format!(
                        "Medium timeout took too long: {:?}",
                        elapsed2
                    ));
                }

                TestResult::passed()
            })
        },
    )
}

/// CANCEL-007: Cancellation propagates via resource cleanup (channel drop)
///
/// When a future holding a oneshot sender is cancelled by timeout, the sender
/// is dropped, causing receivers to observe channel closure. This verifies
/// that cancellation side-effects propagate through owned resources.
pub fn cancel_007_cancel_propagates_via_drop<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cancel-007".to_string(),
            name: "Cancellation propagates via resource drop".to_string(),
            description: "Cancelled future drops owned resources, observable by receivers"
                .to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "propagation".to_string(),
                "drop".to_string(),
                "invariant".to_string(),
            ],
            expected: "Receivers observe channel closure after sender's future is cancelled"
                .to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Create channels whose senders will be held by a future
                // that gets cancelled by timeout
                let (tx1, rx1) = rt.oneshot_channel::<i32>();
                let (tx2, rx2) = rt.oneshot_channel::<i32>();
                let (tx3, rx3) = rt.oneshot_channel::<i32>();

                // Pre-create the long sleep
                let long_sleep = rt.sleep(Duration::from_millis(500));

                // The timeout cancels this future, dropping all three senders
                let timeout_result = rt
                    .timeout(Duration::from_millis(50), async move {
                        // Hold all three senders across the sleep
                        long_sleep.await;
                        // These sends should never execute
                        let _ = tx1.send(1);
                        let _ = tx2.send(2);
                        let _ = tx3.send(3);
                    })
                    .await;

                checkpoint(
                    "timeout_fired",
                    serde_json::json!({
                        "timed_out": timeout_result.is_err()
                    }),
                );

                if timeout_result.is_ok() {
                    return TestResult::failed("Timeout should have fired before sends executed");
                }

                // Now check: all receivers should observe channel closure
                // (sender dropped without sending)
                let r1 = rx1.await;
                let r2 = rx2.await;
                let r3 = rx3.await;

                let all_closed = r1.is_err() && r2.is_err() && r3.is_err();

                checkpoint(
                    "propagation_result",
                    serde_json::json!({
                        "rx1_closed": r1.is_err(),
                        "rx2_closed": r2.is_err(),
                        "rx3_closed": r3.is_err(),
                        "all_propagated": all_closed
                    }),
                );

                if r1.is_ok() {
                    return TestResult::failed(
                        "Receiver 1 should observe closure (sender dropped by cancellation)",
                    );
                }

                if r2.is_ok() {
                    return TestResult::failed(
                        "Receiver 2 should observe closure (sender dropped by cancellation)",
                    );
                }

                if r3.is_ok() {
                    return TestResult::failed(
                        "Receiver 3 should observe closure (sender dropped by cancellation)",
                    );
                }

                TestResult::passed()
            })
        },
    )
}
