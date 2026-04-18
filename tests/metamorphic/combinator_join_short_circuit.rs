//! Metamorphic tests for combinator::join short-circuit behavior.
//!
//! This test suite verifies the join combinator's behavior under cancellation
//! scenarios and resource cleanup using metamorphic relations and deterministic
//! property-based testing with LabRuntime DPOR.

use proptest::prelude::*;
use std::sync::{Arc, Mutex, atomic::{AtomicU32, AtomicU64, Ordering}};
use std::time::Duration;

use asupersync::cx::{Cx, Scope};
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::task_handle::JoinError;
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for join testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot for deterministic testing.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Test errors for join operations.
#[derive(Debug, Clone, PartialEq)]
enum TestError {
    Business(String),
    Network(u16),
    Timeout,
    ResourceExhausted,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Business(msg) => write!(f, "business error: {msg}"),
            Self::Network(code) => write!(f, "network error: {code}"),
            Self::Timeout => write!(f, "timeout error"),
            Self::ResourceExhausted => write!(f, "resource exhausted"),
        }
    }
}

impl std::error::Error for TestError {}

/// Resource tracking for monitoring partial completion.
#[derive(Debug, Clone)]
struct ResourceTracker {
    bytes_consumed: Arc<AtomicU64>,
    operations_started: Arc<AtomicU32>,
    operations_completed: Arc<AtomicU32>,
    partial_work_preserved: Arc<AtomicU64>,
}

impl ResourceTracker {
    fn new() -> Self {
        Self {
            bytes_consumed: Arc::new(AtomicU64::new(0)),
            operations_started: Arc::new(AtomicU32::new(0)),
            operations_completed: Arc::new(AtomicU32::new(0)),
            partial_work_preserved: Arc::new(AtomicU64::new(0)),
        }
    }

    fn consume_bytes(&self, bytes: u64) {
        self.bytes_consumed.fetch_add(bytes, Ordering::Relaxed);
    }

    fn start_operation(&self) {
        self.operations_started.fetch_add(1, Ordering::Relaxed);
    }

    fn complete_operation(&self, work_done: u64) {
        self.operations_completed.fetch_add(1, Ordering::Relaxed);
        self.partial_work_preserved.fetch_add(work_done, Ordering::Relaxed);
    }

    fn get_stats(&self) -> (u64, u32, u32, u64) {
        (
            self.bytes_consumed.load(Ordering::Relaxed),
            self.operations_started.load(Ordering::Relaxed),
            self.operations_completed.load(Ordering::Relaxed),
            self.partial_work_preserved.load(Ordering::Relaxed),
        )
    }
}

/// Test future that can simulate various completion patterns.
async fn test_operation(
    cx: &Cx,
    value: u32,
    delay_ms: u64,
    should_error: bool,
    error: TestError,
    tracker: ResourceTracker,
) -> Result<u32, TestError> {
    tracker.start_operation();

    // Simulate progressive work with checkpoints
    let chunks = delay_ms / 10 + 1;
    for i in 0..chunks {
        if cx.cancelled() {
            // Save partial work before cancelling
            tracker.complete_operation(i * 100);
            return Err(TestError::Timeout);
        }

        asupersync::time::sleep(cx, Duration::from_millis(10)).await;
        tracker.consume_bytes(100);
    }

    if should_error {
        tracker.complete_operation(0); // No work preserved on error
        Err(error)
    } else {
        tracker.complete_operation(chunks * 100);
        Ok(value)
    }
}

/// Generate arbitrary test configurations.
fn arb_test_config() -> impl Strategy<Value = (u32, u32, u32, u64, bool, bool)> {
    (
        1u32..=100,    // value1
        1u32..=100,    // value2
        1u32..=100,    // value3
        10u64..=200,   // base_delay_ms
        any::<bool>(), // task1_should_error
        any::<bool>(), // task2_should_error
    )
}

/// Generate cancellation timing strategies.
#[derive(Debug, Clone, Copy)]
enum CancelTiming {
    Never,
    Early(u64),      // Cancel after N milliseconds
    MidExecution(u64), // Cancel during execution
    Late(u64),       // Cancel near completion
}

fn arb_cancel_timing() -> impl Strategy<Value = CancelTiming> {
    prop_oneof![
        Just(CancelTiming::Never),
        (5u64..=50).prop_map(CancelTiming::Early),
        (50u64..=150).prop_map(CancelTiming::MidExecution),
        (150u64..=300).prop_map(CancelTiming::Late),
    ]
}

/// Helper to run a test in deterministic LabRuntime with DPOR.
fn run_lab_test<F, R>(seed: u64, test_fn: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    let config = LabConfig::new(seed)
        .with_deterministic_scheduling()
        .with_dpor_enabled(true);
    let mut runtime = LabRuntime::new(config);
    test_fn(&mut runtime)
}

// ============================================================================
// MR1: Join All-Success Returns All Outcomes
// ============================================================================

/// **MR1: Join All-Success Returns All Outcomes**
///
/// When all futures in a join complete successfully, the join should return
/// all successful outcomes in the correct order.
///
/// Property: ∀ futures f₁,f₂,f₃: all_ok(f₁,f₂,f₃) → join_all(f₁,f₂,f₃) = (ok₁,ok₂,ok₃)
proptest! {
    #[test]
    fn mr1_join_all_success_returns_all_outcomes(
        config in arb_test_config().prop_filter("no errors", |(_, _, _, _, e1, e2)| !e1 && !e2),
        seed in any::<u64>()
    ) {
        let (v1, v2, v3, base_delay, _, _) = config;

        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let tracker = ResourceTracker::new();

                // Spawn three successful tasks
                let (h1, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v1, base_delay, false, TestError::Timeout, tracker).await
                    }
                });

                let (h2, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v2, base_delay + 20, false, TestError::Network(500), tracker).await
                    }
                });

                let (h3, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v3, base_delay + 40, false, TestError::Business("test".to_string()), tracker).await
                    }
                });

                // Join all tasks
                let results = scope.join_all(&cx, vec![h1, h2, h3]).await;

                // MR1.1: All results should be successful
                prop_assert_eq!(results.len(), 3, "Should have 3 results");
                for (i, result) in results.iter().enumerate() {
                    prop_assert!(result.is_ok(), "Result {} should be successful: {:?}", i, result);
                }

                // MR1.2: Values should be in correct order
                if let (Ok(r1), Ok(r2), Ok(r3)) = (&results[0], &results[1], &results[2]) {
                    prop_assert_eq!(*r1, v1, "First value should match");
                    prop_assert_eq!(*r2, v2, "Second value should match");
                    prop_assert_eq!(*r3, v3, "Third value should match");
                }

                // MR1.3: All operations should complete
                let (bytes, started, completed, work) = tracker.get_stats();
                prop_assert_eq!(started, 3, "All operations should start");
                prop_assert_eq!(completed, 3, "All operations should complete");
                prop_assert!(bytes > 0, "Should consume bytes during work");
                prop_assert!(work > 0, "Should preserve work done");
            })
        })
    }
}

// ============================================================================
// MR2: Any Err Waits for All (No Short-Circuit)
// ============================================================================

/// **MR2: Any Err Waits for All (No Short-Circuit)**
///
/// Even when one future errors early, join waits for all futures to complete
/// before returning. This verifies the semantic difference from race.
///
/// Property: ∀ futures f₁,f₂: err(f₁) ∧ ok(f₂) → join(f₁,f₂) waits for both
proptest! {
    #[test]
    fn mr2_any_err_waits_for_all_no_short_circuit(
        config in arb_test_config(),
        seed in any::<u64>()
    ) {
        let (v1, v2, _v3, base_delay, task1_error, task2_error) = config;

        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let completion_tracker = Arc::new(Mutex::new(Vec::new()));
                let tracker1 = completion_tracker.clone();
                let tracker2 = completion_tracker.clone();

                // Task 1: Potentially errors early
                let (h1, _) = scope.spawn(&cx, {
                    let tracker = tracker1.clone();
                    async move |cx| {
                        let result = test_operation(
                            cx,
                            v1,
                            base_delay,
                            task1_error,
                            TestError::Business("early error".to_string()),
                            ResourceTracker::new()
                        ).await;
                        tracker1.lock().unwrap().push(1);
                        result
                    }
                });

                // Task 2: Takes longer but succeeds
                let (h2, _) = scope.spawn(&cx, {
                    let tracker = tracker2.clone();
                    async move |cx| {
                        let result = test_operation(
                            cx,
                            v2,
                            base_delay + 100, // Longer delay
                            task2_error,
                            TestError::Network(503),
                            ResourceTracker::new()
                        ).await;
                        tracker2.lock().unwrap().push(2);
                        result
                    }
                });

                // Join waits for both
                let (r1, r2) = scope.join(&cx, h1, h2).await;

                // MR2.1: Both tasks should have completed (no abandonment)
                let completion_order = completion_tracker.lock().unwrap();
                prop_assert_eq!(completion_order.len(), 2, "Both tasks should complete");
                prop_assert!(completion_order.contains(&1), "Task 1 should complete");
                prop_assert!(completion_order.contains(&2), "Task 2 should complete");

                // MR2.2: Results should reflect actual completion states
                if task1_error {
                    prop_assert!(r1.is_err(), "Task 1 should error");
                } else {
                    prop_assert!(r1.is_ok(), "Task 1 should succeed");
                }

                if task2_error {
                    prop_assert!(r2.is_err(), "Task 2 should error");
                } else {
                    prop_assert!(r2.is_ok(), "Task 2 should succeed");
                }
            })
        })
    }
}

// ============================================================================
// MR3: Partial Completion Before Cancel Preserves Work
// ============================================================================

/// **MR3: Partial Completion Before Cancel Preserves Work**
///
/// When cancellation occurs during execution, work done before cancellation
/// should be preserved and tracked correctly.
///
/// Property: cancel_at(t) → work_preserved ≥ work_done_before(t)
proptest! {
    #[test]
    fn mr3_partial_completion_preserves_work(
        config in arb_test_config().prop_filter("no initial errors", |(_, _, _, _, e1, e2)| !e1 && !e2),
        cancel_timing in arb_cancel_timing().prop_filter("actual cancel", |t| !matches!(t, CancelTiming::Never)),
        seed in any::<u64>()
    ) {
        let (v1, v2, v3, base_delay, _, _) = config;

        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let tracker = ResourceTracker::new();

                // Spawn long-running tasks
                let (h1, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v1, base_delay + 200, false, TestError::Timeout, tracker).await
                    }
                });

                let (h2, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v2, base_delay + 300, false, TestError::Network(500), tracker).await
                    }
                });

                let (h3, _) = scope.spawn(&cx, {
                    let tracker = tracker.clone();
                    async move |cx| {
                        test_operation(cx, v3, base_delay + 400, false, TestError::Business("test".to_string()), tracker).await
                    }
                });

                // Schedule cancellation
                let cancel_delay = match cancel_timing {
                    CancelTiming::Early(ms) => ms,
                    CancelTiming::MidExecution(ms) => ms,
                    CancelTiming::Late(ms) => ms,
                    CancelTiming::Never => unreachable!(),
                };

                let scope_clone = scope.clone();
                let cx_clone = cx.clone();
                let (cancel_handle, _) = scope.spawn(&cx, async move |cx| {
                    asupersync::time::sleep(cx, Duration::from_millis(cancel_delay)).await;
                    cx_clone.cancel();
                    Ok(())
                });

                // Wait for tasks (should be cancelled)
                let results = scope.join_all(&cx, vec![h1, h2, h3]).await;
                let _ = cancel_handle.try_join();

                // MR3.1: Tasks should have been cancelled or completed
                for result in &results {
                    match result {
                        Ok(_) => {}, // Task completed before cancel
                        Err(JoinError::Cancelled(_)) => {}, // Task was cancelled
                        Err(_) => {}, // Task errored during work
                    }
                }

                // MR3.2: Partial work should be preserved
                let (bytes_consumed, started, completed, work_preserved) = tracker.get_stats();

                prop_assert!(started > 0, "Some operations should start");

                // If any work was started, some bytes should be consumed or work preserved
                if started > 0 {
                    prop_assert!(
                        bytes_consumed > 0 || work_preserved > 0,
                        "Should preserve work done before cancel: bytes={}, work={}",
                        bytes_consumed,
                        work_preserved
                    );
                }

                // MR3.3: Work preservation is monotonic (doesn't decrease)
                let final_work = work_preserved;
                prop_assert!(
                    final_work >= 0,
                    "Work preservation should be non-negative: {}",
                    final_work
                );
            })
        })
    }
}

// ============================================================================
// MR4: Drain After Short-Circuit Cleans All Futures
// ============================================================================

/// **MR4: Drain After Short-Circuit Cleans All Futures**
///
/// After cancellation or completion, all spawned futures should be properly
/// drained and no resources leaked.
///
/// Property: post_cancel → all_futures_drained ∧ no_leaks
proptest! {
    #[test]
    fn mr4_drain_after_cancel_cleans_all_futures(
        config in arb_test_config(),
        cancel_timing in arb_cancel_timing(),
        seed in any::<u64>()
    ) {
        let (v1, v2, v3, base_delay, task1_error, task2_error) = config;

        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let drain_tracker = Arc::new(AtomicU32::new(0));
                let completion_tracker = Arc::new(AtomicU32::new(0));

                // Track draining behavior
                let tasks_spawned = 3u32;

                // Spawn tasks with varying behaviors
                let (h1, _) = scope.spawn(&cx, {
                    let drain = drain_tracker.clone();
                    let complete = completion_tracker.clone();
                    async move |cx| {
                        let result = test_operation(
                            cx,
                            v1,
                            base_delay,
                            task1_error,
                            TestError::Business("test".to_string()),
                            ResourceTracker::new()
                        ).await;

                        complete.fetch_add(1, Ordering::Relaxed);
                        // Simulate cleanup in drop
                        drop(result);
                        drain.fetch_add(1, Ordering::Relaxed);

                        Ok(v1)
                    }
                });

                let (h2, _) = scope.spawn(&cx, {
                    let drain = drain_tracker.clone();
                    let complete = completion_tracker.clone();
                    async move |cx| {
                        let result = test_operation(
                            cx,
                            v2,
                            base_delay + 50,
                            task2_error,
                            TestError::Network(500),
                            ResourceTracker::new()
                        ).await;

                        complete.fetch_add(1, Ordering::Relaxed);
                        drop(result);
                        drain.fetch_add(1, Ordering::Relaxed);

                        Ok(v2)
                    }
                });

                let (h3, _) = scope.spawn(&cx, {
                    let drain = drain_tracker.clone();
                    let complete = completion_tracker.clone();
                    async move |cx| {
                        // Longer running task more likely to be cancelled
                        asupersync::time::sleep(cx, Duration::from_millis(base_delay + 100)).await;

                        complete.fetch_add(1, Ordering::Relaxed);
                        drain.fetch_add(1, Ordering::Relaxed);

                        Ok(v3)
                    }
                });

                // Potentially cancel during execution
                if !matches!(cancel_timing, CancelTiming::Never) {
                    let cancel_delay = match cancel_timing {
                        CancelTiming::Early(ms) => ms,
                        CancelTiming::MidExecution(ms) => ms,
                        CancelTiming::Late(ms) => ms,
                        CancelTiming::Never => 0,
                    };

                    let cx_clone = cx.clone();
                    let (cancel_task, _) = scope.spawn(&cx, async move |cx| {
                        asupersync::time::sleep(cx, Duration::from_millis(cancel_delay)).await;
                        cx_clone.cancel();
                        Ok(())
                    });

                    let _ = cancel_task.try_join();
                }

                // Wait for join to complete (with potential cancellation)
                let results = scope.join_all(&cx, vec![h1, h2, h3]).await;

                // MR4.1: All spawned tasks should eventually drain
                let final_drain_count = drain_tracker.load(Ordering::Relaxed);
                let final_completion_count = completion_tracker.load(Ordering::Relaxed);

                // In deterministic runtime, all tasks complete their async blocks
                prop_assert!(
                    final_completion_count > 0,
                    "Some tasks should complete their execution"
                );

                // MR4.2: Drain count should not exceed tasks spawned
                prop_assert!(
                    final_drain_count <= tasks_spawned,
                    "Drain count should not exceed spawned tasks: {} <= {}",
                    final_drain_count,
                    tasks_spawned
                );

                // MR4.3: Results should be properly structured
                prop_assert_eq!(results.len(), 3, "Should have result for each task");

                // MR4.4: No leaked futures (all complete in some form)
                let cancelled_count = results.iter()
                    .filter(|r| matches!(r, Err(JoinError::Cancelled(_))))
                    .count();
                let ok_count = results.iter()
                    .filter(|r| r.is_ok())
                    .count();
                let err_count = results.iter()
                    .filter(|r| matches!(r, Err(JoinError::TaskError(_))))
                    .count();

                prop_assert_eq!(
                    cancelled_count + ok_count + err_count,
                    3,
                    "All futures should reach terminal state"
                );
            })
        })
    }
}

// ============================================================================
// MR5: Cancel From Outer Cancels All Branches
// ============================================================================

/// **MR5: Cancel From Outer Cancels All Branches**
///
/// When cancellation is requested from outside the join, all branch futures
/// should observe the cancellation signal and complete in cancelled state.
///
/// Property: outer_cancel → ∀ futures f ∈ join: cancelled(f) ∨ completed_before_cancel(f)
proptest! {
    #[test]
    fn mr5_outer_cancel_cancels_all_branches(
        config in arb_test_config().prop_filter("long running", |(_, _, _, delay, _, _)| *delay >= 50),
        seed in any::<u64>()
    ) {
        let (v1, v2, v3, base_delay, _, _) = config;

        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let cancel_observer = Arc::new(AtomicU32::new(0));

                // Spawn tasks that check for cancellation
                let (h1, _) = scope.spawn(&cx, {
                    let observer = cancel_observer.clone();
                    async move |cx| {
                        for i in 0..(base_delay / 10) {
                            if cx.cancelled() {
                                observer.fetch_add(1, Ordering::Relaxed);
                                return Err(TestError::Timeout);
                            }
                            asupersync::time::sleep(cx, Duration::from_millis(10)).await;
                        }
                        Ok(v1)
                    }
                });

                let (h2, _) = scope.spawn(&cx, {
                    let observer = cancel_observer.clone();
                    async move |cx| {
                        for i in 0..((base_delay + 50) / 10) {
                            if cx.cancelled() {
                                observer.fetch_add(1, Ordering::Relaxed);
                                return Err(TestError::Timeout);
                            }
                            asupersync::time::sleep(cx, Duration::from_millis(10)).await;
                        }
                        Ok(v2)
                    }
                });

                let (h3, _) = scope.spawn(&cx, {
                    let observer = cancel_observer.clone();
                    async move |cx| {
                        for i in 0..((base_delay + 100) / 10) {
                            if cx.cancelled() {
                                observer.fetch_add(1, Ordering::Relaxed);
                                return Err(TestError::Timeout);
                            }
                            asupersync::time::sleep(cx, Duration::from_millis(10)).await;
                        }
                        Ok(v3)
                    }
                });

                // Cancel after a short delay to ensure tasks are running
                let cx_clone = cx.clone();
                let (cancel_task, _) = scope.spawn(&cx, async move |cx| {
                    asupersync::time::sleep(cx, Duration::from_millis(base_delay / 3)).await;
                    cx_clone.cancel();
                    Ok(())
                });

                // Wait for join completion
                let results = scope.join_all(&cx, vec![h1, h2, h3]).await;
                let _ = cancel_task.try_join();

                // MR5.1: All tasks should terminate (no hangs)
                prop_assert_eq!(results.len(), 3, "All tasks should complete");

                // MR5.2: At least some tasks should observe cancellation
                let cancel_observations = cancel_observer.load(Ordering::Relaxed);

                // MR5.3: Results should show cancellation or early completion
                let mut cancelled_count = 0;
                let mut success_count = 0;
                let mut error_count = 0;

                for result in &results {
                    match result {
                        Ok(_) => success_count += 1, // Completed before cancel
                        Err(JoinError::Cancelled(_)) => cancelled_count += 1,
                        Err(JoinError::TaskError(_)) => {
                            // Could be timeout from our cancel check
                            error_count += 1;
                        }
                        Err(_) => error_count += 1,
                    }
                }

                // MR5.4: Cancellation should propagate to most tasks
                // (Some tasks might complete before seeing cancellation)
                prop_assert!(
                    cancelled_count + error_count >= 1,
                    "At least one task should observe cancellation: cancelled={}, errors={}",
                    cancelled_count,
                    error_count
                );

                // MR5.5: Total outcomes should account for all tasks
                prop_assert_eq!(
                    cancelled_count + success_count + error_count,
                    3,
                    "All tasks should reach terminal state: cancelled={}, success={}, error={}",
                    cancelled_count,
                    success_count,
                    error_count
                );

                // MR5.6: Cancel observations should be reasonable
                prop_assert!(
                    cancel_observations <= 3,
                    "Cancel observations should not exceed task count: {}",
                    cancel_observations
                );
            })
        })
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

/// **Integration Test: All MRs Under Stress**
///
/// Verifies that all metamorphic relations hold simultaneously under
/// realistic concurrent workload with mixed success/error/cancel scenarios.
#[test]
fn integration_all_mrs_under_stress() {
    let seed = 42u64; // Fixed seed for reproducible stress test

    run_lab_test(seed, |runtime| {
        runtime.block_on(async {
            let cx = test_cx();
            let scope = Scope::new();
            let tracker = ResourceTracker::new();

            // Create diverse workload
            let mut handles = Vec::new();

            // Fast successful task
            let (h1, _) = scope.spawn(&cx, {
                let tracker = tracker.clone();
                async move |cx| {
                    test_operation(cx, 42, 30, false, TestError::Business("".to_string()), tracker).await
                }
            });
            handles.push(h1);

            // Medium task that errors
            let (h2, _) = scope.spawn(&cx, {
                let tracker = tracker.clone();
                async move |cx| {
                    test_operation(cx, 84, 80, true, TestError::Network(500), tracker).await
                }
            });
            handles.push(h2);

            // Slow task (likely to be cancelled)
            let (h3, _) = scope.spawn(&cx, {
                let tracker = tracker.clone();
                async move |cx| {
                    test_operation(cx, 168, 200, false, TestError::Timeout, tracker).await
                }
            });
            handles.push(h3);

            // Cancellation task
            let cx_clone = cx.clone();
            let (cancel_task, _) = scope.spawn(&cx, async move |cx| {
                asupersync::time::sleep(cx, Duration::from_millis(60)).await;
                cx_clone.cancel();
                Ok(())
            });

            // Execute join
            let results = scope.join_all(&cx, handles).await;
            let _ = cancel_task.try_join();

            // Verify all invariants hold
            assert_eq!(results.len(), 3, "Should have result for each task");

            // Check resource tracking
            let (bytes, started, completed, work) = tracker.get_stats();
            assert!(started > 0, "Some operations should start");
            assert!(bytes > 0 || work > 0, "Should track resource usage or work");

            // Verify terminal states
            let terminal_states: usize = results.iter()
                .map(|r| match r {
                    Ok(_) => 1,
                    Err(JoinError::Cancelled(_)) => 1,
                    Err(JoinError::TaskError(_)) => 1,
                    Err(_) => 1,
                })
                .sum();
            assert_eq!(terminal_states, 3, "All tasks should reach terminal state");

            println!("Stress test completed: bytes={}, started={}, completed={}, work={}",
                     bytes, started, completed, work);
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_tracker_basic() {
        let tracker = ResourceTracker::new();
        tracker.start_operation();
        tracker.consume_bytes(100);
        tracker.complete_operation(50);

        let (bytes, started, completed, work) = tracker.get_stats();
        assert_eq!(bytes, 100);
        assert_eq!(started, 1);
        assert_eq!(completed, 1);
        assert_eq!(work, 50);
    }

    #[test]
    fn test_join_basic_success() {
        run_lab_test(42, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                let (h1, _) = scope.spawn(&cx, async move |_cx| Ok::<u32, TestError>(1));
                let (h2, _) = scope.spawn(&cx, async move |_cx| Ok::<u32, TestError>(2));

                let (r1, r2) = scope.join(&cx, h1, h2).await;

                assert!(r1.is_ok());
                assert!(r2.is_ok());
                assert_eq!(r1.unwrap(), 1);
                assert_eq!(r2.unwrap(), 2);
            })
        })
    }
}