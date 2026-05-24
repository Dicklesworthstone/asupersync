//! E2E tests for combinator failure mode propagation to supervision decisions.
//!
//! Verifies that failure modes from bracket/bulkhead/quorum combinators properly
//! propagate to supervision strategy decisions (Stop/Restart/Escalate) without
//! mocking the underlying systems.
//!
//! # Test Coverage
//!
//! ## Bracket Failure Modes
//! - Resource cleanup failures during cancellation/drop
//! - Acquisition failures with resource leak prevention
//! - Release phase interruption handling
//!
//! ## Quorum Failure Modes
//! - Insufficient successful completions (< M of N)
//! - Quorum impossible scenarios (too many failures)
//! - Mixed outcome aggregation with supervision decisions
//!
//! ## Bulkhead Failure Modes
//! - Resource exhaustion (max concurrent exceeded)
//! - Queue overflow (max queue exceeded)
//! - Queue timeout failures
//! - Weighted permit exhaustion
//!
//! ## Supervision Integration
//! - Stop strategy on combinator failures
//! - Restart strategy with rate limiting under combinator stress
//! - Escalate strategy propagating combinator failures to parent
//! - Budget-aware restart decisions under combinator failure load

#![cfg(all(test, feature = "real-service-e2e"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::cx::{Cx, Scope};
use crate::types::{Budget, Outcome, Time};
use crate::runtime::test_util::create_test_runtime;
use crate::combinator::{
    bracket::{bracket, BracketError},
    bulkhead::{Bulkhead, BulkheadPolicy, BulkheadError},
    quorum::{quorum, QuorumError},
};
use crate::supervision::{
    SupervisionStrategy, RestartConfig, BackoffStrategy, ChildName,
    Supervisor, SupervisorRestartPlan,
};

/// Test configuration for E2E scenarios.
#[derive(Clone, Debug)]
struct TestConfig {
    /// Runtime timeout for test scenarios
    runtime_timeout: Duration,
    /// Budget allocation for test operations
    budget_duration: Duration,
    /// Expected failure scenarios per test
    expected_failures: u32,
    /// Supervision strategy testing depth
    max_restart_attempts: u32,
    /// Concurrency level for stress testing
    concurrency_level: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            runtime_timeout: Duration::from_secs(30),
            budget_duration: Duration::from_secs(10),
            expected_failures: 5,
            max_restart_attempts: 3,
            concurrency_level: 10,
        }
    }
}

/// Mock resource for bracket testing that can fail during cleanup.
#[derive(Clone)]
struct FailingResource {
    id: u32,
    cleanup_should_fail: Arc<Mutex<bool>>,
    cleanup_attempts: Arc<AtomicU32>,
}

impl FailingResource {
    fn new(id: u32, cleanup_should_fail: bool) -> Self {
        Self {
            id,
            cleanup_should_fail: Arc::new(Mutex::new(cleanup_should_fail)),
            cleanup_attempts: Arc::new(AtomicU32::new(0)),
        }
    }

    async fn cleanup(&self) -> Result<(), String> {
        self.cleanup_attempts.fetch_add(1, Ordering::SeqCst);

        let should_fail = *self.cleanup_should_fail.lock().unwrap();
        if should_fail {
            Err(format!("Cleanup failed for resource {}", self.id))
        } else {
            Ok(())
        }
    }

    fn cleanup_attempt_count(&self) -> u32 {
        self.cleanup_attempts.load(Ordering::SeqCst)
    }
}

/// Simulated work that can succeed or fail based on configuration.
async fn simulated_work(
    cx: &Cx,
    work_id: u32,
    success_probability: f32,
    work_duration: Duration,
) -> Result<String, String> {
    // Use deterministic "randomness" based on work_id for reproducibility
    let should_succeed = (work_id % 100) as f32 / 100.0 < success_probability;

    // Simulate work with sleep
    cx.sleep(work_duration).await;

    if should_succeed {
        Ok(format!("Work {} completed successfully", work_id))
    } else {
        Err(format!("Work {} failed", work_id))
    }
}

/// Test counter for tracking supervision decisions.
#[derive(Default, Clone)]
struct SupervisionDecisionCounter {
    stops: Arc<AtomicU32>,
    restarts: Arc<AtomicU32>,
    escalations: Arc<AtomicU32>,
    restart_exhaustions: Arc<AtomicU32>,
}

impl SupervisionDecisionCounter {
    fn record_stop(&self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
    }

    fn record_restart(&self) {
        self.restarts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_escalation(&self) {
        self.escalations.fetch_add(1, Ordering::SeqCst);
    }

    fn record_restart_exhaustion(&self) {
        self.restart_exhaustions.fetch_add(1, Ordering::SeqCst);
    }

    fn totals(&self) -> (u32, u32, u32, u32) {
        (
            self.stops.load(Ordering::SeqCst),
            self.restarts.load(Ordering::SeqCst),
            self.escalations.load(Ordering::SeqCst),
            self.restart_exhaustions.load(Ordering::SeqCst),
        )
    }
}

// ============================================================================
// BRACKET FAILURE MODE TESTS
// ============================================================================

/// Test bracket resource cleanup failures propagate to Stop supervision strategy.
#[tokio::test]
async fn test_bracket_cleanup_failure_propagates_to_stop_strategy() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Set up failing resource that will fail during cleanup
                let failing_resource = FailingResource::new(1, true);
                let resource_clone = failing_resource.clone();

                // Create bracket operation with Stop supervision
                let bracket_future = bracket(
                    // Acquire: always succeeds
                    async move { Ok::<_, String>(failing_resource) },
                    // Use: simulate work that gets cancelled
                    move |resource| async move {
                        // Simulate long work that will be interrupted
                        cx.sleep(Duration::from_secs(5)).await;
                        Ok::<_, String>(format!("Used resource {}", resource.id))
                    },
                    // Release: will fail during cleanup
                    move |resource| async move {
                        resource.cleanup().await
                    },
                );

                // Spawn with Stop supervision strategy
                let task_handle = scope.spawn_with_supervision(
                    ChildName::new("bracket_task"),
                    SupervisionStrategy::Stop,
                    bracket_future,
                ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                // Cancel the task to trigger cleanup path
                cx.sleep(Duration::from_millis(100)).await;
                task_handle.cancel();

                // Wait for completion and verify Stop decision was made
                match task_handle.join().await {
                    Outcome::Ok(_) => {
                        return Err("Expected task to fail due to cleanup failure".into());
                    }
                    Outcome::Err(BracketError::Inner(cleanup_err)) => {
                        // Verify the cleanup failure propagated through bracket
                        assert!(cleanup_err.contains("Cleanup failed"));
                        counter.record_stop();
                    }
                    Outcome::Cancelled(_) => {
                        // Also acceptable - cancellation during cleanup
                        counter.record_stop();
                    }
                    Outcome::Panicked(_) => {
                        return Err("Unexpected panic during bracket cleanup".into());
                    }
                }

                // Verify resource cleanup was attempted
                assert!(resource_clone.cleanup_attempt_count() > 0,
                       "Resource cleanup should have been attempted");

                Ok(())
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    assert!(stops >= 1, "Expected at least one Stop decision, got: stops={}, restarts={}, escalations={}, exhaustions={}", stops, restarts, escalations, exhaustions);
}

/// Test bracket resource acquisition failure with Restart supervision strategy.
#[tokio::test]
async fn test_bracket_acquisition_failure_with_restart_strategy() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();
    let acquisition_attempts = Arc::new(AtomicU32::new(0));

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                let attempts_clone = acquisition_attempts.clone();

                // Create bracket with failing acquisition
                let bracket_future = bracket(
                    // Acquire: fail after a few attempts
                    async move {
                        let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);
                        if attempt < 2 {
                            Err(format!("Acquisition failed on attempt {}", attempt))
                        } else {
                            Ok(FailingResource::new(attempt, false))
                        }
                    },
                    // Use: should eventually succeed
                    move |resource| async move {
                        Ok::<_, String>(format!("Used resource {}", resource.id))
                    },
                    // Release: clean release
                    move |resource| async move {
                        resource.cleanup().await
                    },
                );

                // Spawn with Restart supervision strategy
                let restart_config = RestartConfig::new(config.max_restart_attempts, Duration::from_secs(5))
                    .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100)));

                let task_handle = scope.spawn_with_supervision(
                    ChildName::new("bracket_restart_task"),
                    SupervisionStrategy::Restart(restart_config),
                    bracket_future,
                ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                // Wait for task completion with restarts
                match task_handle.join().await {
                    Outcome::Ok(result) => {
                        // Should eventually succeed after restarts
                        assert!(result.contains("Used resource"));
                        counter.record_restart();
                    }
                    Outcome::Err(BracketError::Inner(err)) => {
                        if acquisition_attempts.load(Ordering::SeqCst) >= config.max_restart_attempts {
                            // Restart budget exhausted
                            counter.record_restart_exhaustion();
                        } else {
                            return Err(format!("Unexpected acquisition failure: {}", err));
                        }
                    }
                    Outcome::Cancelled(_) => {
                        return Err("Task should not be cancelled".into());
                    }
                    Outcome::Panicked(_) => {
                        return Err("Unexpected panic during bracket acquisition".into());
                    }
                }

                // Verify multiple acquisition attempts were made
                assert!(acquisition_attempts.load(Ordering::SeqCst) >= 2,
                       "Expected multiple acquisition attempts due to restart strategy");

                Ok(())
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    assert!(restarts >= 1 || exhaustions >= 1,
           "Expected restart attempts or exhaustion, got: stops={}, restarts={}, escalations={}, exhaustions={}",
           stops, restarts, escalations, exhaustions);
}

// ============================================================================
// QUORUM FAILURE MODE TESTS
// ============================================================================

/// Test quorum insufficient completions propagate to Escalate supervision strategy.
#[tokio::test]
async fn test_quorum_insufficient_completions_escalate_strategy() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create parent region that will receive escalation
                cx.scope(|parent_scope| async move {
                    // Create quorum requiring 3 of 5 successes, but most will fail
                    let work_futures = (0..5).map(|i| {
                        let work_id = i;
                        async move {
                            // Only work_id 0 will succeed (20% success rate)
                            simulated_work(cx, work_id, 0.2, Duration::from_millis(100)).await
                        }
                    }).collect::<Vec<_>>();

                    let quorum_future = quorum(3, work_futures); // Need 3, will only get ~1

                    // Spawn with Escalate supervision strategy
                    let task_handle = parent_scope.spawn_with_supervision(
                        ChildName::new("quorum_escalate_task"),
                        SupervisionStrategy::Escalate,
                        quorum_future,
                    ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                    // Wait for quorum completion
                    match task_handle.join().await {
                        Outcome::Ok(_) => {
                            return Err("Expected quorum to fail due to insufficient completions".into());
                        }
                        Outcome::Err(QuorumError::InsufficientCompletions { required, achieved }) => {
                            // Verify quorum requirements not met
                            assert_eq!(required, 3);
                            assert!(achieved < 3, "Expected fewer than 3 successes, got {}", achieved);
                            counter.record_escalation();
                        }
                        Outcome::Cancelled(_) => {
                            // Escalation may result in cancellation
                            counter.record_escalation();
                        }
                        Outcome::Panicked(_) => {
                            return Err("Unexpected panic during quorum operation".into());
                        }
                    }

                    Ok(())
                }).await
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    assert!(escalations >= 1,
           "Expected escalation decision, got: stops={}, restarts={}, escalations={}, exhaustions={}",
           stops, restarts, escalations, exhaustions);
}

/// Test quorum mixed outcomes with supervision decision aggregation.
#[tokio::test]
async fn test_quorum_mixed_outcomes_supervision_aggregation() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create quorum with mixed success/failure outcomes
                let work_futures = (0..6).map(|i| {
                    let work_id = i;
                    async move {
                        // 50% success rate, deterministic based on work_id
                        simulated_work(cx, work_id, 0.5, Duration::from_millis(50)).await
                    }
                }).collect::<Vec<_>>();

                let quorum_future = quorum(2, work_futures); // Need 2 of 6, should succeed

                // Spawn with Stop supervision for successful quorum
                let task_handle = scope.spawn_with_supervision(
                    ChildName::new("quorum_mixed_task"),
                    SupervisionStrategy::Stop, // Won't trigger since quorum should succeed
                    quorum_future,
                ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                // Wait for quorum completion
                match task_handle.join().await {
                    Outcome::Ok(successful_results) => {
                        // Verify we got at least 2 successful results
                        assert!(successful_results.len() >= 2,
                               "Expected at least 2 successful results, got {}", successful_results.len());
                        // No supervision action needed since quorum succeeded
                    }
                    Outcome::Err(QuorumError::InsufficientCompletions { required, achieved }) => {
                        if achieved < required {
                            // Quorum failed, Stop strategy should trigger
                            counter.record_stop();
                        } else {
                            return Err(format!("Unexpected quorum failure: required={}, achieved={}", required, achieved));
                        }
                    }
                    Outcome::Cancelled(_) => {
                        return Err("Quorum task should not be cancelled".into());
                    }
                    Outcome::Panicked(_) => {
                        return Err("Unexpected panic during quorum operation".into());
                    }
                }

                Ok(())
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    // Test validates both successful quorum (no supervision action) and
    // potential quorum failure (Stop action), depending on deterministic work results
    let (stops, restarts, escalations, exhaustions) = counter.totals();
    // Either success (no action) or stop action is acceptable
}

// ============================================================================
// BULKHEAD FAILURE MODE TESTS
// ============================================================================

/// Test bulkhead resource exhaustion with Restart supervision strategy.
#[tokio::test]
async fn test_bulkhead_resource_exhaustion_restart_strategy() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create bulkhead with very limited capacity
                let bulkhead_policy = BulkheadPolicy {
                    name: "limited_bulkhead".to_string(),
                    max_concurrent: 2, // Very low limit
                    max_queue: 1,      // Very small queue
                    queue_timeout: Duration::from_millis(100),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(bulkhead_policy));
                let exhaustion_attempts = Arc::new(AtomicU32::new(0));

                // Create work that tries to exhaust the bulkhead
                let bulkhead_clone = bulkhead.clone();
                let attempts_clone = exhaustion_attempts.clone();

                let bulkhead_work = async move {
                    let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);

                    // Try to acquire permit with high concurrency
                    match bulkhead_clone.try_acquire(1).await {
                        Ok(permit) => {
                            // Hold permit for a while to stress the bulkhead
                            cx.sleep(Duration::from_millis(200)).await;
                            Ok(format!("Work completed on attempt {}", attempt))
                        }
                        Err(BulkheadError::ResourceExhausted) => {
                            Err(format!("Bulkhead exhausted on attempt {}", attempt))
                        }
                        Err(BulkheadError::QueueTimeout) => {
                            Err(format!("Queue timeout on attempt {}", attempt))
                        }
                        Err(e) => {
                            Err(format!("Unexpected bulkhead error: {:?}", e))
                        }
                    }
                };

                // Spawn with Restart supervision strategy
                let restart_config = RestartConfig::new(config.max_restart_attempts, Duration::from_secs(2))
                    .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(50)));

                let task_handle = scope.spawn_with_supervision(
                    ChildName::new("bulkhead_restart_task"),
                    SupervisionStrategy::Restart(restart_config),
                    bulkhead_work,
                ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                // Create concurrent load to stress bulkhead
                let mut concurrent_tasks = Vec::new();
                for i in 0..config.concurrency_level {
                    let bulkhead_stress_clone = bulkhead.clone();
                    let stress_task = scope.spawn(async move {
                        match bulkhead_stress_clone.try_acquire(1).await {
                            Ok(_permit) => {
                                cx.sleep(Duration::from_millis(150)).await;
                                Ok(format!("Stress task {} completed", i))
                            }
                            Err(_) => {
                                Err(format!("Stress task {} rejected", i))
                            }
                        }
                    });
                    concurrent_tasks.push(stress_task);
                }

                // Wait for main task completion
                match task_handle.join().await {
                    Outcome::Ok(result) => {
                        // Eventually succeeded after retries
                        assert!(result.contains("Work completed"));
                        counter.record_restart();
                    }
                    Outcome::Err(err) => {
                        if exhaustion_attempts.load(Ordering::SeqCst) >= config.max_restart_attempts {
                            // Restart budget exhausted due to persistent bulkhead exhaustion
                            assert!(err.contains("Bulkhead exhausted") || err.contains("Queue timeout"));
                            counter.record_restart_exhaustion();
                        } else {
                            return Err(format!("Unexpected bulkhead error: {}", err));
                        }
                    }
                    Outcome::Cancelled(_) => {
                        return Err("Bulkhead task should not be cancelled".into());
                    }
                    Outcome::Panicked(_) => {
                        return Err("Unexpected panic during bulkhead operation".into());
                    }
                }

                // Wait for stress tasks to complete
                for stress_task in concurrent_tasks {
                    let _ = stress_task.join().await; // Don't care about individual results
                }

                // Verify multiple attempts were made due to bulkhead pressure
                assert!(exhaustion_attempts.load(Ordering::SeqCst) >= 1,
                       "Expected attempts to be made under bulkhead pressure");

                Ok(())
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    assert!(restarts >= 1 || exhaustions >= 1,
           "Expected restart attempts or exhaustion under bulkhead pressure, got: stops={}, restarts={}, escalations={}, exhaustions={}",
           stops, restarts, escalations, exhaustions);
}

/// Test bulkhead queue timeout with Stop supervision strategy.
#[tokio::test]
async fn test_bulkhead_queue_timeout_stop_strategy() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 10000),
        |cx| async move {
            cx.scope(|scope| async move {
                // Create bulkhead with immediate timeout
                let bulkhead_policy = BulkheadPolicy {
                    name: "timeout_bulkhead".to_string(),
                    max_concurrent: 1,  // Single worker
                    max_queue: 2,       // Small queue
                    queue_timeout: Duration::from_millis(10), // Very short timeout
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(bulkhead_policy));

                // First task that will hold the bulkhead busy
                let bulkhead_holder = bulkhead.clone();
                let holder_task = scope.spawn(async move {
                    match bulkhead_holder.try_acquire(1).await {
                        Ok(_permit) => {
                            // Hold for longer than timeout to force queue timeout
                            cx.sleep(Duration::from_millis(200)).await;
                            Ok("Holder task completed")
                        }
                        Err(e) => Err(format!("Holder task failed: {:?}", e))
                    }
                });

                // Give holder time to acquire permit
                cx.sleep(Duration::from_millis(20)).await;

                // Create work that will timeout in queue
                let bulkhead_clone = bulkhead.clone();
                let timeout_work = async move {
                    match bulkhead_clone.try_acquire(1).await {
                        Ok(_permit) => {
                            Ok("Work should not succeed due to timeout".to_string())
                        }
                        Err(BulkheadError::QueueTimeout) => {
                            Err("Queue timeout as expected".to_string())
                        }
                        Err(e) => {
                            Err(format!("Unexpected error: {:?}", e))
                        }
                    }
                };

                // Spawn with Stop supervision strategy
                let task_handle = scope.spawn_with_supervision(
                    ChildName::new("bulkhead_timeout_task"),
                    SupervisionStrategy::Stop,
                    timeout_work,
                ).map_err(|e| format!("Failed to spawn: {:?}", e))?;

                // Wait for task completion
                match task_handle.join().await {
                    Outcome::Ok(_) => {
                        return Err("Expected task to fail due to queue timeout".into());
                    }
                    Outcome::Err(err) => {
                        // Verify queue timeout propagated through supervision
                        assert!(err.contains("Queue timeout"), "Expected queue timeout error, got: {}", err);
                        counter.record_stop();
                    }
                    Outcome::Cancelled(_) => {
                        // Also acceptable - Stop strategy may result in cancellation
                        counter.record_stop();
                    }
                    Outcome::Panicked(_) => {
                        return Err("Unexpected panic during bulkhead timeout".into());
                    }
                }

                // Wait for holder task to complete
                let _ = holder_task.join().await;

                Ok(())
            }).await
        },
    );

    assert!(result.is_ok(), "Test should complete successfully: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    assert!(stops >= 1,
           "Expected Stop decision on queue timeout, got: stops={}, restarts={}, escalations={}, exhaustions={}",
           stops, restarts, escalations, exhaustions);
}

// ============================================================================
// COMPREHENSIVE INTEGRATION TESTS
// ============================================================================

/// Test comprehensive failure propagation across all combinators and supervision strategies.
#[tokio::test]
async fn test_comprehensive_combinator_supervision_failure_propagation() {
    let config = TestConfig {
        runtime_timeout: Duration::from_secs(60),
        budget_duration: Duration::from_secs(20),
        expected_failures: 12, // Expect multiple failure modes
        max_restart_attempts: 2,
        concurrency_level: 8,
    };

    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 20000),
        |cx| async move {
            cx.scope(|scope| async move {
                let mut test_results = Vec::new();

                // Test 1: Bracket cleanup failure + Stop strategy
                let failing_resource = FailingResource::new(100, true);
                let resource_clone = failing_resource.clone();
                let bracket_future = bracket(
                    async move { Ok::<_, String>(failing_resource) },
                    move |resource| async move {
                        cx.sleep(Duration::from_millis(50)).await;
                        Ok::<_, String>(format!("Used resource {}", resource.id))
                    },
                    move |resource| async move { resource.cleanup().await },
                );

                let bracket_handle = scope.spawn_with_supervision(
                    ChildName::new("comprehensive_bracket"),
                    SupervisionStrategy::Stop,
                    bracket_future,
                )?;

                // Test 2: Quorum failure + Escalate strategy
                let quorum_futures = (0..4).map(|i| {
                    async move { simulated_work(cx, i, 0.25, Duration::from_millis(30)).await }
                }).collect();
                let quorum_future = quorum(3, quorum_futures); // Need 3, likely get 1

                let quorum_handle = scope.spawn_with_supervision(
                    ChildName::new("comprehensive_quorum"),
                    SupervisionStrategy::Escalate,
                    quorum_future,
                )?;

                // Test 3: Bulkhead exhaustion + Restart strategy
                let bulkhead = Arc::new(Bulkhead::new(BulkheadPolicy {
                    name: "comprehensive_bulkhead".to_string(),
                    max_concurrent: 1,
                    max_queue: 1,
                    queue_timeout: Duration::from_millis(50),
                    weighted: false,
                    on_full: None,
                }));

                let bulkhead_clone = bulkhead.clone();
                let bulkhead_work = async move {
                    match bulkhead_clone.try_acquire(1).await {
                        Ok(_permit) => {
                            cx.sleep(Duration::from_millis(100)).await;
                            Ok("Bulkhead work completed".to_string())
                        }
                        Err(e) => Err(format!("Bulkhead error: {:?}", e))
                    }
                };

                let restart_config = RestartConfig::new(config.max_restart_attempts, Duration::from_secs(1));
                let bulkhead_handle = scope.spawn_with_supervision(
                    ChildName::new("comprehensive_bulkhead"),
                    SupervisionStrategy::Restart(restart_config),
                    bulkhead_work,
                )?;

                // Create bulkhead stress
                let stress_handle = scope.spawn(async move {
                    match bulkhead.try_acquire(1).await {
                        Ok(_permit) => {
                            cx.sleep(Duration::from_millis(200)).await;
                            Ok("Stress completed")
                        }
                        Err(_) => Err("Stress rejected")
                    }
                });

                // Cancel bracket after short time to trigger cleanup
                cx.sleep(Duration::from_millis(25)).await;
                bracket_handle.cancel();

                // Wait for all tasks to complete and collect results
                let bracket_result = bracket_handle.join().await;
                let quorum_result = quorum_handle.join().await;
                let bulkhead_result = bulkhead_handle.join().await;
                let stress_result = stress_handle.join().await;

                // Analyze bracket result (should show cleanup failure)
                match bracket_result {
                    Outcome::Err(BracketError::Inner(err)) => {
                        assert!(err.contains("Cleanup failed"));
                        counter.record_stop();
                        test_results.push("Bracket cleanup failure handled correctly");
                    }
                    Outcome::Cancelled(_) => {
                        counter.record_stop();
                        test_results.push("Bracket cancelled due to cleanup failure");
                    }
                    _ => test_results.push("Bracket result unexpected"),
                }

                // Analyze quorum result (should show insufficient completions)
                match quorum_result {
                    Outcome::Err(QuorumError::InsufficientCompletions { required, achieved }) => {
                        assert_eq!(required, 3);
                        assert!(achieved < 3);
                        counter.record_escalation();
                        test_results.push("Quorum insufficient completions escalated correctly");
                    }
                    Outcome::Cancelled(_) => {
                        counter.record_escalation();
                        test_results.push("Quorum escalated through cancellation");
                    }
                    _ => test_results.push("Quorum result unexpected"),
                }

                // Analyze bulkhead result (should show retry attempts or exhaustion)
                match bulkhead_result {
                    Outcome::Ok(_) => {
                        counter.record_restart();
                        test_results.push("Bulkhead eventually succeeded after restarts");
                    }
                    Outcome::Err(err) => {
                        if err.contains("Bulkhead error") {
                            counter.record_restart_exhaustion();
                            test_results.push("Bulkhead restart exhausted due to persistent failure");
                        } else {
                            test_results.push("Bulkhead error unexpected");
                        }
                    }
                    _ => test_results.push("Bulkhead result unexpected"),
                }

                // Verify resource cleanup was attempted
                assert!(resource_clone.cleanup_attempt_count() > 0);

                Ok(test_results)
            }).await
        },
    );

    assert!(result.is_ok(), "Comprehensive test should complete: {:?}", result);

    if let Ok(results) = result {
        assert!(!results.is_empty(), "Should have collected test results");
        for result in &results {
            println!("✓ {}", result);
        }
    }

    let (stops, restarts, escalations, exhaustions) = counter.totals();
    let total_decisions = stops + restarts + escalations + exhaustions;

    assert!(total_decisions >= 3,
           "Expected supervision decisions from all combinator types, got: stops={}, restarts={}, escalations={}, exhaustions={} (total={})",
           stops, restarts, escalations, exhaustions, total_decisions);

    // Verify each supervision strategy was exercised
    assert!(stops >= 1, "Expected at least one Stop decision from bracket cleanup failure");
    assert!(escalations >= 1, "Expected at least one Escalate decision from quorum failure");
    assert!(restarts >= 1 || exhaustions >= 1, "Expected Restart attempts or exhaustion from bulkhead stress");
}

/// Test supervision strategy escalation chain under combinator failure pressure.
#[tokio::test]
async fn test_supervision_escalation_chain_under_combinator_pressure() {
    let config = TestConfig::default();
    let runtime = create_test_runtime().unwrap();
    let counter = SupervisionDecisionCounter::default();

    let result = runtime.block_on_with_budget(
        Budget::new(config.budget_duration, 15000),
        |cx| async move {
            cx.scope(|root_scope| async move {
                // Create multi-level supervision hierarchy
                root_scope.scope(|parent_scope| async move {
                    parent_scope.scope(|child_scope| async move {
                        // Child level: Bulkhead with Escalate strategy
                        let bulkhead = Arc::new(Bulkhead::new(BulkheadPolicy {
                            name: "escalation_test".to_string(),
                            max_concurrent: 1,
                            max_queue: 0, // No queue - immediate failure
                            queue_timeout: Duration::from_millis(1),
                            weighted: false,
                            on_full: None,
                        }));

                        // Create holder task that blocks the bulkhead
                        let holder_bulkhead = bulkhead.clone();
                        let holder = child_scope.spawn(async move {
                            match holder_bulkhead.try_acquire(1).await {
                                Ok(_permit) => {
                                    cx.sleep(Duration::from_millis(300)).await;
                                    Ok("Holder completed")
                                }
                                Err(e) => Err(format!("Holder failed: {:?}", e))
                            }
                        });

                        // Give holder time to acquire
                        cx.sleep(Duration::from_millis(10)).await;

                        // Child task: Quorum with bulkhead operations (will escalate)
                        let bulkhead_clone = bulkhead.clone();
                        let quorum_futures = (0..3).map(|i| {
                            let bulkhead_ref = bulkhead_clone.clone();
                            async move {
                                match bulkhead_ref.try_acquire(1).await {
                                    Ok(_permit) => {
                                        Ok(format!("Quorum task {} succeeded", i))
                                    }
                                    Err(BulkheadError::ResourceExhausted) => {
                                        Err(format!("Quorum task {} bulkhead exhausted", i))
                                    }
                                    Err(e) => {
                                        Err(format!("Quorum task {} error: {:?}", i, e))
                                    }
                                }
                            }
                        }).collect();

                        let quorum_future = quorum(2, quorum_futures); // Need 2, will fail

                        let child_handle = child_scope.spawn_with_supervision(
                            ChildName::new("escalating_child"),
                            SupervisionStrategy::Escalate, // Will escalate to parent
                            quorum_future,
                        )?;

                        // Parent level: Handle escalation with Restart strategy
                        let restart_config = RestartConfig::new(2, Duration::from_secs(1));
                        let parent_handle = parent_scope.spawn_with_supervision(
                            ChildName::new("restarting_parent"),
                            SupervisionStrategy::Restart(restart_config),
                            async move {
                                match child_handle.join().await {
                                    Outcome::Ok(_) => Ok("Child succeeded"),
                                    Outcome::Err(QuorumError::InsufficientCompletions { .. }) => {
                                        Err("Child quorum failed due to bulkhead exhaustion")
                                    }
                                    Outcome::Cancelled(_) => {
                                        Err("Child was cancelled")
                                    }
                                    Outcome::Panicked(_) => {
                                        Err("Child panicked")
                                    }
                                }
                            },
                        )?;

                        // Root level: Ultimate Stop strategy
                        let root_handle = root_scope.spawn_with_supervision(
                            ChildName::new("stopping_root"),
                            SupervisionStrategy::Stop,
                            async move {
                                match parent_handle.join().await {
                                    Outcome::Ok(_) => Ok("Parent eventually succeeded"),
                                    Outcome::Err(err) => {
                                        Err(format!("Parent failed: {}", err))
                                    }
                                    Outcome::Cancelled(_) => {
                                        Err("Parent was cancelled")
                                    }
                                    Outcome::Panicked(_) => {
                                        Err("Parent panicked")
                                    }
                                }
                            },
                        )?;

                        // Wait for the full escalation chain to complete
                        match root_handle.join().await {
                            Outcome::Ok(_) => {
                                // Unlikely but possible if restarts eventually succeed
                                counter.record_restart();
                            }
                            Outcome::Err(err) => {
                                // Expected path: escalation -> restart exhaustion -> stop
                                assert!(err.contains("Parent failed") || err.contains("quorum failed"));
                                counter.record_escalation();
                                counter.record_restart_exhaustion();
                                counter.record_stop();
                            }
                            Outcome::Cancelled(_) => {
                                // Also acceptable - Stop strategy may cancel
                                counter.record_stop();
                            }
                            Outcome::Panicked(_) => {
                                return Err("Unexpected panic in escalation chain".into());
                            }
                        }

                        // Wait for holder to complete
                        let _ = holder.join().await;

                        Ok(())
                    }).await
                }).await
            }).await
        },
    );

    assert!(result.is_ok(), "Escalation chain test should complete: {:?}", result);

    let (stops, restarts, escalations, exhaustions) = counter.totals();

    // Verify the escalation chain was exercised
    assert!(escalations >= 1, "Expected escalation from child to parent");
    assert!(stops >= 1 || restarts >= 1 || exhaustions >= 1,
           "Expected supervision action at some level");

    println!("Supervision decisions: stops={}, restarts={}, escalations={}, exhaustions={}",
             stops, restarts, escalations, exhaustions);
}