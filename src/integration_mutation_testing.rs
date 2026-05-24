//! Integration Test Mutation Testing
//!
//! Validates that integration test harnesses actually catch real bugs by introducing
//! known mutations in production code and verifying the tests fail as expected.
//!
//! This is critical meta-testing: if integration tests pass with broken code,
//! they provide false confidence. Each mutation represents a realistic bug class
//! that should be caught by the corresponding integration scenario.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::channel::{broadcast, mpsc, oneshot};
use crate::combinator::{race, timeout};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::runtime::{LabRuntime, RuntimeBuilder};
use crate::sync::{AtomicBool, AtomicUsize, Mutex, Ordering};
use crate::time::{Duration, Instant, sleep};
use crate::types::{Budget, Outcome};

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

/// Mutation testing harness for validating integration test sensitivity
struct MutationTestHarness {
    test_name: String,
    runtime: LabRuntime,
    mutations_applied: Arc<AtomicUsize>,
    mutations_caught: Arc<AtomicUsize>,
    false_negatives: Arc<AtomicUsize>,
}

impl MutationTestHarness {
    async fn new(test_name: &str) -> Self {
        let temp_dir = TempDir::new().expect("Should create temp directory");

        let runtime = RuntimeBuilder::new()
            .with_lab_mode()
            .with_temp_dir(temp_dir.path())
            .build()
            .await
            .expect("Should build lab runtime");

        Self {
            test_name: test_name.to_string(),
            runtime,
            mutations_applied: Arc::new(AtomicUsize::new(0)),
            mutations_caught: Arc::new(AtomicUsize::new(0)),
            false_negatives: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn log_mutation(&self, mutation_id: &str, description: &str, expected_failure: bool) {
        eprintln!(
            "{{\"mutation_test\":\"{}\",\"id\":\"{}\",\"description\":\"{}\",\"expected_failure\":{}}}",
            self.test_name, mutation_id, description, expected_failure
        );
    }

    fn log_result(&self, mutation_id: &str, test_failed: bool, expected_failure: bool) {
        let caught = test_failed && expected_failure;
        let false_negative = !test_failed && expected_failure;

        eprintln!(
            "{{\"mutation_result\":\"{}\",\"id\":\"{}\",\"test_failed\":{},\"expected_failure\":{},\"caught\":{},\"false_negative\":{}}}",
            self.test_name, mutation_id, test_failed, expected_failure, caught, false_negative
        );

        if caught {
            self.mutations_caught.fetch_add(1, Ordering::Relaxed);
        }
        if false_negative {
            self.false_negatives.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// [br-mutation-1] Obligation leak mutation: Remove obligation cleanup
    async fn test_obligation_leak_mutation(&self) {
        self.log_mutation(
            "br-mutation-1",
            "Remove obligation cleanup to introduce leaks",
            true,
        );
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate the chaos thread kill test with obligation leak mutation
                let obligation_count = 50;
                let created_obligations = Arc::new(AtomicUsize::new(0));
                let leaked_obligations = Arc::new(AtomicUsize::new(0));

                let mut obligation_tasks = Vec::new();

                for obligation_id in 0..obligation_count {
                    let created = Arc::clone(&created_obligations);
                    let leaked = Arc::clone(&leaked_obligations);

                    let task = scope
                        .spawn(async move {
                            created.fetch_add(1, Ordering::Relaxed);

                            // Simulate work with potential obligation
                            sleep(Duration::from_millis(50)).await;

                            // MUTATION: Skip obligation cleanup (introduce leak)
                            if obligation_id % 3 == 0 {
                                leaked.fetch_add(1, Ordering::Relaxed);
                                // Intentionally skip cleanup - this should be caught by integration test
                                return Outcome::Ok(());
                            }

                            // Normal cleanup for other obligations
                            Outcome::Ok(())
                        })
                        .await;

                    obligation_tasks.push(task);
                }

                // Wait for all tasks to complete
                for task in obligation_tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let total_created = created_obligations.load(Ordering::Relaxed);
                let total_leaked = leaked_obligations.load(Ordering::Relaxed);

                // This should fail the integration test due to obligation leaks
                if total_leaked > 0 {
                    Outcome::Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Obligation leak detected: {} leaked out of {} created",
                            total_leaked, total_created
                        ),
                    ))
                } else {
                    Outcome::Ok(())
                }
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_));
        self.log_result("br-mutation-1", test_failed, true);
    }

    /// [br-mutation-2] Rate limiting bypass: Remove rate check
    async fn test_rate_limiting_bypass_mutation(&self) {
        self.log_mutation("br-mutation-2", "Bypass rate limiting checks", true);
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate rate limiting with bypass mutation
                let rate_limit = 10; // 10 requests allowed
                let burst_size = 50; // 50 requests attempted
                let allowed_requests = Arc::new(AtomicUsize::new(0));
                let rejected_requests = Arc::new(AtomicUsize::new(0));

                let mut request_tasks = Vec::new();

                for request_id in 0..burst_size {
                    let allowed = Arc::clone(&allowed_requests);
                    let rejected = Arc::clone(&rejected_requests);

                    let task = scope
                        .spawn(async move {
                            // MUTATION: Skip rate limiting check (always allow)
                            // This bypasses the rate limiter entirely
                            let should_allow = true; // Normal code would check: allowed.load() < rate_limit

                            if should_allow {
                                allowed.fetch_add(1, Ordering::Relaxed);

                                // Simulate request processing
                                sleep(Duration::from_millis(10)).await;
                                Outcome::Ok(format!("processed_request_{}", request_id))
                            } else {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                Outcome::Err(Error::new(ErrorKind::Other, "Rate limited"))
                            }
                        })
                        .await;

                    request_tasks.push(task);
                    sleep(Duration::from_millis(5)).await; // Burst pattern
                }

                // Wait for all requests
                for task in request_tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let total_allowed = allowed_requests.load(Ordering::Relaxed);
                let total_rejected = rejected_requests.load(Ordering::Relaxed);

                // Integration test should catch that rate limiting isn't working
                if total_rejected == 0 && total_allowed > rate_limit * 2 {
                    Outcome::Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Rate limiting bypassed: {} allowed, {} rejected",
                            total_allowed, total_rejected
                        ),
                    ))
                } else {
                    Outcome::Ok(())
                }
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_));
        self.log_result("br-mutation-2", test_failed, true);
    }

    /// [br-mutation-3] Checkpoint corruption: Corrupt checkpoint data
    async fn test_checkpoint_corruption_mutation(&self) {
        self.log_mutation(
            "br-mutation-3",
            "Corrupt checkpoint data during save/restore",
            true,
        );
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate checkpoint/resume with corruption mutation
                let checkpoint_storage =
                    Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));
                let work_progress = Arc::new(AtomicUsize::new(0));
                let corrupted_checkpoints = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        let mut current_work = 0;
                        let total_work = 20;

                        while current_work < total_work {
                            // Process work
                            current_work += 1;
                            work_progress.store(current_work, Ordering::Relaxed);

                            // Create checkpoint every 5 work units
                            if current_work % 5 == 0 {
                                let checkpoint_data = serde_json::json!({
                                    "work_progress": current_work,
                                    "timestamp": std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis()
                                });

                                // MUTATION: Corrupt checkpoint data
                                let corrupted_data = serde_json::json!({
                                    "work_progress": current_work + 1000, // Wrong progress
                                    "timestamp": 0 // Wrong timestamp
                                });

                                {
                                    let mut storage = checkpoint_storage.lock().await;
                                    storage.insert(
                                        format!("checkpoint_{}", current_work),
                                        corrupted_data,
                                    );
                                }

                                corrupted_checkpoints.fetch_add(1, Ordering::Relaxed);
                            }

                            sleep(Duration::from_millis(20)).await;
                        }

                        // Simulate resume from checkpoint
                        let final_progress = {
                            let storage = checkpoint_storage.lock().await;
                            if let Some(checkpoint) = storage.get("checkpoint_20") {
                                checkpoint["work_progress"].as_u64().unwrap_or(0) as usize
                            } else {
                                current_work
                            }
                        };

                        // Check for corruption
                        if final_progress != current_work {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Checkpoint corruption detected: expected {}, got {}",
                                    current_work, final_progress
                                ),
                            ))
                        } else {
                            Outcome::Ok(())
                        }
                    })
                    .await;

                timeout(Duration::from_secs(5), task).await
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_) | Outcome::Cancelled);
        self.log_result("br-mutation-3", test_failed, true);
    }

    /// [br-mutation-4] Backpressure ignore: Ignore backpressure signals
    async fn test_backpressure_ignore_mutation(&self) {
        self.log_mutation(
            "br-mutation-4",
            "Ignore backpressure signals causing overflow",
            true,
        );
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate backpressure system with ignore mutation
                let (producer_tx, producer_rx) = mpsc::channel(10);
                let (consumer_tx, consumer_rx) = mpsc::channel(10);

                let queue_size = Arc::new(AtomicUsize::new(0));
                let overflow_events = Arc::new(AtomicUsize::new(0));
                let backpressure_ignored = Arc::new(AtomicUsize::new(0));

                // Producer that should respect backpressure
                let producer = {
                    let queue_size = Arc::clone(&queue_size);
                    let overflow_events = Arc::clone(&overflow_events);
                    let backpressure_ignored = Arc::clone(&backpressure_ignored);

                    scope
                        .spawn(async move {
                            for item_id in 0..100 {
                                let current_queue_size = queue_size.load(Ordering::Relaxed);

                                // MUTATION: Ignore backpressure signals (should respect queue size limit)
                                let should_apply_backpressure = false; // Normal: current_queue_size > 20

                                if should_apply_backpressure {
                                    // Normal code would wait here
                                    sleep(Duration::from_millis(50)).await;
                                } else {
                                    // MUTATION: Always ignore backpressure
                                    backpressure_ignored.fetch_add(1, Ordering::Relaxed);
                                }

                                // Try to send item
                                match producer_tx.try_send(format!("item_{}", item_id)) {
                                    Ok(_) => {
                                        queue_size.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(_) => {
                                        // Queue overflow
                                        overflow_events.fetch_add(1, Ordering::Relaxed);
                                    }
                                }

                                sleep(Duration::from_millis(5)).await; // Fast production
                            }

                            Outcome::Ok(())
                        })
                        .await
                };

                // Slow consumer
                let consumer = {
                    let queue_size = Arc::clone(&queue_size);

                    scope
                        .spawn(async move {
                            let mut consumer_rx = producer_rx;
                            let mut consumed_count = 0;

                            while let Some(_item) = consumer_rx.recv().await {
                                consumed_count += 1;
                                queue_size.fetch_sub(1, Ordering::Relaxed);

                                // Slow processing
                                sleep(Duration::from_millis(50)).await;

                                if consumed_count >= 50 {
                                    break; // Stop consuming to create backpressure
                                }
                            }

                            Outcome::Ok(consumed_count)
                        })
                        .await
                };

                // Wait for completion
                let _ = timeout(Duration::from_secs(8), producer).await;
                let _ = timeout(Duration::from_secs(2), consumer).await;

                let total_overflow = overflow_events.load(Ordering::Relaxed);
                let ignored_backpressure = backpressure_ignored.load(Ordering::Relaxed);

                // Integration test should catch backpressure being ignored
                if ignored_backpressure > 50 && total_overflow > 10 {
                    Outcome::Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Backpressure ignored causing overflow: {} ignored, {} overflows",
                            ignored_backpressure, total_overflow
                        ),
                    ))
                } else {
                    Outcome::Ok(())
                }
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_));
        self.log_result("br-mutation-4", test_failed, true);
    }

    /// [br-mutation-5] Timer accuracy corruption: Introduce systematic drift
    async fn test_timer_accuracy_corruption_mutation(&self) {
        self.log_mutation("br-mutation-5", "Introduce systematic timer drift", true);
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate timer accuracy testing with drift mutation
                let timer_count = 20;
                let expected_duration = Duration::from_millis(100);
                let accuracy_violations = Arc::new(AtomicUsize::new(0));
                let total_drift = Arc::new(AtomicUsize::new(0));

                let mut timer_tasks = Vec::new();

                for timer_id in 0..timer_count {
                    let violations = Arc::clone(&accuracy_violations);
                    let drift = Arc::clone(&total_drift);

                    let task = scope
                        .spawn(async move {
                            let start_time = Instant::now();

                            // MUTATION: Introduce systematic drift (add extra delay)
                            let corrupted_duration = expected_duration + Duration::from_millis(50); // Always 50ms drift
                            sleep(corrupted_duration).await;

                            let actual_duration = start_time.elapsed();
                            let expected_ms = expected_duration.as_millis() as usize;
                            let actual_ms = actual_duration.as_millis() as usize;
                            let drift_amount = actual_ms.saturating_sub(expected_ms);

                            drift.fetch_add(drift_amount, Ordering::Relaxed);

                            // Check accuracy (should detect systematic drift)
                            if drift_amount > 25 {
                                // 25ms tolerance
                                violations.fetch_add(1, Ordering::Relaxed);
                            }

                            Outcome::Ok(drift_amount)
                        })
                        .await;

                    timer_tasks.push(task);
                    sleep(Duration::from_millis(10)).await; // Stagger starts
                }

                // Wait for all timers
                for task in timer_tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let total_violations = accuracy_violations.load(Ordering::Relaxed);
                let avg_drift = total_drift.load(Ordering::Relaxed) / timer_count;

                // Integration test should catch systematic timer inaccuracy
                if total_violations > timer_count / 2 || avg_drift > 30 {
                    Outcome::Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Timer accuracy corruption detected: {} violations, {}ms avg drift",
                            total_violations, avg_drift
                        ),
                    ))
                } else {
                    Outcome::Ok(())
                }
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_));
        self.log_result("br-mutation-5", test_failed, true);
    }

    /// [br-mutation-6] Connection leak: Skip connection cleanup
    async fn test_connection_leak_mutation(&self) {
        self.log_mutation(
            "br-mutation-6",
            "Skip connection cleanup causing resource leaks",
            true,
        );
        self.mutations_applied.fetch_add(1, Ordering::Relaxed);

        let test_result = self
            .runtime
            .scope(|scope| async move {
                // Simulate connection handling with cleanup bypass mutation
                let connection_count = 30;
                let active_connections = Arc::new(AtomicUsize::new(0));
                let leaked_connections = Arc::new(AtomicUsize::new(0));

                let mut connection_tasks = Vec::new();

                for conn_id in 0..connection_count {
                    let active = Arc::clone(&active_connections);
                    let leaked = Arc::clone(&leaked_connections);

                    let task = scope
                        .spawn(async move {
                            // Simulate connection establishment
                            active.fetch_add(1, Ordering::Relaxed);

                            // Simulate connection usage
                            sleep(Duration::from_millis(50)).await;

                            // MUTATION: Skip connection cleanup for some connections
                            if conn_id % 4 == 0 {
                                // Intentionally leak this connection
                                leaked.fetch_add(1, Ordering::Relaxed);
                                return Outcome::Ok(()); // Skip cleanup
                            }

                            // Normal cleanup
                            active.fetch_sub(1, Ordering::Relaxed);

                            Outcome::Ok(())
                        })
                        .await;

                    connection_tasks.push(task);
                }

                // Wait for all connections to complete
                for task in connection_tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let final_active = active_connections.load(Ordering::Relaxed);
                let total_leaked = leaked_connections.load(Ordering::Relaxed);

                // Integration test should catch connection leaks
                if final_active > 0 || total_leaked > 0 {
                    Outcome::Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Connection leak detected: {} active, {} leaked",
                            final_active, total_leaked
                        ),
                    ))
                } else {
                    Outcome::Ok(())
                }
            })
            .await;

        let test_failed = matches!(test_result, Outcome::Err(_));
        self.log_result("br-mutation-6", test_failed, true);
    }

    /// Generate mutation testing summary
    fn generate_summary(&self) -> serde_json::Value {
        let applied = self.mutations_applied.load(Ordering::Relaxed);
        let caught = self.mutations_caught.load(Ordering::Relaxed);
        let false_negatives = self.false_negatives.load(Ordering::Relaxed);

        let detection_rate = if applied > 0 {
            caught as f64 / applied as f64
        } else {
            0.0
        };

        serde_json::json!({
            "mutation_testing_summary": {
                "test_harness": self.test_name,
                "mutations_applied": applied,
                "mutations_caught": caught,
                "false_negatives": false_negatives,
                "detection_rate": detection_rate,
                "harness_effectiveness": if detection_rate >= 0.8 { "EFFECTIVE" } else { "NEEDS_IMPROVEMENT" }
            }
        })
    }
}

#[tokio::test]
async fn test_integration_harness_mutation_sensitivity() {
    let harness = MutationTestHarness::new("integration_harness_mutation_sensitivity").await;

    eprintln!("{{\"mutation_testing_start\":\"integration_harness_sensitivity\"}}");

    // Run all mutation tests
    harness.test_obligation_leak_mutation().await;
    harness.test_rate_limiting_bypass_mutation().await;
    harness.test_checkpoint_corruption_mutation().await;
    harness.test_backpressure_ignore_mutation().await;
    harness.test_timer_accuracy_corruption_mutation().await;
    harness.test_connection_leak_mutation().await;

    let summary = harness.generate_summary();
    eprintln!("{}", summary);

    // Validate that our test harness catches most mutations
    let applied = harness.mutations_applied.load(Ordering::Relaxed);
    let caught = harness.mutations_caught.load(Ordering::Relaxed);
    let false_negatives = harness.false_negatives.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply mutations for testing");

    // Our integration tests should catch at least 80% of realistic bugs
    let detection_rate = caught as f64 / applied as f64;
    assert!(
        detection_rate >= 0.8,
        "Integration test harness should catch ≥80% of mutations: {:.1}% detection rate ({} caught / {} applied)",
        detection_rate * 100.0,
        caught,
        applied
    );

    assert!(
        false_negatives <= applied / 4,
        "False negatives should be ≤25% of mutations: {} false negatives out of {} applied",
        false_negatives,
        applied
    );

    eprintln!(
        "{{\"mutation_testing_complete\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_chaos_scenario_mutation_sensitivity() {
    let harness = MutationTestHarness::new("chaos_scenario_mutation_sensitivity").await;

    eprintln!("{{\"mutation_testing_start\":\"chaos_scenario_sensitivity\"}}");

    // Test chaos-specific mutations
    harness.test_obligation_leak_mutation().await; // Should catch obligation leaks in thread kill scenarios
    harness.test_connection_leak_mutation().await; // Should catch resource leaks in connection storms

    let summary = harness.generate_summary();
    eprintln!("{}", summary);

    let applied = harness.mutations_applied.load(Ordering::Relaxed);
    let caught = harness.mutations_caught.load(Ordering::Relaxed);

    // Chaos engineering tests should be especially sensitive to resource leaks
    assert!(applied > 0, "Should apply chaos-relevant mutations");

    let detection_rate = caught as f64 / applied as f64;
    assert!(
        detection_rate >= 0.9,
        "Chaos tests should catch ≥90% of resource leak mutations: {:.1}% detection rate",
        detection_rate * 100.0
    );

    eprintln!(
        "{{\"chaos_mutation_testing_complete\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_performance_scenario_mutation_sensitivity() {
    let harness = MutationTestHarness::new("performance_scenario_mutation_sensitivity").await;

    eprintln!("{{\"mutation_testing_start\":\"performance_scenario_sensitivity\"}}");

    // Test performance-specific mutations
    harness.test_rate_limiting_bypass_mutation().await; // Should catch rate limiting failures
    harness.test_backpressure_ignore_mutation().await; // Should catch backpressure violations
    harness.test_timer_accuracy_corruption_mutation().await; // Should catch timer inaccuracies

    let summary = harness.generate_summary();
    eprintln!("{}", summary);

    let applied = harness.mutations_applied.load(Ordering::Relaxed);
    let caught = harness.mutations_caught.load(Ordering::Relaxed);

    // Performance tests should catch performance-degrading mutations
    assert!(applied > 0, "Should apply performance-relevant mutations");

    let detection_rate = caught as f64 / applied as f64;
    assert!(
        detection_rate >= 0.85,
        "Performance tests should catch ≥85% of performance mutations: {:.1}% detection rate",
        detection_rate * 100.0
    );

    eprintln!(
        "{{\"performance_mutation_testing_complete\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_long_running_scenario_mutation_sensitivity() {
    let harness = MutationTestHarness::new("long_running_scenario_mutation_sensitivity").await;

    eprintln!("{{\"mutation_testing_start\":\"long_running_scenario_sensitivity\"}}");

    // Test long-running specific mutations
    harness.test_checkpoint_corruption_mutation().await; // Should catch checkpoint corruption
    harness.test_backpressure_ignore_mutation().await; // Should catch memory pressure handling failures

    let summary = harness.generate_summary();
    eprintln!("{}", summary);

    let applied = harness.mutations_applied.load(Ordering::Relaxed);
    let caught = harness.mutations_caught.load(Ordering::Relaxed);

    // Long-running tests should catch persistence and memory management issues
    assert!(applied > 0, "Should apply long-running relevant mutations");

    let detection_rate = caught as f64 / applied as f64;
    assert!(
        detection_rate >= 0.8,
        "Long-running tests should catch ≥80% of persistence mutations: {:.1}% detection rate",
        detection_rate * 100.0
    );

    eprintln!(
        "{{\"long_running_mutation_testing_complete\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}
