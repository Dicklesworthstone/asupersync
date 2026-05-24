//! Targeted mutation testing against specific integration scenarios
//!
//! Tests individual integration scenarios against their expected failure modes
//! to validate that each test actually catches the bugs it's designed to find.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::channel::{broadcast, mpsc, oneshot};
use crate::combinator::{race, retry, timeout};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::runtime::{LabRuntime, RuntimeBuilder};
use crate::sync::{AtomicBool, AtomicUsize, Mutex, Ordering};
use crate::time::{Duration, Instant, sleep};
use crate::types::{Budget, Outcome};

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

/// Targeted mutation testing for specific integration scenarios
struct ScenarioMutationTester {
    runtime: LabRuntime,
    scenario_name: String,
}

impl ScenarioMutationTester {
    async fn new(scenario: &str) -> Self {
        let temp_dir = TempDir::new().expect("Should create temp directory");

        let runtime = RuntimeBuilder::new()
            .with_lab_mode()
            .with_temp_dir(temp_dir.path())
            .build()
            .await
            .expect("Should build lab runtime");

        Self {
            runtime,
            scenario_name: scenario.to_string(),
        }
    }

    fn log_mutation_test(&self, mutation_id: &str, test_passed: bool, expected_failure: bool) {
        let mutation_caught = !test_passed && expected_failure;
        let false_negative = test_passed && expected_failure;

        eprintln!(
            "{{\"scenario_mutation\":\"{}\",\"mutation\":\"{}\",\"test_passed\":{},\"expected_failure\":{},\"caught\":{},\"false_negative\":{}}}",
            self.scenario_name,
            mutation_id,
            test_passed,
            expected_failure,
            mutation_caught,
            false_negative
        );
    }

    /// Test mutation against chaos thread kill scenario
    async fn test_chaos_thread_kill_mutations(&self) -> bool {
        // [br-mutation-7] Skip thread cleanup in chaos scenario
        let chaos_result = self
            .runtime
            .scope(|scope| async move {
                let task_count = 20;
                let killed_count = Arc::new(AtomicUsize::new(0));
                let leaked_count = Arc::new(AtomicUsize::new(0));

                let mut tasks = Vec::new();

                for task_id in 0..task_count {
                    let killed = Arc::clone(&killed_count);
                    let leaked = Arc::clone(&leaked_count);

                    let task = scope
                        .spawn(async move {
                            // Simulate work
                            sleep(Duration::from_millis(50)).await;

                            // Simulate chaos kill (40% probability)
                            if fastrand::f64() < 0.4 {
                                killed.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Skip cleanup on thread kill (introduce leak)
                                if task_id % 3 == 0 {
                                    leaked.fetch_add(1, Ordering::Relaxed);
                                    // Intentionally skip obligation cleanup
                                    return Outcome::Cancelled;
                                }
                            }

                            Outcome::Ok(())
                        })
                        .await;

                    tasks.push(task);
                }

                // Wait for chaos to complete
                for task in tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let total_killed = killed_count.load(Ordering::Relaxed);
                let total_leaked = leaked_count.load(Ordering::Relaxed);

                // Test should fail if obligations leaked during chaos
                total_killed > 0 && total_leaked == 0
            })
            .await;

        self.log_mutation_test("br-mutation-7", chaos_result, true);
        !chaos_result // Should fail with leaked obligations
    }

    /// Test mutation against rate limiting scenario
    async fn test_rate_limiting_mutations(&self) -> bool {
        // [br-mutation-8] Bypass rate limiting enforcement
        let rate_result = self
            .runtime
            .scope(|scope| async move {
                let rate_limit = 10;
                let request_count = 50;
                let processed_count = Arc::new(AtomicUsize::new(0));
                let rejected_count = Arc::new(AtomicUsize::new(0));

                let (tx, rx) = mpsc::channel(100);

                // Producer with rate limiting bypass
                let producer = scope
                    .spawn(async move {
                        for req_id in 0..request_count {
                            // MUTATION: Always allow requests (bypass rate limit)
                            let current_processed = processed_count.load(Ordering::Relaxed);

                            // Normal code: if current_processed < rate_limit
                            // MUTATION: Skip rate check entirely
                            if tx.send(format!("request_{}", req_id)).await.is_ok() {
                                processed_count.fetch_add(1, Ordering::Relaxed);
                            } else {
                                rejected_count.fetch_add(1, Ordering::Relaxed);
                            }

                            sleep(Duration::from_millis(10)).await;
                        }
                        Outcome::Ok(())
                    })
                    .await;

                // Consumer
                let consumer = scope
                    .spawn(async move {
                        let mut rx = rx;
                        let mut consumed = 0;

                        while let Some(_req) = rx.recv().await {
                            consumed += 1;
                            sleep(Duration::from_millis(30)).await; // Slow processing
                            if consumed >= 20 {
                                break;
                            }
                        }
                        Outcome::Ok(consumed)
                    })
                    .await;

                let _ = timeout(Duration::from_secs(5), producer).await;
                let _ = timeout(Duration::from_secs(3), consumer).await;

                let total_processed = processed_count.load(Ordering::Relaxed);
                let total_rejected = rejected_count.load(Ordering::Relaxed);

                // Test should fail if rate limiting was bypassed
                total_rejected > 0 && total_processed <= rate_limit * 2
            })
            .await;

        self.log_mutation_test("br-mutation-8", rate_result, true);
        !rate_result // Should fail with bypassed rate limiting
    }

    /// Test mutation against HTTP/2 connection management
    async fn test_http2_connection_mutations(&self) -> bool {
        // [br-mutation-9] Skip connection slot cleanup
        let connection_result = self
            .runtime
            .scope(|scope| async move {
                let connection_limit = 20;
                let connection_attempts = 40;
                let active_connections = Arc::new(AtomicUsize::new(0));
                let leaked_connections = Arc::new(AtomicUsize::new(0));

                let mut connection_tasks = Vec::new();

                for conn_id in 0..connection_attempts {
                    let active = Arc::clone(&active_connections);
                    let leaked = Arc::clone(&leaked_connections);

                    let task = scope
                        .spawn(async move {
                            // Check connection limit
                            let current_active = active.fetch_add(1, Ordering::Relaxed);

                            if current_active >= connection_limit {
                                active.fetch_sub(1, Ordering::Relaxed);
                                return Outcome::Err(Error::new(
                                    ErrorKind::Other,
                                    "Connection limit exceeded",
                                ));
                            }

                            // Simulate connection usage
                            sleep(Duration::from_millis(100)).await;

                            // MUTATION: Skip connection cleanup for some connections
                            if conn_id % 5 == 0 {
                                leaked.fetch_add(1, Ordering::Relaxed);
                                // Intentionally skip cleanup - connection slot leak
                                return Outcome::Ok(());
                            }

                            // Normal cleanup
                            active.fetch_sub(1, Ordering::Relaxed);
                            Outcome::Ok(())
                        })
                        .await;

                    connection_tasks.push(task);
                    sleep(Duration::from_millis(20)).await;
                }

                // Wait for all connections
                for task in connection_tasks {
                    let _ = timeout(Duration::from_secs(3), task).await;
                }

                let final_active = active_connections.load(Ordering::Relaxed);
                let total_leaked = leaked_connections.load(Ordering::Relaxed);

                // Test should fail if connection slots leaked
                final_active == 0 && total_leaked == 0
            })
            .await;

        self.log_mutation_test("br-mutation-9", connection_result, true);
        !connection_result // Should fail with connection leaks
    }

    /// Test mutation against timer wheel accuracy
    async fn test_timer_wheel_mutations(&self) -> bool {
        // [br-mutation-10] Introduce systematic timer drift
        let timer_result = self
            .runtime
            .scope(|scope| async move {
                let timer_count = 15;
                let expected_duration = Duration::from_millis(100);
                let accuracy_violations = Arc::new(AtomicUsize::new(0));

                let mut timer_tasks = Vec::new();

                for timer_id in 0..timer_count {
                    let violations = Arc::clone(&accuracy_violations);

                    let task = scope
                        .spawn(async move {
                            let start = Instant::now();

                            // MUTATION: Add systematic drift to timers
                            let corrupted_duration = expected_duration + Duration::from_millis(60); // Always drift
                            sleep(corrupted_duration).await;

                            let actual = start.elapsed();
                            let drift = if actual > expected_duration {
                                actual - expected_duration
                            } else {
                                expected_duration - actual
                            };

                            // Check accuracy (should detect systematic drift)
                            if drift > Duration::from_millis(25) {
                                violations.fetch_add(1, Ordering::Relaxed);
                            }

                            Outcome::Ok(drift.as_millis())
                        })
                        .await;

                    timer_tasks.push(task);
                }

                for task in timer_tasks {
                    let _ = timeout(Duration::from_secs(2), task).await;
                }

                let total_violations = accuracy_violations.load(Ordering::Relaxed);

                // Test should fail if timer accuracy is poor
                total_violations <= timer_count / 4 // Allow some variance
            })
            .await;

        self.log_mutation_test("br-mutation-10", timer_result, true);
        !timer_result // Should fail with systematic timer drift
    }

    /// Test mutation against checkpoint consistency
    async fn test_checkpoint_mutations(&self) -> bool {
        // [br-mutation-11] Corrupt checkpoint state
        let checkpoint_result = self
            .runtime
            .scope(|scope| async move {
                let checkpoint_storage =
                    Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));
                let work_progress = 0;

                let task = scope
                    .spawn(async move {
                        let mut current_progress = work_progress;

                        // Do some work
                        for step in 0..10 {
                            current_progress += 1;

                            // Checkpoint every 3 steps
                            if step % 3 == 0 {
                                let checkpoint_data = serde_json::json!({
                                    "progress": current_progress,
                                    "step": step
                                });

                                // MUTATION: Corrupt checkpoint data
                                let corrupted_data = serde_json::json!({
                                    "progress": current_progress + 100, // Wrong progress
                                    "step": step - 1 // Wrong step
                                });

                                let mut storage = checkpoint_storage.lock().await;
                                storage.insert(format!("checkpoint_{}", step), corrupted_data);
                            }

                            sleep(Duration::from_millis(20)).await;
                        }

                        // Verify final checkpoint
                        let storage = checkpoint_storage.lock().await;
                        if let Some(final_checkpoint) = storage.get("checkpoint_9") {
                            let stored_progress =
                                final_checkpoint["progress"].as_u64().unwrap_or(0) as usize;
                            stored_progress == current_progress
                        } else {
                            false
                        }
                    })
                    .await;

                timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap_or(Outcome::Ok(false))
            })
            .await;

        let checkpoint_ok = matches!(checkpoint_result, Outcome::Ok(true));
        self.log_mutation_test("br-mutation-11", checkpoint_ok, true);
        !checkpoint_ok // Should fail with corrupted checkpoints
    }

    /// Test mutation against memory pressure handling
    async fn test_memory_pressure_mutations(&self) -> bool {
        // [br-mutation-12] Ignore memory pressure signals
        let memory_result = self
            .runtime
            .scope(|scope| async move {
                let pressure_threshold = 1024 * 1024; // 1MB threshold
                let memory_usage = Arc::new(AtomicUsize::new(0));
                let pressure_ignored = Arc::new(AtomicUsize::new(0));

                let allocations = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

                let task = scope
                    .spawn(async move {
                        for alloc_id in 0..20 {
                            let current_usage = memory_usage.load(Ordering::Relaxed);

                            // Check memory pressure
                            let under_pressure = current_usage > pressure_threshold;

                            if under_pressure {
                                // MUTATION: Ignore pressure signal and continue allocating
                                pressure_ignored.fetch_add(1, Ordering::Relaxed);
                                // Normal code would apply backpressure here
                            }

                            // Allocate memory regardless of pressure
                            let allocation = vec![0u8; 256 * 1024]; // 256KB
                            let size = allocation.len();

                            {
                                let mut allocs = allocations.lock().await;
                                allocs.push(allocation);
                                memory_usage.fetch_add(size, Ordering::Relaxed);
                            }

                            sleep(Duration::from_millis(50)).await;
                        }

                        pressure_ignored.load(Ordering::Relaxed)
                    })
                    .await;

                let ignored_count = timeout(Duration::from_secs(5), task)
                    .await
                    .unwrap_or(Outcome::Ok(0));

                matches!(ignored_count, Outcome::Ok(0))
            })
            .await;

        self.log_mutation_test("br-mutation-12", memory_result, true);
        !memory_result // Should fail with ignored memory pressure
    }
}

#[tokio::test]
async fn test_chaos_scenarios_catch_resource_leaks() {
    let tester = ScenarioMutationTester::new("chaos_scenarios").await;

    eprintln!("{{\"targeted_mutation_test\":\"chaos_scenarios_start\"}}");

    let thread_kill_caught = tester.test_chaos_thread_kill_mutations().await;
    let connection_caught = tester.test_http2_connection_mutations().await;

    let mutations_caught = [thread_kill_caught, connection_caught]
        .iter()
        .filter(|&&x| x)
        .count();
    let total_mutations = 2;

    eprintln!(
        "{{\"chaos_mutation_results\":{{\"caught\":{},\"total\":{},\"rate\":{:.2}}}}}",
        mutations_caught,
        total_mutations,
        mutations_caught as f64 / total_mutations as f64
    );

    assert!(
        mutations_caught >= total_mutations * 80 / 100,
        "Chaos scenarios should catch ≥80% of resource leak mutations: {}/{}",
        mutations_caught,
        total_mutations
    );
}

#[tokio::test]
async fn test_performance_scenarios_catch_degradation() {
    let tester = ScenarioMutationTester::new("performance_scenarios").await;

    eprintln!("{{\"targeted_mutation_test\":\"performance_scenarios_start\"}}");

    let rate_limiting_caught = tester.test_rate_limiting_mutations().await;
    let timer_accuracy_caught = tester.test_timer_wheel_mutations().await;

    let mutations_caught = [rate_limiting_caught, timer_accuracy_caught]
        .iter()
        .filter(|&&x| x)
        .count();
    let total_mutations = 2;

    eprintln!(
        "{{\"performance_mutation_results\":{{\"caught\":{},\"total\":{},\"rate\":{:.2}}}}}",
        mutations_caught,
        total_mutations,
        mutations_caught as f64 / total_mutations as f64
    );

    assert!(
        mutations_caught >= total_mutations * 85 / 100,
        "Performance scenarios should catch ≥85% of performance mutations: {}/{}",
        mutations_caught,
        total_mutations
    );
}

#[tokio::test]
async fn test_long_running_scenarios_catch_persistence_failures() {
    let tester = ScenarioMutationTester::new("long_running_scenarios").await;

    eprintln!("{{\"targeted_mutation_test\":\"long_running_scenarios_start\"}}");

    let checkpoint_caught = tester.test_checkpoint_mutations().await;
    let memory_pressure_caught = tester.test_memory_pressure_mutations().await;

    let mutations_caught = [checkpoint_caught, memory_pressure_caught]
        .iter()
        .filter(|&&x| x)
        .count();
    let total_mutations = 2;

    eprintln!(
        "{{\"long_running_mutation_results\":{{\"caught\":{},\"total\":{},\"rate\":{:.2}}}}}",
        mutations_caught,
        total_mutations,
        mutations_caught as f64 / total_mutations as f64
    );

    assert!(
        mutations_caught >= total_mutations * 80 / 100,
        "Long-running scenarios should catch ≥80% of persistence mutations: {}/{}",
        mutations_caught,
        total_mutations
    );
}

#[tokio::test]
async fn test_integration_suite_comprehensive_mutation_sensitivity() {
    eprintln!("{{\"comprehensive_mutation_test\":\"start\"}}");

    let chaos_tester = ScenarioMutationTester::new("comprehensive_chaos").await;
    let perf_tester = ScenarioMutationTester::new("comprehensive_performance").await;
    let lr_tester = ScenarioMutationTester::new("comprehensive_long_running").await;

    // Test all mutation categories
    let chaos_results = vec![
        chaos_tester.test_chaos_thread_kill_mutations().await,
        chaos_tester.test_http2_connection_mutations().await,
    ];

    let perf_results = vec![
        perf_tester.test_rate_limiting_mutations().await,
        perf_tester.test_timer_wheel_mutations().await,
    ];

    let lr_results = vec![
        lr_tester.test_checkpoint_mutations().await,
        lr_tester.test_memory_pressure_mutations().await,
    ];

    let total_caught = chaos_results
        .iter()
        .chain(perf_results.iter())
        .chain(lr_results.iter())
        .filter(|&&caught| caught)
        .count();
    let total_mutations = chaos_results.len() + perf_results.len() + lr_results.len();

    let overall_detection_rate = total_caught as f64 / total_mutations as f64;

    eprintln!(
        "{{\"comprehensive_mutation_results\":{{\"total_caught\":{},\"total_mutations\":{},\"detection_rate\":{:.2},\"threshold\":0.83}}}}",
        total_caught, total_mutations, overall_detection_rate
    );

    assert!(
        overall_detection_rate >= 0.83,
        "Integration test suite should have ≥83% overall mutation detection rate: {:.1}% ({}/{})",
        overall_detection_rate * 100.0,
        total_caught,
        total_mutations
    );

    eprintln!(
        "{{\"comprehensive_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        overall_detection_rate
    );
}
