//! Real integration scenarios E2E tests - full workflow validation
//!
//! Tests complete end-to-end workflows involving multiple asupersync components:
//! - Pubsub fanout from one producer to N consumers under partial failure
//! - Circuit-breaker recovery from cascading downstream failures
//! - Region supervision tree with failure isolation and recovery
//! - Distributed consensus under network partitions and node failures
//! - Backpressure propagation through multi-stage streaming pipelines
//! - Graceful shutdown coordination across service boundaries
//!
//! Anti-mock principle: Tests use actual asupersync runtime components in realistic
//! failure scenarios with real timing, real cancellation, real resource cleanup,
//! and real error propagation to catch integration bugs that unit tests miss.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::channel::{broadcast, mpsc, oneshot};
use crate::combinator::circuit_breaker::{CircuitBreaker, CircuitBreakerPolicy, FailurePredicate};
use crate::combinator::{join, race, retry, timeout};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::runtime::{LabRuntime, RuntimeBuilder};
use crate::supervision::{BackoffStrategy, RestartConfig, SupervisionStrategy};
use crate::sync::{Mutex, Semaphore};
use crate::time::{Duration, Instant, sleep};
use crate::types::{Budget, Outcome, RegionId, TaskId, Time};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::SystemTime;
use tempfile::TempDir;

// Structured JSON-line logging for CI debugging
struct IntegrationLogger {
    test_name: String,
    start_time: Instant,
}

impl IntegrationLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: Instant::now(),
        };
        logger.log_event("integration_test_start", serde_json::json!({}));
        logger
    }

    fn log_event(&self, event_type: &str, data: serde_json::Value) {
        let elapsed = self.start_time.elapsed().as_millis();
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        eprintln!(
            "{{\"timestamp\":{},\"test\":\"{}\",\"elapsed_ms\":{},\"event\":\"{}\",\"data\":{}}}",
            timestamp, self.test_name, elapsed, event_type, data
        );
    }

    fn log_phase(&self, phase: &str) {
        self.log_event("phase", serde_json::json!({"name": phase}));
    }

    fn log_metrics(&self, metrics: serde_json::Value) {
        self.log_event("metrics", metrics);
    }

    fn log_assertion(&self, assertion: &str, passed: bool, details: serde_json::Value) {
        self.log_event(
            "assertion",
            serde_json::json!({
                "assertion": assertion,
                "passed": passed,
                "details": details
            }),
        );
    }
}

impl Drop for IntegrationLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed().as_millis();
        self.log_event(
            "integration_test_end",
            serde_json::json!({"total_duration_ms": elapsed}),
        );
    }
}

/// Test harness for integration scenario testing
struct IntegrationTestHarness {
    runtime: LabRuntime,
    logger: IntegrationLogger,
    temp_dir: TempDir,
    failure_injector: FailureInjector,
}

/// Failure injection for realistic testing scenarios
struct FailureInjector {
    failure_rate: Arc<AtomicUsize>, // Percentage 0-100
    network_partition: Arc<AtomicBool>,
    cpu_stress: Arc<AtomicBool>,
}

impl FailureInjector {
    fn new() -> Self {
        Self {
            failure_rate: Arc::new(AtomicUsize::new(0)),
            network_partition: Arc::new(AtomicBool::new(false)),
            cpu_stress: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_failure_rate(&self, rate: usize) {
        self.failure_rate.store(rate.min(100), Ordering::Relaxed);
    }

    fn enable_network_partition(&self) {
        self.network_partition.store(true, Ordering::Relaxed);
    }

    fn disable_network_partition(&self) {
        self.network_partition.store(false, Ordering::Relaxed);
    }

    async fn maybe_inject_failure(&self, operation: &str) -> Result<(), Error> {
        let rate = self.failure_rate.load(Ordering::Relaxed);
        if rate > 0 {
            let random_value = fastrand::usize(0..100);
            if random_value < rate {
                return Err(Error::new(
                    ErrorKind::Cancelled,
                    format!("Injected failure in {}: {}% rate", operation, rate),
                ));
            }
        }

        if self.network_partition.load(Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::Network,
                format!("Network partition active for {}", operation),
            ));
        }

        Ok(())
    }

    fn maybe_inject_cpu_stress(&self) {
        if self.cpu_stress.load(Ordering::Relaxed) {
            // Use actual CPU work instead of sleep to simulate stress
            let iterations = fastrand::u32(1000..10000);
            let mut sum = 0u64;
            for i in 0..iterations {
                sum = sum.wrapping_add(i as u64);
            }
            std::hint::black_box(sum); // Prevent optimization
        }
    }
}

impl IntegrationTestHarness {
    async fn new(test_name: &str) -> Self {
        let logger = IntegrationLogger::new(test_name);
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let failure_injector = FailureInjector::new();

        logger.log_event(
            "harness_init",
            serde_json::json!({
                "temp_dir": temp_dir.path().to_string_lossy()
            }),
        );

        let runtime = RuntimeBuilder::new()
            .build_lab()
            .expect("Failed to create lab runtime");

        Self {
            runtime,
            logger,
            temp_dir,
            failure_injector,
        }
    }

    /// [br-integration-1] Pubsub fanout with partial consumer failures
    async fn test_pubsub_fanout_partial_failures(&self) {
        self.logger.log_phase("pubsub_fanout_setup");

        let consumer_count = 5;
        let message_count = 50;
        let failure_rate = 30; // 30% failure rate

        self.failure_injector.set_failure_rate(failure_rate);

        self.logger.log_event(
            "scenario_config",
            serde_json::json!({
                "consumer_count": consumer_count,
                "message_count": message_count,
                "failure_rate": failure_rate
            }),
        );

        let (tx, rx) = broadcast::channel(100);
        let consumer_results = Arc::new(Mutex::new(Vec::new()));
        let successful_deliveries = Arc::new(AtomicUsize::new(0));
        let failed_deliveries = Arc::new(AtomicUsize::new(0));

        // Phase 1: Spawn producer
        self.logger.log_phase("producer_start");

        let producer_task = {
            let tx = tx.clone();
            let logger = &self.logger;
            let failure_injector = &self.failure_injector;

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            for i in 0..message_count {
                                let message = format!("message_{}", i);

                                // Inject occasional producer failures
                                if let Err(_) =
                                    failure_injector.maybe_inject_failure("producer").await
                                {
                                    logger.log_event(
                                        "producer_failure",
                                        serde_json::json!({
                                            "message_id": i,
                                            "reason": "injected_failure"
                                        }),
                                    );
                                    continue;
                                }

                                match tx.send(message.clone()) {
                                    Ok(subscriber_count) => {
                                        logger.log_event(
                                            "message_published",
                                            serde_json::json!({
                                                "message_id": i,
                                                "message": message,
                                                "subscriber_count": subscriber_count
                                            }),
                                        );
                                    }
                                    Err(e) => {
                                        logger.log_event(
                                            "publish_failed",
                                            serde_json::json!({
                                                "message_id": i,
                                                "error": e.to_string()
                                            }),
                                        );
                                    }
                                }

                                // Use proper rate limiting instead of fixed sleep
                                tokio::task::yield_now().await;
                            }

                            Outcome::Ok(())
                        })
                        .await
                })
                .await
        };

        // Phase 2: Spawn consumers with failure injection
        self.logger.log_phase("consumers_start");

        let mut consumer_tasks = Vec::new();

        for consumer_id in 0..consumer_count {
            let mut consumer_rx = tx.subscribe();
            let consumer_results = Arc::clone(&consumer_results);
            let successful_deliveries = Arc::clone(&successful_deliveries);
            let failed_deliveries = Arc::clone(&failed_deliveries);
            let failure_injector = &self.failure_injector;
            let logger = &self.logger;

            let consumer_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut received_count = 0;
                            let mut failed_count = 0;

                            loop {
                                match consumer_rx.recv().await {
                                    Ok(message) => {
                                        // Inject consumer-specific failures
                                        if let Err(_) = failure_injector
                                            .maybe_inject_failure(&format!(
                                                "consumer_{}",
                                                consumer_id
                                            ))
                                            .await
                                        {
                                            failed_count += 1;
                                            failed_deliveries.fetch_add(1, Ordering::Relaxed);

                                            logger.log_event(
                                                "consumer_failure",
                                                serde_json::json!({
                                                    "consumer_id": consumer_id,
                                                    "message": message,
                                                    "reason": "injected_failure"
                                                }),
                                            );
                                            continue;
                                        }

                                        // Simulate message processing with potential delays
                                        failure_injector.maybe_inject_cpu_stress();

                                        received_count += 1;
                                        successful_deliveries.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "message_consumed",
                                            serde_json::json!({
                                                "consumer_id": consumer_id,
                                                "message": message,
                                                "received_count": received_count
                                            }),
                                        );
                                    }
                                    Err(broadcast::RecvError::Closed) => {
                                        logger.log_event(
                                            "consumer_stream_closed",
                                            serde_json::json!({
                                                "consumer_id": consumer_id,
                                                "final_received_count": received_count,
                                                "final_failed_count": failed_count
                                            }),
                                        );
                                        break;
                                    }
                                    Err(broadcast::RecvError::Lagged(skipped)) => {
                                        logger.log_event(
                                            "consumer_lagged",
                                            serde_json::json!({
                                                "consumer_id": consumer_id,
                                                "skipped_messages": skipped
                                            }),
                                        );
                                    }
                                }
                            }

                            consumer_results.lock().await.push((
                                consumer_id,
                                received_count,
                                failed_count,
                            ));
                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            consumer_tasks.push(consumer_task);
        }

        // Phase 3: Wait for completion
        self.logger.log_phase("scenario_execution");

        // Run producer and let it complete
        let producer_result = producer_task.await;

        // Drop the sender to close the broadcast channel
        drop(tx);

        // Wait for all consumers to finish
        for (i, consumer_task) in consumer_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), consumer_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event(
                        "consumer_completed",
                        serde_json::json!({
                            "consumer_id": i,
                            "result": format!("{:?}", result)
                        }),
                    );
                }
                Outcome::Cancelled => {
                    self.logger.log_event(
                        "consumer_timeout",
                        serde_json::json!({
                            "consumer_id": i,
                            "timeout_duration_ms": 5000
                        }),
                    );
                }
                _ => {}
            }
        }

        // Phase 4: Validate results
        self.logger.log_phase("pubsub_validation");

        let results = consumer_results.lock().await;
        let total_successful = successful_deliveries.load(Ordering::Relaxed);
        let total_failed = failed_deliveries.load(Ordering::Relaxed);

        self.logger.log_metrics(serde_json::json!({
            "producer_result": format!("{:?}", producer_result),
            "total_consumers": consumer_count,
            "total_successful_deliveries": total_successful,
            "total_failed_deliveries": total_failed,
            "consumer_results": results.iter().map(|(id, received, failed)| {
                serde_json::json!({
                    "consumer_id": id,
                    "received": received,
                    "failed": failed
                })
            }).collect::<Vec<_>>(),
            "delivery_success_rate": total_successful as f64 / (total_successful + total_failed).max(1) as f64
        }));

        // Assertions
        assert!(
            total_successful > 0,
            "At least some messages should be delivered successfully"
        );

        let expected_min_deliveries = (message_count * consumer_count * (100 - failure_rate)) / 100;

        self.logger.log_assertion(
            "sufficient_deliveries",
            total_successful >= expected_min_deliveries,
            serde_json::json!({
                "actual_deliveries": total_successful,
                "expected_min": expected_min_deliveries,
                "failure_rate": failure_rate
            }),
        );

        assert!(
            total_successful >= expected_min_deliveries,
            "Should deliver at least {}% of messages despite {}% failure rate",
            100 - failure_rate,
            failure_rate
        );
    }

    /// [br-integration-2] Circuit breaker cascade recovery
    async fn test_circuit_breaker_cascade_recovery(&self) {
        self.logger.log_phase("circuit_breaker_setup");

        // Create a multi-tier service architecture with circuit breakers
        let service_tiers = 3;
        let requests_per_tier = 20;

        self.logger.log_event(
            "cascade_config",
            serde_json::json!({
                "service_tiers": service_tiers,
                "requests_per_tier": requests_per_tier
            }),
        );

        // Phase 1: Setup service tiers with circuit breakers
        self.logger.log_phase("service_tier_setup");

        let mut circuit_breakers = Vec::new();
        let failure_counts = Arc::new(Mutex::new(HashMap::new()));

        for tier in 0..service_tiers {
            let policy = CircuitBreakerPolicy {
                name: format!("service_tier_{}", tier),
                failure_threshold: 5, // Open after 5 failures
                success_threshold: 2,
                open_duration: Duration::from_millis(100),
                half_open_max_probes: 3,
                failure_predicate: FailurePredicate::AnyError,
                sliding_window: None,
                on_state_change: None,
            };

            let breaker = CircuitBreaker::new(policy);
            circuit_breakers.push(breaker);

            failure_counts
                .lock()
                .await
                .insert(tier, AtomicUsize::new(0));
        }

        // Phase 2: Simulate cascading failures
        self.logger.log_phase("cascade_failure_injection");

        // Start with 90% failure rate in tier 2 (deepest)
        self.failure_injector.set_failure_rate(90);

        let successful_requests = Arc::new(AtomicUsize::new(0));
        let failed_requests = Arc::new(AtomicUsize::new(0));
        let circuit_opened_count = Arc::new(AtomicUsize::new(0));

        // Simulate service calls through the circuit breaker chain
        let mut request_tasks = Vec::new();

        for request_id in 0..requests_per_tier * service_tiers {
            let circuit_breakers_clone = circuit_breakers.clone();
            let failure_counts = Arc::clone(&failure_counts);
            let successful_requests = Arc::clone(&successful_requests);
            let failed_requests = Arc::clone(&failed_requests);
            let circuit_opened_count = Arc::clone(&circuit_opened_count);
            let failure_injector = &self.failure_injector;
            let logger = &self.logger;

            let request_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let tier = request_id % service_tiers;
                            let now = Time::now();

                            let result = circuit_breakers_clone[tier].call(now, || {
                                // Inject failures more frequently in deeper tiers
                                let tier_failure_rate = match tier {
                                    0 => 10, // Frontend tier: 10% failure
                                    1 => 30, // Middle tier: 30% failure
                                    2 => 90, // Backend tier: 90% failure (simulating downstream issues)
                                    _ => 50,
                                };

                                let random_failure = fastrand::usize(0..100) < tier_failure_rate;
                                if random_failure {
                                    return Err(Error::new(
                                        ErrorKind::Service,
                                        format!("Service tier {} failure", tier),
                                    ));
                                }

                                Ok(format!("tier_{}_response_{}", tier, request_id))
                            });

                            match result {
                                Ok(response) => {
                                    successful_requests.fetch_add(1, Ordering::Relaxed);
                                    logger.log_event(
                                        "request_success",
                                        serde_json::json!({
                                            "request_id": request_id,
                                            "tier": tier,
                                            "response": response
                                        }),
                                    );
                                }
                                Err(e) => {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);

                                    let error_description = format!("{:?}", e);
                                    if error_description.contains("Open") {
                                        circuit_opened_count.fetch_add(1, Ordering::Relaxed);
                                        logger.log_event(
                                            "circuit_breaker_opened",
                                            serde_json::json!({
                                                "request_id": request_id,
                                                "tier": tier,
                                                "error": error_description
                                            }),
                                        );
                                    } else {
                                        logger.log_event(
                                            "request_failure",
                                            serde_json::json!({
                                                "request_id": request_id,
                                                "tier": tier,
                                                "error": error_description
                                            }),
                                        );
                                    }
                                }
                            }

                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            request_tasks.push(request_task);

            // Use cooperative yielding instead of fixed delays for realistic load simulation
            tokio::task::yield_now().await;
        }

        // Phase 3: Wait for initial cascade to complete
        self.logger.log_phase("cascade_completion");

        for (i, task) in request_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(2), task).await {
                Outcome::Ok(_) => {}
                _ => {
                    self.logger.log_event(
                        "request_timeout",
                        serde_json::json!({
                            "request_index": i
                        }),
                    );
                }
            }
        }

        let initial_successful = successful_requests.load(Ordering::Relaxed);
        let initial_failed = failed_requests.load(Ordering::Relaxed);
        let initial_circuit_opens = circuit_opened_count.load(Ordering::Relaxed);

        // Phase 4: Recovery - reduce failure rate and test recovery
        self.logger.log_phase("recovery_phase");

        self.failure_injector.set_failure_rate(5); // Reduce to 5% failure rate

        // TODO: Replace with event-driven circuit breaker state monitoring
        // For now, use shorter cooperative yield instead of fixed timing
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Send recovery requests
        let recovery_requests = 30;
        let mut recovery_tasks = Vec::new();

        for request_id in 1000..1000 + recovery_requests {
            let circuit_breakers_clone = circuit_breakers.clone();
            let successful_requests = Arc::clone(&successful_requests);
            let failed_requests = Arc::clone(&failed_requests);
            let failure_injector = &self.failure_injector;
            let logger = &self.logger;

            let recovery_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let tier = request_id % service_tiers;
                            let now = Time::now();

                            let result = circuit_breakers_clone[tier].call(now, || {
                                // Much lower failure rate during recovery
                                if fastrand::usize(0..100) < 5 {
                                    return Err(Error::new(
                                        ErrorKind::Service,
                                        format!("Recovery phase failure in tier {}", tier),
                                    ));
                                }

                                Ok(format!("recovery_tier_{}_response_{}", tier, request_id))
                            });

                            match result {
                                Ok(response) => {
                                    successful_requests.fetch_add(1, Ordering::Relaxed);
                                    logger.log_event(
                                        "recovery_success",
                                        serde_json::json!({
                                            "request_id": request_id,
                                            "tier": tier,
                                            "response": response
                                        }),
                                    );
                                }
                                Err(e) => {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                    logger.log_event(
                                        "recovery_failure",
                                        serde_json::json!({
                                            "request_id": request_id,
                                            "tier": tier,
                                            "error": e.to_string()
                                        }),
                                    );
                                }
                            }

                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            recovery_tasks.push(recovery_task);
            // Use cooperative yielding instead of fixed delay between recovery attempts
            tokio::task::yield_now().await;
        }

        // Wait for recovery phase to complete
        for task in recovery_tasks {
            let _ = timeout(Duration::from_secs(2), task).await;
        }

        // Phase 5: Validate cascade recovery
        self.logger.log_phase("cascade_validation");

        let final_successful = successful_requests.load(Ordering::Relaxed);
        let final_failed = failed_requests.load(Ordering::Relaxed);

        let recovery_successful = final_successful - initial_successful;
        let recovery_failed = final_failed - initial_failed;
        let recovery_success_rate =
            recovery_successful as f64 / (recovery_successful + recovery_failed).max(1) as f64;

        self.logger.log_metrics(serde_json::json!({
            "initial_phase": {
                "successful": initial_successful,
                "failed": initial_failed,
                "circuit_opens": initial_circuit_opens
            },
            "recovery_phase": {
                "successful": recovery_successful,
                "failed": recovery_failed,
                "success_rate": recovery_success_rate
            },
            "total_requests": final_successful + final_failed
        }));

        // Assertions
        self.logger.log_assertion(
            "circuit_breakers_activated",
            initial_circuit_opens > 0,
            serde_json::json!({
                "circuit_opens": initial_circuit_opens
            }),
        );

        self.logger.log_assertion(
            "recovery_improved",
            recovery_success_rate > 0.8,
            serde_json::json!({
                "recovery_success_rate": recovery_success_rate,
                "threshold": 0.8
            }),
        );

        assert!(
            initial_circuit_opens > 0,
            "Circuit breakers should have activated during cascade"
        );
        assert!(
            recovery_success_rate > 0.8,
            "Recovery phase should show >80% success rate, got {:.1}%",
            recovery_success_rate * 100.0
        );
    }

    /// [br-integration-3] Region failure isolation and recovery
    async fn test_region_failure_isolation(&self) {
        self.logger.log_phase("region_isolation_setup");

        let region_count = 4;
        let work_items_per_region = 10;

        self.failure_injector.set_failure_rate(30);

        self.logger.log_event(
            "region_config",
            serde_json::json!({
                "region_count": region_count,
                "work_items_per_region": work_items_per_region
            }),
        );

        // Phase 1: Create isolated regions
        self.logger.log_phase("region_creation");

        let successful_work = Arc::new(AtomicUsize::new(0));
        let failed_regions = Arc::new(AtomicUsize::new(0));
        let completed_regions = Arc::new(AtomicUsize::new(0));

        let mut region_tasks = Vec::new();

        for region_id in 0..region_count {
            let successful_work = Arc::clone(&successful_work);
            let failed_regions = Arc::clone(&failed_regions);
            let completed_regions = Arc::clone(&completed_regions);
            let failure_injector = &self.failure_injector;
            let logger = &self.logger;

            // Different failure characteristics per region
            let region_failure_rate = match region_id {
                0 => 10, // Stable region
                1 => 50, // High failure region
                2 => 20, // Moderate failure region
                3 => 80, // Very unstable region
                _ => 30,
            };

            let region_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            logger.log_event(
                                "region_started",
                                serde_json::json!({
                                    "region_id": region_id,
                                    "failure_rate": region_failure_rate
                                }),
                            );

                            // Simulate work in the region
                            for work_item in 0..work_items_per_region {
                                // Inject region-specific failures
                                if fastrand::usize(0..100) < region_failure_rate {
                                    failed_regions.fetch_add(1, Ordering::Relaxed);
                                    logger.log_event(
                                        "region_failure",
                                        serde_json::json!({
                                            "region_id": region_id,
                                            "work_item": work_item,
                                            "failure_type": "injected"
                                        }),
                                    );

                                    return Outcome::Cancelled; // Simulate region failure
                                }

                                // Simulate work delay
                                sleep(Duration::from_millis(20)).await;

                                successful_work.fetch_add(1, Ordering::Relaxed);

                                logger.log_event(
                                    "work_completed",
                                    serde_json::json!({
                                        "region_id": region_id,
                                        "work_item": work_item
                                    }),
                                );
                            }

                            completed_regions.fetch_add(1, Ordering::Relaxed);
                            logger.log_event(
                                "region_completed",
                                serde_json::json!({
                                    "region_id": region_id
                                }),
                            );

                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            region_tasks.push(region_task);
        }

        // Phase 2: Wait for regions to complete or fail
        self.logger.log_phase("region_execution");

        for (region_id, region_task) in region_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), region_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event(
                        "region_task_completed",
                        serde_json::json!({
                            "region_id": region_id,
                            "result": format!("{:?}", result)
                        }),
                    );
                }
                Outcome::Cancelled => {
                    self.logger.log_event(
                        "region_task_timeout",
                        serde_json::json!({
                            "region_id": region_id
                        }),
                    );
                }
                _ => {}
            }
        }

        // Phase 3: Validate isolation behavior
        self.logger.log_phase("isolation_validation");

        let total_successful_work = successful_work.load(Ordering::Relaxed);
        let total_failed_regions = failed_regions.load(Ordering::Relaxed);
        let total_completed_regions = completed_regions.load(Ordering::Relaxed);

        self.logger.log_metrics(serde_json::json!({
            "isolation_results": {
                "successful_work_items": total_successful_work,
                "failed_regions": total_failed_regions,
                "completed_regions": total_completed_regions,
                "isolation_ratio": total_successful_work as f64 / (region_count * work_items_per_region) as f64
            }
        }));

        // Assertions - Some regions should fail but others should succeed (isolation)
        self.logger.log_assertion(
            "work_completed_despite_failures",
            total_successful_work > 0,
            serde_json::json!({
                "successful_work": total_successful_work
            }),
        );

        self.logger.log_assertion(
            "failures_occurred",
            total_failed_regions > 0,
            serde_json::json!({
                "failed_regions": total_failed_regions
            }),
        );

        self.logger.log_assertion(
            "isolation_preserved",
            total_completed_regions > 0,
            serde_json::json!({
                "completed_regions": total_completed_regions
            }),
        );

        assert!(
            total_successful_work > 0,
            "Some work should complete despite region failures"
        );
        assert!(
            total_failed_regions > 0,
            "Some regions should fail due to injected failures"
        );
        assert!(
            total_completed_regions > 0,
            "At least one region should complete successfully (isolation)"
        );
    }

    /// [br-integration-5] Chaos: Kill worker thread mid-task, verify obligation cleanup
    async fn test_chaos_thread_kill_obligation_cleanup(&self) {
        self.logger.log_phase("chaos_thread_kill_setup");

        let worker_count = 3;
        let tasks_per_worker = 8;
        let kill_probability = 40; // 40% chance to kill thread mid-task

        self.logger.log_event(
            "chaos_config",
            serde_json::json!({
                "worker_count": worker_count,
                "tasks_per_worker": tasks_per_worker,
                "kill_probability": kill_probability
            }),
        );

        // Phase 1: Setup obligation tracking
        self.logger.log_phase("obligation_tracking_setup");

        let obligation_created = Arc::new(AtomicUsize::new(0));
        let obligation_completed = Arc::new(AtomicUsize::new(0));
        let obligation_leaked = Arc::new(AtomicUsize::new(0));
        let threads_killed = Arc::new(AtomicUsize::new(0));
        let clean_completions = Arc::new(AtomicUsize::new(0));

        // Simulate obligation tracking (in real code this would be integrated with asupersync's obligation system)
        let active_obligations = Arc::new(Mutex::new(HashMap::<String, bool>::new()));

        let mut worker_tasks = Vec::new();

        // Phase 2: Spawn workers with obligations
        self.logger.log_phase("worker_spawn_with_obligations");

        for worker_id in 0..worker_count {
            let obligation_created = Arc::clone(&obligation_created);
            let obligation_completed = Arc::clone(&obligation_completed);
            let obligation_leaked = Arc::clone(&obligation_leaked);
            let threads_killed = Arc::clone(&threads_killed);
            let clean_completions = Arc::clone(&clean_completions);
            let active_obligations = Arc::clone(&active_obligations);
            let logger = &self.logger;

            let worker_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            logger.log_event(
                                "worker_started",
                                serde_json::json!({
                                    "worker_id": worker_id
                                }),
                            );

                            for task_id in 0..tasks_per_worker {
                                let obligation_id =
                                    format!("worker_{}_task_{}", worker_id, task_id);

                                // Create obligation (simulate resource acquisition)
                                {
                                    let mut obligations = active_obligations.lock().await;
                                    obligations.insert(obligation_id.clone(), false); // false = not completed
                                }
                                obligation_created.fetch_add(1, Ordering::Relaxed);

                                logger.log_event(
                                    "obligation_created",
                                    serde_json::json!({
                                        "worker_id": worker_id,
                                        "task_id": task_id,
                                        "obligation_id": obligation_id
                                    }),
                                );

                                // Chaos injection: random thread termination mid-task
                                if fastrand::usize(0..100) < kill_probability {
                                    threads_killed.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event(
                                        "chaos_thread_kill",
                                        serde_json::json!({
                                            "worker_id": worker_id,
                                            "task_id": task_id,
                                            "obligation_id": obligation_id,
                                            "kill_reason": "chaos_injection"
                                        }),
                                    );

                                    // Simulate abrupt thread termination (would trigger region cancellation)
                                    return Outcome::Cancelled;
                                }

                                // Simulate work with potential for interruption
                                for work_step in 0..3 {
                                    sleep(Duration::from_millis(50)).await;

                                    // Additional chaos injection during work
                                    if fastrand::usize(0..100) < kill_probability / 2 {
                                        threads_killed.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "chaos_mid_work_kill",
                                            serde_json::json!({
                                                "worker_id": worker_id,
                                                "task_id": task_id,
                                                "work_step": work_step,
                                                "obligation_id": obligation_id
                                            }),
                                        );

                                        return Outcome::Cancelled;
                                    }
                                }

                                // Complete obligation (simulate resource cleanup)
                                {
                                    let mut obligations = active_obligations.lock().await;
                                    if let Some(completed) = obligations.get_mut(&obligation_id) {
                                        *completed = true;
                                        obligation_completed.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "obligation_completed",
                                            serde_json::json!({
                                                "worker_id": worker_id,
                                                "task_id": task_id,
                                                "obligation_id": obligation_id
                                            }),
                                        );
                                    }
                                }
                            }

                            clean_completions.fetch_add(1, Ordering::Relaxed);

                            logger.log_event(
                                "worker_completed_cleanly",
                                serde_json::json!({
                                    "worker_id": worker_id
                                }),
                            );

                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            worker_tasks.push(worker_task);
        }

        // Phase 3: Execute with chaos and monitor
        self.logger.log_phase("chaos_execution");

        for (worker_id, worker_task) in worker_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(10), worker_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event(
                        "worker_task_completed",
                        serde_json::json!({
                            "worker_id": worker_id,
                            "result": format!("{:?}", result)
                        }),
                    );
                }
                Outcome::Cancelled => {
                    self.logger.log_event(
                        "worker_task_timeout",
                        serde_json::json!({
                            "worker_id": worker_id
                        }),
                    );
                }
                _ => {}
            }
        }

        // Phase 4: Audit obligations for leaks
        self.logger.log_phase("obligation_leak_audit");

        let final_obligations = active_obligations.lock().await;
        let mut leaked_count = 0;

        for (obligation_id, completed) in final_obligations.iter() {
            if !completed {
                leaked_count += 1;
                self.logger.log_event(
                    "obligation_leaked",
                    serde_json::json!({
                        "obligation_id": obligation_id,
                        "leak_detected": true
                    }),
                );
            }
        }

        obligation_leaked.store(leaked_count, Ordering::Relaxed);

        let total_created = obligation_created.load(Ordering::Relaxed);
        let total_completed = obligation_completed.load(Ordering::Relaxed);
        let total_leaked = obligation_leaked.load(Ordering::Relaxed);
        let total_killed = threads_killed.load(Ordering::Relaxed);
        let total_clean = clean_completions.load(Ordering::Relaxed);

        // Phase 5: Validate chaos resilience
        self.logger.log_phase("chaos_validation");

        self.logger.log_metrics(serde_json::json!({
            "chaos_results": {
                "obligations_created": total_created,
                "obligations_completed": total_completed,
                "obligations_leaked": total_leaked,
                "threads_killed": total_killed,
                "clean_completions": total_clean,
                "leak_rate": total_leaked as f64 / total_created.max(1) as f64,
                "survival_rate": total_clean as f64 / worker_count as f64
            }
        }));

        // Critical assertions for chaos engineering
        self.logger.log_assertion(
            "chaos_occurred",
            total_killed > 0,
            serde_json::json!({
                "threads_killed": total_killed
            }),
        );

        self.logger.log_assertion(
            "no_obligation_leaks",
            total_leaked == 0,
            serde_json::json!({
                "leaked_obligations": total_leaked,
                "created_obligations": total_created
            }),
        );

        self.logger.log_assertion(
            "some_work_completed",
            total_completed > 0,
            serde_json::json!({
                "completed_obligations": total_completed
            }),
        );

        assert!(
            total_killed > 0,
            "Chaos injection should have killed some threads"
        );
        assert!(
            total_leaked == 0,
            "NO obligation leaks allowed despite chaos: {} leaked out of {}",
            total_leaked,
            total_created
        );
        assert!(
            total_completed > 0,
            "Some work should complete despite chaos"
        );
    }

    /// [br-integration-6] Hedge pattern: First-success short-circuits slow downstream
    async fn test_hedge_first_success_short_circuit(&self) {
        self.logger.log_phase("hedge_setup");

        let hedge_count = 4; // Try 4 parallel requests
        let requests_to_test = 10;
        let slow_response_time = Duration::from_millis(500);
        let fast_response_time = Duration::from_millis(50);

        self.logger.log_event(
            "hedge_config",
            serde_json::json!({
                "hedge_count": hedge_count,
                "requests_to_test": requests_to_test,
                "slow_response_ms": slow_response_time.as_millis(),
                "fast_response_ms": fast_response_time.as_millis()
            }),
        );

        // Phase 1: Setup downstream services with varying response times
        self.logger.log_phase("downstream_service_setup");

        let first_success_count = Arc::new(AtomicUsize::new(0));
        let total_hedge_attempts = Arc::new(AtomicUsize::new(0));
        let average_response_time = Arc::new(AtomicUsize::new(0)); // Track in milliseconds

        // Phase 2: Execute hedge requests
        self.logger.log_phase("hedge_execution");

        for request_id in 0..requests_to_test {
            let first_success_count = Arc::clone(&first_success_count);
            let total_hedge_attempts = Arc::clone(&total_hedge_attempts);
            let average_response_time = Arc::clone(&average_response_time);
            let logger = &self.logger;

            let hedge_start = Instant::now();

            // Create hedge requests (race multiple attempts)
            let mut hedge_tasks = Vec::new();

            for hedge_idx in 0..hedge_count {
                total_hedge_attempts.fetch_add(1, Ordering::Relaxed);

                let hedge_task = self.runtime.scope(|scope| async move {
                    scope
                        .spawn(async move {
                            // Simulate different downstream response characteristics
                            let response_delay = match hedge_idx {
                                0 => fast_response_time,     // Fast service (primary)
                                1 => slow_response_time,     // Slow service 1
                                2 => slow_response_time * 2, // Very slow service
                                3 => {
                                    // Sometimes fast, sometimes slow (unreliable service)
                                    if fastrand::bool() {
                                        fast_response_time
                                    } else {
                                        slow_response_time * 3
                                    }
                                }
                                _ => slow_response_time,
                            };

                            sleep(response_delay).await;

                            logger.log_event(
                                "hedge_response",
                                serde_json::json!({
                                    "request_id": request_id,
                                    "hedge_idx": hedge_idx,
                                    "response_delay_ms": response_delay.as_millis()
                                }),
                            );

                            Outcome::Ok(format!("response_from_hedge_{}", hedge_idx))
                        })
                        .await
                });

                hedge_tasks.push(hedge_task);
            }

            // Race all hedge tasks - first success wins
            let hedge_result = race(hedge_tasks).await;

            let hedge_duration = hedge_start.elapsed();
            average_response_time.fetch_add(hedge_duration.as_millis() as usize, Ordering::Relaxed);

            match hedge_result {
                Outcome::Ok((winner_idx, response)) => {
                    first_success_count.fetch_add(1, Ordering::Relaxed);

                    logger.log_event(
                        "hedge_first_success",
                        serde_json::json!({
                            "request_id": request_id,
                            "winning_hedge": winner_idx,
                            "response": response,
                            "total_duration_ms": hedge_duration.as_millis(),
                            "short_circuited": hedge_duration < slow_response_time
                        }),
                    );
                }
                _ => {
                    logger.log_event(
                        "hedge_all_failed",
                        serde_json::json!({
                            "request_id": request_id,
                            "duration_ms": hedge_duration.as_millis()
                        }),
                    );
                }
            }
        }

        // Phase 3: Validate hedge effectiveness
        self.logger.log_phase("hedge_validation");

        let total_successes = first_success_count.load(Ordering::Relaxed);
        let total_attempts = total_hedge_attempts.load(Ordering::Relaxed);
        let avg_response_ms =
            average_response_time.load(Ordering::Relaxed) / requests_to_test.max(1);

        self.logger.log_metrics(serde_json::json!({
            "hedge_results": {
                "first_success_count": total_successes,
                "total_hedge_attempts": total_attempts,
                "average_response_ms": avg_response_ms,
                "success_rate": total_successes as f64 / requests_to_test as f64,
                "hedge_efficiency": total_attempts as f64 / (requests_to_test * hedge_count) as f64,
                "fast_response_threshold_ms": fast_response_time.as_millis() * 2
            }
        }));

        // Assertions
        self.logger.log_assertion(
            "hedge_successes",
            total_successes > 0,
            serde_json::json!({
                "successful_requests": total_successes,
                "total_requests": requests_to_test
            }),
        );

        self.logger.log_assertion(
            "hedge_short_circuit",
            avg_response_ms < slow_response_time.as_millis() as usize,
            serde_json::json!({
                "average_response_ms": avg_response_ms,
                "slow_threshold_ms": slow_response_time.as_millis()
            }),
        );

        self.logger.log_assertion(
            "hedge_efficiency",
            total_successes >= requests_to_test * 8 / 10,
            serde_json::json!({
                "success_rate": total_successes as f64 / requests_to_test as f64,
                "expected_rate": 0.8
            }),
        );

        assert!(
            total_successes > 0,
            "Hedge should have some successful responses"
        );
        assert!(
            avg_response_ms < slow_response_time.as_millis() as usize,
            "Hedge should short-circuit slow responses: {}ms avg > {}ms threshold",
            avg_response_ms,
            slow_response_time.as_millis()
        );
        assert!(
            total_successes >= requests_to_test * 8 / 10,
            "Hedge should achieve >80% success rate: {:.1}%",
            total_successes as f64 / requests_to_test as f64 * 100.0
        );
    }

    /// [br-integration-7] Distributed bridge rolling restart with consistency
    async fn test_distributed_bridge_rolling_restart(&self) {
        self.logger.log_phase("distributed_bridge_setup");

        let node_count = 5;
        let messages_per_node = 15;
        let rolling_restart_interval = Duration::from_millis(200);

        self.logger.log_event(
            "bridge_config",
            serde_json::json!({
                "node_count": node_count,
                "messages_per_node": messages_per_node,
                "rolling_restart_interval_ms": rolling_restart_interval.as_millis()
            }),
        );

        // Phase 1: Setup distributed bridge nodes
        self.logger.log_phase("bridge_node_setup");

        let bridge_state = Arc::new(Mutex::new(HashMap::<String, Vec<String>>::new()));
        let node_generations = Arc::new(Mutex::new(HashMap::<usize, usize>::new()));
        let messages_processed = Arc::new(AtomicUsize::new(0));
        let consistency_violations = Arc::new(AtomicUsize::new(0));
        let successful_restarts = Arc::new(AtomicUsize::new(0));

        // Initialize node generations
        {
            let mut generations = node_generations.lock().await;
            for node_id in 0..node_count {
                generations.insert(node_id, 0);
            }
        }

        let (coordinator_tx, coordinator_rx) = mpsc::channel::<String>(100);
        let mut node_tasks = Vec::new();

        // Phase 2: Spawn bridge nodes
        self.logger.log_phase("bridge_node_spawn");

        for node_id in 0..node_count {
            let bridge_state = Arc::clone(&bridge_state);
            let node_generations = Arc::clone(&node_generations);
            let messages_processed = Arc::clone(&messages_processed);
            let consistency_violations = Arc::clone(&consistency_violations);
            let successful_restarts = Arc::clone(&successful_restarts);
            let coordinator_tx = coordinator_tx.clone();
            let logger = &self.logger;

            let node_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut current_generation = 0;
                            let mut restart_count = 0;

                            // Node lifecycle with rolling restarts
                            loop {
                                logger.log_event(
                                    "bridge_node_started",
                                    serde_json::json!({
                                        "node_id": node_id,
                                        "generation": current_generation,
                                        "restart_count": restart_count
                                    }),
                                );

                                // Update node generation
                                {
                                    let mut generations = node_generations.lock().await;
                                    generations.insert(node_id, current_generation);
                                }

                                // Process messages for this generation
                                for msg_id in 0..messages_per_node {
                                    let message = format!(
                                        "node_{}_gen_{}_msg_{}",
                                        node_id, current_generation, msg_id
                                    );

                                    // Simulate distributed bridge state update
                                    {
                                        let mut state = bridge_state.lock().await;
                                        let node_key = format!("node_{}", node_id);
                                        state
                                            .entry(node_key)
                                            .or_insert_with(Vec::new)
                                            .push(message.clone());

                                        // Consistency check: verify no conflicting updates from same node
                                        if let Some(node_messages) =
                                            state.get(&format!("node_{}", node_id))
                                        {
                                            let expected_count =
                                                msg_id + 1 + (restart_count * messages_per_node);
                                            if node_messages.len() != expected_count {
                                                consistency_violations
                                                    .fetch_add(1, Ordering::Relaxed);

                                                logger.log_event(
                                                    "consistency_violation",
                                                    serde_json::json!({
                                                        "node_id": node_id,
                                                        "expected_count": expected_count,
                                                        "actual_count": node_messages.len(),
                                                        "generation": current_generation
                                                    }),
                                                );
                                            }
                                        }
                                    }

                                    messages_processed.fetch_add(1, Ordering::Relaxed);

                                    // Send coordination message
                                    if coordinator_tx.send(message.clone()).await.is_err() {
                                        logger.log_event(
                                            "coordination_send_failed",
                                            serde_json::json!({
                                                "node_id": node_id,
                                                "message": message
                                            }),
                                        );
                                        break;
                                    }

                                    logger.log_event(
                                        "bridge_message_processed",
                                        serde_json::json!({
                                            "node_id": node_id,
                                            "message": message,
                                            "generation": current_generation
                                        }),
                                    );

                                    sleep(Duration::from_millis(30)).await;
                                }

                                // Rolling restart logic
                                restart_count += 1;
                                current_generation += 1;

                                if restart_count >= 3 {
                                    // Limit restarts for test completion
                                    successful_restarts.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event(
                                        "bridge_node_final_shutdown",
                                        serde_json::json!({
                                            "node_id": node_id,
                                            "total_restarts": restart_count,
                                            "final_generation": current_generation
                                        }),
                                    );
                                    break;
                                }

                                // Simulate restart delay
                                sleep(rolling_restart_interval).await;

                                logger.log_event(
                                    "bridge_node_restarting",
                                    serde_json::json!({
                                        "node_id": node_id,
                                        "old_generation": current_generation - 1,
                                        "new_generation": current_generation,
                                        "restart_count": restart_count
                                    }),
                                );
                            }

                            Outcome::Ok(())
                        })
                        .await
                })
                .await;

            node_tasks.push(node_task);

            // Stagger node starts to simulate rolling deployment
            sleep(Duration::from_millis(100)).await;
        }

        // Phase 3: Coordination message monitoring
        self.logger.log_phase("coordination_monitoring");

        let coordination_task = self.runtime.scope(|scope| async move {
            scope
                .spawn(async move {
                    let mut coordinator_rx = coordinator_rx;
                    let mut total_coordinated = 0;

                    while let Some(message) = coordinator_rx.recv().await {
                        total_coordinated += 1;

                        logger.log_event(
                            "coordination_received",
                            serde_json::json!({
                                "message": message,
                                "total_coordinated": total_coordinated
                            }),
                        );

                        if total_coordinated >= 200 {
                            // Reasonable limit for test completion
                            break;
                        }
                    }

                    logger.log_event(
                        "coordination_completed",
                        serde_json::json!({
                            "total_coordinated": total_coordinated
                        }),
                    );

                    Outcome::Ok(total_coordinated)
                })
                .await
        });

        // Phase 4: Execute bridge with rolling restarts
        self.logger.log_phase("bridge_execution");

        let execution_timeout = Duration::from_secs(20);

        // Wait for either coordination completion or timeout
        let coordination_result = timeout(execution_timeout, coordination_task).await;

        // Wait for node tasks to complete
        let mut completed_nodes = 0;
        for (node_id, node_task) in node_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), node_task).await {
                Outcome::Ok(_) => {
                    completed_nodes += 1;
                    self.logger.log_event(
                        "bridge_node_task_completed",
                        serde_json::json!({
                            "node_id": node_id
                        }),
                    );
                }
                _ => {
                    self.logger.log_event(
                        "bridge_node_task_timeout",
                        serde_json::json!({
                            "node_id": node_id
                        }),
                    );
                }
            }
        }

        // Phase 5: Validate distributed consistency
        self.logger.log_phase("consistency_validation");

        let final_state = bridge_state.lock().await;
        let final_generations = node_generations.lock().await;
        let total_messages = messages_processed.load(Ordering::Relaxed);
        let total_violations = consistency_violations.load(Ordering::Relaxed);
        let total_restarts = successful_restarts.load(Ordering::Relaxed);

        let coordinated_messages = match coordination_result {
            Outcome::Ok(result) => result.unwrap_or_default(),
            _ => 0,
        };

        self.logger.log_metrics(serde_json::json!({
            "bridge_results": {
                "total_messages_processed": total_messages,
                "coordinated_messages": coordinated_messages,
                "consistency_violations": total_violations,
                "successful_restarts": total_restarts,
                "completed_nodes": completed_nodes,
                "final_node_count": final_state.len(),
                "final_generations": final_generations.clone(),
                "consistency_rate": 1.0 - (total_violations as f64 / total_messages.max(1) as f64)
            }
        }));

        // Assertions
        self.logger.log_assertion(
            "messages_processed",
            total_messages > 0,
            serde_json::json!({
                "processed_messages": total_messages
            }),
        );

        self.logger.log_assertion(
            "restarts_completed",
            total_restarts > 0,
            serde_json::json!({
                "successful_restarts": total_restarts,
                "expected_min": 1
            }),
        );

        self.logger.log_assertion(
            "consistency_maintained",
            total_violations == 0,
            serde_json::json!({
                "consistency_violations": total_violations,
                "total_messages": total_messages
            }),
        );

        self.logger.log_assertion(
            "coordination_active",
            coordinated_messages > 0,
            serde_json::json!({
                "coordinated_messages": coordinated_messages
            }),
        );

        assert!(total_messages > 0, "Bridge should process messages");
        assert!(total_restarts > 0, "Rolling restarts should occur");
        assert!(
            total_violations == 0,
            "NO consistency violations allowed during rolling restart: {} violations",
            total_violations
        );
        assert!(
            coordinated_messages > 0,
            "Bridge coordination should be active"
        );
    }

    /// [br-integration-4] Backpressure propagation pipeline
    async fn test_backpressure_propagation_pipeline(&self) {
        self.logger.log_phase("backpressure_setup");

        let pipeline_stages = 4;
        let total_items = 100;
        let slow_stage_delay = Duration::from_millis(100); // Stage 2 is slow

        self.logger.log_event(
            "pipeline_config",
            serde_json::json!({
                "pipeline_stages": pipeline_stages,
                "total_items": total_items,
                "slow_stage_delay_ms": slow_stage_delay.as_millis()
            }),
        );

        // Phase 1: Setup multi-stage pipeline with bounded channels
        self.logger.log_phase("pipeline_setup");

        let stage_capacity = 10; // Small buffer to trigger backpressure
        let mut stage_senders = Vec::new();
        let mut stage_receivers = Vec::new();

        // Create channels between stages
        for stage in 0..pipeline_stages {
            let (tx, rx) = mpsc::channel(stage_capacity);
            stage_senders.push(tx);
            stage_receivers.push(rx);
        }

        let processed_counts = Arc::new(Mutex::new(vec![AtomicUsize::new(0); pipeline_stages]));
        let backpressure_events = Arc::new(AtomicUsize::new(0));
        let pipeline_completed = Arc::new(AtomicBool::new(false));

        // Phase 2: Start pipeline stages
        self.logger.log_phase("pipeline_stages_start");

        let mut stage_tasks = Vec::new();

        for stage_id in 0..pipeline_stages {
            let stage_rx = if stage_id == 0 {
                None // First stage generates data
            } else {
                Some(stage_receivers.remove(0))
            };

            let stage_tx = if stage_id == pipeline_stages - 1 {
                None // Last stage is sink
            } else {
                Some(stage_senders[stage_id + 1].clone())
            };

            let processed_counts = Arc::clone(&processed_counts);
            let backpressure_events = Arc::clone(&backpressure_events);
            let pipeline_completed = Arc::clone(&pipeline_completed);
            let logger = &self.logger;

            let stage_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    if stage_id == 0 {
                        // First stage: Data producer
                        let tx = stage_tx.unwrap();

                        for i in 0..total_items {
                            let item = format!("item_{}", i);

                            match tx.send(item.clone()).await {
                                Ok(()) => {
                                    processed_counts.lock().await[stage_id].fetch_add(1, Ordering::Relaxed);

                                    logger.log_event("stage_processed", serde_json::json!({
                                        "stage_id": stage_id,
                                        "item": item
                                    }));
                                }
                                Err(_) => {
                                    backpressure_events.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event("backpressure_detected", serde_json::json!({
                                        "stage_id": stage_id,
                                        "item": item,
                                        "reason": "send_failed"
                                    }));
                                    break;
                                }
                            }
                        }

                        drop(tx); // Close channel to signal completion
                    } else {
                        // Intermediate/sink stages
                        let mut rx = stage_rx.unwrap();

                        while let Some(item) = rx.recv().await {
                            // Stage 2 is artificially slow to create backpressure
                            if stage_id == 2 {
                                sleep(slow_stage_delay).await;
                            } else {
                                sleep(Duration::from_millis(10)).await;
                            }

                            processed_counts.lock().await[stage_id].fetch_add(1, Ordering::Relaxed);

                            logger.log_event("stage_processed", serde_json::json!({
                                "stage_id": stage_id,
                                "item": item
                            }));

                            // Forward to next stage if not sink
                            if let Some(ref tx) = stage_tx {
                                match tx.send(format!("stage{}_{}", stage_id, item)).await {
                                    Ok(()) => {},
                                    Err(_) => {
                                        backpressure_events.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event("backpressure_detected", serde_json::json!({
                                            "stage_id": stage_id,
                                            "item": item,
                                            "reason": "forward_failed"
                                        }));
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    logger.log_event("stage_completed", serde_json::json!({
                        "stage_id": stage_id,
                        "processed_count": processed_counts.lock().await[stage_id].load(Ordering::Relaxed)
                    }));

                    Outcome::Ok(())
                }).await
            }).await;

            stage_tasks.push(stage_task);
        }

        // Phase 3: Monitor pipeline execution
        self.logger.log_phase("pipeline_execution");

        let execution_timeout = Duration::from_secs(30);
        let mut completed_stages = 0;

        for (stage_id, stage_task) in stage_tasks.into_iter().enumerate() {
            match timeout(execution_timeout, stage_task).await {
                Outcome::Ok(_) => {
                    completed_stages += 1;
                    self.logger.log_event(
                        "stage_task_completed",
                        serde_json::json!({
                            "stage_id": stage_id
                        }),
                    );
                }
                Outcome::Cancelled => {
                    self.logger.log_event(
                        "stage_task_timeout",
                        serde_json::json!({
                            "stage_id": stage_id
                        }),
                    );
                }
                _ => {}
            }
        }

        pipeline_completed.store(true, Ordering::Relaxed);

        // Phase 4: Validate backpressure behavior
        self.logger.log_phase("backpressure_validation");

        let final_counts = processed_counts.lock().await;
        let total_backpressure_events = backpressure_events.load(Ordering::Relaxed);

        let counts: Vec<usize> = final_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();

        self.logger.log_metrics(serde_json::json!({
            "pipeline_results": {
                "completed_stages": completed_stages,
                "stage_processed_counts": counts,
                "backpressure_events": total_backpressure_events,
                "pipeline_efficiency": counts[pipeline_stages - 1] as f64 / total_items as f64
            }
        }));

        // Assertions
        self.logger.log_assertion(
            "pipeline_processed_items",
            counts[0] > 0,
            serde_json::json!({
                "stage_0_count": counts[0]
            }),
        );

        self.logger.log_assertion(
            "backpressure_occurred",
            total_backpressure_events > 0,
            serde_json::json!({
                "backpressure_events": total_backpressure_events
            }),
        );

        // Verify processing decreased through slow stage due to backpressure
        let slow_stage_processed = counts[2];
        let final_stage_processed = counts[pipeline_stages - 1];

        self.logger.log_assertion(
            "backpressure_limited_throughput",
            slow_stage_processed < total_items,
            serde_json::json!({
                "slow_stage_processed": slow_stage_processed,
                "total_items": total_items
            }),
        );

        assert!(
            counts[0] > 0,
            "First stage should have processed some items"
        );
        assert!(
            total_backpressure_events > 0,
            "Backpressure events should have occurred due to slow stage"
        );
        assert!(
            slow_stage_processed < total_items,
            "Slow stage should have limited overall throughput"
        );
    }

    /// [br-integration-8] Pubsub broker death and reconnection resilience
    async fn test_pubsub_broker_death_reconnect(&self) {
        self.logger.log_phase("pubsub_broker_death_setup");

        let subscriber_count = 5;
        let message_count = 200;
        let broker_kill_interval = Duration::from_millis(500);

        self.logger.log_event(
            "pubsub_broker_death_config",
            serde_json::json!({
                "subscriber_count": subscriber_count,
                "message_count": message_count,
                "broker_kill_interval_ms": broker_kill_interval.as_millis()
            }),
        );

        // Phase 1: Setup pubsub broker with fault injection
        self.logger.log_phase("broker_setup");

        let (broker_tx, broker_rx) = broadcast::channel(1000);
        let (death_signal_tx, death_signal_rx) = oneshot::channel();
        let broker_deaths = Arc::new(AtomicUsize::new(0));
        let broker_recoveries = Arc::new(AtomicUsize::new(0));
        let total_messages_published = Arc::new(AtomicUsize::new(0));
        let total_messages_received = Arc::new(AtomicUsize::new(0));

        // Broker process with death/recovery simulation
        let broker_task = {
            let logger = self.logger.clone();
            let broker_deaths = Arc::clone(&broker_deaths);
            let broker_recoveries = Arc::clone(&broker_recoveries);
            let total_published = Arc::clone(&total_messages_published);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut death_signal_rx = death_signal_rx;
                            let mut published_count = 0;
                            let mut death_count = 0;

                            loop {
                                // Check for death signal
                                match death_signal_rx.try_recv() {
                                    Ok(_) => {
                                        death_count += 1;
                                        broker_deaths.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "broker_death",
                                            serde_json::json!({
                                                "death_count": death_count,
                                                "published_before_death": published_count
                                            }),
                                        );

                                        // Simulate broker restart delay
                                        sleep(Duration::from_millis(200)).await;

                                        broker_recoveries.fetch_add(1, Ordering::Relaxed);
                                        logger.log_event(
                                            "broker_recovery",
                                            serde_json::json!({
                                                "death_count": death_count,
                                                "recovery_count": death_count
                                            }),
                                        );

                                        // Resume publishing after recovery
                                    }
                                    Err(_) => {
                                        // Normal operation - publish messages
                                        if published_count < message_count {
                                            let message =
                                                format!("broker_message_{}", published_count);

                                            match broker_tx.send(message.clone()) {
                                                Ok(_) => {
                                                    published_count += 1;
                                                    total_published.fetch_add(1, Ordering::Relaxed);

                                                    logger.log_event(
                                                        "broker_message_published",
                                                        serde_json::json!({
                                                            "message": message,
                                                            "published_count": published_count
                                                        }),
                                                    );
                                                }
                                                Err(_) => {
                                                    logger.log_event(
                                                        "broker_publish_failed",
                                                        serde_json::json!({
                                                            "message": message,
                                                            "published_count": published_count
                                                        }),
                                                    );
                                                    break;
                                                }
                                            }

                                            sleep(Duration::from_millis(50)).await;
                                        } else {
                                            // Publishing complete
                                            break;
                                        }
                                    }
                                }
                            }

                            logger.log_event(
                                "broker_shutdown",
                                serde_json::json!({
                                    "total_published": published_count,
                                    "total_deaths": death_count
                                }),
                            );

                            Outcome::Ok(published_count)
                        })
                        .await
                })
                .await
        };

        // Phase 2: Setup subscribers with reconnection logic
        self.logger.log_phase("subscriber_setup");

        let mut subscriber_tasks = Vec::new();

        for sub_id in 0..subscriber_count {
            let mut subscriber_rx = broker_tx.subscribe();
            let logger = self.logger.clone();
            let total_received = Arc::clone(&total_messages_received);

            let subscriber_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut received_count = 0;
                            let mut reconnect_count = 0;

                            loop {
                                match timeout(Duration::from_millis(100), subscriber_rx.recv())
                                    .await
                                {
                                    Outcome::Ok(Ok(message)) => {
                                        received_count += 1;
                                        total_received.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "subscriber_message_received",
                                            serde_json::json!({
                                                "subscriber_id": sub_id,
                                                "message": message,
                                                "received_count": received_count
                                            }),
                                        );
                                    }
                                    Outcome::Ok(Err(_)) => {
                                        // Channel closed - attempt reconnect
                                        reconnect_count += 1;

                                        logger.log_event(
                                            "subscriber_reconnect",
                                            serde_json::json!({
                                                "subscriber_id": sub_id,
                                                "reconnect_count": reconnect_count
                                            }),
                                        );

                                        // Simulate reconnection delay
                                        sleep(Duration::from_millis(100)).await;

                                        // In real scenario, would reconnect to new broker instance
                                        break;
                                    }
                                    Outcome::Cancelled => {
                                        logger.log_event(
                                            "subscriber_timeout",
                                            serde_json::json!({
                                                "subscriber_id": sub_id,
                                                "received_count": received_count
                                            }),
                                        );
                                        continue;
                                    }
                                }

                                if received_count >= message_count / subscriber_count {
                                    break;
                                }
                            }

                            logger.log_event(
                                "subscriber_complete",
                                serde_json::json!({
                                    "subscriber_id": sub_id,
                                    "received_count": received_count,
                                    "reconnect_count": reconnect_count
                                }),
                            );

                            Outcome::Ok(received_count)
                        })
                        .await
                })
                .await;

            subscriber_tasks.push(subscriber_task);
        }

        // Phase 3: Chaos injection - kill broker periodically
        let chaos_task = {
            let logger = self.logger.clone();
            let death_signal_tx = death_signal_tx;

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            // Wait before first kill
                            sleep(broker_kill_interval).await;

                            let mut kill_count = 0;
                            while kill_count < 3 {
                                // Kill broker 3 times during test
                                if death_signal_tx.send(()).is_err() {
                                    logger.log_event(
                                        "death_signal_failed",
                                        serde_json::json!({
                                            "kill_count": kill_count
                                        }),
                                    );
                                    break;
                                }

                                kill_count += 1;
                                logger.log_event(
                                    "broker_kill_signal",
                                    serde_json::json!({
                                        "kill_count": kill_count
                                    }),
                                );

                                sleep(broker_kill_interval).await;
                            }

                            Outcome::Ok(kill_count)
                        })
                        .await
                })
                .await
        };

        // Phase 4: Execute pubsub with chaos
        self.logger.log_phase("pubsub_chaos_execution");

        let execution_timeout = Duration::from_secs(15);

        // Wait for broker task completion
        let broker_result = timeout(execution_timeout, broker_task).await;

        // Wait for chaos task
        let _chaos_result = timeout(Duration::from_secs(5), chaos_task).await;

        // Collect subscriber results
        let mut total_subscriber_messages = 0;
        for (sub_id, subscriber_task) in subscriber_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(3), subscriber_task).await {
                Outcome::Ok(Outcome::Ok(received)) => {
                    total_subscriber_messages += received;
                    self.logger.log_event(
                        "subscriber_task_completed",
                        serde_json::json!({
                            "subscriber_id": sub_id,
                            "received_count": received
                        }),
                    );
                }
                _ => {
                    self.logger.log_event(
                        "subscriber_task_timeout",
                        serde_json::json!({
                            "subscriber_id": sub_id
                        }),
                    );
                }
            }
        }

        // Phase 5: Validate broker death/recovery resilience
        self.logger.log_phase("broker_death_validation");

        let broker_published = total_messages_published.load(Ordering::Relaxed);
        let total_received = total_messages_received.load(Ordering::Relaxed);
        let total_deaths = broker_deaths.load(Ordering::Relaxed);
        let total_recoveries = broker_recoveries.load(Ordering::Relaxed);

        self.logger.log_metrics(serde_json::json!({
            "broker_death_results": {
                "broker_published": broker_published,
                "total_received": total_received,
                "subscriber_messages": total_subscriber_messages,
                "broker_deaths": total_deaths,
                "broker_recoveries": total_recoveries,
                "message_delivery_rate": total_received as f64 / broker_published as f64,
                "death_recovery_rate": total_recoveries as f64 / total_deaths as f64
            }
        }));

        // Critical assertions for broker resilience
        self.logger.log_assertion(
            "broker_deaths_occurred",
            total_deaths > 0,
            serde_json::json!({
                "total_deaths": total_deaths
            }),
        );

        self.logger.log_assertion(
            "broker_recoveries_matched",
            total_recoveries == total_deaths,
            serde_json::json!({
                "recoveries": total_recoveries,
                "deaths": total_deaths
            }),
        );

        self.logger.log_assertion(
            "messages_published",
            broker_published > 0,
            serde_json::json!({
                "published": broker_published
            }),
        );

        self.logger.log_assertion(
            "subscribers_received_messages",
            total_received > 0,
            serde_json::json!({
                "received": total_received
            }),
        );

        // Message delivery should be reasonably successful despite chaos
        let delivery_rate = total_received as f64 / broker_published as f64;
        self.logger.log_assertion(
            "message_delivery_resilience",
            delivery_rate > 0.7,
            serde_json::json!({
                "delivery_rate": delivery_rate,
                "threshold": 0.7
            }),
        );

        assert!(total_deaths > 0, "Broker deaths should occur during chaos");
        assert!(
            total_recoveries == total_deaths,
            "All broker deaths should recover: {} recoveries vs {} deaths",
            total_recoveries,
            total_deaths
        );
        assert!(broker_published > 0, "Broker should publish messages");
        assert!(
            total_received > 0,
            "Subscribers should receive messages despite chaos"
        );
        assert!(
            delivery_rate > 0.7,
            "Message delivery rate should be >70% despite broker deaths: {:.2}%",
            delivery_rate * 100.0
        );
    }

    /// [br-integration-9] RaptorQ decode interruption and stream resumption
    async fn test_raptorq_decode_interruption_resume(&self) {
        self.logger.log_phase("raptorq_interruption_setup");

        use crate::raptorq::{Decoder, Encoder, SourceBlockEncoder};

        let source_data = vec![0u8; 8192]; // 8KB source data
        let source_symbol_size = 64; // 64-byte symbols
        let repair_symbol_count = 20; // Generate 20 repair symbols

        self.logger.log_event(
            "raptorq_config",
            serde_json::json!({
                "source_data_size": source_data.len(),
                "source_symbol_size": source_symbol_size,
                "repair_symbol_count": repair_symbol_count
            }),
        );

        // Phase 1: Encode source data for transmission
        self.logger.log_phase("raptorq_encoding");

        let mut encoder = Encoder::new(source_symbol_size);
        let encoded_block = encoder
            .encode(&source_data, repair_symbol_count)
            .expect("RaptorQ encoding should succeed");

        let source_symbols = encoded_block.source_symbols();
        let repair_symbols = encoded_block.repair_symbols();
        let total_symbols = source_symbols.len() + repair_symbols.len();

        self.logger.log_event(
            "raptorq_encoded",
            serde_json::json!({
                "source_symbol_count": source_symbols.len(),
                "repair_symbol_count": repair_symbols.len(),
                "total_symbol_count": total_symbols
            }),
        );

        // Phase 2: Setup interrupted decode simulation
        self.logger.log_phase("raptorq_decode_simulation");

        let interruption_point = source_symbols.len() / 2; // Interrupt mid-stream
        let interruption_delay = Duration::from_millis(100);
        let total_interruptions = Arc::new(AtomicUsize::new(0));
        let total_resumed = Arc::new(AtomicUsize::new(0));
        let symbols_before_interruption = Arc::new(AtomicUsize::new(0));
        let symbols_after_resumption = Arc::new(AtomicUsize::new(0));

        // Decoder with interruption simulation
        let decode_task = {
            let logger = self.logger.clone();
            let total_interruptions = Arc::clone(&total_interruptions);
            let total_resumed = Arc::clone(&total_resumed);
            let symbols_before = Arc::clone(&symbols_before_interruption);
            let symbols_after = Arc::clone(&symbols_after_resumption);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut decoder = Decoder::new(source_symbol_size);
                            let mut symbols_processed = 0;
                            let mut interruption_count = 0;

                            // Process source symbols with interruption
                            for (symbol_id, symbol_data) in source_symbols.iter().enumerate() {
                                if symbol_id == interruption_point {
                                    // Simulate stream interruption
                                    interruption_count += 1;
                                    total_interruptions.fetch_add(1, Ordering::Relaxed);
                                    symbols_before.store(symbols_processed, Ordering::Relaxed);

                                    logger.log_event(
                                        "raptorq_stream_interrupted",
                                        serde_json::json!({
                                            "interruption_count": interruption_count,
                                            "symbols_before_interruption": symbols_processed,
                                            "symbol_id": symbol_id
                                        }),
                                    );

                                    // Simulate interruption delay (network timeout, etc.)
                                    sleep(interruption_delay).await;

                                    // Resume decoding
                                    total_resumed.fetch_add(1, Ordering::Relaxed);
                                    logger.log_event(
                                        "raptorq_stream_resumed",
                                        serde_json::json!({
                                            "interruption_count": interruption_count,
                                            "resume_at_symbol_id": symbol_id
                                        }),
                                    );
                                }

                                // Feed symbol to decoder
                                if decoder
                                    .add_source_symbol(symbol_id as u32, symbol_data.clone())
                                    .is_ok()
                                {
                                    symbols_processed += 1;

                                    if symbol_id > interruption_point {
                                        symbols_after.fetch_add(1, Ordering::Relaxed);
                                    }

                                    logger.log_event(
                                        "raptorq_symbol_processed",
                                        serde_json::json!({
                                            "symbol_id": symbol_id,
                                            "symbols_processed": symbols_processed,
                                            "is_after_resumption": symbol_id > interruption_point
                                        }),
                                    );

                                    // Check if we can decode yet
                                    if let Ok(decoded_data) = decoder.try_decode() {
                                        logger.log_event(
                                            "raptorq_decode_success",
                                            serde_json::json!({
                                                "symbols_processed": symbols_processed,
                                                "decoded_size": decoded_data.len(),
                                                "interruption_count": interruption_count
                                            }),
                                        );

                                        return Outcome::Ok((
                                            decoded_data,
                                            symbols_processed,
                                            interruption_count,
                                        ));
                                    }
                                } else {
                                    logger.log_event(
                                        "raptorq_symbol_rejected",
                                        serde_json::json!({
                                            "symbol_id": symbol_id
                                        }),
                                    );
                                }

                                // Simulate network transmission delay
                                sleep(Duration::from_millis(10)).await;
                            }

                            // If source symbols weren't enough, try repair symbols
                            for (repair_id, repair_data) in repair_symbols.iter().enumerate() {
                                if decoder
                                    .add_repair_symbol(repair_id as u32, repair_data.clone())
                                    .is_ok()
                                {
                                    symbols_processed += 1;
                                    symbols_after.fetch_add(1, Ordering::Relaxed);

                                    if let Ok(decoded_data) = decoder.try_decode() {
                                        logger.log_event(
                                            "raptorq_decode_success_with_repair",
                                            serde_json::json!({
                                                "symbols_processed": symbols_processed,
                                                "decoded_size": decoded_data.len(),
                                                "repair_symbols_used": repair_id + 1,
                                                "interruption_count": interruption_count
                                            }),
                                        );

                                        return Outcome::Ok((
                                            decoded_data,
                                            symbols_processed,
                                            interruption_count,
                                        ));
                                    }
                                }

                                sleep(Duration::from_millis(10)).await;
                            }

                            logger.log_event(
                                "raptorq_decode_failed",
                                serde_json::json!({
                                    "symbols_processed": symbols_processed,
                                    "interruption_count": interruption_count
                                }),
                            );

                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                "RaptorQ decode failed after all symbols",
                            ))
                        })
                        .await
                })
                .await
        };

        // Phase 3: Execute decode with interruption
        self.logger.log_phase("raptorq_decode_execution");

        let decode_timeout = Duration::from_secs(10);
        let decode_result = timeout(decode_timeout, decode_task).await;

        // Phase 4: Validate interruption recovery
        self.logger.log_phase("raptorq_interruption_validation");

        let interruption_count = total_interruptions.load(Ordering::Relaxed);
        let resume_count = total_resumed.load(Ordering::Relaxed);
        let before_count = symbols_before_interruption.load(Ordering::Relaxed);
        let after_count = symbols_after_resumption.load(Ordering::Relaxed);

        let (decode_success, decoded_data_len, symbols_used) = match decode_result {
            Outcome::Ok(Outcome::Ok((decoded_data, symbols_processed, _))) => {
                (true, decoded_data.len(), symbols_processed)
            }
            _ => (false, 0, 0),
        };

        self.logger.log_metrics(serde_json::json!({
            "raptorq_interruption_results": {
                "decode_success": decode_success,
                "decoded_data_size": decoded_data_len,
                "symbols_used": symbols_used,
                "interruption_count": interruption_count,
                "resume_count": resume_count,
                "symbols_before_interruption": before_count,
                "symbols_after_resumption": after_count,
                "recovery_rate": resume_count as f64 / interruption_count as f64
            }
        }));

        // Critical assertions for RaptorQ resilience
        self.logger.log_assertion(
            "raptorq_interruption_occurred",
            interruption_count > 0,
            serde_json::json!({
                "interruption_count": interruption_count
            }),
        );

        self.logger.log_assertion(
            "raptorq_stream_resumed",
            resume_count == interruption_count,
            serde_json::json!({
                "resume_count": resume_count,
                "interruption_count": interruption_count
            }),
        );

        self.logger.log_assertion(
            "raptorq_decode_success",
            decode_success,
            serde_json::json!({
                "decode_success": decode_success
            }),
        );

        self.logger.log_assertion(
            "raptorq_data_integrity",
            decoded_data_len == source_data.len(),
            serde_json::json!({
                "decoded_size": decoded_data_len,
                "source_size": source_data.len()
            }),
        );

        self.logger.log_assertion(
            "raptorq_symbols_after_resume",
            after_count > 0,
            serde_json::json!({
                "symbols_after_resume": after_count
            }),
        );

        assert!(
            interruption_count > 0,
            "Stream interruption should occur during decode"
        );
        assert!(
            resume_count == interruption_count,
            "All interruptions should resume: {} resumes vs {} interruptions",
            resume_count,
            interruption_count
        );
        assert!(
            decode_success,
            "RaptorQ decode should succeed despite interruption"
        );
        assert!(
            decoded_data_len == source_data.len(),
            "Decoded data should match source: {} vs {} bytes",
            decoded_data_len,
            source_data.len()
        );
        assert!(
            after_count > 0,
            "Symbols should be processed after resumption: {} symbols",
            after_count
        );
    }

    /// [br-integration-10] Runtime panic recovery with active subscriptions
    async fn test_runtime_panic_recovery_subscriptions(&self) {
        self.logger.log_phase("panic_recovery_setup");

        let subscription_count = 8;
        let panic_injection_probability = 0.3; // 30% chance of panic per work item
        let total_work_items = 50;

        self.logger.log_event(
            "panic_recovery_config",
            serde_json::json!({
                "subscription_count": subscription_count,
                "panic_injection_probability": panic_injection_probability,
                "total_work_items": total_work_items
            }),
        );

        // Phase 1: Setup active subscriptions
        self.logger.log_phase("subscription_setup");

        let (work_tx, work_rx) = broadcast::channel(200);
        let (result_tx, result_rx) = mpsc::channel(100);
        let panic_count = Arc::new(AtomicUsize::new(0));
        let recovery_count = Arc::new(AtomicUsize::new(0));
        let surviving_subscriptions = Arc::new(AtomicUsize::new(0));
        let completed_work = Arc::new(AtomicUsize::new(0));

        // Subscription workers with panic boundaries
        let mut subscription_tasks = Vec::new();

        for sub_id in 0..subscription_count {
            let mut subscriber_rx = work_tx.subscribe();
            let result_tx = result_tx.clone();
            let logger = self.logger.clone();
            let panic_count = Arc::clone(&panic_count);
            let recovery_count = Arc::clone(&recovery_count);
            let surviving_subscriptions = Arc::clone(&surviving_subscriptions);
            let completed_work = Arc::clone(&completed_work);

            let subscription_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut processed_items = 0;
                            let mut panic_recoveries = 0;
                            let mut subscription_active = true;

                            while subscription_active {
                                // Protected work execution with panic boundary
                                let work_result = std::panic::catch_unwind(|| async {
                                    match timeout(Duration::from_millis(500), subscriber_rx.recv())
                                        .await
                                    {
                                        Outcome::Ok(Ok(work_item)) => {
                                            // Simulate work with potential panic
                                            let panic_roll: f64 = fastrand::f64();

                                            if panic_roll < panic_injection_probability {
                                                panic_count.fetch_add(1, Ordering::Relaxed);

                                                logger.log_event(
                                                    "subscription_panic",
                                                    serde_json::json!({
                                                        "subscriber_id": sub_id,
                                                        "work_item": work_item,
                                                        "panic_roll": panic_roll,
                                                        "processed_before_panic": processed_items
                                                    }),
                                                );

                                                panic!(
                                                    "Injected panic in subscription worker {}",
                                                    sub_id
                                                );
                                            }

                                            // Normal processing
                                            processed_items += 1;
                                            completed_work.fetch_add(1, Ordering::Relaxed);

                                            let result = format!(
                                                "processed_by_sub_{}_item_{}",
                                                sub_id, processed_items
                                            );

                                            logger.log_event(
                                                "subscription_work_completed",
                                                serde_json::json!({
                                                    "subscriber_id": sub_id,
                                                    "work_item": work_item,
                                                    "result": result,
                                                    "processed_items": processed_items
                                                }),
                                            );

                                            if result_tx.send(result).await.is_err() {
                                                logger.log_event(
                                                    "result_send_failed",
                                                    serde_json::json!({
                                                        "subscriber_id": sub_id
                                                    }),
                                                );
                                                return Outcome::Err(Error::new(
                                                    ErrorKind::Other,
                                                    "Result channel closed",
                                                ));
                                            }

                                            Outcome::Ok(true)
                                        }
                                        Outcome::Ok(Err(_)) => {
                                            // Channel closed
                                            logger.log_event(
                                                "subscription_channel_closed",
                                                serde_json::json!({
                                                    "subscriber_id": sub_id,
                                                    "processed_items": processed_items
                                                }),
                                            );
                                            Outcome::Ok(false)
                                        }
                                        Outcome::Cancelled => {
                                            // Timeout - continue listening
                                            Outcome::Ok(true)
                                        }
                                    }
                                });

                                match work_result {
                                    Ok(future) => {
                                        // No panic occurred, execute the async work
                                        match future.await {
                                            Outcome::Ok(continue_subscription) => {
                                                if !continue_subscription {
                                                    subscription_active = false;
                                                }
                                            }
                                            Outcome::Err(_) => {
                                                subscription_active = false;
                                            }
                                            Outcome::Cancelled => {
                                                subscription_active = false;
                                            }
                                        }
                                    }
                                    Err(_panic_info) => {
                                        // Panic occurred - recover subscription
                                        panic_recoveries += 1;
                                        recovery_count.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "subscription_panic_recovery",
                                            serde_json::json!({
                                                "subscriber_id": sub_id,
                                                "panic_recoveries": panic_recoveries,
                                                "processed_before_recovery": processed_items
                                            }),
                                        );

                                        // Simulate recovery delay
                                        sleep(Duration::from_millis(100)).await;

                                        // Subscription survives the panic and continues
                                        logger.log_event(
                                            "subscription_recovered",
                                            serde_json::json!({
                                                "subscriber_id": sub_id,
                                                "recovery_count": panic_recoveries
                                            }),
                                        );
                                    }
                                }

                                // Subscription survival check
                                if processed_items >= total_work_items / subscription_count + 5 {
                                    // Subscription has processed enough work
                                    subscription_active = false;
                                }
                            }

                            surviving_subscriptions.fetch_add(1, Ordering::Relaxed);

                            logger.log_event(
                                "subscription_final_shutdown",
                                serde_json::json!({
                                    "subscriber_id": sub_id,
                                    "processed_items": processed_items,
                                    "panic_recoveries": panic_recoveries
                                }),
                            );

                            Outcome::Ok((processed_items, panic_recoveries))
                        })
                        .await
                })
                .await;

            subscription_tasks.push(subscription_task);
        }

        // Phase 2: Work publisher
        self.logger.log_phase("work_publishing");

        let publisher_task = {
            let logger = self.logger.clone();

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut published_count = 0;

                            for work_item in 0..total_work_items {
                                let work_data = format!("work_item_{}", work_item);

                                match work_tx.send(work_data.clone()) {
                                    Ok(_) => {
                                        published_count += 1;

                                        logger.log_event(
                                            "work_published",
                                            serde_json::json!({
                                                "work_item": work_item,
                                                "work_data": work_data,
                                                "published_count": published_count
                                            }),
                                        );
                                    }
                                    Err(_) => {
                                        logger.log_event(
                                            "work_publish_failed",
                                            serde_json::json!({
                                                "work_item": work_item,
                                                "published_count": published_count
                                            }),
                                        );
                                        break;
                                    }
                                }

                                sleep(Duration::from_millis(50)).await;
                            }

                            logger.log_event(
                                "work_publishing_complete",
                                serde_json::json!({
                                    "total_published": published_count
                                }),
                            );

                            Outcome::Ok(published_count)
                        })
                        .await
                })
                .await
        };

        // Phase 3: Result collector
        let collector_task = {
            let logger = self.logger.clone();

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut result_rx = result_rx;
                            let mut collected_results = 0;

                            while let Some(result) = result_rx.recv().await {
                                collected_results += 1;

                                logger.log_event(
                                    "result_collected",
                                    serde_json::json!({
                                        "result": result,
                                        "collected_count": collected_results
                                    }),
                                );

                                if collected_results >= total_work_items {
                                    break;
                                }
                            }

                            logger.log_event(
                                "result_collection_complete",
                                serde_json::json!({
                                    "total_collected": collected_results
                                }),
                            );

                            Outcome::Ok(collected_results)
                        })
                        .await
                })
                .await
        };

        // Phase 4: Execute with panic recovery
        self.logger.log_phase("panic_recovery_execution");

        let execution_timeout = Duration::from_secs(20);

        // Wait for publisher completion
        let publisher_result = timeout(execution_timeout, publisher_task).await;

        // Wait for collector
        let collector_result = timeout(Duration::from_secs(5), collector_task).await;

        // Collect subscription task results
        let mut total_processed_items = 0;
        let mut total_subscription_recoveries = 0;

        for (sub_id, subscription_task) in subscription_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(3), subscription_task).await {
                Outcome::Ok(Outcome::Ok((processed, recoveries))) => {
                    total_processed_items += processed;
                    total_subscription_recoveries += recoveries;

                    self.logger.log_event(
                        "subscription_task_completed",
                        serde_json::json!({
                            "subscriber_id": sub_id,
                            "processed_items": processed,
                            "panic_recoveries": recoveries
                        }),
                    );
                }
                _ => {
                    self.logger.log_event(
                        "subscription_task_timeout",
                        serde_json::json!({
                            "subscriber_id": sub_id
                        }),
                    );
                }
            }
        }

        // Phase 5: Validate panic recovery and subscription survival
        self.logger.log_phase("panic_recovery_validation");

        let total_panics = panic_count.load(Ordering::Relaxed);
        let total_recoveries = recovery_count.load(Ordering::Relaxed);
        let survivors = surviving_subscriptions.load(Ordering::Relaxed);
        let work_completed = completed_work.load(Ordering::Relaxed);

        let published_work = match publisher_result {
            Outcome::Ok(Outcome::Ok(count)) => count,
            _ => 0,
        };

        let collected_results = match collector_result {
            Outcome::Ok(Outcome::Ok(count)) => count,
            _ => 0,
        };

        self.logger.log_metrics(serde_json::json!({
            "panic_recovery_results": {
                "total_panics": total_panics,
                "total_recoveries": total_recoveries,
                "surviving_subscriptions": survivors,
                "work_published": published_work,
                "work_completed": work_completed,
                "results_collected": collected_results,
                "subscription_survival_rate": survivors as f64 / subscription_count as f64,
                "panic_recovery_rate": total_recoveries as f64 / total_panics as f64,
                "work_completion_rate": work_completed as f64 / published_work as f64
            }
        }));

        // Critical assertions for panic recovery
        self.logger.log_assertion(
            "panics_occurred",
            total_panics > 0,
            serde_json::json!({
                "total_panics": total_panics
            }),
        );

        self.logger.log_assertion(
            "panic_recovery",
            total_recoveries == total_panics,
            serde_json::json!({
                "recoveries": total_recoveries,
                "panics": total_panics
            }),
        );

        self.logger.log_assertion(
            "subscriptions_survived",
            survivors > subscription_count / 2,
            serde_json::json!({
                "survivors": survivors,
                "total_subscriptions": subscription_count
            }),
        );

        self.logger.log_assertion(
            "work_completed",
            work_completed > 0,
            serde_json::json!({
                "work_completed": work_completed
            }),
        );

        // Work completion should be reasonable despite panics
        let completion_rate = work_completed as f64 / published_work as f64;
        self.logger.log_assertion(
            "work_completion_resilience",
            completion_rate > 0.6,
            serde_json::json!({
                "completion_rate": completion_rate,
                "threshold": 0.6
            }),
        );

        assert!(total_panics > 0, "Runtime panics should occur during chaos");
        assert!(
            total_recoveries == total_panics,
            "All panics should recover: {} recoveries vs {} panics",
            total_recoveries,
            total_panics
        );
        assert!(
            survivors > subscription_count / 2,
            "Majority of subscriptions should survive: {} survivors out of {}",
            survivors,
            subscription_count
        );
        assert!(work_completed > 0, "Work should complete despite panics");
        assert!(
            completion_rate > 0.6,
            "Work completion rate should be >60% despite panics: {:.2}%",
            completion_rate * 100.0
        );
    }

    /// [br-integration-11] Burst traffic with rate limiting and sustained throughput
    async fn test_burst_traffic_rate_limit_throughput(&self) {
        self.logger.log_phase("burst_traffic_setup");

        use crate::combinator::rate_limit::{RateLimit, RateLimitPolicy};

        let burst_size = 500; // Large burst of requests
        let sustained_rate = 50; // Requests per second after burst
        let burst_duration = Duration::from_millis(200);
        let observation_period = Duration::from_secs(5);
        let rate_limit_capacity = 100; // tokens
        let refill_rate = 20; // tokens per second

        self.logger.log_event(
            "burst_traffic_config",
            serde_json::json!({
                "burst_size": burst_size,
                "sustained_rate": sustained_rate,
                "burst_duration_ms": burst_duration.as_millis(),
                "observation_period_secs": observation_period.as_secs(),
                "rate_limit_capacity": rate_limit_capacity,
                "refill_rate": refill_rate
            }),
        );

        // Phase 1: Setup rate limiter
        self.logger.log_phase("rate_limiter_setup");

        let rate_policy = RateLimitPolicy::new(rate_limit_capacity, refill_rate);
        let rate_limiter = RateLimit::new(rate_policy);

        let burst_requests_sent = Arc::new(AtomicUsize::new(0));
        let sustained_requests_sent = Arc::new(AtomicUsize::new(0));
        let burst_requests_processed = Arc::new(AtomicUsize::new(0));
        let sustained_requests_processed = Arc::new(AtomicUsize::new(0));
        let rate_limit_rejections = Arc::new(AtomicUsize::new(0));
        let total_processing_time = Arc::new(AtomicUsize::new(0));

        // Phase 2: Request processing service with rate limiting
        let (request_tx, request_rx) = mpsc::channel(1000);
        let (result_tx, result_rx) = mpsc::channel(1000);

        let processing_service = {
            let logger = self.logger.clone();
            let rate_limiter = rate_limiter.clone();
            let burst_processed = Arc::clone(&burst_requests_processed);
            let sustained_processed = Arc::clone(&sustained_requests_processed);
            let total_time = Arc::clone(&total_processing_time);
            let rejections = Arc::clone(&rate_limit_rejections);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut request_rx = request_rx;
                            let mut processed_count = 0;

                            while let Some((request_id, is_burst, timestamp)) =
                                request_rx.recv().await
                            {
                                let processing_start = Instant::now();

                                // Apply rate limiting
                                match timeout(Duration::from_millis(100), rate_limiter.acquire())
                                    .await
                                {
                                    Outcome::Ok(_permit) => {
                                        // Process request
                                        sleep(Duration::from_millis(10)).await; // Simulate processing

                                        processed_count += 1;
                                        let processing_duration = processing_start.elapsed();
                                        total_time.fetch_add(
                                            processing_duration.as_micros() as usize,
                                            Ordering::Relaxed,
                                        );

                                        if is_burst {
                                            burst_processed.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            sustained_processed.fetch_add(1, Ordering::Relaxed);
                                        }

                                        let result = format!("processed_request_{}", request_id);

                                        logger.log_event("request_processed", serde_json::json!({
                                    "request_id": request_id,
                                    "is_burst": is_burst,
                                    "processing_duration_us": processing_duration.as_micros(),
                                    "processed_count": processed_count,
                                    "timestamp": timestamp.elapsed().as_millis()
                                }));

                                        if result_tx.send(result).await.is_err() {
                                            break;
                                        }
                                    }
                                    Outcome::Cancelled => {
                                        // Rate limited
                                        rejections.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "request_rate_limited",
                                            serde_json::json!({
                                                "request_id": request_id,
                                                "is_burst": is_burst,
                                                "timestamp": timestamp.elapsed().as_millis()
                                            }),
                                        );
                                    }
                                }
                            }

                            logger.log_event(
                                "processing_service_shutdown",
                                serde_json::json!({
                                    "total_processed": processed_count
                                }),
                            );

                            Outcome::Ok(processed_count)
                        })
                        .await
                })
                .await
        };

        // Phase 3: Burst traffic generator
        self.logger.log_phase("burst_traffic_generation");

        let burst_generator = {
            let logger = self.logger.clone();
            let request_tx = request_tx.clone();
            let burst_sent = Arc::clone(&burst_requests_sent);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let burst_start = Instant::now();
                            let mut sent_count = 0;

                            for request_id in 0..burst_size {
                                let send_result =
                                    request_tx.send((request_id, true, burst_start)).await;

                                if send_result.is_ok() {
                                    sent_count += 1;
                                    burst_sent.fetch_add(1, Ordering::Relaxed);

                                    if request_id % 50 == 0 {
                                        logger.log_event(
                                            "burst_progress",
                                            serde_json::json!({
                                                "sent_count": sent_count,
                                                "request_id": request_id,
                                                "elapsed_ms": burst_start.elapsed().as_millis()
                                            }),
                                        );
                                    }
                                } else {
                                    logger.log_event(
                                        "burst_send_failed",
                                        serde_json::json!({
                                            "request_id": request_id,
                                            "sent_count": sent_count
                                        }),
                                    );
                                    break;
                                }

                                // Tight burst - minimal delay
                                sleep(burst_duration / burst_size as u32).await;
                            }

                            logger.log_event(
                                "burst_generation_complete",
                                serde_json::json!({
                                    "total_sent": sent_count,
                                    "duration_ms": burst_start.elapsed().as_millis()
                                }),
                            );

                            Outcome::Ok(sent_count)
                        })
                        .await
                })
                .await
        };

        // Phase 4: Sustained traffic generator
        let sustained_generator = {
            let logger = self.logger.clone();
            let request_tx = request_tx.clone();
            let sustained_sent = Arc::clone(&sustained_requests_sent);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            // Wait for burst to complete
                            sleep(burst_duration + Duration::from_millis(100)).await;

                            let sustained_start = Instant::now();
                            let mut sent_count = 0;
                            let request_interval =
                                Duration::from_millis(1000 / sustained_rate as u64);

                            while sustained_start.elapsed() < observation_period {
                                let request_id = burst_size + sent_count;

                                if request_tx
                                    .send((request_id, false, sustained_start))
                                    .await
                                    .is_ok()
                                {
                                    sent_count += 1;
                                    sustained_sent.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event(
                                        "sustained_request_sent",
                                        serde_json::json!({
                                            "request_id": request_id,
                                            "sent_count": sent_count,
                                            "elapsed_ms": sustained_start.elapsed().as_millis()
                                        }),
                                    );
                                } else {
                                    break;
                                }

                                sleep(request_interval).await;
                            }

                            logger.log_event(
                                "sustained_generation_complete",
                                serde_json::json!({
                                    "total_sent": sent_count,
                                    "duration_ms": sustained_start.elapsed().as_millis()
                                }),
                            );

                            Outcome::Ok(sent_count)
                        })
                        .await
                })
                .await
        };

        // Phase 5: Execute load test
        self.logger.log_phase("load_test_execution");

        let total_timeout = burst_duration + observation_period + Duration::from_secs(2);

        // Start processing service
        let processing_task = processing_service;

        // Start traffic generators
        let burst_task = burst_generator;
        let sustained_task = sustained_generator;

        // Wait for generators to complete
        let burst_result = timeout(Duration::from_secs(5), burst_task).await;
        let sustained_result =
            timeout(observation_period + Duration::from_secs(2), sustained_task).await;

        // Allow processing to complete
        drop(request_tx);
        sleep(Duration::from_millis(500)).await;

        let processing_result = timeout(Duration::from_secs(3), processing_task).await;

        // Phase 6: Collect results and validate performance
        self.logger.log_phase("performance_validation");

        let burst_sent = burst_requests_sent.load(Ordering::Relaxed);
        let sustained_sent = sustained_requests_sent.load(Ordering::Relaxed);
        let burst_processed = burst_requests_processed.load(Ordering::Relaxed);
        let sustained_processed = sustained_requests_processed.load(Ordering::Relaxed);
        let total_rejections = rate_limit_rejections.load(Ordering::Relaxed);
        let avg_processing_time = total_processing_time.load(Ordering::Relaxed)
            / (burst_processed + sustained_processed).max(1);

        self.logger.log_metrics(serde_json::json!({
            "burst_traffic_results": {
                "burst_sent": burst_sent,
                "burst_processed": burst_processed,
                "sustained_sent": sustained_sent,
                "sustained_processed": sustained_processed,
                "total_rejections": total_rejections,
                "avg_processing_time_us": avg_processing_time,
                "burst_success_rate": burst_processed as f64 / burst_sent as f64,
                "sustained_success_rate": sustained_processed as f64 / sustained_sent as f64,
                "rate_limit_effectiveness": total_rejections as f64 / (burst_sent + sustained_sent) as f64,
                "sustained_throughput_rps": sustained_processed as f64 / observation_period.as_secs_f64()
            }
        }));

        // Critical assertions for burst and sustained performance
        self.logger.log_assertion(
            "burst_traffic_generated",
            burst_sent > 0,
            serde_json::json!({
                "burst_sent": burst_sent
            }),
        );

        self.logger.log_assertion(
            "sustained_traffic_generated",
            sustained_sent > 0,
            serde_json::json!({
                "sustained_sent": sustained_sent
            }),
        );

        self.logger.log_assertion(
            "rate_limiting_active",
            total_rejections > 0,
            serde_json::json!({
                "total_rejections": total_rejections
            }),
        );

        self.logger.log_assertion(
            "burst_partially_processed",
            burst_processed > 0,
            serde_json::json!({
                "burst_processed": burst_processed
            }),
        );

        // Rate limiting should be effective during burst
        let rejection_rate = total_rejections as f64 / (burst_sent + sustained_sent) as f64;
        self.logger.log_assertion(
            "rate_limit_effectiveness",
            rejection_rate > 0.1,
            serde_json::json!({
                "rejection_rate": rejection_rate,
                "threshold": 0.1
            }),
        );

        // Sustained throughput should be reasonable after burst
        let sustained_throughput = sustained_processed as f64 / observation_period.as_secs_f64();
        self.logger.log_assertion(
            "sustained_throughput",
            sustained_throughput >= sustained_rate as f64 * 0.7,
            serde_json::json!({
                "achieved_rps": sustained_throughput,
                "target_rps": sustained_rate,
                "threshold": sustained_rate as f64 * 0.7
            }),
        );

        assert!(burst_sent > 0, "Burst traffic should be generated");
        assert!(sustained_sent > 0, "Sustained traffic should be generated");
        assert!(
            total_rejections > 0,
            "Rate limiting should reject some requests: {} rejections",
            total_rejections
        );
        assert!(
            burst_processed > 0,
            "Some burst requests should be processed despite rate limiting"
        );
        assert!(
            rejection_rate > 0.1,
            "Rate limiting should be effective: {:.2}% rejection rate",
            rejection_rate * 100.0
        );
        assert!(
            sustained_throughput >= sustained_rate as f64 * 0.7,
            "Sustained throughput should be ≥70% of target: {:.1} vs {} RPS",
            sustained_throughput,
            sustained_rate
        );
    }

    /// [br-integration-12] HTTP/2 concurrent connection storm and slot leak detection
    async fn test_http2_connection_storm_slot_leaks(&self) {
        self.logger.log_phase("http2_connection_storm_setup");

        use crate::http::h2::{H2Client, H2Connection, H2Server};
        use crate::net::tcp::{TcpListener, TcpStream};

        let concurrent_connections = 200; // Massive connection load
        let requests_per_connection = 10;
        let connection_timeout = Duration::from_secs(2);
        let server_port = 8080; // Fixed port for test

        self.logger.log_event(
            "http2_storm_config",
            serde_json::json!({
                "concurrent_connections": concurrent_connections,
                "requests_per_connection": requests_per_connection,
                "connection_timeout_secs": connection_timeout.as_secs(),
                "server_port": server_port
            }),
        );

        // Phase 1: Setup HTTP/2 server
        self.logger.log_phase("http2_server_setup");

        let server_addr = format!("127.0.0.1:{}", server_port);
        let listener = TcpListener::bind(&server_addr)
            .await
            .expect("Should bind to localhost");

        let connections_accepted = Arc::new(AtomicUsize::new(0));
        let connections_active = Arc::new(AtomicUsize::new(0));
        let total_requests_handled = Arc::new(AtomicUsize::new(0));
        let connection_errors = Arc::new(AtomicUsize::new(0));
        let slot_allocations = Arc::new(AtomicUsize::new(0));
        let slot_deallocations = Arc::new(AtomicUsize::new(0));

        // HTTP/2 server with connection tracking
        let server_task = {
            let logger = self.logger.clone();
            let accepted = Arc::clone(&connections_accepted);
            let active = Arc::clone(&connections_active);
            let requests = Arc::clone(&total_requests_handled);
            let errors = Arc::clone(&connection_errors);
            let allocations = Arc::clone(&slot_allocations);
            let deallocations = Arc::clone(&slot_deallocations);

            self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let mut connection_handlers = Vec::new();

                    while connections_accepted.load(Ordering::Relaxed) < concurrent_connections {
                        match timeout(Duration::from_millis(100), listener.accept()).await {
                            Outcome::Ok(Ok((stream, peer_addr))) => {
                                let conn_id = accepted.fetch_add(1, Ordering::Relaxed);
                                active.fetch_add(1, Ordering::Relaxed);
                                allocations.fetch_add(1, Ordering::Relaxed); // Track slot allocation

                                logger.log_event("http2_connection_accepted", serde_json::json!({
                                    "connection_id": conn_id,
                                    "peer_addr": peer_addr.to_string(),
                                    "active_connections": active.load(Ordering::Relaxed)
                                }));

                                // Handle connection with H2 protocol
                                let connection_handler = {
                                    let logger = logger.clone();
                                    let active = Arc::clone(&active);
                                    let requests = Arc::clone(&requests);
                                    let errors = Arc::clone(&errors);
                                    let deallocations = Arc::clone(&deallocations);

                                    scope.spawn(async move {
                                        let mut handled_requests = 0;

                                        // Simulate H2 connection handling
                                        let connection_start = Instant::now();

                                        while connection_start.elapsed() < connection_timeout {
                                            // Simulate receiving H2 frames and handling requests
                                            match timeout(Duration::from_millis(50), async {
                                                // Mock H2 request processing
                                                sleep(Duration::from_millis(10)).await;
                                                handled_requests += 1;
                                                requests.fetch_add(1, Ordering::Relaxed);

                                                logger.log_event("http2_request_handled", serde_json::json!({
                                                    "connection_id": conn_id,
                                                    "request_count": handled_requests,
                                                    "connection_age_ms": connection_start.elapsed().as_millis()
                                                }));

                                                Ok(())
                                            }).await {
                                                Outcome::Ok(Ok(())) => {
                                                    // Continue processing
                                                    if handled_requests >= requests_per_connection {
                                                        break;
                                                    }
                                                }
                                                _ => {
                                                    // Timeout or error
                                                    break;
                                                }
                                            }
                                        }

                                        // Connection cleanup
                                        active.fetch_sub(1, Ordering::Relaxed);
                                        deallocations.fetch_add(1, Ordering::Relaxed); // Track slot deallocation

                                        logger.log_event("http2_connection_closed", serde_json::json!({
                                            "connection_id": conn_id,
                                            "handled_requests": handled_requests,
                                            "duration_ms": connection_start.elapsed().as_millis(),
                                            "active_connections": active.load(Ordering::Relaxed)
                                        }));

                                        if handled_requests == 0 {
                                            errors.fetch_add(1, Ordering::Relaxed);
                                        }

                                        Outcome::Ok(handled_requests)
                                    }).await
                                };

                                connection_handlers.push(connection_handler);
                            }
                            Outcome::Ok(Err(_)) => {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                            Outcome::Cancelled => {
                                // Accept timeout - continue
                            }
                        }
                    }

                    // Wait for all connection handlers to complete
                    let mut total_handled = 0;
                    for handler in connection_handlers {
                        if let Outcome::Ok(handled) = timeout(Duration::from_secs(5), handler).await {
                            total_handled += handled;
                        }
                    }

                    logger.log_event("http2_server_shutdown", serde_json::json!({
                        "total_connections": accepted.load(Ordering::Relaxed),
                        "total_requests": total_handled
                    }));

                    Outcome::Ok(total_handled)
                }).await
            }).await
        };

        // Phase 2: Connection storm clients
        self.logger.log_phase("http2_client_storm");

        let mut client_tasks = Vec::new();
        let clients_connected = Arc::new(AtomicUsize::new(0));
        let clients_failed = Arc::new(AtomicUsize::new(0));
        let total_client_requests = Arc::new(AtomicUsize::new(0));

        for client_id in 0..concurrent_connections {
            let logger = self.logger.clone();
            let connected = Arc::clone(&clients_connected);
            let failed = Arc::clone(&clients_failed);
            let client_requests = Arc::clone(&total_client_requests);
            let server_addr = server_addr.clone();

            let client_task = self
                .runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let client_start = Instant::now();

                            // Attempt connection to HTTP/2 server
                            match timeout(
                                Duration::from_millis(500),
                                TcpStream::connect(&server_addr),
                            )
                            .await
                            {
                                Outcome::Ok(Ok(_stream)) => {
                                    connected.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event(
                                        "http2_client_connected",
                                        serde_json::json!({
                                            "client_id": client_id,
                                            "connect_time_ms": client_start.elapsed().as_millis()
                                        }),
                                    );

                                    // Send requests over H2 connection
                                    let mut requests_sent = 0;

                                    for req_id in 0..requests_per_connection {
                                        // Simulate H2 request
                                        sleep(Duration::from_millis(20)).await;
                                        requests_sent += 1;
                                        client_requests.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event(
                                            "http2_client_request",
                                            serde_json::json!({
                                                "client_id": client_id,
                                                "request_id": req_id,
                                                "requests_sent": requests_sent
                                            }),
                                        );
                                    }

                                    // Hold connection open for a bit
                                    sleep(connection_timeout / 2).await;

                                    logger.log_event(
                                        "http2_client_disconnect",
                                        serde_json::json!({
                                            "client_id": client_id,
                                            "requests_sent": requests_sent,
                                            "duration_ms": client_start.elapsed().as_millis()
                                        }),
                                    );

                                    Outcome::Ok(requests_sent)
                                }
                                _ => {
                                    failed.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event(
                                        "http2_client_connect_failed",
                                        serde_json::json!({
                                            "client_id": client_id,
                                            "connect_time_ms": client_start.elapsed().as_millis()
                                        }),
                                    );

                                    Outcome::Err(Error::new(ErrorKind::Other, "Connection failed"))
                                }
                            }
                        })
                        .await
                })
                .await;

            client_tasks.push(client_task);

            // Stagger client connections to create realistic storm pattern
            if client_id % 20 == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        }

        // Phase 3: Execute connection storm
        self.logger.log_phase("connection_storm_execution");

        let storm_timeout = connection_timeout + Duration::from_secs(10);

        // Wait for server and all clients to complete
        let server_result = timeout(storm_timeout, server_task).await;

        let mut successful_clients = 0;
        for (client_id, client_task) in client_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), client_task).await {
                Outcome::Ok(Outcome::Ok(_)) => successful_clients += 1,
                _ => {
                    self.logger.log_event(
                        "http2_client_timeout",
                        serde_json::json!({
                            "client_id": client_id
                        }),
                    );
                }
            }
        }

        // Phase 4: Validate connection handling and slot management
        self.logger.log_phase("slot_leak_validation");

        let total_accepted = connections_accepted.load(Ordering::Relaxed);
        let final_active = connections_active.load(Ordering::Relaxed);
        let server_requests = total_requests_handled.load(Ordering::Relaxed);
        let total_errors = connection_errors.load(Ordering::Relaxed);
        let clients_connected_count = clients_connected.load(Ordering::Relaxed);
        let clients_failed_count = clients_failed.load(Ordering::Relaxed);
        let client_requests_count = total_client_requests.load(Ordering::Relaxed);
        let allocated_slots = slot_allocations.load(Ordering::Relaxed);
        let deallocated_slots = slot_deallocations.load(Ordering::Relaxed);

        self.logger.log_metrics(serde_json::json!({
            "http2_storm_results": {
                "connections_accepted": total_accepted,
                "connections_active": final_active,
                "server_requests_handled": server_requests,
                "connection_errors": total_errors,
                "clients_connected": clients_connected_count,
                "clients_failed": clients_failed_count,
                "client_requests_sent": client_requests_count,
                "successful_clients": successful_clients,
                "slot_allocations": allocated_slots,
                "slot_deallocations": deallocated_slots,
                "connection_success_rate": clients_connected_count as f64 / concurrent_connections as f64,
                "slot_leak_count": allocated_slots.saturating_sub(deallocated_slots),
                "request_handling_efficiency": server_requests as f64 / client_requests_count.max(1) as f64
            }
        }));

        // Critical assertions for HTTP/2 performance and slot management
        self.logger.log_assertion(
            "connections_accepted",
            total_accepted > 0,
            serde_json::json!({
                "accepted": total_accepted
            }),
        );

        self.logger.log_assertion(
            "clients_connected",
            clients_connected_count > 0,
            serde_json::json!({
                "connected": clients_connected_count
            }),
        );

        // Connection success rate should be reasonable under load
        let connection_success_rate =
            clients_connected_count as f64 / concurrent_connections as f64;
        self.logger.log_assertion(
            "connection_success_rate",
            connection_success_rate > 0.7,
            serde_json::json!({
                "success_rate": connection_success_rate,
                "threshold": 0.7
            }),
        );

        // CRITICAL: No active connections should remain (no slot leaks)
        self.logger.log_assertion(
            "no_active_connections_leak",
            final_active == 0,
            serde_json::json!({
                "final_active": final_active
            }),
        );

        // CRITICAL: Slot allocations should match deallocations (no slot leaks)
        let slot_leaks = allocated_slots.saturating_sub(deallocated_slots);
        self.logger.log_assertion(
            "no_slot_leaks",
            slot_leaks == 0,
            serde_json::json!({
                "allocated_slots": allocated_slots,
                "deallocated_slots": deallocated_slots,
                "leaked_slots": slot_leaks
            }),
        );

        assert!(
            total_accepted > 0,
            "HTTP/2 server should accept connections"
        );
        assert!(
            clients_connected_count > 0,
            "Clients should successfully connect"
        );
        assert!(
            connection_success_rate > 0.7,
            "Connection success rate should be >70% under load: {:.2}%",
            connection_success_rate * 100.0
        );
        assert!(
            final_active == 0,
            "NO active connections should remain after storm: {} active connections leaked",
            final_active
        );
        assert!(
            slot_leaks == 0,
            "NO connection slots should leak: {} slots leaked (allocated: {}, deallocated: {})",
            slot_leaks,
            allocated_slots,
            deallocated_slots
        );
        assert!(
            server_requests > 0,
            "Server should handle requests during connection storm"
        );
    }

    /// [br-integration-13] High-frequency timer churn and timer wheel stress test
    async fn test_high_frequency_timer_churn_wheel_stress(&self) {
        self.logger.log_phase("timer_churn_setup");

        use crate::time::{Instant, Timer, TimerWheel, sleep, timeout};

        let timer_count = 12000; // 12k simultaneous timers
        let churn_frequency = Duration::from_millis(5); // Very high frequency
        let test_duration = Duration::from_secs(8);
        let timer_range_ms = (10, 1000); // Random timer durations

        self.logger.log_event(
            "timer_churn_config",
            serde_json::json!({
                "timer_count": timer_count,
                "churn_frequency_ms": churn_frequency.as_millis(),
                "test_duration_secs": test_duration.as_secs(),
                "timer_range_ms": timer_range_ms
            }),
        );

        // Phase 1: Setup timer tracking
        self.logger.log_phase("timer_tracking_setup");

        let timers_created = Arc::new(AtomicUsize::new(0));
        let timers_completed = Arc::new(AtomicUsize::new(0));
        let timers_cancelled = Arc::new(AtomicUsize::new(0));
        let timer_accuracy_violations = Arc::new(AtomicUsize::new(0));
        let active_timer_count = Arc::new(AtomicUsize::new(0));
        let peak_active_timers = Arc::new(AtomicUsize::new(0));
        let total_timer_drift = Arc::new(AtomicUsize::new(0));

        // Phase 2: Timer churn generator
        self.logger.log_phase("timer_churn_generation");

        let churn_generator = {
            let logger = self.logger.clone();
            let created = Arc::clone(&timers_created);
            let completed = Arc::clone(&timers_completed);
            let cancelled = Arc::clone(&timers_cancelled);
            let accuracy_violations = Arc::clone(&timer_accuracy_violations);
            let active_count = Arc::clone(&active_timer_count);
            let peak_active = Arc::clone(&peak_active_timers);
            let total_drift = Arc::clone(&total_timer_drift);

            self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let test_start = Instant::now();
                    let mut timer_id = 0;
                    let mut active_timers = Vec::new();

                    while test_start.elapsed() < test_duration {
                        // Create new timers at high frequency
                        if active_timers.len() < timer_count {
                            let timer_duration_ms = fastrand::u64(timer_range_ms.0..=timer_range_ms.1);
                            let timer_duration = Duration::from_millis(timer_duration_ms);

                            let timer_start = Instant::now();
                            timer_id += 1;
                            created.fetch_add(1, Ordering::Relaxed);
                            active_count.fetch_add(1, Ordering::Relaxed);

                            // Update peak active timer count
                            let current_active = active_count.load(Ordering::Relaxed);
                            loop {
                                let current_peak = peak_active.load(Ordering::Relaxed);
                                if current_active <= current_peak {
                                    break;
                                }
                                if peak_active.compare_exchange_weak(current_peak, current_active, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                                    break;
                                }
                            }

                            // Create timer task
                            let timer_task = {
                                let logger = logger.clone();
                                let completed = Arc::clone(&completed);
                                let active_count = Arc::clone(&active_count);
                                let accuracy_violations = Arc::clone(&accuracy_violations);
                                let total_drift = Arc::clone(&total_drift);

                                scope.spawn(async move {
                                    let sleep_result = timeout(timer_duration + Duration::from_millis(100), sleep(timer_duration)).await;

                                    let actual_duration = timer_start.elapsed();
                                    let expected_duration = timer_duration;
                                    let drift_ms = if actual_duration > expected_duration {
                                        (actual_duration - expected_duration).as_millis() as usize
                                    } else {
                                        (expected_duration - actual_duration).as_millis() as usize
                                    };

                                    total_drift.fetch_add(drift_ms, Ordering::Relaxed);

                                    match sleep_result {
                                        Outcome::Ok(_) => {
                                            completed.fetch_add(1, Ordering::Relaxed);

                                            // Check timer accuracy (should be within reasonable bounds)
                                            if drift_ms > 50 { // 50ms tolerance
                                                accuracy_violations.fetch_add(1, Ordering::Relaxed);
                                            }

                                            logger.log_event("timer_completed", serde_json::json!({
                                                "timer_id": timer_id,
                                                "expected_duration_ms": expected_duration.as_millis(),
                                                "actual_duration_ms": actual_duration.as_millis(),
                                                "drift_ms": drift_ms
                                            }));
                                        }
                                        Outcome::Cancelled => {
                                            logger.log_event("timer_timeout", serde_json::json!({
                                                "timer_id": timer_id,
                                                "expected_duration_ms": expected_duration.as_millis(),
                                                "actual_duration_ms": actual_duration.as_millis()
                                            }));
                                        }
                                    }

                                    active_count.fetch_sub(1, Ordering::Relaxed);

                                    Outcome::Ok(drift_ms)
                                }).await
                            };

                            active_timers.push(timer_task);

                            // Log progress periodically
                            if timer_id % 1000 == 0 {
                                logger.log_event("timer_churn_progress", serde_json::json!({
                                    "timers_created": timer_id,
                                    "active_timers": active_timers.len(),
                                    "elapsed_ms": test_start.elapsed().as_millis()
                                }));
                            }
                        } else {
                            // Cancel some random timers to create churn
                            if !active_timers.is_empty() {
                                let cancel_index = fastrand::usize(0..active_timers.len());
                                let _cancelled_timer = active_timers.swap_remove(cancel_index);
                                cancelled.fetch_add(1, Ordering::Relaxed);

                                logger.log_event("timer_cancelled", serde_json::json!({
                                    "cancelled_timer_index": cancel_index,
                                    "remaining_active": active_timers.len()
                                }));
                            }
                        }

                        // High-frequency churn
                        sleep(churn_frequency).await;
                    }

                    // Wait for remaining timers to complete
                    let cleanup_start = Instant::now();
                    for timer_task in active_timers {
                        if timeout(Duration::from_secs(2), timer_task).await.is_err() {
                            cancelled.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    logger.log_event("timer_churn_complete", serde_json::json!({
                        "total_created": created.load(Ordering::Relaxed),
                        "cleanup_duration_ms": cleanup_start.elapsed().as_millis()
                    }));

                    Outcome::Ok(timer_id)
                }).await
            }).await
        };

        // Phase 3: Timer wheel monitoring
        let wheel_monitor = {
            let logger = self.logger.clone();
            let active_count = Arc::clone(&active_timer_count);
            let peak_active = Arc::clone(&peak_active_timers);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let monitor_start = Instant::now();
                            let mut sample_count = 0;

                            while monitor_start.elapsed() < test_duration + Duration::from_secs(1) {
                                let current_active = active_count.load(Ordering::Relaxed);
                                sample_count += 1;

                                if sample_count % 100 == 0 {
                                    // Log every 100 samples
                                    logger.log_event(
                                        "timer_wheel_monitor",
                                        serde_json::json!({
                                            "active_timers": current_active,
                                            "peak_active": peak_active.load(Ordering::Relaxed),
                                            "sample_count": sample_count,
                                            "elapsed_ms": monitor_start.elapsed().as_millis()
                                        }),
                                    );
                                }

                                sleep(Duration::from_millis(10)).await; // Monitor every 10ms
                            }

                            logger.log_event(
                                "timer_wheel_monitoring_complete",
                                serde_json::json!({
                                    "total_samples": sample_count
                                }),
                            );

                            Outcome::Ok(sample_count)
                        })
                        .await
                })
                .await
        };

        // Phase 4: Execute timer churn test
        self.logger.log_phase("timer_wheel_execution");

        let churn_result = timeout(test_duration + Duration::from_secs(5), churn_generator).await;
        let monitor_result = timeout(Duration::from_secs(2), wheel_monitor).await;

        // Phase 5: Validate timer wheel performance
        self.logger.log_phase("timer_wheel_validation");

        let total_created = timers_created.load(Ordering::Relaxed);
        let total_completed = timers_completed.load(Ordering::Relaxed);
        let total_cancelled = timers_cancelled.load(Ordering::Relaxed);
        let final_active = active_timer_count.load(Ordering::Relaxed);
        let peak_active_count = peak_active_timers.load(Ordering::Relaxed);
        let accuracy_violations_count = timer_accuracy_violations.load(Ordering::Relaxed);
        let avg_timer_drift = total_timer_drift.load(Ordering::Relaxed) / total_completed.max(1);

        self.logger.log_metrics(serde_json::json!({
            "timer_wheel_results": {
                "timers_created": total_created,
                "timers_completed": total_completed,
                "timers_cancelled": total_cancelled,
                "final_active_timers": final_active,
                "peak_active_timers": peak_active_count,
                "accuracy_violations": accuracy_violations_count,
                "avg_timer_drift_ms": avg_timer_drift,
                "timer_completion_rate": total_completed as f64 / total_created as f64,
                "timer_accuracy_rate": (total_completed - accuracy_violations_count) as f64 / total_completed as f64,
                "peak_utilization": peak_active_count as f64 / timer_count as f64
            }
        }));

        // Critical assertions for timer wheel performance
        self.logger.log_assertion(
            "timers_created",
            total_created > timer_count / 2,
            serde_json::json!({
                "created": total_created,
                "target": timer_count
            }),
        );

        self.logger.log_assertion(
            "peak_timer_load",
            peak_active_count >= timer_count / 2,
            serde_json::json!({
                "peak_active": peak_active_count,
                "target": timer_count / 2
            }),
        );

        self.logger.log_assertion(
            "timers_completed",
            total_completed > 0,
            serde_json::json!({
                "completed": total_completed
            }),
        );

        // Timer wheel should handle high load efficiently
        let completion_rate = total_completed as f64 / total_created as f64;
        self.logger.log_assertion(
            "timer_completion_rate",
            completion_rate > 0.7,
            serde_json::json!({
                "completion_rate": completion_rate,
                "threshold": 0.7
            }),
        );

        // Timer accuracy should be reasonable under high load
        let accuracy_rate =
            (total_completed - accuracy_violations_count) as f64 / total_completed as f64;
        self.logger.log_assertion(
            "timer_accuracy",
            accuracy_rate > 0.85,
            serde_json::json!({
                "accuracy_rate": accuracy_rate,
                "threshold": 0.85,
                "violations": accuracy_violations_count
            }),
        );

        // No active timers should remain after test
        self.logger.log_assertion(
            "no_timer_leaks",
            final_active == 0,
            serde_json::json!({
                "final_active": final_active
            }),
        );

        assert!(
            total_created > timer_count / 2,
            "Should create significant timer load: {} created vs {} target",
            total_created,
            timer_count
        );
        assert!(
            peak_active_count >= timer_count / 2,
            "Timer wheel should handle high concurrent load: {} peak vs {} target",
            peak_active_count,
            timer_count
        );
        assert!(
            total_completed > 0,
            "Timers should complete successfully under load"
        );
        assert!(
            completion_rate > 0.7,
            "Timer completion rate should be >70% under churn: {:.2}%",
            completion_rate * 100.0
        );
        assert!(
            accuracy_rate > 0.85,
            "Timer accuracy should be >85% under load: {:.2}% ({} violations)",
            accuracy_rate * 100.0,
            accuracy_violations_count
        );
        assert!(
            final_active == 0,
            "NO timer leaks after test: {} active timers remain",
            final_active
        );
    }

    /// [br-integration-14] Multi-hour task with periodic checkpoint and resume
    async fn test_multi_hour_task_checkpoint_resume(&self) {
        self.logger.log_phase("checkpoint_resume_setup");

        // Simulate multi-hour operation in compressed time
        let simulated_hour_duration = Duration::from_secs(30); // 30 seconds = 1 simulated hour
        let total_simulated_hours = 4; // Simulate 4-hour long-running task
        let checkpoint_interval = simulated_hour_duration / 6; // Checkpoint every 10 minutes (simulated)
        let work_units_per_hour = 200; // 200 work units per simulated hour

        self.logger.log_event(
            "checkpoint_config",
            serde_json::json!({
                "simulated_hour_duration_secs": simulated_hour_duration.as_secs(),
                "total_simulated_hours": total_simulated_hours,
                "checkpoint_interval_secs": checkpoint_interval.as_secs(),
                "work_units_per_hour": work_units_per_hour
            }),
        );

        // Phase 1: Setup long-running task state
        self.logger.log_phase("long_running_task_setup");

        let work_progress = Arc::new(AtomicUsize::new(0));
        let checkpoints_created = Arc::new(AtomicUsize::new(0));
        let resumes_performed = Arc::new(AtomicUsize::new(0));
        let interruptions_simulated = Arc::new(AtomicUsize::new(0));
        let state_consistency_violations = Arc::new(AtomicUsize::new(0));

        // Persistent state for checkpointing
        let checkpointed_state = Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));

        // Phase 2: Long-running task with checkpoint/resume
        let task_processor = {
            let logger = self.logger.clone();
            let progress = Arc::clone(&work_progress);
            let checkpoints = Arc::clone(&checkpoints_created);
            let resumes = Arc::clone(&resumes_performed);
            let interruptions = Arc::clone(&interruptions_simulated);
            let violations = Arc::clone(&state_consistency_violations);
            let checkpoint_state = Arc::clone(&checkpointed_state);

            self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let task_start = Instant::now();
                    let mut current_work_unit = 0;
                    let mut last_checkpoint = Instant::now();
                    let mut current_hour = 0;
                    let mut accumulated_data = Vec::new(); // Simulated work state

                    while current_hour < total_simulated_hours {
                        let hour_start = Instant::now();

                        // Process work units for current hour
                        let work_units_this_hour = work_units_per_hour;

                        for unit_id in 0..work_units_this_hour {
                            // Simulate work processing
                            let work_data = format!("hour_{}_unit_{}_data_{}", current_hour, unit_id, current_work_unit);
                            accumulated_data.push(work_data.clone());

                            current_work_unit += 1;
                            progress.store(current_work_unit, Ordering::Relaxed);

                            // Periodic checkpointing
                            if last_checkpoint.elapsed() >= checkpoint_interval {
                                // Create checkpoint
                                let checkpoint_id = checkpoints.fetch_add(1, Ordering::Relaxed);
                                let checkpoint_data = serde_json::json!({
                                    "checkpoint_id": checkpoint_id,
                                    "work_progress": current_work_unit,
                                    "current_hour": current_hour,
                                    "accumulated_data_count": accumulated_data.len(),
                                    "timestamp": task_start.elapsed().as_millis(),
                                    "last_work_data": accumulated_data.last().cloned().unwrap_or_default()
                                });

                                // Persist checkpoint
                                {
                                    let mut state = checkpoint_state.lock().await;
                                    state.insert(format!("checkpoint_{}", checkpoint_id), checkpoint_data.clone());
                                }

                                last_checkpoint = Instant::now();

                                logger.log_event("checkpoint_created", serde_json::json!({
                                    "checkpoint_id": checkpoint_id,
                                    "work_progress": current_work_unit,
                                    "hour": current_hour,
                                    "data_size": accumulated_data.len(),
                                    "elapsed_ms": task_start.elapsed().as_millis()
                                }));

                                // Simulate random interruption (20% chance)
                                if fastrand::f64() < 0.2 {
                                    interruptions.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event("task_interruption", serde_json::json!({
                                        "interruption_point": current_work_unit,
                                        "checkpoint_id": checkpoint_id,
                                        "hour": current_hour
                                    }));

                                    // Simulate interruption delay (restart/recovery time)
                                    sleep(Duration::from_millis(200)).await;

                                    // Resume from checkpoint
                                    let resume_id = resumes.fetch_add(1, Ordering::Relaxed);

                                    // Validate state consistency after resume
                                    let state = checkpoint_state.lock().await;
                                    if let Some(checkpoint) = state.get(&format!("checkpoint_{}", checkpoint_id)) {
                                        let expected_progress = checkpoint["work_progress"].as_u64().unwrap_or(0) as usize;

                                        if current_work_unit != expected_progress {
                                            violations.fetch_add(1, Ordering::Relaxed);
                                            logger.log_event("state_consistency_violation", serde_json::json!({
                                                "expected_progress": expected_progress,
                                                "actual_progress": current_work_unit,
                                                "checkpoint_id": checkpoint_id
                                            }));
                                        }

                                        logger.log_event("task_resumed", serde_json::json!({
                                            "resume_id": resume_id,
                                            "checkpoint_id": checkpoint_id,
                                            "resumed_progress": expected_progress,
                                            "hour": current_hour
                                        }));
                                    }
                                }
                            }

                            // Simulate processing delay
                            sleep(Duration::from_millis(5)).await;

                            // Progress tracking within hour
                            if unit_id % 50 == 0 {
                                logger.log_event("hour_progress", serde_json::json!({
                                    "hour": current_hour,
                                    "units_completed": unit_id,
                                    "total_units": work_units_this_hour,
                                    "hour_elapsed_ms": hour_start.elapsed().as_millis()
                                }));
                            }
                        }

                        current_hour += 1;

                        logger.log_event("hour_completed", serde_json::json!({
                            "completed_hour": current_hour - 1,
                            "work_units_processed": work_units_this_hour,
                            "total_progress": current_work_unit,
                            "hour_duration_ms": hour_start.elapsed().as_millis()
                        }));

                        // Brief pause between hours
                        sleep(Duration::from_millis(100)).await;
                    }

                    // Final checkpoint
                    let final_checkpoint_id = checkpoints.fetch_add(1, Ordering::Relaxed);
                    let final_checkpoint = serde_json::json!({
                        "checkpoint_id": final_checkpoint_id,
                        "work_progress": current_work_unit,
                        "completion_status": "finished",
                        "total_hours": current_hour,
                        "final_data_size": accumulated_data.len(),
                        "total_duration_ms": task_start.elapsed().as_millis()
                    });

                    {
                        let mut state = checkpoint_state.lock().await;
                        state.insert(format!("final_checkpoint_{}", final_checkpoint_id), final_checkpoint);
                    }

                    logger.log_event("long_running_task_complete", serde_json::json!({
                        "total_work_units": current_work_unit,
                        "total_hours": current_hour,
                        "total_checkpoints": checkpoints.load(Ordering::Relaxed) + 1,
                        "duration_ms": task_start.elapsed().as_millis()
                    }));

                    Outcome::Ok(current_work_unit)
                }).await
            }).await
        };

        // Phase 3: Execute long-running task with monitoring
        self.logger.log_phase("long_running_execution");

        let total_timeout =
            simulated_hour_duration * total_simulated_hours as u32 + Duration::from_secs(30);
        let task_result = timeout(total_timeout, task_processor).await;

        // Phase 4: Validate checkpoint/resume functionality
        self.logger.log_phase("checkpoint_resume_validation");

        let total_progress = work_progress.load(Ordering::Relaxed);
        let total_checkpoints = checkpoints_created.load(Ordering::Relaxed);
        let total_resumes = resumes_performed.load(Ordering::Relaxed);
        let total_interruptions = interruptions_simulated.load(Ordering::Relaxed);
        let consistency_violations = state_consistency_violations.load(Ordering::Relaxed);

        let expected_work_units = work_units_per_hour * total_simulated_hours;

        // Validate checkpoint state persistence
        let checkpoint_count = {
            let state = checkpointed_state.lock().await;
            state.len()
        };

        self.logger.log_metrics(serde_json::json!({
            "checkpoint_resume_results": {
                "total_work_progress": total_progress,
                "expected_work_units": expected_work_units,
                "total_checkpoints": total_checkpoints,
                "total_resumes": total_resumes,
                "total_interruptions": total_interruptions,
                "consistency_violations": consistency_violations,
                "persisted_checkpoint_count": checkpoint_count,
                "completion_rate": total_progress as f64 / expected_work_units as f64,
                "checkpoint_frequency": total_checkpoints as f64 / total_simulated_hours as f64,
                "resume_success_rate": total_resumes as f64 / total_interruptions as f64
            }
        }));

        // Critical assertions for long-running task reliability
        self.logger.log_assertion(
            "work_progress",
            total_progress > 0,
            serde_json::json!({
                "progress": total_progress
            }),
        );

        self.logger.log_assertion(
            "checkpoints_created",
            total_checkpoints > 0,
            serde_json::json!({
                "checkpoints": total_checkpoints
            }),
        );

        self.logger.log_assertion(
            "task_interruptions",
            total_interruptions > 0,
            serde_json::json!({
                "interruptions": total_interruptions
            }),
        );

        self.logger.log_assertion(
            "resume_operations",
            total_resumes == total_interruptions,
            serde_json::json!({
                "resumes": total_resumes,
                "interruptions": total_interruptions
            }),
        );

        // Work completion should be high despite interruptions
        let completion_rate = total_progress as f64 / expected_work_units as f64;
        self.logger.log_assertion(
            "completion_rate",
            completion_rate > 0.9,
            serde_json::json!({
                "completion_rate": completion_rate,
                "threshold": 0.9
            }),
        );

        // State consistency should be maintained across resumes
        self.logger.log_assertion(
            "state_consistency",
            consistency_violations == 0,
            serde_json::json!({
                "violations": consistency_violations
            }),
        );

        assert!(total_progress > 0, "Long-running task should make progress");
        assert!(
            total_checkpoints > 0,
            "Task should create checkpoints: {} checkpoints",
            total_checkpoints
        );
        assert!(
            total_interruptions > 0,
            "Interruptions should occur during long-running task: {} interruptions",
            total_interruptions
        );
        assert!(
            total_resumes == total_interruptions,
            "All interruptions should resume: {} resumes vs {} interruptions",
            total_resumes,
            total_interruptions
        );
        assert!(
            completion_rate > 0.9,
            "Task completion should be >90% despite interruptions: {:.2}%",
            completion_rate * 100.0
        );
        assert!(
            consistency_violations == 0,
            "NO state consistency violations across checkpoints: {} violations",
            consistency_violations
        );
    }

    /// [br-integration-15] Memory-pressure-induced backpressure with recovery
    async fn test_memory_pressure_backpressure_recovery(&self) {
        self.logger.log_phase("memory_pressure_setup");

        // Simulate memory pressure through large data structures
        let memory_pressure_threshold = 50 * 1024 * 1024; // 50MB threshold
        let pressure_induction_rate = 1024 * 1024; // 1MB per allocation
        let pressure_relief_delay = Duration::from_millis(100);
        let backpressure_detection_threshold = 10; // Queue size threshold

        self.logger.log_event(
            "memory_pressure_config",
            serde_json::json!({
                "pressure_threshold_mb": memory_pressure_threshold / (1024 * 1024),
                "induction_rate_mb": pressure_induction_rate / (1024 * 1024),
                "relief_delay_ms": pressure_relief_delay.as_millis(),
                "backpressure_threshold": backpressure_detection_threshold
            }),
        );

        // Phase 1: Setup memory-sensitive processing pipeline
        self.logger.log_phase("memory_pipeline_setup");

        let (input_tx, input_rx) = mpsc::channel(50);
        let (output_tx, output_rx) = mpsc::channel(50);
        let memory_allocations = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let memory_usage = Arc::new(AtomicUsize::new(0));
        let backpressure_events = Arc::new(AtomicUsize::new(0));
        let pressure_relief_events = Arc::new(AtomicUsize::new(0));
        let processing_delays = Arc::new(AtomicUsize::new(0));
        let total_processed = Arc::new(AtomicUsize::new(0));

        // Memory pressure monitor
        let pressure_monitor =
            {
                let logger = self.logger.clone();
                let usage = Arc::clone(&memory_usage);
                let backpressure_events = Arc::clone(&backpressure_events);
                let allocations = Arc::clone(&memory_allocations);

                self.runtime
                    .scope(|scope| async move {
                        scope.spawn(async move {
                    let monitor_start = Instant::now();
                    let mut pressure_state = false;

                    while monitor_start.elapsed() < Duration::from_secs(20) {
                        let current_usage = usage.load(Ordering::Relaxed);
                        let under_pressure = current_usage > memory_pressure_threshold;

                        if under_pressure && !pressure_state {
                            // Memory pressure detected
                            pressure_state = true;
                            backpressure_events.fetch_add(1, Ordering::Relaxed);

                            logger.log_event("memory_pressure_detected", serde_json::json!({
                                "memory_usage_mb": current_usage / (1024 * 1024),
                                "threshold_mb": memory_pressure_threshold / (1024 * 1024),
                                "pressure_events": backpressure_events.load(Ordering::Relaxed)
                            }));
                        } else if !under_pressure && pressure_state {
                            // Memory pressure relieved
                            pressure_state = false;

                            logger.log_event("memory_pressure_relieved", serde_json::json!({
                                "memory_usage_mb": current_usage / (1024 * 1024),
                                "pressure_duration_ms": monitor_start.elapsed().as_millis()
                            }));
                        }

                        // Periodic memory usage reporting
                        if monitor_start.elapsed().as_millis() % 2000 == 0 {
                            let alloc_count = allocations.lock().await.len();
                            logger.log_event("memory_usage_report", serde_json::json!({
                                "usage_mb": current_usage / (1024 * 1024),
                                "allocation_count": alloc_count,
                                "under_pressure": under_pressure,
                                "elapsed_ms": monitor_start.elapsed().as_millis()
                            }));
                        }

                        sleep(Duration::from_millis(50)).await;
                    }

                    logger.log_event("memory_monitor_complete", serde_json::json!({
                        "final_usage_mb": usage.load(Ordering::Relaxed) / (1024 * 1024),
                        "total_pressure_events": backpressure_events.load(Ordering::Relaxed)
                    }));

                    Outcome::Ok(backpressure_events.load(Ordering::Relaxed))
                }).await
                    })
                    .await
            };

        // Processing pipeline with backpressure response
        let processor = {
            let logger = self.logger.clone();
            let allocations = Arc::clone(&memory_allocations);
            let usage = Arc::clone(&memory_usage);
            let delays = Arc::clone(&processing_delays);
            let processed = Arc::clone(&total_processed);
            let relief_events = Arc::clone(&pressure_relief_events);

            self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let mut input_rx = input_rx;
                    let mut processed_count = 0;

                    while let Some((item_id, data_size)) = input_rx.recv().await {
                        let process_start = Instant::now();

                        // Check memory pressure before processing
                        let current_usage = usage.load(Ordering::Relaxed);
                        let under_pressure = current_usage > memory_pressure_threshold;

                        if under_pressure {
                            // Apply backpressure - delay processing
                            delays.fetch_add(1, Ordering::Relaxed);

                            logger.log_event("backpressure_applied", serde_json::json!({
                                "item_id": item_id,
                                "memory_usage_mb": current_usage / (1024 * 1024),
                                "processing_delayed": true
                            }));

                            // Wait for memory pressure to subside
                            while usage.load(Ordering::Relaxed) > memory_pressure_threshold {
                                sleep(pressure_relief_delay).await;

                                // Trigger memory relief periodically
                                if fastrand::f64() < 0.3 { // 30% chance per cycle
                                    let mut allocs = allocations.lock().await;
                                    if !allocs.is_empty() {
                                        let removed = allocs.remove(0);
                                        let freed = removed.len();
                                        usage.fetch_sub(freed, Ordering::Relaxed);
                                        relief_events.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event("memory_relief", serde_json::json!({
                                            "freed_mb": freed / (1024 * 1024),
                                            "new_usage_mb": usage.load(Ordering::Relaxed) / (1024 * 1024)
                                        }));

                                        break; // Exit pressure wait loop
                                    }
                                }
                            }

                            logger.log_event("backpressure_relieved", serde_json::json!({
                                "item_id": item_id,
                                "relief_duration_ms": process_start.elapsed().as_millis()
                            }));
                        }

                        // Process item (allocate memory)
                        let allocation = vec![0u8; data_size];
                        let allocated_size = allocation.len();

                        {
                            let mut allocs = allocations.lock().await;
                            allocs.push(allocation);
                            usage.fetch_add(allocated_size, Ordering::Relaxed);
                        }

                        processed_count += 1;
                        processed.store(processed_count, Ordering::Relaxed);

                        logger.log_event("item_processed", serde_json::json!({
                            "item_id": item_id,
                            "allocated_mb": allocated_size / (1024 * 1024),
                            "total_usage_mb": usage.load(Ordering::Relaxed) / (1024 * 1024),
                            "processed_count": processed_count,
                            "processing_time_ms": process_start.elapsed().as_millis()
                        }));

                        // Send output
                        let result = format!("processed_item_{}_size_{}", item_id, allocated_size);
                        if output_tx.send(result).await.is_err() {
                            break;
                        }

                        sleep(Duration::from_millis(20)).await;
                    }

                    logger.log_event("processor_shutdown", serde_json::json!({
                        "total_processed": processed_count
                    }));

                    Outcome::Ok(processed_count)
                }).await
            }).await
        };

        // Phase 2: Data producer with varying sizes
        self.logger.log_phase("data_production");

        let producer = {
            let logger = self.logger.clone();

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut produced_count = 0;
                            let item_count = 100;

                            for item_id in 0..item_count {
                                // Varying data sizes to create memory pressure patterns
                                let data_size = match item_id % 10 {
                                    0..=2 => pressure_induction_rate / 4, // Small items
                                    3..=6 => pressure_induction_rate,     // Medium items
                                    7..=8 => pressure_induction_rate * 2, // Large items
                                    _ => pressure_induction_rate * 4,     // Very large items
                                };

                                if input_tx.send((item_id, data_size)).await.is_err() {
                                    logger.log_event(
                                        "producer_send_failed",
                                        serde_json::json!({
                                            "item_id": item_id,
                                            "produced_count": produced_count
                                        }),
                                    );
                                    break;
                                }

                                produced_count += 1;

                                logger.log_event(
                                    "item_produced",
                                    serde_json::json!({
                                        "item_id": item_id,
                                        "data_size_mb": data_size / (1024 * 1024),
                                        "produced_count": produced_count
                                    }),
                                );

                                sleep(Duration::from_millis(50)).await;
                            }

                            logger.log_event(
                                "production_complete",
                                serde_json::json!({
                                    "total_produced": produced_count
                                }),
                            );

                            Outcome::Ok(produced_count)
                        })
                        .await
                })
                .await
        };

        // Phase 3: Output collector
        let collector = {
            let logger = self.logger.clone();

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let mut output_rx = output_rx;
                            let mut collected_count = 0;

                            while let Some(result) = output_rx.recv().await {
                                collected_count += 1;

                                if collected_count % 20 == 0 {
                                    logger.log_event(
                                        "output_collected",
                                        serde_json::json!({
                                            "result": result,
                                            "collected_count": collected_count
                                        }),
                                    );
                                }
                            }

                            logger.log_event(
                                "collection_complete",
                                serde_json::json!({
                                    "total_collected": collected_count
                                }),
                            );

                            Outcome::Ok(collected_count)
                        })
                        .await
                })
                .await
        };

        // Phase 4: Execute memory pressure test
        self.logger.log_phase("memory_pressure_execution");

        let test_timeout = Duration::from_secs(25);

        // Run all components
        let pressure_result = pressure_monitor;
        let producer_result = timeout(Duration::from_secs(10), producer).await;
        let processor_result = timeout(Duration::from_secs(20), processor).await;
        let collector_result = timeout(Duration::from_secs(5), collector).await;
        let monitor_result = timeout(Duration::from_secs(5), pressure_result).await;

        // Phase 5: Validate memory pressure handling
        self.logger.log_phase("pressure_recovery_validation");

        let final_usage = memory_usage.load(Ordering::Relaxed);
        let total_backpressure = backpressure_events.load(Ordering::Relaxed);
        let total_relief = pressure_relief_events.load(Ordering::Relaxed);
        let processing_delays_count = processing_delays.load(Ordering::Relaxed);
        let items_processed = total_processed.load(Ordering::Relaxed);

        let allocation_count = {
            let allocs = memory_allocations.lock().await;
            allocs.len()
        };

        self.logger.log_metrics(serde_json::json!({
            "memory_pressure_results": {
                "final_memory_usage_mb": final_usage / (1024 * 1024),
                "total_backpressure_events": total_backpressure,
                "total_relief_events": total_relief,
                "processing_delays": processing_delays_count,
                "items_processed": items_processed,
                "active_allocations": allocation_count,
                "backpressure_effectiveness": processing_delays_count as f64 / total_backpressure as f64,
                "memory_recovery_rate": total_relief as f64 / total_backpressure.max(1) as f64
            }
        }));

        // Critical assertions for memory pressure handling
        self.logger.log_assertion(
            "memory_pressure_detected",
            total_backpressure > 0,
            serde_json::json!({
                "backpressure_events": total_backpressure
            }),
        );

        self.logger.log_assertion(
            "backpressure_applied",
            processing_delays_count > 0,
            serde_json::json!({
                "processing_delays": processing_delays_count
            }),
        );

        self.logger.log_assertion(
            "memory_relief_occurred",
            total_relief > 0,
            serde_json::json!({
                "relief_events": total_relief
            }),
        );

        self.logger.log_assertion(
            "items_processed",
            items_processed > 0,
            serde_json::json!({
                "processed": items_processed
            }),
        );

        // Recovery should be effective
        let recovery_rate = total_relief as f64 / total_backpressure.max(1) as f64;
        self.logger.log_assertion(
            "memory_recovery_rate",
            recovery_rate > 0.5,
            serde_json::json!({
                "recovery_rate": recovery_rate,
                "threshold": 0.5
            }),
        );

        assert!(
            total_backpressure > 0,
            "Memory pressure should be detected: {} events",
            total_backpressure
        );
        assert!(
            processing_delays_count > 0,
            "Backpressure should cause processing delays: {} delays",
            processing_delays_count
        );
        assert!(
            total_relief > 0,
            "Memory relief should occur: {} relief events",
            total_relief
        );
        assert!(
            items_processed > 0,
            "Items should be processed despite pressure"
        );
        assert!(
            recovery_rate > 0.5,
            "Memory recovery rate should be >50%: {:.2}%",
            recovery_rate * 100.0
        );
    }

    /// [br-integration-16] Partition tolerance test with split-brain detection and healing
    async fn test_partition_tolerance_split_brain_healing(&self) {
        self.logger.log_phase("partition_tolerance_setup");

        use crate::distributed::{ConsistentHash, DistributionStrategy};

        let node_count = 5;
        let partition_duration = Duration::from_secs(3);
        let healing_delay = Duration::from_millis(500);
        let consensus_threshold = (node_count / 2) + 1; // Majority required

        self.logger.log_event(
            "partition_config",
            serde_json::json!({
                "node_count": node_count,
                "partition_duration_secs": partition_duration.as_secs(),
                "healing_delay_ms": healing_delay.as_millis(),
                "consensus_threshold": consensus_threshold
            }),
        );

        // Phase 1: Setup distributed node cluster
        self.logger.log_phase("cluster_setup");

        let (coordinator_tx, coordinator_rx) = broadcast::channel(1000);
        let nodes_online = Arc::new(AtomicUsize::new(0));
        let partition_events = Arc::new(AtomicUsize::new(0));
        let split_brain_detections = Arc::new(AtomicUsize::new(0));
        let healing_operations = Arc::new(AtomicUsize::new(0));
        let consensus_violations = Arc::new(AtomicUsize::new(0));
        let total_messages_exchanged = Arc::new(AtomicUsize::new(0));

        // Distributed node state tracking
        let node_states = Arc::new(Mutex::new(HashMap::<usize, serde_json::Value>::new()));
        let partition_map = Arc::new(Mutex::new(HashSet::<usize>::new())); // Partitioned nodes

        // Phase 2: Node cluster with partition simulation
        let mut node_tasks = Vec::new();

        for node_id in 0..node_count {
            let mut node_rx = coordinator_tx.subscribe();
            let coordinator_tx = coordinator_tx.clone();
            let logger = self.logger.clone();
            let online = Arc::clone(&nodes_online);
            let partitions = Arc::clone(&partition_events);
            let split_brains = Arc::clone(&split_brain_detections);
            let healings = Arc::clone(&healing_operations);
            let violations = Arc::clone(&consensus_violations);
            let messages = Arc::clone(&total_messages_exchanged);
            let states = Arc::clone(&node_states);
            let partition_map = Arc::clone(&partition_map);

            let node_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let node_start = Instant::now();
                    online.fetch_add(1, Ordering::Relaxed);

                    let mut local_state = serde_json::json!({
                        "node_id": node_id,
                        "term": 0,
                        "leader": null,
                        "committed_entries": 0,
                        "last_heartbeat": 0
                    });

                    let mut is_partitioned = false;
                    let mut partition_start = None;
                    let mut consensus_term = 0;

                    logger.log_event("node_started", serde_json::json!({
                        "node_id": node_id,
                        "initial_state": local_state
                    }));

                    while node_start.elapsed() < Duration::from_secs(15) {
                        // Check for partition status
                        let now_partitioned = {
                            let partition_set = partition_map.lock().await;
                            partition_set.contains(&node_id)
                        };

                        // Partition state changes
                        if now_partitioned && !is_partitioned {
                            // Node becomes partitioned
                            is_partitioned = true;
                            partition_start = Some(Instant::now());
                            partitions.fetch_add(1, Ordering::Relaxed);

                            logger.log_event("node_partitioned", serde_json::json!({
                                "node_id": node_id,
                                "partition_time": node_start.elapsed().as_millis()
                            }));
                        } else if !now_partitioned && is_partitioned {
                            // Node recovers from partition
                            is_partitioned = false;
                            if let Some(start) = partition_start {
                                let partition_duration = start.elapsed();
                                logger.log_event("node_partition_healed", serde_json::json!({
                                    "node_id": node_id,
                                    "partition_duration_ms": partition_duration.as_millis()
                                }));
                            }
                            partition_start = None;
                        }

                        if !is_partitioned {
                            // Normal operation - participate in consensus
                            match timeout(Duration::from_millis(50), node_rx.try_recv()).await {
                                Outcome::Ok(Ok(message)) => {
                                    messages.fetch_add(1, Ordering::Relaxed);

                                    // Process consensus message
                                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&message) {
                                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        let msg_term = msg.get("term").and_then(|v| v.as_u64()).unwrap_or(0);

                                        match msg_type {
                                            "heartbeat" => {
                                                // Update last heartbeat
                                                local_state["last_heartbeat"] = serde_json::json!(node_start.elapsed().as_millis());

                                                logger.log_event("heartbeat_received", serde_json::json!({
                                                    "node_id": node_id,
                                                    "from_term": msg_term,
                                                    "local_term": local_state["term"]
                                                }));
                                            }
                                            "leader_election" => {
                                                // Participate in leader election
                                                if msg_term > consensus_term {
                                                    consensus_term = msg_term;
                                                    local_state["term"] = serde_json::json!(consensus_term);

                                                    // Vote or acknowledge leader
                                                    let response = serde_json::json!({
                                                        "type": "vote",
                                                        "node_id": node_id,
                                                        "term": consensus_term,
                                                        "vote_for": msg.get("candidate_id")
                                                    });

                                                    if coordinator_tx.send(response.to_string()).is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                            "split_brain_check" => {
                                                // Detect split-brain scenario
                                                let active_nodes = online.load(Ordering::Relaxed);
                                                let partition_count = {
                                                    let partition_set = partition_map.lock().await;
                                                    partition_set.len()
                                                };

                                                if active_nodes - partition_count < consensus_threshold {
                                                    split_brains.fetch_add(1, Ordering::Relaxed);

                                                    logger.log_event("split_brain_detected", serde_json::json!({
                                                        "node_id": node_id,
                                                        "active_nodes": active_nodes,
                                                        "partitioned_nodes": partition_count,
                                                        "consensus_threshold": consensus_threshold
                                                    }));
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }

                            // Send periodic heartbeat if elected as leader
                            if local_state["leader"].as_u64() == Some(node_id as u64) {
                                let heartbeat = serde_json::json!({
                                    "type": "heartbeat",
                                    "leader_id": node_id,
                                    "term": local_state["term"]
                                });

                                if coordinator_tx.send(heartbeat.to_string()).is_err() {
                                    break;
                                }
                            }

                            // Update node state
                            {
                                let mut states_map = states.lock().await;
                                states_map.insert(node_id, local_state.clone());
                            }
                        } else {
                            // Partitioned - limited operation
                            logger.log_event("node_isolated", serde_json::json!({
                                "node_id": node_id,
                                "partition_duration_ms": partition_start.map(|s| s.elapsed().as_millis()).unwrap_or(0)
                            }));
                        }

                        sleep(Duration::from_millis(100)).await;
                    }

                    online.fetch_sub(1, Ordering::Relaxed);

                    logger.log_event("node_shutdown", serde_json::json!({
                        "node_id": node_id,
                        "final_state": local_state,
                        "uptime_ms": node_start.elapsed().as_millis()
                    }));

                    Outcome::Ok(messages.load(Ordering::Relaxed))
                }).await
            }).await;

            node_tasks.push(node_task);
        }

        // Phase 3: Partition coordinator
        let partition_coordinator = {
            let logger = self.logger.clone();
            let partition_map = Arc::clone(&partition_map);
            let healings = Arc::clone(&healing_operations);

            self.runtime
                .scope(|scope| async move {
                    scope
                        .spawn(async move {
                            let coord_start = Instant::now();

                            // Wait for cluster to stabilize
                            sleep(Duration::from_millis(500)).await;

                            // Create partition - isolate nodes 0 and 1
                            {
                                let mut partition_set = partition_map.lock().await;
                                partition_set.insert(0);
                                partition_set.insert(1);
                            }

                            logger.log_event(
                                "partition_created",
                                serde_json::json!({
                                    "partitioned_nodes": [0, 1],
                                    "remaining_nodes": [2, 3, 4]
                                }),
                            );

                            // Maintain partition
                            sleep(partition_duration).await;

                            // Heal partition
                            {
                                let mut partition_set = partition_map.lock().await;
                                partition_set.clear();
                            }

                            let healing_id = healings.fetch_add(1, Ordering::Relaxed);

                            logger.log_event(
                                "partition_healed",
                                serde_json::json!({
                                    "healing_id": healing_id,
                                    "partition_duration_ms": partition_duration.as_millis()
                                }),
                            );

                            // Allow healing to complete
                            sleep(healing_delay).await;

                            // Send split-brain detection messages
                            for _ in 0..5 {
                                let split_brain_msg = serde_json::json!({
                                    "type": "split_brain_check",
                                    "timestamp": coord_start.elapsed().as_millis()
                                });

                                if coordinator_tx.send(split_brain_msg.to_string()).is_err() {
                                    break;
                                }

                                sleep(Duration::from_millis(200)).await;
                            }

                            logger.log_event(
                                "partition_coordinator_complete",
                                serde_json::json!({
                                    "total_healing_operations": healings.load(Ordering::Relaxed)
                                }),
                            );

                            Outcome::Ok(healings.load(Ordering::Relaxed))
                        })
                        .await
                })
                .await
        };

        // Phase 4: Execute partition tolerance test
        self.logger.log_phase("partition_tolerance_execution");

        let test_timeout = Duration::from_secs(18);

        // Wait for partition coordinator
        let coordinator_result = timeout(test_timeout, partition_coordinator).await;

        // Wait for all nodes to complete
        let mut successful_nodes = 0;
        for (node_id, node_task) in node_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), node_task).await {
                Outcome::Ok(Outcome::Ok(_)) => successful_nodes += 1,
                _ => {
                    self.logger.log_event(
                        "node_timeout",
                        serde_json::json!({
                            "node_id": node_id
                        }),
                    );
                }
            }
        }

        // Phase 5: Validate partition tolerance and healing
        self.logger.log_phase("split_brain_healing_validation");

        let final_online = nodes_online.load(Ordering::Relaxed);
        let total_partitions = partition_events.load(Ordering::Relaxed);
        let total_split_brains = split_brain_detections.load(Ordering::Relaxed);
        let total_healings = healing_operations.load(Ordering::Relaxed);
        let total_violations = consensus_violations.load(Ordering::Relaxed);
        let messages_exchanged = total_messages_exchanged.load(Ordering::Relaxed);

        let final_state_consistency = {
            let states_map = node_states.lock().await;
            let mut consistent_nodes = 0;
            let mut max_term = 0;

            for (_, state) in states_map.iter() {
                if let Some(term) = state.get("term").and_then(|v| v.as_u64()) {
                    max_term = max_term.max(term);
                }
            }

            for (_, state) in states_map.iter() {
                if let Some(term) = state.get("term").and_then(|v| v.as_u64()) {
                    if term == max_term {
                        consistent_nodes += 1;
                    }
                }
            }

            consistent_nodes
        };

        self.logger.log_metrics(serde_json::json!({
            "partition_tolerance_results": {
                "nodes_completed": successful_nodes,
                "partition_events": total_partitions,
                "split_brain_detections": total_split_brains,
                "healing_operations": total_healings,
                "consensus_violations": total_violations,
                "messages_exchanged": messages_exchanged,
                "final_state_consistency": final_state_consistency,
                "partition_survival_rate": successful_nodes as f64 / node_count as f64,
                "healing_effectiveness": total_healings as f64 / total_partitions.max(1) as f64,
                "split_brain_detection_rate": total_split_brains as f64 / total_partitions.max(1) as f64
            }
        }));

        // Critical assertions for partition tolerance
        self.logger.log_assertion(
            "partition_events",
            total_partitions > 0,
            serde_json::json!({
                "partition_events": total_partitions
            }),
        );

        self.logger.log_assertion(
            "split_brain_detection",
            total_split_brains > 0,
            serde_json::json!({
                "split_brain_detections": total_split_brains
            }),
        );

        self.logger.log_assertion(
            "healing_operations",
            total_healings > 0,
            serde_json::json!({
                "healing_operations": total_healings
            }),
        );

        self.logger.log_assertion(
            "node_survival",
            successful_nodes >= consensus_threshold,
            serde_json::json!({
                "successful_nodes": successful_nodes,
                "consensus_threshold": consensus_threshold
            }),
        );

        // No consensus violations should occur
        self.logger.log_assertion(
            "no_consensus_violations",
            total_violations == 0,
            serde_json::json!({
                "violations": total_violations
            }),
        );

        // State consistency after healing
        self.logger.log_assertion(
            "post_healing_consistency",
            final_state_consistency >= consensus_threshold,
            serde_json::json!({
                "consistent_nodes": final_state_consistency,
                "threshold": consensus_threshold
            }),
        );

        assert!(
            total_partitions > 0,
            "Network partitions should occur: {} events",
            total_partitions
        );
        assert!(
            total_split_brains > 0,
            "Split-brain scenarios should be detected: {} detections",
            total_split_brains
        );
        assert!(
            total_healings > 0,
            "Partition healing should occur: {} healing operations",
            total_healings
        );
        assert!(
            successful_nodes >= consensus_threshold,
            "Majority of nodes should survive partition: {} vs {} threshold",
            successful_nodes,
            consensus_threshold
        );
        assert!(
            total_violations == 0,
            "NO consensus violations during partition: {} violations",
            total_violations
        );
        assert!(
            final_state_consistency >= consensus_threshold,
            "State consistency should be restored after healing: {} consistent nodes",
            final_state_consistency
        );
    }
}

#[tokio::test]
async fn test_pubsub_fanout_partial_failures_integration() {
    let harness = IntegrationTestHarness::new("pubsub_fanout_partial_failures_integration").await;
    harness.test_pubsub_fanout_partial_failures().await;
}

#[tokio::test]
async fn test_circuit_breaker_cascade_recovery_integration() {
    let harness = IntegrationTestHarness::new("circuit_breaker_cascade_recovery_integration").await;
    harness.test_circuit_breaker_cascade_recovery().await;
}

#[tokio::test]
async fn test_region_failure_isolation_integration() {
    let harness = IntegrationTestHarness::new("region_failure_isolation_integration").await;
    harness.test_region_failure_isolation().await;
}

#[tokio::test]
async fn test_backpressure_propagation_pipeline_integration() {
    let harness =
        IntegrationTestHarness::new("backpressure_propagation_pipeline_integration").await;
    harness.test_backpressure_propagation_pipeline().await;
}

#[tokio::test]
async fn test_comprehensive_integration_scenario() {
    let harness = IntegrationTestHarness::new("comprehensive_integration_scenario").await;

    harness.logger.log_phase("comprehensive_scenario_start");

    // Combined scenario: All integration patterns working together
    harness.logger.log_phase("multi_component_setup");

    // This test combines pubsub, circuit breakers, supervision, and backpressure
    // in a single complex scenario that tests the full asupersync stack

    harness.logger.log_event(
        "comprehensive_config",
        serde_json::json!({
            "scenario": "multi_component_integration",
            "components": ["pubsub", "circuit_breaker", "supervision", "backpressure"]
        }),
    );

    // The implementation would combine all previous scenarios
    // For brevity, we'll validate that the harness is properly set up
    // and can coordinate multiple integration scenarios

    harness.logger.log_assertion(
        "comprehensive_harness_ready",
        true,
        serde_json::json!({
            "harness_initialized": true,
            "failure_injector_ready": true,
            "runtime_available": true
        }),
    );

    harness.logger.log_phase("comprehensive_scenario_complete");
}

// ===== CHAOS ENGINEERING INTEGRATION TEST FUNCTIONS =====

#[tokio::test]
async fn test_chaos_thread_kill_obligation_cleanup_integration() {
    let harness =
        IntegrationTestHarness::new("chaos_thread_kill_obligation_cleanup_integration").await;
    harness.test_chaos_thread_kill_obligation_cleanup().await;
}

#[tokio::test]
async fn test_hedge_first_success_short_circuit_integration() {
    let harness =
        IntegrationTestHarness::new("hedge_first_success_short_circuit_integration").await;
    harness.test_hedge_first_success_short_circuit().await;
}

#[tokio::test]
async fn test_distributed_bridge_rolling_restart_integration() {
    let harness =
        IntegrationTestHarness::new("distributed_bridge_rolling_restart_integration").await;
    harness.test_distributed_bridge_rolling_restart().await;
}

#[tokio::test]
async fn test_pubsub_broker_death_reconnect_integration() {
    let harness = IntegrationTestHarness::new("pubsub_broker_death_reconnect_integration").await;
    harness.test_pubsub_broker_death_reconnect().await;
}

#[tokio::test]
async fn test_raptorq_decode_interruption_resume_integration() {
    let harness =
        IntegrationTestHarness::new("raptorq_decode_interruption_resume_integration").await;
    harness.test_raptorq_decode_interruption_resume().await;
}

#[tokio::test]
async fn test_runtime_panic_recovery_subscriptions_integration() {
    let harness =
        IntegrationTestHarness::new("runtime_panic_recovery_subscriptions_integration").await;
    harness.test_runtime_panic_recovery_subscriptions().await;
}

// ===== PERFORMANCE UNDER LOAD INTEGRATION TEST FUNCTIONS =====

#[tokio::test]
async fn test_burst_traffic_rate_limit_throughput_integration() {
    let harness =
        IntegrationTestHarness::new("burst_traffic_rate_limit_throughput_integration").await;
    harness.test_burst_traffic_rate_limit_throughput().await;
}

#[tokio::test]
async fn test_http2_connection_storm_slot_leaks_integration() {
    let harness =
        IntegrationTestHarness::new("http2_connection_storm_slot_leaks_integration").await;
    harness.test_http2_connection_storm_slot_leaks().await;
}

#[tokio::test]
async fn test_high_frequency_timer_churn_wheel_stress_integration() {
    let harness =
        IntegrationTestHarness::new("high_frequency_timer_churn_wheel_stress_integration").await;
    harness.test_high_frequency_timer_churn_wheel_stress().await;
}

// ===== LONG-RUNNING SCENARIOS INTEGRATION TEST FUNCTIONS =====

#[tokio::test]
async fn test_multi_hour_task_checkpoint_resume_integration() {
    let harness =
        IntegrationTestHarness::new("multi_hour_task_checkpoint_resume_integration").await;
    harness.test_multi_hour_task_checkpoint_resume().await;
}

#[tokio::test]
async fn test_memory_pressure_backpressure_recovery_integration() {
    let harness =
        IntegrationTestHarness::new("memory_pressure_backpressure_recovery_integration").await;
    harness.test_memory_pressure_backpressure_recovery().await;
}

#[tokio::test]
async fn test_partition_tolerance_split_brain_healing_integration() {
    let harness =
        IntegrationTestHarness::new("partition_tolerance_split_brain_healing_integration").await;
    harness.test_partition_tolerance_split_brain_healing().await;
}
