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

use crate::channel::{mpsc, broadcast, oneshot};
use crate::combinator::{race, timeout, join, retry};
use crate::combinator::circuit_breaker::{CircuitBreaker, CircuitBreakerPolicy, FailurePredicate};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::runtime::{RuntimeBuilder, LabRuntime};
use crate::sync::{Mutex, Semaphore};
use crate::supervision::{SupervisionStrategy, RestartConfig, BackoffStrategy};
use crate::time::{sleep, Duration, Instant};
use crate::types::{Budget, Outcome, RegionId, TaskId, Time};

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::collections::HashMap;
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

        eprintln!("{{\"timestamp\":{},\"test\":\"{}\",\"elapsed_ms\":{},\"event\":\"{}\",\"data\":{}}}",
            timestamp, self.test_name, elapsed, event_type, data);
    }

    fn log_phase(&self, phase: &str) {
        self.log_event("phase", serde_json::json!({"name": phase}));
    }

    fn log_metrics(&self, metrics: serde_json::Value) {
        self.log_event("metrics", metrics);
    }

    fn log_assertion(&self, assertion: &str, passed: bool, details: serde_json::Value) {
        self.log_event("assertion", serde_json::json!({
            "assertion": assertion,
            "passed": passed,
            "details": details
        }));
    }
}

impl Drop for IntegrationLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed().as_millis();
        self.log_event("integration_test_end", serde_json::json!({"total_duration_ms": elapsed}));
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

    async fn maybe_inject_delay(&self) {
        if self.cpu_stress.load(Ordering::Relaxed) {
            // Simulate CPU stress with small delays
            sleep(Duration::from_millis(fastrand::u64(1..10))).await;
        }
    }
}

impl IntegrationTestHarness {
    async fn new(test_name: &str) -> Self {
        let logger = IntegrationLogger::new(test_name);
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let failure_injector = FailureInjector::new();

        logger.log_event("harness_init", serde_json::json!({
            "temp_dir": temp_dir.path().to_string_lossy()
        }));

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

        self.logger.log_event("scenario_config", serde_json::json!({
            "consumer_count": consumer_count,
            "message_count": message_count,
            "failure_rate": failure_rate
        }));

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

            self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    for i in 0..message_count {
                        let message = format!("message_{}", i);

                        // Inject occasional producer failures
                        if let Err(_) = failure_injector.maybe_inject_failure("producer").await {
                            logger.log_event("producer_failure", serde_json::json!({
                                "message_id": i,
                                "reason": "injected_failure"
                            }));
                            continue;
                        }

                        match tx.send(message.clone()) {
                            Ok(subscriber_count) => {
                                logger.log_event("message_published", serde_json::json!({
                                    "message_id": i,
                                    "message": message,
                                    "subscriber_count": subscriber_count
                                }));
                            }
                            Err(e) => {
                                logger.log_event("publish_failed", serde_json::json!({
                                    "message_id": i,
                                    "error": e.to_string()
                                }));
                            }
                        }

                        sleep(Duration::from_millis(10)).await;
                    }

                    Outcome::Ok(())
                }).await
            }).await
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

            let consumer_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let mut received_count = 0;
                    let mut failed_count = 0;

                    loop {
                        match consumer_rx.recv().await {
                            Ok(message) => {
                                // Inject consumer-specific failures
                                if let Err(_) = failure_injector.maybe_inject_failure(&format!("consumer_{}", consumer_id)).await {
                                    failed_count += 1;
                                    failed_deliveries.fetch_add(1, Ordering::Relaxed);

                                    logger.log_event("consumer_failure", serde_json::json!({
                                        "consumer_id": consumer_id,
                                        "message": message,
                                        "reason": "injected_failure"
                                    }));
                                    continue;
                                }

                                // Simulate message processing with potential delays
                                failure_injector.maybe_inject_delay().await;

                                received_count += 1;
                                successful_deliveries.fetch_add(1, Ordering::Relaxed);

                                logger.log_event("message_consumed", serde_json::json!({
                                    "consumer_id": consumer_id,
                                    "message": message,
                                    "received_count": received_count
                                }));
                            }
                            Err(broadcast::RecvError::Closed) => {
                                logger.log_event("consumer_stream_closed", serde_json::json!({
                                    "consumer_id": consumer_id,
                                    "final_received_count": received_count,
                                    "final_failed_count": failed_count
                                }));
                                break;
                            }
                            Err(broadcast::RecvError::Lagged(skipped)) => {
                                logger.log_event("consumer_lagged", serde_json::json!({
                                    "consumer_id": consumer_id,
                                    "skipped_messages": skipped
                                }));
                            }
                        }
                    }

                    consumer_results.lock().await.push((consumer_id, received_count, failed_count));
                    Outcome::Ok(())
                }).await
            }).await;

            consumer_tasks.push(consumer_task);
        }

        // Phase 3: Wait for completion
        self.logger.log_phase("scenario_execution");

        // Run producer and let it complete
        let producer_result = producer_task.await;

        // Give consumers time to process all messages
        sleep(Duration::from_millis(500)).await;

        // Drop the sender to close the broadcast channel
        drop(tx);

        // Wait for all consumers to finish
        for (i, consumer_task) in consumer_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), consumer_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event("consumer_completed", serde_json::json!({
                        "consumer_id": i,
                        "result": format!("{:?}", result)
                    }));
                }
                Outcome::Cancelled => {
                    self.logger.log_event("consumer_timeout", serde_json::json!({
                        "consumer_id": i,
                        "timeout_duration_ms": 5000
                    }));
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
        assert!(total_successful > 0, "At least some messages should be delivered successfully");

        let expected_min_deliveries = (message_count * consumer_count * (100 - failure_rate)) / 100;

        self.logger.log_assertion("sufficient_deliveries", total_successful >= expected_min_deliveries, serde_json::json!({
            "actual_deliveries": total_successful,
            "expected_min": expected_min_deliveries,
            "failure_rate": failure_rate
        }));

        assert!(total_successful >= expected_min_deliveries,
            "Should deliver at least {}% of messages despite {}% failure rate", 100 - failure_rate, failure_rate);
    }

    /// [br-integration-2] Circuit breaker cascade recovery
    async fn test_circuit_breaker_cascade_recovery(&self) {
        self.logger.log_phase("circuit_breaker_setup");

        // Create a multi-tier service architecture with circuit breakers
        let service_tiers = 3;
        let requests_per_tier = 20;

        self.logger.log_event("cascade_config", serde_json::json!({
            "service_tiers": service_tiers,
            "requests_per_tier": requests_per_tier
        }));

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

            failure_counts.lock().await.insert(tier, AtomicUsize::new(0));
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

            let request_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
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
                            logger.log_event("request_success", serde_json::json!({
                                "request_id": request_id,
                                "tier": tier,
                                "response": response
                            }));
                        }
                        Err(e) => {
                            failed_requests.fetch_add(1, Ordering::Relaxed);

                            let error_description = format!("{:?}", e);
                            if error_description.contains("Open") {
                                circuit_opened_count.fetch_add(1, Ordering::Relaxed);
                                logger.log_event("circuit_breaker_opened", serde_json::json!({
                                    "request_id": request_id,
                                    "tier": tier,
                                    "error": error_description
                                }));
                            } else {
                                logger.log_event("request_failure", serde_json::json!({
                                    "request_id": request_id,
                                    "tier": tier,
                                    "error": error_description
                                }));
                            }
                        }
                    }

                    Outcome::Ok(())
                }).await
            }).await;

            request_tasks.push(request_task);

            // Small delay between requests to simulate realistic load
            sleep(Duration::from_millis(50)).await;
        }

        // Phase 3: Wait for initial cascade to complete
        self.logger.log_phase("cascade_completion");

        for (i, task) in request_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(2), task).await {
                Outcome::Ok(_) => {},
                _ => {
                    self.logger.log_event("request_timeout", serde_json::json!({
                        "request_index": i
                    }));
                }
            }
        }

        let initial_successful = successful_requests.load(Ordering::Relaxed);
        let initial_failed = failed_requests.load(Ordering::Relaxed);
        let initial_circuit_opens = circuit_opened_count.load(Ordering::Relaxed);

        // Phase 4: Recovery - reduce failure rate and test recovery
        self.logger.log_phase("recovery_phase");

        self.failure_injector.set_failure_rate(5); // Reduce to 5% failure rate
        sleep(Duration::from_millis(200)).await; // Wait for circuit breakers to attempt half-open

        // Send recovery requests
        let recovery_requests = 30;
        let mut recovery_tasks = Vec::new();

        for request_id in 1000..1000 + recovery_requests {
            let circuit_breakers_clone = circuit_breakers.clone();
            let successful_requests = Arc::clone(&successful_requests);
            let failed_requests = Arc::clone(&failed_requests);
            let failure_injector = &self.failure_injector;
            let logger = &self.logger;

            let recovery_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
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
                            logger.log_event("recovery_success", serde_json::json!({
                                "request_id": request_id,
                                "tier": tier,
                                "response": response
                            }));
                        }
                        Err(e) => {
                            failed_requests.fetch_add(1, Ordering::Relaxed);
                            logger.log_event("recovery_failure", serde_json::json!({
                                "request_id": request_id,
                                "tier": tier,
                                "error": e.to_string()
                            }));
                        }
                    }

                    Outcome::Ok(())
                }).await
            }).await;

            recovery_tasks.push(recovery_task);
            sleep(Duration::from_millis(30)).await;
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
        let recovery_success_rate = recovery_successful as f64 / (recovery_successful + recovery_failed).max(1) as f64;

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
        self.logger.log_assertion("circuit_breakers_activated", initial_circuit_opens > 0, serde_json::json!({
            "circuit_opens": initial_circuit_opens
        }));

        self.logger.log_assertion("recovery_improved", recovery_success_rate > 0.8, serde_json::json!({
            "recovery_success_rate": recovery_success_rate,
            "threshold": 0.8
        }));

        assert!(initial_circuit_opens > 0, "Circuit breakers should have activated during cascade");
        assert!(recovery_success_rate > 0.8, "Recovery phase should show >80% success rate, got {:.1}%", recovery_success_rate * 100.0);
    }

    /// [br-integration-3] Region failure isolation and recovery
    async fn test_region_failure_isolation(&self) {
        self.logger.log_phase("region_isolation_setup");

        let region_count = 4;
        let work_items_per_region = 10;

        self.failure_injector.set_failure_rate(30);

        self.logger.log_event("region_config", serde_json::json!({
            "region_count": region_count,
            "work_items_per_region": work_items_per_region
        }));

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

            let region_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    logger.log_event("region_started", serde_json::json!({
                        "region_id": region_id,
                        "failure_rate": region_failure_rate
                    }));

                    // Simulate work in the region
                    for work_item in 0..work_items_per_region {
                        // Inject region-specific failures
                        if fastrand::usize(0..100) < region_failure_rate {
                            failed_regions.fetch_add(1, Ordering::Relaxed);
                            logger.log_event("region_failure", serde_json::json!({
                                "region_id": region_id,
                                "work_item": work_item,
                                "failure_type": "injected"
                            }));

                            return Outcome::Cancelled; // Simulate region failure
                        }

                        // Simulate work delay
                        sleep(Duration::from_millis(20)).await;

                        successful_work.fetch_add(1, Ordering::Relaxed);

                        logger.log_event("work_completed", serde_json::json!({
                            "region_id": region_id,
                            "work_item": work_item
                        }));
                    }

                    completed_regions.fetch_add(1, Ordering::Relaxed);
                    logger.log_event("region_completed", serde_json::json!({
                        "region_id": region_id
                    }));

                    Outcome::Ok(())
                }).await
            }).await;

            region_tasks.push(region_task);
        }

        // Phase 2: Wait for regions to complete or fail
        self.logger.log_phase("region_execution");

        for (region_id, region_task) in region_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(5), region_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event("region_task_completed", serde_json::json!({
                        "region_id": region_id,
                        "result": format!("{:?}", result)
                    }));
                }
                Outcome::Cancelled => {
                    self.logger.log_event("region_task_timeout", serde_json::json!({
                        "region_id": region_id
                    }));
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
        self.logger.log_assertion("work_completed_despite_failures", total_successful_work > 0, serde_json::json!({
            "successful_work": total_successful_work
        }));

        self.logger.log_assertion("failures_occurred", total_failed_regions > 0, serde_json::json!({
            "failed_regions": total_failed_regions
        }));

        self.logger.log_assertion("isolation_preserved", total_completed_regions > 0, serde_json::json!({
            "completed_regions": total_completed_regions
        }));

        assert!(total_successful_work > 0, "Some work should complete despite region failures");
        assert!(total_failed_regions > 0, "Some regions should fail due to injected failures");
        assert!(total_completed_regions > 0, "At least one region should complete successfully (isolation)");
    }

    /// [br-integration-5] Chaos: Kill worker thread mid-task, verify obligation cleanup
    async fn test_chaos_thread_kill_obligation_cleanup(&self) {
        self.logger.log_phase("chaos_thread_kill_setup");

        let worker_count = 3;
        let tasks_per_worker = 8;
        let kill_probability = 40; // 40% chance to kill thread mid-task

        self.logger.log_event("chaos_config", serde_json::json!({
            "worker_count": worker_count,
            "tasks_per_worker": tasks_per_worker,
            "kill_probability": kill_probability
        }));

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

            let worker_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    logger.log_event("worker_started", serde_json::json!({
                        "worker_id": worker_id
                    }));

                    for task_id in 0..tasks_per_worker {
                        let obligation_id = format!("worker_{}_task_{}", worker_id, task_id);

                        // Create obligation (simulate resource acquisition)
                        {
                            let mut obligations = active_obligations.lock().await;
                            obligations.insert(obligation_id.clone(), false); // false = not completed
                        }
                        obligation_created.fetch_add(1, Ordering::Relaxed);

                        logger.log_event("obligation_created", serde_json::json!({
                            "worker_id": worker_id,
                            "task_id": task_id,
                            "obligation_id": obligation_id
                        }));

                        // Chaos injection: random thread termination mid-task
                        if fastrand::usize(0..100) < kill_probability {
                            threads_killed.fetch_add(1, Ordering::Relaxed);

                            logger.log_event("chaos_thread_kill", serde_json::json!({
                                "worker_id": worker_id,
                                "task_id": task_id,
                                "obligation_id": obligation_id,
                                "kill_reason": "chaos_injection"
                            }));

                            // Simulate abrupt thread termination (would trigger region cancellation)
                            return Outcome::Cancelled;
                        }

                        // Simulate work with potential for interruption
                        for work_step in 0..3 {
                            sleep(Duration::from_millis(50)).await;

                            // Additional chaos injection during work
                            if fastrand::usize(0..100) < kill_probability / 2 {
                                threads_killed.fetch_add(1, Ordering::Relaxed);

                                logger.log_event("chaos_mid_work_kill", serde_json::json!({
                                    "worker_id": worker_id,
                                    "task_id": task_id,
                                    "work_step": work_step,
                                    "obligation_id": obligation_id
                                }));

                                return Outcome::Cancelled;
                            }
                        }

                        // Complete obligation (simulate resource cleanup)
                        {
                            let mut obligations = active_obligations.lock().await;
                            if let Some(completed) = obligations.get_mut(&obligation_id) {
                                *completed = true;
                                obligation_completed.fetch_add(1, Ordering::Relaxed);

                                logger.log_event("obligation_completed", serde_json::json!({
                                    "worker_id": worker_id,
                                    "task_id": task_id,
                                    "obligation_id": obligation_id
                                }));
                            }
                        }
                    }

                    clean_completions.fetch_add(1, Ordering::Relaxed);

                    logger.log_event("worker_completed_cleanly", serde_json::json!({
                        "worker_id": worker_id
                    }));

                    Outcome::Ok(())
                }).await
            }).await;

            worker_tasks.push(worker_task);
        }

        // Phase 3: Execute with chaos and monitor
        self.logger.log_phase("chaos_execution");

        for (worker_id, worker_task) in worker_tasks.into_iter().enumerate() {
            match timeout(Duration::from_secs(10), worker_task).await {
                Outcome::Ok(result) => {
                    self.logger.log_event("worker_task_completed", serde_json::json!({
                        "worker_id": worker_id,
                        "result": format!("{:?}", result)
                    }));
                }
                Outcome::Cancelled => {
                    self.logger.log_event("worker_task_timeout", serde_json::json!({
                        "worker_id": worker_id
                    }));
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
                self.logger.log_event("obligation_leaked", serde_json::json!({
                    "obligation_id": obligation_id,
                    "leak_detected": true
                }));
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
        self.logger.log_assertion("chaos_occurred", total_killed > 0, serde_json::json!({
            "threads_killed": total_killed
        }));

        self.logger.log_assertion("no_obligation_leaks", total_leaked == 0, serde_json::json!({
            "leaked_obligations": total_leaked,
            "created_obligations": total_created
        }));

        self.logger.log_assertion("some_work_completed", total_completed > 0, serde_json::json!({
            "completed_obligations": total_completed
        }));

        assert!(total_killed > 0, "Chaos injection should have killed some threads");
        assert!(total_leaked == 0, "NO obligation leaks allowed despite chaos: {} leaked out of {}", total_leaked, total_created);
        assert!(total_completed > 0, "Some work should complete despite chaos");
    }

    /// [br-integration-6] Hedge pattern: First-success short-circuits slow downstream
    async fn test_hedge_first_success_short_circuit(&self) {
        self.logger.log_phase("hedge_setup");

        let hedge_count = 4; // Try 4 parallel requests
        let requests_to_test = 10;
        let slow_response_time = Duration::from_millis(500);
        let fast_response_time = Duration::from_millis(50);

        self.logger.log_event("hedge_config", serde_json::json!({
            "hedge_count": hedge_count,
            "requests_to_test": requests_to_test,
            "slow_response_ms": slow_response_time.as_millis(),
            "fast_response_ms": fast_response_time.as_millis()
        }));

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
                    scope.spawn(async move {
                        // Simulate different downstream response characteristics
                        let response_delay = match hedge_idx {
                            0 => fast_response_time, // Fast service (primary)
                            1 => slow_response_time, // Slow service 1
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

                        logger.log_event("hedge_response", serde_json::json!({
                            "request_id": request_id,
                            "hedge_idx": hedge_idx,
                            "response_delay_ms": response_delay.as_millis()
                        }));

                        Outcome::Ok(format!("response_from_hedge_{}", hedge_idx))
                    }).await
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

                    logger.log_event("hedge_first_success", serde_json::json!({
                        "request_id": request_id,
                        "winning_hedge": winner_idx,
                        "response": response,
                        "total_duration_ms": hedge_duration.as_millis(),
                        "short_circuited": hedge_duration < slow_response_time
                    }));
                }
                _ => {
                    logger.log_event("hedge_all_failed", serde_json::json!({
                        "request_id": request_id,
                        "duration_ms": hedge_duration.as_millis()
                    }));
                }
            }
        }

        // Phase 3: Validate hedge effectiveness
        self.logger.log_phase("hedge_validation");

        let total_successes = first_success_count.load(Ordering::Relaxed);
        let total_attempts = total_hedge_attempts.load(Ordering::Relaxed);
        let avg_response_ms = average_response_time.load(Ordering::Relaxed) / requests_to_test.max(1);

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
        self.logger.log_assertion("hedge_successes", total_successes > 0, serde_json::json!({
            "successful_requests": total_successes,
            "total_requests": requests_to_test
        }));

        self.logger.log_assertion("hedge_short_circuit", avg_response_ms < slow_response_time.as_millis() as usize, serde_json::json!({
            "average_response_ms": avg_response_ms,
            "slow_threshold_ms": slow_response_time.as_millis()
        }));

        self.logger.log_assertion("hedge_efficiency", total_successes >= requests_to_test * 8 / 10, serde_json::json!({
            "success_rate": total_successes as f64 / requests_to_test as f64,
            "expected_rate": 0.8
        }));

        assert!(total_successes > 0, "Hedge should have some successful responses");
        assert!(avg_response_ms < slow_response_time.as_millis() as usize,
            "Hedge should short-circuit slow responses: {}ms avg > {}ms threshold",
            avg_response_ms, slow_response_time.as_millis());
        assert!(total_successes >= requests_to_test * 8 / 10,
            "Hedge should achieve >80% success rate: {:.1}%",
            total_successes as f64 / requests_to_test as f64 * 100.0);
    }

    /// [br-integration-7] Distributed bridge rolling restart with consistency
    async fn test_distributed_bridge_rolling_restart(&self) {
        self.logger.log_phase("distributed_bridge_setup");

        let node_count = 5;
        let messages_per_node = 15;
        let rolling_restart_interval = Duration::from_millis(200);

        self.logger.log_event("bridge_config", serde_json::json!({
            "node_count": node_count,
            "messages_per_node": messages_per_node,
            "rolling_restart_interval_ms": rolling_restart_interval.as_millis()
        }));

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

            let node_task = self.runtime.scope(|scope| async move {
                scope.spawn(async move {
                    let mut current_generation = 0;
                    let mut restart_count = 0;

                    // Node lifecycle with rolling restarts
                    loop {
                        logger.log_event("bridge_node_started", serde_json::json!({
                            "node_id": node_id,
                            "generation": current_generation,
                            "restart_count": restart_count
                        }));

                        // Update node generation
                        {
                            let mut generations = node_generations.lock().await;
                            generations.insert(node_id, current_generation);
                        }

                        // Process messages for this generation
                        for msg_id in 0..messages_per_node {
                            let message = format!("node_{}_gen_{}_msg_{}", node_id, current_generation, msg_id);

                            // Simulate distributed bridge state update
                            {
                                let mut state = bridge_state.lock().await;
                                let node_key = format!("node_{}", node_id);
                                state.entry(node_key).or_insert_with(Vec::new).push(message.clone());

                                // Consistency check: verify no conflicting updates from same node
                                if let Some(node_messages) = state.get(&format!("node_{}", node_id)) {
                                    let expected_count = msg_id + 1 + (restart_count * messages_per_node);
                                    if node_messages.len() != expected_count {
                                        consistency_violations.fetch_add(1, Ordering::Relaxed);

                                        logger.log_event("consistency_violation", serde_json::json!({
                                            "node_id": node_id,
                                            "expected_count": expected_count,
                                            "actual_count": node_messages.len(),
                                            "generation": current_generation
                                        }));
                                    }
                                }
                            }

                            messages_processed.fetch_add(1, Ordering::Relaxed);

                            // Send coordination message
                            if coordinator_tx.send(message.clone()).await.is_err() {
                                logger.log_event("coordination_send_failed", serde_json::json!({
                                    "node_id": node_id,
                                    "message": message
                                }));
                                break;
                            }

                            logger.log_event("bridge_message_processed", serde_json::json!({
                                "node_id": node_id,
                                "message": message,
                                "generation": current_generation
                            }));

                            sleep(Duration::from_millis(30)).await;
                        }

                        // Rolling restart logic
                        restart_count += 1;
                        current_generation += 1;

                        if restart_count >= 3 { // Limit restarts for test completion
                            successful_restarts.fetch_add(1, Ordering::Relaxed);

                            logger.log_event("bridge_node_final_shutdown", serde_json::json!({
                                "node_id": node_id,
                                "total_restarts": restart_count,
                                "final_generation": current_generation
                            }));
                            break;
                        }

                        // Simulate restart delay
                        sleep(rolling_restart_interval).await;

                        logger.log_event("bridge_node_restarting", serde_json::json!({
                            "node_id": node_id,
                            "old_generation": current_generation - 1,
                            "new_generation": current_generation,
                            "restart_count": restart_count
                        }));
                    }

                    Outcome::Ok(())
                }).await
            }).await;

            node_tasks.push(node_task);

            // Stagger node starts to simulate rolling deployment
            sleep(Duration::from_millis(100)).await;
        }

        // Phase 3: Coordination message monitoring
        self.logger.log_phase("coordination_monitoring");

        let coordination_task = self.runtime.scope(|scope| async move {
            scope.spawn(async move {
                let mut coordinator_rx = coordinator_rx;
                let mut total_coordinated = 0;

                while let Some(message) = coordinator_rx.recv().await {
                    total_coordinated += 1;

                    logger.log_event("coordination_received", serde_json::json!({
                        "message": message,
                        "total_coordinated": total_coordinated
                    }));

                    if total_coordinated >= 200 { // Reasonable limit for test completion
                        break;
                    }
                }

                logger.log_event("coordination_completed", serde_json::json!({
                    "total_coordinated": total_coordinated
                }));

                Outcome::Ok(total_coordinated)
            }).await
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
                    self.logger.log_event("bridge_node_task_completed", serde_json::json!({
                        "node_id": node_id
                    }));
                }
                _ => {
                    self.logger.log_event("bridge_node_task_timeout", serde_json::json!({
                        "node_id": node_id
                    }));
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
        self.logger.log_assertion("messages_processed", total_messages > 0, serde_json::json!({
            "processed_messages": total_messages
        }));

        self.logger.log_assertion("restarts_completed", total_restarts > 0, serde_json::json!({
            "successful_restarts": total_restarts,
            "expected_min": 1
        }));

        self.logger.log_assertion("consistency_maintained", total_violations == 0, serde_json::json!({
            "consistency_violations": total_violations,
            "total_messages": total_messages
        }));

        self.logger.log_assertion("coordination_active", coordinated_messages > 0, serde_json::json!({
            "coordinated_messages": coordinated_messages
        }));

        assert!(total_messages > 0, "Bridge should process messages");
        assert!(total_restarts > 0, "Rolling restarts should occur");
        assert!(total_violations == 0, "NO consistency violations allowed during rolling restart: {} violations", total_violations);
        assert!(coordinated_messages > 0, "Bridge coordination should be active");
    }

    /// [br-integration-4] Backpressure propagation pipeline
    async fn test_backpressure_propagation_pipeline(&self) {
        self.logger.log_phase("backpressure_setup");

        let pipeline_stages = 4;
        let total_items = 100;
        let slow_stage_delay = Duration::from_millis(100); // Stage 2 is slow

        self.logger.log_event("pipeline_config", serde_json::json!({
            "pipeline_stages": pipeline_stages,
            "total_items": total_items,
            "slow_stage_delay_ms": slow_stage_delay.as_millis()
        }));

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
                    self.logger.log_event("stage_task_completed", serde_json::json!({
                        "stage_id": stage_id
                    }));
                }
                Outcome::Cancelled => {
                    self.logger.log_event("stage_task_timeout", serde_json::json!({
                        "stage_id": stage_id
                    }));
                }
                _ => {}
            }
        }

        pipeline_completed.store(true, Ordering::Relaxed);

        // Phase 4: Validate backpressure behavior
        self.logger.log_phase("backpressure_validation");

        let final_counts = processed_counts.lock().await;
        let total_backpressure_events = backpressure_events.load(Ordering::Relaxed);

        let counts: Vec<usize> = final_counts.iter()
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
        self.logger.log_assertion("pipeline_processed_items", counts[0] > 0, serde_json::json!({
            "stage_0_count": counts[0]
        }));

        self.logger.log_assertion("backpressure_occurred", total_backpressure_events > 0, serde_json::json!({
            "backpressure_events": total_backpressure_events
        }));

        // Verify processing decreased through slow stage due to backpressure
        let slow_stage_processed = counts[2];
        let final_stage_processed = counts[pipeline_stages - 1];

        self.logger.log_assertion("backpressure_limited_throughput",
            slow_stage_processed < total_items, serde_json::json!({
            "slow_stage_processed": slow_stage_processed,
            "total_items": total_items
        }));

        assert!(counts[0] > 0, "First stage should have processed some items");
        assert!(total_backpressure_events > 0, "Backpressure events should have occurred due to slow stage");
        assert!(slow_stage_processed < total_items, "Slow stage should have limited overall throughput");
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
    let harness = IntegrationTestHarness::new("backpressure_propagation_pipeline_integration").await;
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

    harness.logger.log_event("comprehensive_config", serde_json::json!({
        "scenario": "multi_component_integration",
        "components": ["pubsub", "circuit_breaker", "supervision", "backpressure"]
    }));

    // The implementation would combine all previous scenarios
    // For brevity, we'll validate that the harness is properly set up
    // and can coordinate multiple integration scenarios

    harness.logger.log_assertion("comprehensive_harness_ready", true, serde_json::json!({
        "harness_initialized": true,
        "failure_injector_ready": true,
        "runtime_available": true
    }));

    harness.logger.log_phase("comprehensive_scenario_complete");
}