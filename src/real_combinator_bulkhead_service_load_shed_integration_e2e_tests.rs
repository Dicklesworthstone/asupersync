//! br-e2e-144: Real combinator/bulkhead ↔ service/load_shed integration tests
//!
//! Verifies that bulkhead's saturation threshold correctly triggers load_shed
//! without dropping in-flight requests. Tests the integration between:
//!
//! - `combinator::bulkhead`: Resource isolation and saturation detection
//! - `service::load_shed`: Load shedding policies and threshold enforcement
//!
//! Key integration properties:
//! - Bulkhead saturation threshold correctly triggers load_shed activation
//! - In-flight requests are preserved during load shedding transitions
//! - Load shedding policies respect bulkhead capacity constraints
//! - Resource accounting remains consistent across both subsystems
//! - Graceful degradation without request dropping

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        channel::{mpsc, oneshot},
        combinator::bulkhead::{Bulkhead, BulkheadConfig, BulkheadStats, ResourceToken},
        cx::Cx,
        error::{Error, ErrorKind},
        runtime::Runtime,
        service::load_shed::{LoadShedConfig, LoadShedPolicy, LoadShedding, ShedDecision},
        sync::{Mutex, Semaphore},
        test_utils::{TestTracer, init_test_runtime},
        time::{Duration, Sleep},
        types::{Budget, Outcome, TaskId},
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::Instant;

    /// Test framework for bulkhead-load_shed integration scenarios
    struct BulkheadLoadShedTestFramework {
        runtime: Runtime,
        tracer: TestTracer,
        bulkhead: Bulkhead,
        load_shed: LoadShedding,
        stats: Arc<IntegrationStats>,
    }

    /// Statistics for bulkhead-load_shed integration
    #[derive(Debug)]
    struct IntegrationStats {
        requests_submitted: AtomicU64,
        requests_accepted: AtomicU64,
        requests_shed: AtomicU64,
        requests_completed: AtomicU64,
        saturation_events: AtomicU64,
        load_shed_activations: AtomicU64,
        in_flight_preserved: AtomicU64,
        policy_transitions: AtomicU64,
    }

    /// Configuration for integration testing scenarios
    struct IntegrationConfig {
        bulkhead_capacity: usize,
        saturation_threshold: f64,
        load_shed_policy: LoadShedPolicy,
        request_duration: Duration,
        ramp_rate: Duration,
    }

    /// Represents a request in the bulkhead-load_shed system
    struct IntegrationRequest {
        id: u64,
        submitted_at: Instant,
        priority: u8,
        resource_cost: u32,
        expected_duration: Duration,
    }

    /// Tracks request lifecycle through bulkhead and load_shed
    struct RequestTracker {
        active_requests: Arc<Mutex<HashMap<u64, IntegrationRequest>>>,
        completion_times: Arc<Mutex<VecDeque<(u64, Duration)>>>,
        shed_reasons: Arc<Mutex<HashMap<u64, ShedDecision>>>,
    }

    /// Policy controller for dynamic load shedding
    struct PolicyController {
        current_policy: Arc<Mutex<LoadShedPolicy>>,
        saturation_monitor: Arc<AtomicBool>,
        threshold_calculator: Arc<ThresholdCalculator>,
    }

    /// Calculates dynamic thresholds based on bulkhead state
    struct ThresholdCalculator {
        baseline_threshold: f64,
        adaptive_factor: Arc<AtomicU64>, // Fixed point: value * 1000
        saturation_history: Arc<Mutex<VecDeque<(Instant, f64)>>>,
    }

    impl BulkheadLoadShedTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let tracer = TestTracer::new();

            // Configure bulkhead with capacity and monitoring
            let bulkhead_config = BulkheadConfig {
                max_concurrent: config.bulkhead_capacity,
                max_queued: config.bulkhead_capacity * 2,
                timeout: Duration::from_secs(30),
                enable_stats: true,
            };
            let bulkhead = Bulkhead::new(bulkhead_config)?;

            // Configure load shedding with policy integration
            let load_shed_config = LoadShedConfig {
                policy: config.load_shed_policy.clone(),
                saturation_threshold: config.saturation_threshold,
                shed_probability: 0.1,
                grace_period: Duration::from_millis(100),
            };
            let load_shed = LoadShedding::new(load_shed_config)?;

            let stats = Arc::new(IntegrationStats {
                requests_submitted: AtomicU64::new(0),
                requests_accepted: AtomicU64::new(0),
                requests_shed: AtomicU64::new(0),
                requests_completed: AtomicU64::new(0),
                saturation_events: AtomicU64::new(0),
                load_shed_activations: AtomicU64::new(0),
                in_flight_preserved: AtomicU64::new(0),
                policy_transitions: AtomicU64::new(0),
            });

            Ok(Self {
                runtime,
                tracer,
                bulkhead,
                load_shed,
                stats,
            })
        }

        /// Execute integration test with request pattern
        async fn execute_integration_test(
            &self,
            cx: &Cx,
            request_pattern: Vec<IntegrationRequest>,
        ) -> Result<IntegrationResults, Error> {
            let tracker = Arc::new(RequestTracker {
                active_requests: Arc::new(Mutex::new(HashMap::new())),
                completion_times: Arc::new(Mutex::new(VecDeque::new())),
                shed_reasons: Arc::new(Mutex::new(HashMap::new())),
            });

            let policy_controller = Arc::new(PolicyController {
                current_policy: Arc::new(Mutex::new(LoadShedPolicy::Probabilistic)),
                saturation_monitor: Arc::new(AtomicBool::new(false)),
                threshold_calculator: Arc::new(ThresholdCalculator::new(0.8)),
            });

            // Start monitoring loop for bulkhead-load_shed coordination
            let monitor_handle = self
                .start_coordination_monitor(cx, &policy_controller)
                .await?;

            // Process requests through bulkhead and load_shed
            for request in request_pattern {
                let should_shed = self
                    .evaluate_load_shedding(cx, &request, &policy_controller)
                    .await?;

                if should_shed {
                    self.stats.requests_shed.fetch_add(1, Ordering::Relaxed);
                    let mut shed_reasons = tracker.shed_reasons.lock().await;
                    shed_reasons.insert(request.id, ShedDecision::LoadTooHigh);
                    continue;
                }

                // Attempt bulkhead admission
                match self.bulkhead.try_acquire(cx).await {
                    Ok(token) => {
                        self.stats.requests_accepted.fetch_add(1, Ordering::Relaxed);

                        // Track active request
                        let mut active = tracker.active_requests.lock().await;
                        active.insert(request.id, request.clone());
                        drop(active);

                        // Process request
                        let tracker_ref = Arc::clone(&tracker);
                        let stats_ref = Arc::clone(&self.stats);
                        cx.spawn(async move {
                            Sleep::new(request.expected_duration).await;

                            // Complete request
                            let mut active = tracker_ref.active_requests.lock().await;
                            active.remove(&request.id);
                            drop(active);

                            let mut completions = tracker_ref.completion_times.lock().await;
                            completions.push_back((request.id, request.submitted_at.elapsed()));
                            drop(completions);

                            stats_ref.requests_completed.fetch_add(1, Ordering::Relaxed);
                            drop(token); // Release bulkhead token
                        })
                        .await?;
                    }
                    Err(_) => {
                        // Bulkhead full - trigger saturation monitoring
                        self.stats.saturation_events.fetch_add(1, Ordering::Relaxed);
                        policy_controller
                            .saturation_monitor
                            .store(true, Ordering::Relaxed);
                    }
                }

                self.stats
                    .requests_submitted
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Wait for completion and collect results
            Sleep::new(Duration::from_secs(5)).await;
            monitor_handle.cancel().await;

            Ok(IntegrationResults {
                total_submitted: self.stats.requests_submitted.load(Ordering::Relaxed),
                total_accepted: self.stats.requests_accepted.load(Ordering::Relaxed),
                total_shed: self.stats.requests_shed.load(Ordering::Relaxed),
                total_completed: self.stats.requests_completed.load(Ordering::Relaxed),
                saturation_events: self.stats.saturation_events.load(Ordering::Relaxed),
                load_shed_activations: self.stats.load_shed_activations.load(Ordering::Relaxed),
                in_flight_preserved: self.stats.in_flight_preserved.load(Ordering::Relaxed),
                policy_transitions: self.stats.policy_transitions.load(Ordering::Relaxed),
            })
        }

        /// Evaluate whether request should be shed based on current state
        async fn evaluate_load_shedding(
            &self,
            cx: &Cx,
            request: &IntegrationRequest,
            policy_controller: &PolicyController,
        ) -> Result<bool, Error> {
            let bulkhead_stats = self.bulkhead.stats().await?;
            let current_utilization = bulkhead_stats.utilization_ratio();

            // Check if saturation threshold is exceeded
            let threshold = policy_controller
                .threshold_calculator
                .calculate_threshold(current_utilization)
                .await;
            if current_utilization > threshold {
                policy_controller
                    .saturation_monitor
                    .store(true, Ordering::Relaxed);
                self.stats
                    .load_shed_activations
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Apply load shedding policy
            let policy = {
                let p = policy_controller.current_policy.lock().await;
                p.clone()
            };

            match policy {
                LoadShedPolicy::Probabilistic => {
                    let shed_probability = (current_utilization - threshold).max(0.0) * 2.0;
                    Ok(fastrand::f64() < shed_probability)
                }
                LoadShedPolicy::Priority => {
                    let priority_threshold = (threshold * 255.0) as u8;
                    Ok(request.priority < priority_threshold)
                }
                LoadShedPolicy::ResourceCost => {
                    let cost_threshold = (threshold * 1000.0) as u32;
                    Ok(request.resource_cost > cost_threshold)
                }
                _ => Ok(false),
            }
        }

        /// Start coordination monitoring between bulkhead and load_shed
        async fn start_coordination_monitor(
            &self,
            cx: &Cx,
            policy_controller: &PolicyController,
        ) -> Result<oneshot::Receiver<()>, Error> {
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let stats_ref = Arc::clone(&self.stats);
            let policy_ref = Arc::clone(&policy_controller.current_policy);
            let saturation_ref = Arc::clone(&policy_controller.saturation_monitor);

            cx.spawn(async move {
                let mut monitor_interval = Sleep::new(Duration::from_millis(50));

                loop {
                    monitor_interval.await;

                    // Check for policy transitions needed based on saturation
                    if saturation_ref.load(Ordering::Relaxed) {
                        let mut current_policy = policy_ref.lock().await;
                        let new_policy = match *current_policy {
                            LoadShedPolicy::None => LoadShedPolicy::Probabilistic,
                            LoadShedPolicy::Probabilistic => LoadShedPolicy::Priority,
                            LoadShedPolicy::Priority => LoadShedPolicy::ResourceCost,
                            _ => *current_policy,
                        };

                        if new_policy != *current_policy {
                            *current_policy = new_policy;
                            stats_ref.policy_transitions.fetch_add(1, Ordering::Relaxed);
                        }

                        saturation_ref.store(false, Ordering::Relaxed);
                    }

                    // Check for cancellation
                    if cancel_rx.try_recv().is_ok() {
                        break;
                    }
                }
            })
            .await?;

            Ok(cancel_rx)
        }
    }

    impl ThresholdCalculator {
        fn new(baseline: f64) -> Self {
            Self {
                baseline_threshold: baseline,
                adaptive_factor: Arc::new(AtomicU64::new(1000)), // 1.0 in fixed point
                saturation_history: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        async fn calculate_threshold(&self, current_utilization: f64) -> f64 {
            let mut history = self.saturation_history.lock().await;
            let now = Instant::now();

            // Add current measurement
            history.push_back((now, current_utilization));

            // Remove old measurements (keep last 100ms)
            while let Some(&(timestamp, _)) = history.front() {
                if now.duration_since(timestamp) > Duration::from_millis(100) {
                    history.pop_front();
                } else {
                    break;
                }
            }

            // Calculate adaptive factor based on recent history
            if history.len() > 5 {
                let avg_utilization: f64 =
                    history.iter().map(|(_, u)| u).sum::<f64>() / history.len() as f64;
                let stability = 1.0
                    - (history
                        .iter()
                        .map(|(_, u)| (u - avg_utilization).abs())
                        .sum::<f64>()
                        / history.len() as f64);

                let adaptive_factor = 1.0 + (stability - 0.5) * 0.2; // Adjust threshold based on stability
                self.adaptive_factor
                    .store((adaptive_factor * 1000.0) as u64, Ordering::Relaxed);
            }

            let factor = self.adaptive_factor.load(Ordering::Relaxed) as f64 / 1000.0;
            self.baseline_threshold * factor
        }
    }

    /// Results from bulkhead-load_shed integration test
    #[derive(Debug)]
    struct IntegrationResults {
        total_submitted: u64,
        total_accepted: u64,
        total_shed: u64,
        total_completed: u64,
        saturation_events: u64,
        load_shed_activations: u64,
        in_flight_preserved: u64,
        policy_transitions: u64,
    }

    #[tokio::test]
    async fn test_bulkhead_saturation_triggers_load_shed() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            bulkhead_capacity: 10,
            saturation_threshold: 0.8,
            load_shed_policy: LoadShedPolicy::Probabilistic,
            request_duration: Duration::from_millis(100),
            ramp_rate: Duration::from_millis(10),
        };

        let framework = BulkheadLoadShedTestFramework::new(&cx, config)
            .await
            .unwrap();

        // Generate request pattern that will saturate bulkhead
        let mut requests = Vec::new();
        for i in 0..50 {
            requests.push(IntegrationRequest {
                id: i,
                submitted_at: Instant::now(),
                priority: (i % 10) as u8 * 25, // Varied priority
                resource_cost: 100 + (i % 5) as u32 * 50,
                expected_duration: Duration::from_millis(100 + (i % 3) as u64 * 50),
            });
        }

        let results = framework
            .execute_integration_test(&cx, requests)
            .await
            .unwrap();

        // Verify bulkhead saturation triggered load shedding
        assert!(
            results.saturation_events > 0,
            "Bulkhead should have experienced saturation"
        );
        assert!(
            results.load_shed_activations > 0,
            "Load shedding should have been activated"
        );
        assert!(
            results.total_shed > 0,
            "Some requests should have been shed"
        );
        assert!(
            results.total_accepted <= 10,
            "Accepted requests should not exceed bulkhead capacity"
        );

        // Verify in-flight requests were preserved
        assert_eq!(
            results.total_accepted, results.total_completed,
            "All accepted requests should complete"
        );

        cx.trace("Bulkhead saturation correctly triggered load shedding")
            .await;
    }

    #[tokio::test]
    async fn test_in_flight_requests_preserved_during_load_shed() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            bulkhead_capacity: 5,
            saturation_threshold: 0.6,
            load_shed_policy: LoadShedPolicy::Priority,
            request_duration: Duration::from_millis(200),
            ramp_rate: Duration::from_millis(20),
        };

        let framework = BulkheadLoadShedTestFramework::new(&cx, config)
            .await
            .unwrap();

        // Submit initial requests to fill bulkhead
        let mut requests = Vec::new();
        for i in 0..5 {
            requests.push(IntegrationRequest {
                id: i,
                submitted_at: Instant::now(),
                priority: 200, // High priority
                resource_cost: 100,
                expected_duration: Duration::from_millis(200),
            });
        }

        // Add requests that should be shed
        for i in 5..15 {
            requests.push(IntegrationRequest {
                id: i,
                submitted_at: Instant::now(),
                priority: 50, // Low priority - should be shed
                resource_cost: 150,
                expected_duration: Duration::from_millis(100),
            });
        }

        let results = framework
            .execute_integration_test(&cx, requests)
            .await
            .unwrap();

        // Verify behavior
        assert_eq!(
            results.total_accepted, 5,
            "Only bulkhead capacity should be accepted"
        );
        assert_eq!(
            results.total_completed, 5,
            "All in-flight requests should complete"
        );
        assert!(
            results.total_shed >= 5,
            "Low priority requests should be shed"
        );
        assert_eq!(
            results.in_flight_preserved, results.total_completed,
            "In-flight requests preserved"
        );

        cx.trace("In-flight requests preserved during load shedding transition")
            .await;
    }

    #[tokio::test]
    async fn test_dynamic_policy_adaptation() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            bulkhead_capacity: 8,
            saturation_threshold: 0.75,
            load_shed_policy: LoadShedPolicy::None,
            request_duration: Duration::from_millis(150),
            ramp_rate: Duration::from_millis(15),
        };

        let framework = BulkheadLoadShedTestFramework::new(&cx, config)
            .await
            .unwrap();

        // Generate pattern with increasing load
        let mut requests = Vec::new();
        for i in 0..40 {
            let load_factor = (i as f64 / 40.0) * 2.0; // Gradually increase load
            requests.push(IntegrationRequest {
                id: i,
                submitted_at: Instant::now(),
                priority: ((1.0 - load_factor) * 255.0) as u8,
                resource_cost: (load_factor * 300.0) as u32,
                expected_duration: Duration::from_millis(150),
            });
        }

        let results = framework
            .execute_integration_test(&cx, requests)
            .await
            .unwrap();

        // Verify adaptive policy transitions occurred
        assert!(
            results.policy_transitions > 0,
            "Policy should have adapted to increasing load"
        );
        assert!(
            results.saturation_events > 0,
            "Should have detected saturation"
        );
        assert!(
            results.load_shed_activations > 0,
            "Load shedding should have activated"
        );

        // Verify system stability
        let acceptance_rate = results.total_accepted as f64 / results.total_submitted as f64;
        assert!(
            acceptance_rate > 0.2 && acceptance_rate < 1.0,
            "System should maintain controlled acceptance rate"
        );

        cx.trace("Dynamic policy adaptation maintained system stability")
            .await;
    }

    #[tokio::test]
    async fn test_threshold_coordination_edge_cases() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            bulkhead_capacity: 3,
            saturation_threshold: 0.9,
            load_shed_policy: LoadShedPolicy::ResourceCost,
            request_duration: Duration::from_millis(50),
            ramp_rate: Duration::from_millis(5),
        };

        let framework = BulkheadLoadShedTestFramework::new(&cx, config)
            .await
            .unwrap();

        // Test edge cases: rapid saturation/desaturation cycles
        let mut requests = Vec::new();
        for cycle in 0..5 {
            // Burst of requests
            for i in 0..6 {
                requests.push(IntegrationRequest {
                    id: cycle * 10 + i,
                    submitted_at: Instant::now(),
                    priority: 255,
                    resource_cost: if i < 3 { 50 } else { 500 }, // Mix of costs
                    expected_duration: Duration::from_millis(50),
                });
            }

            // Gap between bursts
            requests.push(IntegrationRequest {
                id: cycle * 10 + 9,
                submitted_at: Instant::now(),
                priority: 128,
                resource_cost: 100,
                expected_duration: Duration::from_millis(200), // Longer gap
            });
        }

        let results = framework
            .execute_integration_test(&cx, requests)
            .await
            .unwrap();

        // Verify edge case handling
        assert!(
            results.saturation_events >= 5,
            "Should handle multiple saturation cycles"
        );
        assert!(results.total_shed > 0, "High-cost requests should be shed");
        assert_eq!(
            results.total_accepted, results.total_completed,
            "No request drops during transitions"
        );

        cx.trace("Threshold coordination handled edge cases correctly")
            .await;
    }

    #[tokio::test]
    async fn test_resource_accounting_consistency() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            bulkhead_capacity: 12,
            saturation_threshold: 0.7,
            load_shed_policy: LoadShedPolicy::Probabilistic,
            request_duration: Duration::from_millis(100),
            ramp_rate: Duration::from_millis(8),
        };

        let framework = BulkheadLoadShedTestFramework::new(&cx, config)
            .await
            .unwrap();

        // Generate requests with varied resource requirements
        let mut requests = Vec::new();
        let mut expected_total_cost = 0u64;

        for i in 0..30 {
            let resource_cost = match i % 4 {
                0 => 50,  // Light requests
                1 => 100, // Medium requests
                2 => 200, // Heavy requests
                _ => 500, // Very heavy requests
            };

            expected_total_cost += resource_cost as u64;

            requests.push(IntegrationRequest {
                id: i,
                submitted_at: Instant::now(),
                priority: 128,
                resource_cost,
                expected_duration: Duration::from_millis(100),
            });
        }

        let results = framework
            .execute_integration_test(&cx, requests)
            .await
            .unwrap();

        // Verify resource accounting consistency
        let total_processed = results.total_accepted + results.total_shed;
        assert_eq!(
            total_processed, results.total_submitted,
            "All requests should be accounted for"
        );
        assert_eq!(
            results.total_accepted, results.total_completed,
            "Resource accounting consistent"
        );

        // Verify load shedding preserved system capacity
        assert!(
            results.total_accepted <= config.bulkhead_capacity as u64,
            "Capacity respected"
        );

        cx.trace("Resource accounting remained consistent across subsystems")
            .await;
    }
}
