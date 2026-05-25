//! Real E2E integration tests: lab/oracle/quiescence ↔ obligation/leak_check (br-e2e-185).
//!
//! Tests that quiescence oracle correctly observes leak_check assertion in production-like load.
//! Verifies the integration between:
//!
//! - `lab::oracle::quiescence`: Quiescence oracle monitoring system state transitions
//! - `obligation::leak_check`: Obligation leak detection and assertion system
//!
//! Key integration properties:
//! - Quiescence oracle correctly detects obligation leaks under production load
//! - Leak check assertions properly trigger oracle state transitions
//! - Oracle maintains accuracy during high-frequency obligation churn
//! - Production-scale load patterns don't compromise leak detection
//! - Quiescence detection remains reliable with concurrent obligation lifecycles
//! - Oracle timing windows capture transient leak states correctly

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::{Cx, Scope},
        error::{Error, Result},
        lab::{
            oracle::{
                quiescence::{
                    QuiescenceOracle, QuiescenceState, QuiescenceTransition,
                    QuiescenceConfig, StateObserver, TransitionEvent,
                },
                ObservationWindow, OracleEvent, OracleMetrics,
            },
            LabRuntime, VirtualTime, DeterministicScheduler,
        },
        obligation::{
            leak_check::{
                LeakChecker, LeakCheckConfig, LeakAssertion, LeakDetectionResult,
                ObligationTracker, LeakCheckpoint, LeakSeverity,
            },
            ObligationId, ObligationKind, ObligationState, ObligationEvent,
            ObligationRegistry, ObligationHandle,
        },
        runtime::{spawn, Runtime},
        sync::{Arc, Mutex, RwLock},
        time::{sleep, Duration, Instant},
        types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time},
    };
    use std::{
        collections::{HashMap, HashSet, VecDeque, BTreeMap},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Quiescence Oracle + Leak Check Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IntegrationEventType {
        OracleInitialized,
        LeakCheckerStarted,
        ObligationCreated,
        ObligationLeaked,
        LeakDetected,
        QuiescenceAchieved,
        QuiescenceBroken,
        LoadPhaseStarted,
        LoadPhaseCompleted,
        AssertionTriggered,
        StateTransition,
    }

    #[derive(Debug, Clone)]
    struct IntegrationEvent {
        event_type: IntegrationEventType,
        obligation_id: Option<ObligationId>,
        quiescence_state: Option<QuiescenceState>,
        leak_severity: Option<LeakSeverity>,
        load_factor: Option<f64>,
        timestamp: Instant,
        metadata: HashMap<String, String>,
    }

    #[derive(Debug)]
    struct QuiescenceLeakTestFramework {
        runtime: Arc<Runtime>,
        lab_runtime: Arc<LabRuntime>,
        quiescence_oracle: Arc<QuiescenceOracle>,
        leak_checker: Arc<RwLock<LeakChecker>>,
        obligation_registry: Arc<RwLock<ObligationRegistry>>,
        integration_events: Arc<Mutex<Vec<IntegrationEvent>>>,
        load_generator: Arc<Mutex<LoadGenerator>>,
        oracle_metrics: Arc<Mutex<OracleMetrics>>,
        production_config: ProductionLoadConfig,
    }

    #[derive(Debug, Clone)]
    struct ProductionLoadConfig {
        peak_obligation_rate: u32,  // obligations per second
        concurrent_workers: usize,
        load_duration: Duration,
        leak_injection_rate: f64,   // probability of intentional leak
        burst_patterns: Vec<BurstPattern>,
        quiescence_windows: Vec<Duration>,
    }

    #[derive(Debug, Clone)]
    struct BurstPattern {
        intensity_multiplier: f64,
        duration: Duration,
        obligation_types: Vec<ObligationKind>,
    }

    #[derive(Debug)]
    struct LoadGenerator {
        active_obligations: HashMap<ObligationId, ObligationLifecycle>,
        completion_patterns: Vec<CompletionPattern>,
        leak_scenarios: Vec<LeakScenario>,
        load_phase: LoadPhase,
        metrics: LoadMetrics,
    }

    #[derive(Debug, Clone)]
    struct ObligationLifecycle {
        id: ObligationId,
        kind: ObligationKind,
        created_at: Instant,
        expected_completion: Instant,
        should_leak: bool,
        completion_probability: f64,
    }

    #[derive(Debug, Clone)]
    struct CompletionPattern {
        delay_distribution: DelayDistribution,
        success_rate: f64,
        leak_probability: f64,
    }

    #[derive(Debug, Clone)]
    enum DelayDistribution {
        Constant(Duration),
        Uniform { min: Duration, max: Duration },
        Exponential { mean: Duration },
        Normal { mean: Duration, stddev: Duration },
    }

    #[derive(Debug, Clone)]
    struct LeakScenario {
        scenario_name: String,
        trigger_condition: LeakTriggerCondition,
        leak_count: usize,
        expected_detection_time: Duration,
    }

    #[derive(Debug, Clone)]
    enum LeakTriggerCondition {
        TimeElapsed(Duration),
        ObligationCount(usize),
        LoadFactor(f64),
        QuiescenceState(QuiescenceState),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LoadPhase {
        Rampup,
        Sustained,
        Burst,
        Quiesce,
        Complete,
    }

    #[derive(Debug, Default)]
    struct LoadMetrics {
        total_obligations_created: u64,
        total_obligations_completed: u64,
        total_obligations_leaked: u64,
        peak_concurrent_obligations: usize,
        average_completion_time: Duration,
        quiescence_periods: Vec<Duration>,
        leak_detection_latencies: Vec<Duration>,
        oracle_state_transitions: u64,
    }

    impl QuiescenceLeakTestFramework {
        async fn new() -> Result<Self> {
            let runtime = Arc::new(Runtime::new().await?);
            let lab_runtime = Arc::new(LabRuntime::new_deterministic().await?);

            let oracle_config = QuiescenceConfig::new()
                .with_observation_window(Duration::from_millis(100))
                .with_transition_threshold(0.95)
                .with_leak_sensitivity(LeakSeverity::Medium);

            let quiescence_oracle = Arc::new(QuiescenceOracle::new(oracle_config).await?);

            let leak_config = LeakCheckConfig::new()
                .with_check_interval(Duration::from_millis(50))
                .with_assertion_mode(true)
                .with_production_tolerances(true);

            let leak_checker = Arc::new(RwLock::new(LeakChecker::new(leak_config).await?));
            let obligation_registry = Arc::new(RwLock::new(ObligationRegistry::new()));
            let integration_events = Arc::new(Mutex::new(Vec::new()));
            let load_generator = Arc::new(Mutex::new(LoadGenerator::new()));
            let oracle_metrics = Arc::new(Mutex::new(OracleMetrics::default()));

            let production_config = ProductionLoadConfig {
                peak_obligation_rate: 500, // 500 obligations/sec
                concurrent_workers: 8,
                load_duration: Duration::from_secs(30),
                leak_injection_rate: 0.01, // 1% intentional leak rate
                burst_patterns: vec![
                    BurstPattern {
                        intensity_multiplier: 3.0,
                        duration: Duration::from_secs(2),
                        obligation_types: vec![ObligationKind::Permit, ObligationKind::Lease],
                    },
                    BurstPattern {
                        intensity_multiplier: 5.0,
                        duration: Duration::from_millis(500),
                        obligation_types: vec![ObligationKind::Ack],
                    },
                ],
                quiescence_windows: vec![
                    Duration::from_millis(200),
                    Duration::from_millis(500),
                    Duration::from_secs(1),
                ],
            };

            Ok(Self {
                runtime,
                lab_runtime,
                quiescence_oracle,
                leak_checker,
                obligation_registry,
                integration_events,
                load_generator,
                oracle_metrics,
                production_config,
            })
        }

        async fn start_integrated_monitoring(&self, cx: &Cx) -> Result<()> {
            // Connect oracle to leak checker
            let oracle = self.quiescence_oracle.clone();
            let leak_checker = self.leak_checker.clone();
            let events = self.integration_events.clone();

            // Start oracle observation task
            spawn(cx, Budget::unlimited(), async move {
                let mut observer = oracle.create_observer().await?;

                loop {
                    match observer.wait_for_transition().await {
                        Ok(transition) => {
                            // Record oracle state transition
                            let event = IntegrationEvent {
                                event_type: IntegrationEventType::StateTransition,
                                obligation_id: None,
                                quiescence_state: Some(transition.new_state),
                                leak_severity: None,
                                load_factor: None,
                                timestamp: Instant::now(),
                                metadata: [("transition".to_string(), format!("{:?}", transition))].into(),
                            };
                            events.lock().await.push(event);

                            // Trigger leak check on quiescence transition
                            if matches!(transition.new_state, QuiescenceState::Achieved) {
                                let mut checker = leak_checker.write().await;
                                if let Ok(results) = checker.perform_leak_check().await {
                                    if !results.is_empty() {
                                        let leak_event = IntegrationEvent {
                                            event_type: IntegrationEventType::LeakDetected,
                                            obligation_id: results.first().map(|r| r.obligation_id),
                                            quiescence_state: Some(QuiescenceState::Achieved),
                                            leak_severity: results.iter().map(|r| r.severity).max(),
                                            load_factor: None,
                                            timestamp: Instant::now(),
                                            metadata: [("leak_count".to_string(), results.len().to_string())].into(),
                                        };
                                        events.lock().await.push(leak_event);
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                Ok(())
            });

            // Start leak checker monitoring task
            let leak_checker_ref = self.leak_checker.clone();
            let events_ref = self.integration_events.clone();

            spawn(cx, Budget::unlimited(), async move {
                let mut check_interval = tokio::time::interval(Duration::from_millis(50));

                loop {
                    check_interval.tick().await;

                    let leak_results = {
                        let mut checker = leak_checker_ref.write().await;
                        checker.perform_leak_check().await.unwrap_or_default()
                    };

                    if !leak_results.is_empty() {
                        for result in leak_results {
                            let event = IntegrationEvent {
                                event_type: IntegrationEventType::LeakDetected,
                                obligation_id: Some(result.obligation_id),
                                quiescence_state: None,
                                leak_severity: Some(result.severity),
                                load_factor: None,
                                timestamp: Instant::now(),
                                metadata: [("assertion_message".to_string(), result.assertion_message)].into(),
                            };
                            events_ref.lock().await.push(event);
                        }
                    }
                }
            });

            Ok(())
        }

        async fn generate_production_load(&self, cx: &Cx) -> Result<()> {
            let config = &self.production_config;
            let obligation_rate = config.peak_obligation_rate;
            let worker_count = config.concurrent_workers;

            // Update load phase
            {
                let mut generator = self.load_generator.lock().await;
                generator.load_phase = LoadPhase::Rampup;
            }

            let framework_ref = &self;

            // Spawn worker tasks for concurrent load generation
            let tasks: Vec<_> = (0..worker_count).map(|worker_id| {
                spawn(cx, Budget::unlimited(), async move {
                    let obligations_per_worker = obligation_rate / worker_count as u32;
                    let interval = Duration::from_nanos(1_000_000_000 / obligations_per_worker as u64);

                    for obligation_seq in 0..obligations_per_worker * 30 { // 30 seconds worth
                        let obligation_id = ObligationId::new_for_test(worker_id as u64, obligation_seq as u64);

                        // Determine obligation characteristics
                        let should_leak = rand::random::<f64>() < config.leak_injection_rate;
                        let obligation_kind = match obligation_seq % 3 {
                            0 => ObligationKind::Permit,
                            1 => ObligationKind::Ack,
                            _ => ObligationKind::Lease,
                        };

                        // Create obligation
                        framework_ref.create_tracked_obligation(
                            cx,
                            obligation_id,
                            obligation_kind,
                            should_leak,
                        ).await?;

                        // Wait for next obligation
                        sleep(interval).await;

                        // Check for load phase transitions
                        let current_phase = framework_ref.load_generator.lock().await.load_phase;
                        if matches!(current_phase, LoadPhase::Complete) {
                            break;
                        }
                    }

                    Ok(())
                })
            }).collect();

            // Wait for load generation to complete
            for task in tasks {
                let _ = task.join().await;
            }

            // Update to quiesce phase
            {
                let mut generator = self.load_generator.lock().await;
                generator.load_phase = LoadPhase::Quiesce;
            }

            Ok(())
        }

        async fn create_tracked_obligation(
            &self,
            cx: &Cx,
            obligation_id: ObligationId,
            kind: ObligationKind,
            should_leak: bool,
        ) -> Result<()> {
            // Register obligation in registry
            {
                let mut registry = self.obligation_registry.write().await;
                let handle = ObligationHandle::new(obligation_id, kind);
                registry.register_obligation(handle)?;
            }

            // Track in load generator
            {
                let mut generator = self.load_generator.lock().await;
                let lifecycle = ObligationLifecycle {
                    id: obligation_id,
                    kind,
                    created_at: Instant::now(),
                    expected_completion: Instant::now() + Duration::from_millis(rand::random::<u64>() % 1000),
                    should_leak,
                    completion_probability: if should_leak { 0.0 } else { 0.95 },
                };
                generator.active_obligations.insert(obligation_id, lifecycle);
                generator.metrics.total_obligations_created += 1;
            }

            // Record integration event
            let event = IntegrationEvent {
                event_type: IntegrationEventType::ObligationCreated,
                obligation_id: Some(obligation_id),
                quiescence_state: None,
                leak_severity: None,
                load_factor: Some(self.get_current_load_factor().await),
                timestamp: Instant::now(),
                metadata: [
                    ("kind".to_string(), format!("{:?}", kind)),
                    ("should_leak".to_string(), should_leak.to_string()),
                ].into(),
            };
            self.integration_events.lock().await.push(event);

            // Schedule completion or leak
            if should_leak {
                // Intentionally don't complete - let it leak
                self.schedule_leak(cx, obligation_id).await?;
            } else {
                // Schedule normal completion
                self.schedule_completion(cx, obligation_id).await?;
            }

            Ok(())
        }

        async fn schedule_completion(&self, cx: &Cx, obligation_id: ObligationId) -> Result<()> {
            let completion_delay = {
                let generator = self.load_generator.lock().await;
                if let Some(lifecycle) = generator.active_obligations.get(&obligation_id) {
                    lifecycle.expected_completion.saturating_duration_since(Instant::now())
                } else {
                    Duration::from_millis(100)
                }
            };

            let framework_ref = self.clone();
            spawn(cx, Budget::unlimited(), async move {
                sleep(completion_delay).await;
                framework_ref.complete_obligation(obligation_id).await.ok();
            });

            Ok(())
        }

        async fn schedule_leak(&self, cx: &Cx, obligation_id: ObligationId) -> Result<()> {
            // Record that this obligation will leak
            let event = IntegrationEvent {
                event_type: IntegrationEventType::ObligationLeaked,
                obligation_id: Some(obligation_id),
                quiescence_state: None,
                leak_severity: Some(LeakSeverity::Medium),
                load_factor: Some(self.get_current_load_factor().await),
                timestamp: Instant::now(),
                metadata: [("intentional".to_string(), "true".to_string())].into(),
            };
            self.integration_events.lock().await.push(event);

            // Update metrics
            {
                let mut generator = self.load_generator.lock().await;
                generator.metrics.total_obligations_leaked += 1;
            }

            Ok(())
        }

        async fn complete_obligation(&self, obligation_id: ObligationId) -> Result<()> {
            // Remove from registry
            {
                let mut registry = self.obligation_registry.write().await;
                registry.complete_obligation(obligation_id)?;
            }

            // Update load generator
            {
                let mut generator = self.load_generator.lock().await;
                if generator.active_obligations.remove(&obligation_id).is_some() {
                    generator.metrics.total_obligations_completed += 1;
                }
            }

            Ok(())
        }

        async fn wait_for_quiescence(&self, timeout: Duration) -> Result<bool> {
            let start = Instant::now();

            loop {
                let current_state = self.quiescence_oracle.current_state().await?;
                if matches!(current_state, QuiescenceState::Achieved) {
                    return Ok(true);
                }

                if start.elapsed() > timeout {
                    return Ok(false);
                }

                sleep(Duration::from_millis(10)).await;
            }
        }

        async fn trigger_leak_assertions(&self) -> Result<Vec<LeakDetectionResult>> {
            let mut leak_checker = self.leak_checker.write().await;
            let results = leak_checker.perform_leak_check().await?;

            // Record assertion events
            for result in &results {
                let event = IntegrationEvent {
                    event_type: IntegrationEventType::AssertionTriggered,
                    obligation_id: Some(result.obligation_id),
                    quiescence_state: None,
                    leak_severity: Some(result.severity),
                    load_factor: Some(self.get_current_load_factor().await),
                    timestamp: Instant::now(),
                    metadata: [("assertion".to_string(), result.assertion_message.clone())].into(),
                };
                self.integration_events.lock().await.push(event);
            }

            Ok(results)
        }

        async fn get_current_load_factor(&self) -> f64 {
            let generator = self.load_generator.lock().await;
            let active_count = generator.active_obligations.len() as f64;
            let peak_capacity = (self.production_config.peak_obligation_rate as f64) * 2.0; // Allow 2s worth
            active_count / peak_capacity
        }

        async fn verify_oracle_accuracy(&self) -> Result<bool> {
            let events = self.integration_events.lock().await;

            // Count leak detection events and oracle transitions
            let leak_events: Vec<_> = events.iter()
                .filter(|e| matches!(e.event_type, IntegrationEventType::LeakDetected))
                .collect();

            let quiescence_events: Vec<_> = events.iter()
                .filter(|e| matches!(e.event_type, IntegrationEventType::StateTransition))
                .collect();

            // Verify that oracle detected state changes correctly
            let expected_leaks = events.iter()
                .filter(|e| matches!(e.event_type, IntegrationEventType::ObligationLeaked))
                .count();

            let detected_leaks = leak_events.len();

            // Oracle should detect at least 80% of intentional leaks under production load
            let detection_rate = detected_leaks as f64 / expected_leaks.max(1) as f64;
            Ok(detection_rate >= 0.8)
        }

        async fn get_integration_event_count(&self, event_type: IntegrationEventType) -> usize {
            self.integration_events.lock().await
                .iter()
                .filter(|event| event.event_type == event_type)
                .count()
        }

        async fn get_load_metrics(&self) -> LoadMetrics {
            self.load_generator.lock().await.metrics.clone()
        }
    }

    // Clone implementation for the framework (needed for Arc usage)
    impl Clone for QuiescenceLeakTestFramework {
        fn clone(&self) -> Self {
            Self {
                runtime: self.runtime.clone(),
                lab_runtime: self.lab_runtime.clone(),
                quiescence_oracle: self.quiescence_oracle.clone(),
                leak_checker: self.leak_checker.clone(),
                obligation_registry: self.obligation_registry.clone(),
                integration_events: self.integration_events.clone(),
                load_generator: self.load_generator.clone(),
                oracle_metrics: self.oracle_metrics.clone(),
                production_config: self.production_config.clone(),
            }
        }
    }

    impl LoadGenerator {
        fn new() -> Self {
            Self {
                active_obligations: HashMap::new(),
                completion_patterns: vec![
                    CompletionPattern {
                        delay_distribution: DelayDistribution::Exponential {
                            mean: Duration::from_millis(200),
                        },
                        success_rate: 0.95,
                        leak_probability: 0.01,
                    },
                ],
                leak_scenarios: vec![
                    LeakScenario {
                        scenario_name: "High Load Leak".to_string(),
                        trigger_condition: LeakTriggerCondition::LoadFactor(0.8),
                        leak_count: 5,
                        expected_detection_time: Duration::from_millis(500),
                    },
                    LeakScenario {
                        scenario_name: "Quiescence Leak".to_string(),
                        trigger_condition: LeakTriggerCondition::QuiescenceState(QuiescenceState::Achieved),
                        leak_count: 2,
                        expected_detection_time: Duration::from_millis(100),
                    },
                ],
                load_phase: LoadPhase::Rampup,
                metrics: LoadMetrics::default(),
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_oracle_leak_detection_integration() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            // Start integrated monitoring
            framework.start_integrated_monitoring(cx).await.unwrap();

            // Create some obligations with known leaks
            for i in 0..10 {
                let should_leak = i % 3 == 0; // 33% leak rate
                framework.create_tracked_obligation(
                    cx,
                    ObligationId::new_for_test(1, i),
                    ObligationKind::Permit,
                    should_leak,
                ).await.unwrap();
            }

            // Wait for obligations to be processed
            sleep(Duration::from_secs(1)).await;

            // Trigger leak check
            let leak_results = framework.trigger_leak_assertions().await.unwrap();

            // Should detect the intentional leaks
            assert!(!leak_results.is_empty(), "Should detect some leaks");

            // Wait for quiescence
            let quiescence_achieved = framework.wait_for_quiescence(Duration::from_secs(2)).await.unwrap();
            assert!(quiescence_achieved, "Should achieve quiescence after obligations complete");

            // Verify oracle recorded appropriate events
            let leak_detections = framework.get_integration_event_count(IntegrationEventType::LeakDetected).await;
            assert!(leak_detections > 0, "Should have detected leaks");

            let state_transitions = framework.get_integration_event_count(IntegrationEventType::StateTransition).await;
            assert!(state_transitions > 0, "Should have oracle state transitions");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_production_load_leak_detection() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            // Start integrated monitoring
            framework.start_integrated_monitoring(cx).await.unwrap();

            // Generate production-like load
            framework.generate_production_load(cx).await.unwrap();

            // Wait for load generation to complete
            sleep(Duration::from_secs(2)).await;

            // Verify oracle accuracy under production load
            let oracle_accurate = framework.verify_oracle_accuracy().await.unwrap();
            assert!(oracle_accurate, "Oracle should maintain accuracy under production load");

            // Check that leaks were detected
            let leak_detections = framework.get_integration_event_count(IntegrationEventType::LeakDetected).await;
            assert!(leak_detections > 0, "Should detect leaks under production load");

            // Verify load metrics
            let metrics = framework.get_load_metrics().await;
            assert!(metrics.total_obligations_created > 1000, "Should create substantial obligations");
            assert!(metrics.total_obligations_leaked > 0, "Should have some intentional leaks");

            // Oracle should eventually achieve quiescence
            let quiescence_achieved = framework.wait_for_quiescence(Duration::from_secs(5)).await.unwrap();
            assert!(quiescence_achieved, "Should achieve quiescence after production load");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_leak_assertion_accuracy() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.start_integrated_monitoring(cx).await.unwrap();

            let framework_ref = &framework;

            // Create concurrent obligation streams with different leak patterns
            let tasks: Vec<_> = (0..4).map(|stream_id| {
                spawn(cx, Budget::unlimited(), async move {
                    for i in 0..50 {
                        let obligation_id = ObligationId::new_for_test(stream_id as u64, i);
                        let should_leak = match stream_id {
                            0 => i % 10 == 0,  // 10% leak rate
                            1 => i % 5 == 0,   // 20% leak rate
                            2 => false,        // No leaks
                            _ => i % 20 == 0,  // 5% leak rate
                        };

                        framework_ref.create_tracked_obligation(
                            cx,
                            obligation_id,
                            ObligationKind::Permit,
                            should_leak,
                        ).await.unwrap();

                        // Vary timing to create realistic patterns
                        sleep(Duration::from_millis(10 + (i % 50) as u64)).await;
                    }
                    Ok(())
                })
            }).collect();

            // Wait for concurrent streams to complete
            for task in tasks {
                let _ = task.join().await;
            }

            // Wait for processing
            sleep(Duration::from_secs(1)).await;

            // Trigger comprehensive leak check
            let leak_results = framework.trigger_leak_assertions().await.unwrap();

            // Should detect leaks proportional to injection rate
            let expected_leaks = framework.get_integration_event_count(IntegrationEventType::ObligationLeaked).await;
            let detected_leaks = leak_results.len();

            assert!(detected_leaks > 0, "Should detect some leaks");
            assert!(detected_leaks >= expected_leaks / 2, "Should detect at least half of intentional leaks");

            // Oracle should observe the leak detection activity
            let oracle_events = framework.get_integration_event_count(IntegrationEventType::StateTransition).await;
            assert!(oracle_events > 0, "Oracle should observe state changes");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_quiescence_timing_with_leak_assertions() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.start_integrated_monitoring(cx).await.unwrap();

            // Phase 1: Create obligations without leaks
            for i in 0..20 {
                framework.create_tracked_obligation(
                    cx,
                    ObligationId::new_for_test(1, i),
                    ObligationKind::Ack,
                    false, // No leaks
                ).await.unwrap();
            }

            // Wait for clean quiescence
            let clean_quiescence = framework.wait_for_quiescence(Duration::from_secs(2)).await.unwrap();
            assert!(clean_quiescence, "Should achieve quiescence with clean obligations");

            // Phase 2: Introduce leaky obligations
            for i in 20..30 {
                framework.create_tracked_obligation(
                    cx,
                    ObligationId::new_for_test(1, i),
                    ObligationKind::Permit,
                    true, // All leak
                ).await.unwrap();
            }

            // Wait and check that quiescence is broken
            sleep(Duration::from_millis(500)).await;
            let current_state = framework.quiescence_oracle.current_state().await.unwrap();
            assert!(!matches!(current_state, QuiescenceState::Achieved),
                "Quiescence should be broken by leaks");

            // Trigger leak detection
            let leak_results = framework.trigger_leak_assertions().await.unwrap();
            assert_eq!(leak_results.len(), 10, "Should detect all 10 intentional leaks");

            // Verify oracle observed the leak introduction
            let state_transitions = framework.get_integration_event_count(IntegrationEventType::StateTransition).await;
            assert!(state_transitions >= 2, "Should have transitions: achieved -> broken");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_leak_severity_classification() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.start_integrated_monitoring(cx).await.unwrap();

            // Create obligations with different leak characteristics
            let leak_scenarios = vec![
                (ObligationKind::Permit, 5),   // Medium severity
                (ObligationKind::Ack, 1),      // Low severity
                (ObligationKind::Lease, 10),   // High severity
            ];

            for (kind, count) in leak_scenarios {
                for i in 0..count {
                    framework.create_tracked_obligation(
                        cx,
                        ObligationId::new_for_test(kind as u64, i),
                        kind,
                        true, // All leak
                    ).await.unwrap();
                }
            }

            sleep(Duration::from_millis(500)).await;

            // Trigger leak detection
            let leak_results = framework.trigger_leak_assertions().await.unwrap();
            assert!(!leak_results.is_empty(), "Should detect leaks");

            // Verify severity classification
            let high_severity = leak_results.iter()
                .filter(|r| matches!(r.severity, LeakSeverity::High))
                .count();
            let medium_severity = leak_results.iter()
                .filter(|r| matches!(r.severity, LeakSeverity::Medium))
                .count();

            assert!(high_severity > 0, "Should classify some leaks as high severity");
            assert!(medium_severity > 0, "Should classify some leaks as medium severity");

            // Oracle should respond appropriately to high severity leaks
            let events = framework.integration_events.lock().await;
            let high_severity_events: Vec<_> = events.iter()
                .filter(|e| matches!(e.leak_severity, Some(LeakSeverity::High)))
                .collect();

            assert!(!high_severity_events.is_empty(),
                "Should record high severity leak events");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_oracle_recovery_after_leak_resolution() {
        let framework = QuiescenceLeakTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.start_integrated_monitoring(cx).await.unwrap();

            // Phase 1: Create system with leaks
            for i in 0..15 {
                let should_leak = i < 5; // First 5 leak, others complete normally
                framework.create_tracked_obligation(
                    cx,
                    ObligationId::new_for_test(1, i),
                    ObligationKind::Permit,
                    should_leak,
                ).await.unwrap();
            }

            sleep(Duration::from_millis(800)).await;

            // Detect initial leaks
            let initial_leaks = framework.trigger_leak_assertions().await.unwrap();
            assert_eq!(initial_leaks.len(), 5, "Should detect 5 intentional leaks");

            // Phase 2: "Resolve" leaks by completing the leaked obligations manually
            for i in 0..5 {
                framework.complete_obligation(ObligationId::new_for_test(1, i)).await.unwrap();
            }

            // Wait for oracle to observe resolution
            sleep(Duration::from_millis(300)).await;

            // Phase 3: Verify oracle achieves quiescence after leak resolution
            let recovery_achieved = framework.wait_for_quiescence(Duration::from_secs(2)).await.unwrap();
            assert!(recovery_achieved, "Oracle should achieve quiescence after leak resolution");

            // Verify no more leaks detected
            let final_leaks = framework.trigger_leak_assertions().await.unwrap();
            assert!(final_leaks.is_empty(), "Should detect no leaks after resolution");

            // Check state transition pattern: broken -> achieved
            let state_transitions = framework.get_integration_event_count(IntegrationEventType::StateTransition).await;
            assert!(state_transitions >= 2, "Should have transitions for leak introduction and resolution");

            Ok(())
        }).await.unwrap();
    }
}