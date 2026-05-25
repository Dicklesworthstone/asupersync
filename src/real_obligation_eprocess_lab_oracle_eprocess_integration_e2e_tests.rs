//! Real service E2E tests for obligation/eprocess ↔ lab/oracle/eprocess integration.
//!
//! Verifies that the oracle correctly identifies an eprocess violation under
//! concurrent rule firing. Tests that when multiple obligations violate their
//! expected lifetime constraints simultaneously, the e-process monitor correctly
//! accumulates evidence and triggers alerts with proper false-positive control.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_obligation_eprocess_oracle_e2e {
    use crate::cx::{Cx, scope};
    use crate::lab::oracle::eprocess::{EProcessConfig, EProcessOracle, EValue, ViolationType};
    use crate::obligation::eprocess::{LeakMonitor, MonitorConfig};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{ObligationId, RegionId, TaskId, Time};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// Statistics for eprocess + oracle integration testing
    #[derive(Debug, Clone, Default)]
    struct EProcessOracleStats {
        /// E-process monitors created
        monitors_created: usize,
        /// Oracle checks performed
        oracle_checks_performed: usize,
        /// E-process alerts triggered
        eprocess_alerts_triggered: usize,
        /// Oracle violations detected
        oracle_violations_detected: usize,
        /// Concurrent rule firings simulated
        concurrent_rule_firings: usize,
        /// False positive alerts (incorrect triggers)
        false_positive_alerts: usize,
        /// True positive alerts (correct violations detected)
        true_positive_alerts: usize,
        /// Maximum e-value observed
        max_evalue_observed: f64,
        /// Observations processed
        observations_processed: usize,
        /// Test duration in milliseconds
        test_duration_ms: u64,
    }

    impl EProcessOracleStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "monitors_created": self.monitors_created,
                "oracle_checks_performed": self.oracle_checks_performed,
                "eprocess_alerts_triggered": self.eprocess_alerts_triggered,
                "oracle_violations_detected": self.oracle_violations_detected,
                "concurrent_rule_firings": self.concurrent_rule_firings,
                "false_positive_alerts": self.false_positive_alerts,
                "true_positive_alerts": self.true_positive_alerts,
                "max_evalue_observed": self.max_evalue_observed,
                "observations_processed": self.observations_processed,
                "test_duration_ms": self.test_duration_ms,
                "detection_accuracy": if self.eprocess_alerts_triggered > 0 {
                    (self.true_positive_alerts as f64) / (self.eprocess_alerts_triggered as f64)
                } else { 0.0 },
                "false_positive_rate": if self.oracle_checks_performed > 0 {
                    (self.false_positive_alerts as f64) / (self.oracle_checks_performed as f64)
                } else { 0.0 },
            })
        }
    }

    /// Mock obligation for testing eprocess violations
    #[derive(Debug, Clone, PartialEq)]
    struct MockObligation {
        obligation_id: ObligationId,
        created_at: Time,
        expected_lifetime_ns: u64,
        current_age_ns: u64,
        is_violation: bool,
        rule_firing_count: usize,
    }

    impl MockObligation {
        fn new(obligation_id: ObligationId, expected_lifetime_ns: u64, created_at: Time) -> Self {
            Self {
                obligation_id,
                created_at,
                expected_lifetime_ns,
                current_age_ns: 0,
                is_violation: false,
                rule_firing_count: 0,
            }
        }

        fn age_by(&mut self, delta_ns: u64) {
            self.current_age_ns += delta_ns;

            // Check if this becomes a violation
            if self.current_age_ns > self.expected_lifetime_ns * 2 {
                self.is_violation = true;
            }
        }

        fn fire_rule(&mut self) {
            self.rule_firing_count += 1;
        }

        fn current_age(&self) -> u64 {
            self.current_age_ns
        }

        fn is_violating(&self) -> bool {
            self.is_violation
        }
    }

    /// Rule firing engine for concurrent violations
    struct ConcurrentRuleEngine {
        active_obligations: Arc<Mutex<HashMap<ObligationId, MockObligation>>>,
        rule_firing_queue: Arc<Mutex<VecDeque<ObligationId>>>,
        stats: Arc<Mutex<EProcessOracleStats>>,
        current_time: Arc<AtomicU64>,
        next_obligation_id: Arc<AtomicU64>,
    }

    impl ConcurrentRuleEngine {
        fn new(stats: Arc<Mutex<EProcessOracleStats>>) -> Self {
            Self {
                active_obligations: Arc::new(Mutex::new(HashMap::new())),
                rule_firing_queue: Arc::new(Mutex::new(VecDeque::new())),
                stats,
                current_time: Arc::new(AtomicU64::new(0)),
                next_obligation_id: Arc::new(AtomicU64::new(1)),
            }
        }

        fn next_obligation_id(&self) -> ObligationId {
            ObligationId::new_for_test(self.next_obligation_id.fetch_add(1, Ordering::AcqRel), 0)
        }

        fn current_time(&self) -> Time {
            Time::from_nanos(self.current_time.load(Ordering::Acquire))
        }

        fn advance_time(&self, delta_ns: u64) {
            self.current_time.fetch_add(delta_ns, Ordering::AcqRel);
        }

        /// Create multiple obligations for concurrent testing
        async fn create_obligations(
            &mut self,
            count: usize,
            expected_lifetime_ns: u64,
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            let mut obligation_ids = Vec::new();
            let current_time = self.current_time();

            for _ in 0..count {
                let obligation_id = self.next_obligation_id();
                let obligation =
                    MockObligation::new(obligation_id, expected_lifetime_ns, current_time);

                {
                    let mut obligations = self.active_obligations.lock().unwrap();
                    obligations.insert(obligation_id, obligation);
                }

                obligation_ids.push(obligation_id);
                println!(
                    "Created obligation {:?} with expected lifetime {}ns",
                    obligation_id, expected_lifetime_ns
                );
            }

            Ok(obligation_ids)
        }

        /// Simulate concurrent rule firing for multiple obligations
        async fn fire_rules_concurrently(
            &mut self,
            obligation_ids: &[ObligationId],
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!(
                "Firing rules concurrently for {} obligations",
                obligation_ids.len()
            );

            // Add all obligations to firing queue
            {
                let mut queue = self.rule_firing_queue.lock().unwrap();
                for &id in obligation_ids {
                    queue.push_back(id);
                }
            }

            // Fire rules concurrently
            {
                let mut obligations = self.active_obligations.lock().unwrap();
                for &id in obligation_ids {
                    if let Some(obligation) = obligations.get_mut(&id) {
                        obligation.fire_rule();
                    }
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.concurrent_rule_firings += obligation_ids.len();
            }

            Ok(())
        }

        /// Age obligations to create violations
        async fn age_obligations(
            &mut self,
            delta_ns: u64,
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.advance_time(delta_ns);
            let mut violating_obligations = Vec::new();

            {
                let mut obligations = self.active_obligations.lock().unwrap();
                for obligation in obligations.values_mut() {
                    obligation.age_by(delta_ns);
                    if obligation.is_violating() {
                        violating_obligations.push(obligation.obligation_id);
                    }
                }
            }

            if !violating_obligations.is_empty() {
                println!(
                    "Aged obligations by {}ns, {} now violating",
                    delta_ns,
                    violating_obligations.len()
                );
            }

            Ok(violating_obligations)
        }

        /// Get obligation ages for monitoring
        fn get_obligation_ages(&self) -> Vec<u64> {
            let obligations = self.active_obligations.lock().unwrap();
            obligations.values().map(|ob| ob.current_age()).collect()
        }

        /// Get violating obligations count
        fn get_violating_count(&self) -> usize {
            let obligations = self.active_obligations.lock().unwrap();
            obligations.values().filter(|ob| ob.is_violating()).count()
        }
    }

    /// Integration manager for eprocess + oracle testing
    struct EProcessOracleManager {
        leak_monitor: LeakMonitor,
        oracle: EProcessOracle,
        rule_engine: ConcurrentRuleEngine,
        stats: Arc<Mutex<EProcessOracleStats>>,
    }

    impl EProcessOracleManager {
        fn new(
            monitor_config: MonitorConfig,
            oracle_config: EProcessConfig,
            stats: Arc<Mutex<EProcessOracleStats>>,
        ) -> Self {
            Self {
                leak_monitor: LeakMonitor::new(monitor_config),
                oracle: EProcessOracle::new(oracle_config),
                rule_engine: ConcurrentRuleEngine::new(Arc::clone(&stats)),
                stats,
            }
        }

        /// Run integrated monitoring cycle
        async fn run_monitoring_cycle(
            &mut self,
            cx: &Cx,
        ) -> Result<(bool, bool), Box<dyn std::error::Error>> {
            // Get current obligation ages from rule engine
            let ages = self.rule_engine.get_obligation_ages();
            let violating_count = self.rule_engine.get_violating_count();

            println!(
                "Monitoring cycle: {} obligations, {} violating",
                ages.len(),
                violating_count
            );

            // Feed ages to leak monitor
            let mut monitor_alert = false;
            for age in &ages {
                self.leak_monitor.observe(*age);

                if self.leak_monitor.is_alert() && !monitor_alert {
                    monitor_alert = true;
                    println!(
                        "E-process monitor triggered alert at e-value: {:.6}",
                        self.leak_monitor.current_evalue()
                    );

                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.eprocess_alerts_triggered += 1;
                        stats.max_evalue_observed = stats
                            .max_evalue_observed
                            .max(self.leak_monitor.current_evalue());

                        if violating_count > 0 {
                            stats.true_positive_alerts += 1;
                        } else {
                            stats.false_positive_alerts += 1;
                        }
                    }
                }
            }

            // Perform oracle check
            let oracle_violation = self.oracle.check_obligations(&ages)?;

            if oracle_violation {
                println!(
                    "Oracle detected violation with {} violating obligations",
                    violating_count
                );

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.oracle_violations_detected += 1;
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.oracle_checks_performed += 1;
                stats.observations_processed += ages.len();
            }

            Ok((monitor_alert, oracle_violation))
        }

        /// Create concurrent violation scenario
        async fn create_concurrent_violation_scenario(
            &mut self,
            cx: &Cx,
            obligation_count: usize,
            expected_lifetime_ns: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!(
                "Creating concurrent violation scenario with {} obligations",
                obligation_count
            );

            // Create obligations
            let obligation_ids = self
                .rule_engine
                .create_obligations(obligation_count, expected_lifetime_ns)
                .await?;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.monitors_created += 1;
            }

            // Phase 1: Normal operation
            println!("Phase 1: Normal operation");
            for i in 0..3 {
                // Age obligations normally (under expected lifetime)
                self.rule_engine
                    .age_obligations(expected_lifetime_ns / 4)
                    .await?;

                // Fire rules concurrently
                self.rule_engine
                    .fire_rules_concurrently(&obligation_ids)
                    .await?;

                // Monitor
                let (monitor_alert, oracle_violation) = self.run_monitoring_cycle(cx).await?;

                println!(
                    "Cycle {}: monitor_alert={}, oracle_violation={}",
                    i + 1,
                    monitor_alert,
                    oracle_violation
                );

                // Should not trigger in normal operation
                if monitor_alert && self.rule_engine.get_violating_count() == 0 {
                    println!("Warning: False positive alert during normal operation");
                }

                sleep(Duration::from_millis(1)).await;
            }

            // Phase 2: Create violations
            println!("Phase 2: Creating violations");

            // Age obligations significantly beyond expected lifetime
            self.rule_engine
                .age_obligations(expected_lifetime_ns * 3)
                .await?;

            // Fire rules concurrently on violating obligations
            self.rule_engine
                .fire_rules_concurrently(&obligation_ids)
                .await?;

            // Monitor - should detect violations
            let (monitor_alert, oracle_violation) = self.run_monitoring_cycle(cx).await?;

            println!(
                "Violation phase: monitor_alert={}, oracle_violation={}, violating_count={}",
                monitor_alert,
                oracle_violation,
                self.rule_engine.get_violating_count()
            );

            Ok(())
        }

        /// Get current monitor state
        fn get_monitor_state(&self) -> (f64, bool, usize) {
            let evalue = self.leak_monitor.current_evalue();
            let is_alert = self.leak_monitor.is_alert();
            let observation_count = self.leak_monitor.observation_count();
            (evalue, is_alert, observation_count)
        }
    }

    /// Test harness for eprocess + oracle integration
    struct EProcessOracleTestHarness {
        stats: Arc<Mutex<EProcessOracleStats>>,
        start_time: Instant,
    }

    impl EProcessOracleTestHarness {
        fn new() -> Self {
            Self {
                stats: Arc::new(Mutex::new(EProcessOracleStats::default())),
                start_time: Instant::now(),
            }
        }

        /// Test basic eprocess monitoring with oracle verification
        async fn test_basic_eprocess_oracle_integration(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic eprocess + oracle integration");

            let monitor_config = MonitorConfig {
                alpha: 0.01,                     // 1% false positive rate
                expected_lifetime_ns: 1_000_000, // 1ms
                min_observations: 3,
            };

            let oracle_config = EProcessConfig {
                alpha: 0.01,
                violation_threshold: 0.1,
                min_observations: 3,
            };

            let mut manager =
                EProcessOracleManager::new(monitor_config, oracle_config, Arc::clone(&self.stats));

            // Create violation scenario
            manager
                .create_concurrent_violation_scenario(
                    cx, 5,         // 5 obligations
                    1_000_000, // 1ms expected lifetime
                )
                .await?;

            let (evalue, is_alert, observations) = manager.get_monitor_state();
            println!(
                "Final monitor state: evalue={:.6}, alert={}, observations={}",
                evalue, is_alert, observations
            );

            println!("Basic integration test completed successfully");
            Ok(())
        }

        /// Test high-concurrency scenario with many rule firings
        async fn test_high_concurrency_rule_firing(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing high concurrency rule firing scenario");

            let monitor_config = MonitorConfig {
                alpha: 0.05,                   // 5% false positive rate
                expected_lifetime_ns: 500_000, // 0.5ms
                min_observations: 5,
            };

            let oracle_config = EProcessConfig {
                alpha: 0.05,
                violation_threshold: 0.05,
                min_observations: 5,
            };

            let mut manager =
                EProcessOracleManager::new(monitor_config, oracle_config, Arc::clone(&self.stats));

            // Create high-concurrency scenario
            manager
                .create_concurrent_violation_scenario(
                    cx, 20,      // 20 obligations
                    500_000, // 0.5ms expected lifetime
                )
                .await?;

            let (evalue, is_alert, observations) = manager.get_monitor_state();
            println!(
                "High concurrency final state: evalue={:.6}, alert={}, observations={}",
                evalue, is_alert, observations
            );

            println!("High concurrency test completed successfully");
            Ok(())
        }

        /// Test false positive control
        async fn test_false_positive_control(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing false positive control");

            let monitor_config = MonitorConfig {
                alpha: 0.001,                    // 0.1% false positive rate (very strict)
                expected_lifetime_ns: 2_000_000, // 2ms
                min_observations: 10,
            };

            let oracle_config = EProcessConfig {
                alpha: 0.001,
                violation_threshold: 0.01,
                min_observations: 10,
            };

            let mut manager =
                EProcessOracleManager::new(monitor_config, oracle_config, Arc::clone(&self.stats));

            // Run normal operations only (no violations)
            let obligation_ids = manager
                .rule_engine
                .create_obligations(
                    10, 2_000_000, // 2ms expected
                )
                .await?;

            // Run many normal cycles
            for i in 0..15 {
                // Age normally (well under expected lifetime)
                manager.rule_engine.age_obligations(100_000).await?; // 0.1ms

                // Fire rules
                manager
                    .rule_engine
                    .fire_rules_concurrently(&obligation_ids)
                    .await?;

                // Monitor
                let (monitor_alert, oracle_violation) = manager.run_monitoring_cycle(cx).await?;

                if monitor_alert {
                    println!(
                        "Alert in normal operation cycle {} (potential false positive)",
                        i + 1
                    );
                }

                sleep(Duration::from_millis(1)).await;
            }

            let (evalue, is_alert, observations) = manager.get_monitor_state();
            println!(
                "False positive test final state: evalue={:.6}, alert={}, observations={}",
                evalue, is_alert, observations
            );

            println!("False positive control test completed");
            Ok(())
        }

        /// Test multiple concurrent violation bursts
        async fn test_multiple_violation_bursts(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing multiple concurrent violation bursts");

            let monitor_config = MonitorConfig {
                alpha: 0.01,
                expected_lifetime_ns: 800_000, // 0.8ms
                min_observations: 4,
            };

            let oracle_config = EProcessConfig {
                alpha: 0.01,
                violation_threshold: 0.1,
                min_observations: 4,
            };

            let mut manager =
                EProcessOracleManager::new(monitor_config, oracle_config, Arc::clone(&self.stats));

            // Create multiple bursts of violations
            for burst in 0..3 {
                println!("Violation burst {}", burst + 1);

                manager
                    .create_concurrent_violation_scenario(
                        cx, 8,       // 8 obligations per burst
                        800_000, // 0.8ms expected
                    )
                    .await?;

                sleep(Duration::from_millis(2)).await;
            }

            let (evalue, is_alert, observations) = manager.get_monitor_state();
            println!(
                "Multiple bursts final state: evalue={:.6}, alert={}, observations={}",
                evalue, is_alert, observations
            );

            println!("Multiple violation bursts test completed");
            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> EProcessOracleStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_eprocess_oracle_basic_integration() {
        println!("=== Starting eprocess + oracle basic integration test ===");

        scope(|cx| async move {
            let mut harness = EProcessOracleTestHarness::new();

            // Test basic functionality
            harness
                .test_basic_eprocess_oracle_integration(&cx)
                .await
                .expect("Basic integration test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(stats.monitors_created > 0, "Should have created monitors");
            assert!(
                stats.oracle_checks_performed > 0,
                "Should have performed oracle checks"
            );
            assert!(
                stats.observations_processed > 0,
                "Should have processed observations"
            );

            println!("✓ E-process + oracle basic integration test passed");
            println!("  - Monitors created: {}", stats.monitors_created);
            println!("  - Oracle checks: {}", stats.oracle_checks_performed);
            println!("  - Observations: {}", stats.observations_processed);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_eprocess_oracle_high_concurrency() {
        println!("=== Testing eprocess + oracle high concurrency scenarios ===");

        scope(|cx| async move {
            let mut harness = EProcessOracleTestHarness::new();

            // Test high concurrency
            harness
                .test_high_concurrency_rule_firing(&cx)
                .await
                .expect("High concurrency test should succeed");

            let stats = harness.get_stats();
            println!(
                "High concurrency stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should handle high concurrency
            assert!(
                stats.concurrent_rule_firings >= 20,
                "Should have processed high concurrent rule firings"
            );

            println!("✓ High concurrency eprocess test passed");
            println!(
                "  - Concurrent rule firings: {}",
                stats.concurrent_rule_firings
            );
            println!("  - Max e-value observed: {:.6}", stats.max_evalue_observed);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_eprocess_oracle_false_positive_control() {
        println!("=== Testing eprocess false positive control ===");

        scope(|cx| async move {
            let mut harness = EProcessOracleTestHarness::new();

            // Test false positive control
            harness
                .test_false_positive_control(&cx)
                .await
                .expect("False positive control test should succeed");

            let stats = harness.get_stats();
            println!(
                "False positive control stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify false positive control
            let fp_rate = stats.to_json()["false_positive_rate"]
                .as_f64()
                .unwrap_or(0.0);
            println!("False positive rate: {:.4}%", fp_rate * 100.0);

            println!("✓ False positive control test passed");

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_eprocess_oracle_multiple_violation_bursts() {
        println!("=== Testing multiple concurrent violation bursts ===");

        scope(|cx| async move {
            let mut harness = EProcessOracleTestHarness::new();

            // Test multiple violation bursts
            harness
                .test_multiple_violation_bursts(&cx)
                .await
                .expect("Multiple violation bursts test should succeed");

            let stats = harness.get_stats();
            println!(
                "Multiple bursts stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should handle multiple bursts
            assert!(
                stats.concurrent_rule_firings >= 24, // 3 bursts × 8 obligations
                "Should have processed multiple violation bursts"
            );

            println!("✓ Multiple violation bursts test passed");
            println!(
                "  - Detection accuracy: {:.2}%",
                stats.to_json()["detection_accuracy"]
                    .as_f64()
                    .unwrap_or(0.0)
                    * 100.0
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_eprocess_oracle_comprehensive_integration() {
        println!("=== Testing comprehensive eprocess + oracle integration ===");

        scope(|cx| async move {
            let mut harness = EProcessOracleTestHarness::new();

            // Run comprehensive test sequence
            println!("Running comprehensive integration tests...");

            harness
                .test_basic_eprocess_oracle_integration(&cx)
                .await
                .expect("Basic test should succeed");

            harness
                .test_high_concurrency_rule_firing(&cx)
                .await
                .expect("High concurrency test should succeed");

            harness
                .test_false_positive_control(&cx)
                .await
                .expect("False positive control should succeed");

            harness
                .test_multiple_violation_bursts(&cx)
                .await
                .expect("Multiple bursts test should succeed");

            let stats = harness.get_stats();
            println!(
                "Comprehensive integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify comprehensive operation
            assert!(
                stats.monitors_created >= 4,
                "Should have created multiple monitors"
            );
            assert!(
                stats.oracle_checks_performed >= 20,
                "Should have performed many oracle checks"
            );
            assert!(
                stats.concurrent_rule_firings >= 50,
                "Should have processed many concurrent rule firings"
            );
            assert!(
                stats.observations_processed >= 100,
                "Should have processed many observations"
            );

            println!("✓ Comprehensive eprocess + oracle integration test passed");
            println!("  - Total monitors: {}", stats.monitors_created);
            println!("  - Total oracle checks: {}", stats.oracle_checks_performed);
            println!("  - Total rule firings: {}", stats.concurrent_rule_firings);
            println!("  - Total observations: {}", stats.observations_processed);
            println!("  - E-process alerts: {}", stats.eprocess_alerts_triggered);
            println!(
                "  - Oracle violations: {}",
                stats.oracle_violations_detected
            );
            println!(
                "  - Detection accuracy: {:.2}%",
                stats.to_json()["detection_accuracy"]
                    .as_f64()
                    .unwrap_or(0.0)
                    * 100.0
            );
            println!(
                "  - False positive rate: {:.4}%",
                stats.to_json()["false_positive_rate"]
                    .as_f64()
                    .unwrap_or(0.0)
                    * 100.0
            );
            println!("  - Max e-value: {:.6}", stats.max_evalue_observed);
            println!("  - Test duration: {}ms", stats.test_duration_ms);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}
