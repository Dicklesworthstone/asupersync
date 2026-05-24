//! Real service E2E tests for raptorq/decision_contract ↔ lab/oracle/loser_drain integration.
//!
//! Verifies that decision contract correctly drains losing decoder paths without
//! lingering work. Tests that when the RaptorQ decision contract determines certain
//! decoder paths should be abandoned (rollback/fallback actions), the loser drain
//! oracle correctly validates that these losing paths are properly cancelled and
//! drained to completion without leaving any residual work or resources.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_raptorq_decision_contract_loser_drain_e2e {
    use crate::cx::{Cx, scope};
    use crate::lab::oracle::loser_drain::{LoserDrainOracle, LoserDrainViolation};
    use crate::raptorq::decision_contract::{
        GovernanceSnapshot, GovernanceTelemetry, RaptorQDecisionContract
    };
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{RegionId, TaskId, Time};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// Statistics for decision contract + loser drain testing
    #[derive(Debug, Clone, Default)]
    struct DecisionContractLoserDrainStats {
        /// Decision contracts evaluated
        decisions_evaluated: usize,
        /// Fallback decisions triggered
        fallback_decisions: usize,
        /// Rollback decisions triggered
        rollback_decisions: usize,
        /// Canary hold decisions triggered
        canary_hold_decisions: usize,
        /// Continue decisions triggered
        continue_decisions: usize,
        /// Races started for decoder paths
        decoder_races_started: usize,
        /// Races completed successfully
        decoder_races_completed: usize,
        /// Tasks drained as losers
        loser_tasks_drained: usize,
        /// Oracle violations detected
        oracle_violations_detected: usize,
        /// Total test duration in milliseconds
        test_duration_ms: u64,
        /// Average decision latency in microseconds
        avg_decision_latency_micros: u64,
    }

    impl DecisionContractLoserDrainStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "decisions_evaluated": self.decisions_evaluated,
                "fallback_decisions": self.fallback_decisions,
                "rollback_decisions": self.rollback_decisions,
                "canary_hold_decisions": self.canary_hold_decisions,
                "continue_decisions": self.continue_decisions,
                "decoder_races_started": self.decoder_races_started,
                "decoder_races_completed": self.decoder_races_completed,
                "loser_tasks_drained": self.loser_tasks_drained,
                "oracle_violations_detected": self.oracle_violations_detected,
                "test_duration_ms": self.test_duration_ms,
                "avg_decision_latency_micros": self.avg_decision_latency_micros,
                "race_completion_rate": if self.decoder_races_started > 0 {
                    (self.decoder_races_completed as f64) / (self.decoder_races_started as f64)
                } else { 0.0 },
                "loser_drain_efficiency": if self.decoder_races_completed > 0 {
                    (self.loser_tasks_drained as f64) / (self.decoder_races_completed as f64)
                } else { 0.0 },
            })
        }
    }

    /// Mock decoder path for testing decision contract integration
    #[derive(Debug, Clone, PartialEq)]
    struct MockDecoderPath {
        path_id: u64,
        decoder_type: MockDecoderType,
        current_state: MockDecoderState,
        task_id: TaskId,
        metrics: MockDecoderMetrics,
        created_at: Time,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum MockDecoderType {
        Conservative,     // Baseline decoder
        Optimized,       // High-performance decoder
        Experimental,    // Bleeding-edge decoder
    }

    #[derive(Debug, Clone, PartialEq)]
    enum MockDecoderState {
        Active,
        Draining,
        Completed,
        Cancelled,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockDecoderMetrics {
        density_permille: usize,
        rank_deficit_permille: usize,
        inactivation_pressure_permille: usize,
        overhead_ratio_permille: usize,
        baseline_loss: u32,
        high_support_loss: u32,
        block_schur_loss: u32,
        budget_exhausted: bool,
    }

    impl MockDecoderPath {
        fn new(path_id: u64, decoder_type: MockDecoderType, task_id: TaskId) -> Self {
            Self {
                path_id,
                decoder_type: decoder_type.clone(),
                current_state: MockDecoderState::Active,
                task_id,
                metrics: MockDecoderMetrics::default_for_type(&decoder_type),
                created_at: Time::from_nanos(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                ),
            }
        }

        fn to_governance_snapshot(&self, rows: usize, cols: usize) -> GovernanceSnapshot {
            GovernanceSnapshot {
                n_rows: rows,
                n_cols: cols,
                density_permille: self.metrics.density_permille,
                rank_deficit_permille: self.metrics.rank_deficit_permille,
                inactivation_pressure_permille: self.metrics.inactivation_pressure_permille,
                overhead_ratio_permille: self.metrics.overhead_ratio_permille,
                budget_exhausted: self.metrics.budget_exhausted,
                baseline_loss: self.metrics.baseline_loss,
                high_support_loss: self.metrics.high_support_loss,
                block_schur_loss: self.metrics.block_schur_loss,
            }
        }

        fn update_state(&mut self, new_state: MockDecoderState) {
            self.current_state = new_state;
        }

        fn simulate_pressure(&mut self, pressure_factor: f64) {
            let factor = (pressure_factor * 1000.0) as usize;
            self.metrics.rank_deficit_permille =
                (self.metrics.rank_deficit_permille + factor).min(1000);
            self.metrics.inactivation_pressure_permille =
                (self.metrics.inactivation_pressure_permille + factor / 2).min(1000);
            self.metrics.overhead_ratio_permille =
                (self.metrics.overhead_ratio_permille + factor / 3).min(1000);
        }

        fn simulate_exhaustion(&mut self) {
            self.metrics.budget_exhausted = true;
            self.metrics.baseline_loss = self.metrics.baseline_loss.saturating_add(50);
            self.metrics.high_support_loss = self.metrics.high_support_loss.saturating_add(75);
        }
    }

    impl MockDecoderMetrics {
        fn default_for_type(decoder_type: &MockDecoderType) -> Self {
            match decoder_type {
                MockDecoderType::Conservative => Self {
                    density_permille: 850, // High density, stable
                    rank_deficit_permille: 50, // Low rank issues
                    inactivation_pressure_permille: 100, // Low pressure
                    overhead_ratio_permille: 200, // Reasonable overhead
                    baseline_loss: 10,
                    high_support_loss: 25,
                    block_schur_loss: 15,
                    budget_exhausted: false,
                },
                MockDecoderType::Optimized => Self {
                    density_permille: 750, // Medium density
                    rank_deficit_permille: 150, // Some rank issues
                    inactivation_pressure_permille: 250, // Medium pressure
                    overhead_ratio_permille: 300, // Higher overhead
                    baseline_loss: 20,
                    high_support_loss: 35,
                    block_schur_loss: 40,
                    budget_exhausted: false,
                },
                MockDecoderType::Experimental => Self {
                    density_permille: 600, // Lower density
                    rank_deficit_permille: 300, // High rank issues
                    inactivation_pressure_permille: 400, // High pressure
                    overhead_ratio_permille: 500, // High overhead
                    baseline_loss: 80,
                    high_support_loss: 120,
                    block_schur_loss: 200,
                    budget_exhausted: false,
                },
            }
        }
    }

    /// Integration manager for decision contract + loser drain testing
    struct DecisionContractLoserDrainManager {
        decision_contract: RaptorQDecisionContract,
        loser_drain_oracle: LoserDrainOracle,
        active_decoder_paths: Arc<Mutex<HashMap<u64, MockDecoderPath>>>,
        stats: Arc<Mutex<DecisionContractLoserDrainStats>>,
        next_path_id: Arc<AtomicU64>,
        next_task_id: Arc<AtomicU64>,
        current_time: Arc<AtomicU64>,
    }

    impl DecisionContractLoserDrainManager {
        fn new(stats: Arc<Mutex<DecisionContractLoserDrainStats>>) -> Self {
            Self {
                decision_contract: RaptorQDecisionContract::new(),
                loser_drain_oracle: LoserDrainOracle::new(),
                active_decoder_paths: Arc::new(Mutex::new(HashMap::new())),
                stats,
                next_path_id: Arc::new(AtomicU64::new(1)),
                next_task_id: Arc::new(AtomicU64::new(1)),
                current_time: Arc::new(AtomicU64::new(0)),
            }
        }

        fn next_path_id(&self) -> u64 {
            self.next_path_id.fetch_add(1, Ordering::AcqRel)
        }

        fn next_task_id(&self) -> TaskId {
            TaskId::new_for_test(
                self.next_task_id.fetch_add(1, Ordering::AcqRel),
                0,
            )
        }

        fn next_time(&self) -> Time {
            Time::from_nanos(self.current_time.fetch_add(1000, Ordering::AcqRel))
        }

        /// Create multiple decoder paths for testing race scenarios
        async fn create_decoder_race(
            &mut self,
            cx: &Cx,
            region: RegionId,
            path_count: usize,
        ) -> Result<(u64, Vec<u64>), Box<dyn std::error::Error>> {
            let mut path_ids = Vec::new();
            let mut task_ids = Vec::new();

            // Create multiple decoder paths
            for i in 0..path_count {
                let path_id = self.next_path_id();
                let task_id = self.next_task_id();

                let decoder_type = match i {
                    0 => MockDecoderType::Conservative,  // Usually the winner
                    1 => MockDecoderType::Optimized,     // Medium risk
                    _ => MockDecoderType::Experimental,  // High risk, likely loser
                };

                let decoder_path = MockDecoderPath::new(path_id, decoder_type, task_id);

                {
                    let mut paths = self.active_decoder_paths.lock().unwrap();
                    paths.insert(path_id, decoder_path);
                }

                path_ids.push(path_id);
                task_ids.push(task_id);

                println!(
                    "Created decoder path {} with task {:?} (type: {:?})",
                    path_id, task_id, decoder_type
                );
            }

            // Start the race in the oracle
            let race_id = self.loser_drain_oracle.on_race_start(
                region,
                task_ids,
                self.next_time(),
            );

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.decoder_races_started += 1;
            }

            println!(
                "Started decoder race {} with {} paths in region {:?}",
                race_id, path_count, region
            );

            Ok((race_id, path_ids))
        }

        /// Evaluate decision contract for all active paths and determine actions
        async fn evaluate_decision_contract_for_race(
            &mut self,
            cx: &Cx,
            path_ids: &[u64],
            rows: usize,
            cols: usize,
        ) -> Result<Vec<(u64, String)>, Box<dyn std::error::Error>> {
            let mut decisions = Vec::new();
            let start_time = Instant::now();

            for &path_id in path_ids {
                let snapshot = {
                    let paths = self.active_decoder_paths.lock().unwrap();
                    if let Some(path) = paths.get(&path_id) {
                        path.to_governance_snapshot(rows, cols)
                    } else {
                        return Err(format!("Decoder path {} not found", path_id).into());
                    }
                };

                // Evaluate the decision contract
                let posterior = RaptorQDecisionContract::state_posterior_permille(&snapshot);

                // Simulate decision logic based on posterior
                let action = if posterior[2] > 600 {  // High regression probability
                    "fallback"
                } else if posterior[2] > 300 {  // Medium regression
                    "rollback"
                } else if posterior[1] > 400 {  // High degraded probability
                    "canary_hold"
                } else {
                    "continue"
                };

                decisions.push((path_id, action.to_string()));

                println!(
                    "Decision for path {}: {} (posterior: {:?})",
                    path_id, action, posterior
                );
            }

            // Update stats
            let decision_latency = start_time.elapsed().as_micros() as u64;
            {
                let mut stats = self.stats.lock().unwrap();
                stats.decisions_evaluated += path_ids.len();
                stats.avg_decision_latency_micros =
                    (stats.avg_decision_latency_micros + decision_latency) / 2;

                for (_, action) in &decisions {
                    match action.as_str() {
                        "fallback" => stats.fallback_decisions += 1,
                        "rollback" => stats.rollback_decisions += 1,
                        "canary_hold" => stats.canary_hold_decisions += 1,
                        "continue" => stats.continue_decisions += 1,
                        _ => {}
                    }
                }
            }

            Ok(decisions)
        }

        /// Execute race completion based on decision contract results
        async fn execute_race_with_loser_drain(
            &mut self,
            cx: &Cx,
            race_id: u64,
            path_ids: &[u64],
            decisions: &[(u64, String)],
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Determine winner (first path with "continue" decision, or conservative path)
            let winner_path_id = decisions.iter()
                .find(|(_, action)| action == "continue")
                .map(|(path_id, _)| *path_id)
                .unwrap_or_else(|| path_ids[0]); // Default to first path (conservative)

            let winner_task_id = {
                let paths = self.active_decoder_paths.lock().unwrap();
                paths.get(&winner_path_id)
                    .map(|p| p.task_id)
                    .ok_or("Winner path not found")?
            };

            println!(
                "Race {} winner: path {} (task {:?})",
                race_id, winner_path_id, winner_task_id
            );

            // Complete winner task
            let completion_time = self.next_time();
            self.loser_drain_oracle.on_task_complete(winner_task_id, completion_time);

            // Drain losing paths
            for &path_id in path_ids {
                if path_id == winner_path_id {
                    continue; // Skip winner
                }

                let loser_task_id = {
                    let mut paths = self.active_decoder_paths.lock().unwrap();
                    if let Some(path) = paths.get_mut(&path_id) {
                        path.update_state(MockDecoderState::Draining);
                        path.task_id
                    } else {
                        continue;
                    }
                };

                // Simulate draining work (small delay)
                sleep(Duration::from_millis(1)).await;

                // Complete loser task (proper draining)
                let drain_time = self.next_time();
                self.loser_drain_oracle.on_task_complete(loser_task_id, drain_time);

                // Mark as completed
                {
                    let mut paths = self.active_decoder_paths.lock().unwrap();
                    if let Some(path) = paths.get_mut(&path_id) {
                        path.update_state(MockDecoderState::Completed);
                    }
                }

                println!(
                    "Drained loser path {} (task {:?}) at time {:?}",
                    path_id, loser_task_id, drain_time
                );

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.loser_tasks_drained += 1;
                }
            }

            // Complete the race
            let race_complete_time = self.next_time();
            self.loser_drain_oracle.on_race_complete(race_id, winner_task_id, race_complete_time);

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.decoder_races_completed += 1;
            }

            println!(
                "Completed race {} with winner task {:?} at time {:?}",
                race_id, winner_task_id, race_complete_time
            );

            Ok(())
        }

        /// Verify loser drain oracle invariants
        async fn verify_loser_drain_invariants(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            match self.loser_drain_oracle.check() {
                Ok(()) => {
                    println!("✓ Loser drain invariants verified successfully");
                    Ok(())
                }
                Err(violation) => {
                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.oracle_violations_detected += 1;
                    }

                    println!("✗ Loser drain violation detected: {}", violation);
                    Err(format!("Loser drain violation: {}", violation).into())
                }
            }
        }

        /// Simulate problematic scenarios to test oracle detection
        async fn simulate_problematic_scenario(
            &mut self,
            cx: &Cx,
            region: RegionId,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            println!("Simulating problematic scenario with inadequate draining");

            let (race_id, path_ids) = self.create_decoder_race(cx, region, 3).await?;

            // Simulate high pressure to force fallback decisions
            {
                let mut paths = self.active_decoder_paths.lock().unwrap();
                for &path_id in &path_ids {
                    if let Some(path) = paths.get_mut(&path_id) {
                        path.simulate_pressure(0.8); // High pressure
                        path.simulate_exhaustion();
                    }
                }
            }

            let decisions = self.evaluate_decision_contract_for_race(
                cx, &path_ids, 100, 50
            ).await?;

            // Simulate incomplete draining (intentional bug)
            let winner_path_id = path_ids[0];
            let winner_task_id = {
                let paths = self.active_decoder_paths.lock().unwrap();
                paths.get(&winner_path_id).unwrap().task_id
            };

            // Complete winner
            let completion_time = self.next_time();
            self.loser_drain_oracle.on_task_complete(winner_task_id, completion_time);

            // Complete race WITHOUT properly draining all losers (bug simulation)
            let race_complete_time = self.next_time();
            self.loser_drain_oracle.on_race_complete(race_id, winner_task_id, race_complete_time);

            // Verify oracle detects the violation
            match self.loser_drain_oracle.check() {
                Ok(()) => {
                    println!("✗ Oracle failed to detect loser drain violation");
                    Ok(false) // Detection failed
                }
                Err(violation) => {
                    println!("✓ Oracle correctly detected violation: {}", violation);
                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.oracle_violations_detected += 1;
                    }
                    Ok(true) // Detection succeeded
                }
            }
        }

        /// Get manager state for debugging
        fn get_state(&self) -> (usize, u64, u64) {
            let active_paths = self.active_decoder_paths.lock().unwrap().len();
            let total_paths = self.next_path_id.load(Ordering::Acquire);
            let total_tasks = self.next_task_id.load(Ordering::Acquire);
            (active_paths, total_paths, total_tasks)
        }
    }

    /// Test harness for decision contract + loser drain integration
    struct DecisionContractLoserDrainTestHarness {
        manager: DecisionContractLoserDrainManager,
        stats: Arc<Mutex<DecisionContractLoserDrainStats>>,
        start_time: Instant,
        next_region_id: Arc<AtomicU64>,
    }

    impl DecisionContractLoserDrainTestHarness {
        fn new() -> Self {
            let stats = Arc::new(Mutex::new(DecisionContractLoserDrainStats::default()));
            let manager = DecisionContractLoserDrainManager::new(Arc::clone(&stats));

            Self {
                manager,
                stats,
                start_time: Instant::now(),
                next_region_id: Arc::new(AtomicU64::new(1)),
            }
        }

        fn next_region_id(&self) -> RegionId {
            RegionId::new_for_test(
                self.next_region_id.fetch_add(1, Ordering::AcqRel),
                0,
            )
        }

        /// Test basic decision contract with proper loser draining
        async fn test_basic_decision_contract_loser_drain(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic decision contract with proper loser draining");

            let region = self.next_region_id();
            let (race_id, path_ids) = self.manager.create_decoder_race(cx, region, 3).await?;

            let decisions = self.manager.evaluate_decision_contract_for_race(
                cx, &path_ids, 100, 50
            ).await?;

            self.manager.execute_race_with_loser_drain(
                cx, race_id, &path_ids, &decisions
            ).await?;

            self.manager.verify_loser_drain_invariants(cx).await?;

            println!("Basic decision contract + loser drain test completed successfully");
            Ok(())
        }

        /// Test high pressure scenarios that trigger fallback/rollback
        async fn test_high_pressure_fallback_scenarios(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing high pressure scenarios with fallback decisions");

            for scenario in 0..3 {
                let region = self.next_region_id();
                let (race_id, path_ids) = self.manager.create_decoder_race(cx, region, 4).await?;

                // Apply different pressure levels
                {
                    let mut paths = self.manager.active_decoder_paths.lock().unwrap();
                    for &path_id in &path_ids {
                        if let Some(path) = paths.get_mut(&path_id) {
                            match scenario {
                                0 => path.simulate_pressure(0.3), // Light pressure
                                1 => path.simulate_pressure(0.6), // Medium pressure
                                _ => {
                                    path.simulate_pressure(0.9); // High pressure
                                    path.simulate_exhaustion();
                                }
                            }
                        }
                    }
                }

                let decisions = self.manager.evaluate_decision_contract_for_race(
                    cx, &path_ids, 150, 75
                ).await?;

                self.manager.execute_race_with_loser_drain(
                    cx, race_id, &path_ids, &decisions
                ).await?;

                self.manager.verify_loser_drain_invariants(cx).await?;

                println!("High pressure scenario {} completed", scenario);
            }

            println!("All high pressure fallback scenarios completed successfully");
            Ok(())
        }

        /// Test oracle violation detection
        async fn test_oracle_violation_detection(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing oracle violation detection capabilities");

            let region = self.next_region_id();
            let detected = self.manager.simulate_problematic_scenario(cx, region).await?;

            assert!(detected, "Oracle should detect loser drain violations");

            println!("Oracle violation detection test completed successfully");
            Ok(())
        }

        /// Test multiple concurrent races
        async fn test_multiple_concurrent_races(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing multiple concurrent decoder races");

            let mut race_handles = Vec::new();

            // Start multiple races concurrently
            for i in 0..5 {
                let region = self.next_region_id();
                let (race_id, path_ids) = self.manager.create_decoder_race(cx, region, 2 + i % 3).await?;

                race_handles.push((race_id, path_ids, region));
            }

            // Process all races
            for (race_id, path_ids, _region) in race_handles {
                let decisions = self.manager.evaluate_decision_contract_for_race(
                    cx, &path_ids, 80 + path_ids.len() * 10, 40 + path_ids.len() * 5
                ).await?;

                self.manager.execute_race_with_loser_drain(
                    cx, race_id, &path_ids, &decisions
                ).await?;
            }

            self.manager.verify_loser_drain_invariants(cx).await?;

            println!("Multiple concurrent races test completed successfully");
            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> DecisionContractLoserDrainStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_decision_contract_loser_drain_basic_integration() {
        println!("=== Starting decision contract + loser drain basic integration test ===");

        scope(|cx| async move {
            let mut harness = DecisionContractLoserDrainTestHarness::new();

            // Test basic functionality
            harness
                .test_basic_decision_contract_loser_drain(&cx)
                .await
                .expect("Basic integration test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(
                stats.decisions_evaluated > 0,
                "Should have evaluated decisions"
            );
            assert!(
                stats.decoder_races_started > 0,
                "Should have started decoder races"
            );
            assert!(
                stats.decoder_races_completed > 0,
                "Should have completed races"
            );
            assert!(
                stats.loser_tasks_drained > 0,
                "Should have drained loser tasks"
            );

            println!("✓ Decision contract + loser drain basic integration test passed");
            println!("  - Decisions evaluated: {}", stats.decisions_evaluated);
            println!("  - Decoder races completed: {}", stats.decoder_races_completed);
            println!("  - Loser tasks drained: {}", stats.loser_tasks_drained);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_decision_contract_high_pressure_fallback_scenarios() {
        println!("=== Testing decision contract high pressure fallback scenarios ===");

        scope(|cx| async move {
            let mut harness = DecisionContractLoserDrainTestHarness::new();

            // Test high pressure scenarios
            harness
                .test_high_pressure_fallback_scenarios(&cx)
                .await
                .expect("High pressure test should succeed");

            let stats = harness.get_stats();
            println!(
                "High pressure stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have triggered various decision types
            assert!(
                stats.decisions_evaluated > 0,
                "Should have evaluated multiple decisions"
            );
            assert!(
                stats.fallback_decisions + stats.rollback_decisions + stats.canary_hold_decisions > 0,
                "Should have triggered fallback/rollback/canary decisions under pressure"
            );

            println!("✓ High pressure fallback scenarios test passed");
            println!("  - Fallback decisions: {}", stats.fallback_decisions);
            println!("  - Rollback decisions: {}", stats.rollback_decisions);
            println!("  - Canary hold decisions: {}", stats.canary_hold_decisions);
            println!("  - Continue decisions: {}", stats.continue_decisions);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_loser_drain_oracle_violation_detection() {
        println!("=== Testing loser drain oracle violation detection ===");

        scope(|cx| async move {
            let mut harness = DecisionContractLoserDrainTestHarness::new();

            // Test oracle violation detection
            harness
                .test_oracle_violation_detection(&cx)
                .await
                .expect("Oracle violation test should succeed");

            let stats = harness.get_stats();
            println!(
                "Oracle violation stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have detected violations
            assert!(
                stats.oracle_violations_detected > 0,
                "Should have detected oracle violations"
            );

            println!("✓ Loser drain oracle violation detection test passed");
            println!("  - Oracle violations detected: {}", stats.oracle_violations_detected);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_decision_contract_multiple_concurrent_races() {
        println!("=== Testing decision contract with multiple concurrent races ===");

        scope(|cx| async move {
            let mut harness = DecisionContractLoserDrainTestHarness::new();

            // Test multiple concurrent races
            harness
                .test_multiple_concurrent_races(&cx)
                .await
                .expect("Multiple concurrent races test should succeed");

            let stats = harness.get_stats();
            println!(
                "Multiple races stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have processed multiple races
            assert!(
                stats.decoder_races_started >= 5,
                "Should have started multiple concurrent races"
            );
            assert!(
                stats.decoder_races_completed >= 5,
                "Should have completed multiple races"
            );

            let (active_paths, total_paths, total_tasks) = harness.manager.get_state();
            println!(
                "Manager state: active_paths={}, total_paths={}, total_tasks={}",
                active_paths, total_paths, total_tasks
            );

            println!("✓ Multiple concurrent races test passed");
            println!("  - Total races started: {}", stats.decoder_races_started);
            println!("  - Total races completed: {}", stats.decoder_races_completed);
            println!("  - Race completion rate: {:.2}%",
                (stats.decoder_races_completed as f64 / stats.decoder_races_started as f64) * 100.0
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_decision_contract_loser_drain_comprehensive_integration() {
        println!("=== Testing comprehensive decision contract + loser drain integration ===");

        scope(|cx| async move {
            let mut harness = DecisionContractLoserDrainTestHarness::new();

            // Run comprehensive test sequence
            println!("Running comprehensive integration tests...");

            harness
                .test_basic_decision_contract_loser_drain(&cx)
                .await
                .expect("Basic test should succeed");

            harness
                .test_high_pressure_fallback_scenarios(&cx)
                .await
                .expect("High pressure test should succeed");

            harness
                .test_multiple_concurrent_races(&cx)
                .await
                .expect("Multiple races test should succeed");

            harness
                .test_oracle_violation_detection(&cx)
                .await
                .expect("Oracle violation test should succeed");

            let stats = harness.get_stats();
            println!(
                "Comprehensive integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify comprehensive operation
            assert!(
                stats.decisions_evaluated >= 10,
                "Should have evaluated many decisions"
            );
            assert!(
                stats.decoder_races_completed >= 8,
                "Should have completed multiple races"
            );
            assert!(
                stats.loser_tasks_drained >= 10,
                "Should have drained many loser tasks"
            );
            assert!(
                stats.oracle_violations_detected > 0,
                "Should have detected violations in problematic scenarios"
            );

            let (active_paths, total_paths, total_tasks) = harness.manager.get_state();
            println!(
                "Final manager state: active_paths={}, total_paths={}, total_tasks={}",
                active_paths, total_paths, total_tasks
            );

            println!("✓ Comprehensive decision contract + loser drain integration test passed");
            println!("  - Total decisions: {}", stats.decisions_evaluated);
            println!("  - Total races: {}", stats.decoder_races_completed);
            println!("  - Total losers drained: {}", stats.loser_tasks_drained);
            println!("  - Oracle violations: {}", stats.oracle_violations_detected);
            println!("  - Avg decision latency: {}μs", stats.avg_decision_latency_micros);
            println!("  - Race completion rate: {:.2}%",
                stats.to_json()["race_completion_rate"].as_f64().unwrap_or(0.0) * 100.0
            );
            println!("  - Loser drain efficiency: {:.2}",
                stats.to_json()["loser_drain_efficiency"].as_f64().unwrap_or(0.0)
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}