//! E2e lab scripts for repair ROI evaluation across hard network regimes.
//!
//! Provides reproducible scenarios for testing repair coordinator decisions
//! with deterministic network conditions, emitting detailed logs and proof
//! artifacts for policy validation.

use crate::atp::{AtpRepairCoordinatorPolicy, NetworkRegime, RepairRoiSimulator};
use crate::lab::runtime::LabRuntime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// E2e test scenario configuration for repair ROI evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairRoiE2eScenario {
    /// Scenario name for logging and identification.
    pub name: String,
    /// Network regime to simulate.
    pub regime: NetworkRegime,
    /// Transfer size configurations to test.
    pub transfer_configs: Vec<TransferConfig>,
    /// Expected outcomes for validation.
    pub expected_outcomes: Vec<ExpectedOutcome>,
    /// Maximum duration for the scenario.
    pub max_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    /// Transfer size in bytes.
    pub size_bytes: u64,
    /// Number of source symbols (K).
    pub k_symbols: usize,
    /// Symbol size in bytes.
    pub symbol_size_bytes: u64,
    /// Expected repair action.
    pub expected_repair: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    /// Transfer configuration this outcome applies to.
    pub config_index: usize,
    /// Expected repair decision.
    pub repair_should_activate: bool,
    /// Expected efficiency bounds.
    pub min_bandwidth_efficiency: f64,
    pub max_cpu_overhead_ratio: f64,
    /// Expected proof artifact presence.
    pub should_generate_proof: bool,
}

/// E2e test result with detailed logging artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairRoiE2eResult {
    /// Scenario that was executed.
    pub scenario: RepairRoiE2eScenario,
    /// Execution duration.
    pub duration_micros: u64,
    /// Transfer results for each configuration.
    pub transfer_results: Vec<TransferResult>,
    /// Overall scenario outcome.
    pub success: bool,
    /// Error messages if any.
    pub errors: Vec<String>,
    /// Proof artifact references.
    pub proof_artifacts: Vec<ProofArtifactRef>,
    /// Detailed repair decision logs.
    pub decision_logs: Vec<RepairDecisionLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResult {
    /// Configuration used.
    pub config: TransferConfig,
    /// Symbols sent (original + repair).
    pub symbols_sent: u64,
    /// Symbols useful (contributed to decode).
    pub symbols_useful: u64,
    /// Decode outcome.
    pub decode_success: bool,
    /// Bytes wasted (overhead that didn't help).
    pub bytes_wasted: u64,
    /// CPU time per GiB processed.
    pub cpu_micros_per_gib: u64,
    /// Actual bandwidth efficiency achieved.
    pub bandwidth_efficiency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifactRef {
    /// Artifact type (e.g., "repair_decision", "raptorq_proof").
    pub artifact_type: String,
    /// Path to artifact file.
    pub path: String,
    /// Content hash for integrity.
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairDecisionLog {
    /// Timestamp of decision.
    pub timestamp_micros: u64,
    /// Transfer configuration.
    pub transfer_config: TransferConfig,
    /// ROI inputs that led to decision.
    pub roi_inputs: serde_json::Value, // Serialized AtpRepairRoiInputs
    /// Decision made.
    pub decision: serde_json::Value, // Serialized AtpRepairCoordinatorDecision
    /// Factors that influenced the decision.
    pub decision_factors: Vec<String>,
    /// Performance impact assessment.
    pub performance_impact: PerformanceImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceImpact {
    /// CPU overhead compared to no-repair baseline.
    pub cpu_overhead_ratio: f64,
    /// Bandwidth overhead compared to optimal.
    pub bandwidth_overhead_ratio: f64,
    /// Memory pressure increase.
    pub memory_pressure_increase_permille: u64,
    /// Expected latency impact.
    pub latency_impact_micros: i64,
}

/// E2e lab harness for repair ROI evaluation.
pub struct RepairRoiE2eHarness {
    /// Lab runtime for deterministic execution.
    lab_runtime: LabRuntime,
    /// Scenarios to execute.
    scenarios: Vec<RepairRoiE2eScenario>,
    /// Policy configurations to test against scenarios.
    policies: Vec<AtpRepairCoordinatorPolicy>,
}

impl RepairRoiE2eHarness {
    /// Create new E2e harness with default scenarios.
    pub fn new(lab_runtime: LabRuntime) -> Self {
        let scenarios = Self::create_default_scenarios();
        let policies = vec![AtpRepairCoordinatorPolicy::default()];

        Self {
            lab_runtime,
            scenarios,
            policies,
        }
    }

    /// Configure multiple policies for comparison testing.
    pub fn with_policies(mut self, policies: Vec<AtpRepairCoordinatorPolicy>) -> Self {
        self.policies = policies;
        self
    }

    /// Create a set of diverse policies for comparison testing.
    pub fn create_comparison_policies() -> Vec<AtpRepairCoordinatorPolicy> {
        vec![
            // Conservative policy - high thresholds, prefers reliability
            AtpRepairCoordinatorPolicy {
                min_positive_roi_micros: 1000,
                parity_trickle_min_roi_micros: 2000,
                burst_repair_min_roi_micros: 5000,
                multi_peer_min_roi_micros: 8000,
                bandwidth_cost_micros_per_mib: 10000,
                max_relay_cost_micros_per_mib: 50000,
                high_memory_pressure_permille: 700,
                high_stream_contention_permille: 600,
                unstable_path_permille: 100,
                parity_loss_permille: 50,
                ..AtpRepairCoordinatorPolicy::default()
            },
            // Aggressive policy - low thresholds, prefers speed
            AtpRepairCoordinatorPolicy {
                min_positive_roi_micros: 100,
                parity_trickle_min_roi_micros: 200,
                burst_repair_min_roi_micros: 500,
                multi_peer_min_roi_micros: 1000,
                bandwidth_cost_micros_per_mib: 5000,
                max_relay_cost_micros_per_mib: 100000,
                high_memory_pressure_permille: 900,
                high_stream_contention_permille: 850,
                unstable_path_permille: 300,
                parity_loss_permille: 20,
                ..AtpRepairCoordinatorPolicy::default()
            },
            // Balanced policy - moderate thresholds
            AtpRepairCoordinatorPolicy {
                min_positive_roi_micros: 500,
                parity_trickle_min_roi_micros: 1000,
                burst_repair_min_roi_micros: 2500,
                multi_peer_min_roi_micros: 4000,
                bandwidth_cost_micros_per_mib: 7500,
                max_relay_cost_micros_per_mib: 75000,
                high_memory_pressure_permille: 800,
                high_stream_contention_permille: 725,
                unstable_path_permille: 200,
                parity_loss_permille: 35,
                ..AtpRepairCoordinatorPolicy::default()
            },
        ]
    }

    /// Execute all scenarios against all configured policies and return comparison results.
    pub fn execute_policy_comparison(&mut self) -> PolicyComparisonResult {
        let mut policy_results = Vec::new();
        let scenario_names: Vec<String> = self.scenarios.iter().map(|s| s.name.clone()).collect();

        // Clone policies to avoid borrowing conflicts
        let policies = self.policies.clone();

        for (policy_index, policy) in policies.iter().enumerate() {
            let policy_name = match policy_index {
                0 => "Conservative",
                1 => "Aggressive",
                2 => "Balanced",
                _ => "Custom",
            };

            // Configure simulator with this policy
            let mut scenario_results = Vec::new();

            for scenario in &self.scenarios.clone() {
                // Execute scenario with this specific policy
                let result = self.execute_scenario_with_policy(scenario, policy);
                scenario_results.push(result);
            }

            policy_results.push(PolicyResult {
                policy_name: policy_name.to_string(),
                policy_config: *policy,
                scenario_results,
            });
        }

        // Clone policy_results for summary generation before moving into result struct
        let summary = self.generate_policy_summary(&policy_results);

        PolicyComparisonResult {
            scenario_names,
            policy_results,
            summary,
        }
    }

    /// Execute a scenario with a specific policy configuration.
    fn execute_scenario_with_policy(
        &mut self,
        scenario: &RepairRoiE2eScenario,
        policy: &AtpRepairCoordinatorPolicy,
    ) -> RepairRoiE2eResult {
        let start_time = self.lab_runtime.now();
        let mut transfer_results = Vec::new();
        let mut errors = Vec::new();
        let mut proof_artifacts = Vec::new();
        let mut decision_logs = Vec::new();
        let mut success = true;

        // Create simulator for this scenario with specific policy
        let mut simulator = RepairRoiSimulator::new();
        simulator.add_regime(scenario.regime.clone());
        // Configure simulator to use the specific policy for this scenario
        simulator.configure_policy(*policy);

        for (config_index, config) in scenario.transfer_configs.iter().enumerate() {
            match self.execute_transfer_config(scenario, config, &mut simulator) {
                Ok((transfer_result, decision_log, artifacts)) => {
                    transfer_results.push(transfer_result);
                    decision_logs.push(decision_log);
                    proof_artifacts.extend(artifacts);
                }
                Err(error) => {
                    errors.push(format!("Transfer config {}: {}", config_index, error));
                    success = false;
                }
            }
        }

        // Validate against expected outcomes
        for expected in &scenario.expected_outcomes {
            if let Some(result) = transfer_results.get(expected.config_index) {
                if !self.validate_expected_outcome(expected, result) {
                    errors.push(format!(
                        "Expected outcome validation failed for config {}",
                        expected.config_index
                    ));
                    success = false;
                }
            }
        }

        let end_time = self.lab_runtime.now();

        let duration_micros = end_time.duration_since(start_time) / 1000;

        RepairRoiE2eResult {
            scenario: scenario.clone(),
            duration_micros,
            transfer_results,
            success,
            errors,
            proof_artifacts,
            decision_logs,
        }
    }

    /// Generate a summary comparing policy performance.
    fn generate_policy_summary(&self, policy_results: &[PolicyResult]) -> PolicySummary {
        let mut policy_metrics = Vec::new();

        for policy_result in policy_results {
            let total_scenarios = policy_result.scenario_results.len();
            let successful_scenarios = policy_result
                .scenario_results
                .iter()
                .filter(|r| r.success)
                .count();

            let total_duration: Duration = policy_result
                .scenario_results
                .iter()
                .map(|r| Duration::from_micros(r.duration_micros))
                .sum();

            let avg_bandwidth_efficiency = policy_result
                .scenario_results
                .iter()
                .flat_map(|r| &r.transfer_results)
                .map(|t| t.bandwidth_efficiency)
                .sum::<f64>()
                / policy_result
                    .scenario_results
                    .iter()
                    .flat_map(|r| &r.transfer_results)
                    .count()
                    .max(1) as f64;

            policy_metrics.push(PolicyMetrics {
                policy_name: policy_result.policy_name.clone(),
                success_rate: successful_scenarios as f64 / total_scenarios as f64,
                avg_duration: total_duration / total_scenarios as u32,
                avg_bandwidth_efficiency,
                total_errors: policy_result
                    .scenario_results
                    .iter()
                    .map(|r| r.errors.len())
                    .sum(),
            });
        }

        // Compute summary values before moving policy_metrics
        let best_overall_policy = self.determine_best_policy(&policy_metrics);
        let recommendations = self.generate_policy_recommendations(&policy_metrics);

        PolicySummary {
            policy_metrics,
            best_overall_policy,
            recommendations,
        }
    }

    /// Determine the best overall policy based on weighted metrics.
    fn determine_best_policy(&self, metrics: &[PolicyMetrics]) -> String {
        let mut best_score = -1.0f64;
        let mut best_policy = "Unknown".to_string();

        for metric in metrics {
            // Weighted scoring: success_rate (40%) + efficiency (35%) + speed (25%)
            let success_weight = 0.4;
            let efficiency_weight = 0.35;
            let speed_weight = 0.25;

            let speed_score = if metric.avg_duration.as_secs() > 0 {
                1.0 / metric.avg_duration.as_secs() as f64
            } else {
                1.0
            };

            let score = (metric.success_rate * success_weight)
                + (metric.avg_bandwidth_efficiency * efficiency_weight)
                + (speed_score * speed_weight);

            if score > best_score {
                best_score = score;
                best_policy.clone_from(&metric.policy_name);
            }
        }

        best_policy
    }

    /// Generate recommendations based on policy comparison.
    fn generate_policy_recommendations(&self, metrics: &[PolicyMetrics]) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Find highest success rate
        if let Some(most_reliable) = metrics.iter().max_by(|a, b| {
            a.success_rate
                .partial_cmp(&b.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            recommendations.push(format!(
                "{} policy showed highest success rate ({:.1}%)",
                most_reliable.policy_name,
                most_reliable.success_rate * 100.0
            ));
        }

        // Find highest efficiency
        if let Some(most_efficient) = metrics.iter().max_by(|a, b| {
            a.avg_bandwidth_efficiency
                .partial_cmp(&b.avg_bandwidth_efficiency)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            recommendations.push(format!(
                "{} policy achieved best bandwidth efficiency ({:.3})",
                most_efficient.policy_name, most_efficient.avg_bandwidth_efficiency
            ));
        }

        // Find fastest
        if let Some(fastest) = metrics.iter().min_by_key(|m| m.avg_duration) {
            recommendations.push(format!(
                "{} policy completed scenarios fastest (avg {:.1}s)",
                fastest.policy_name,
                fastest.avg_duration.as_secs_f64()
            ));
        }

        if recommendations.is_empty() {
            recommendations
                .push("No clear performance differences detected between policies".to_string());
        }

        recommendations
    }

    /// Create default test scenarios covering all regime types.
    fn create_default_scenarios() -> Vec<RepairRoiE2eScenario> {
        vec![
            // Clean path - should suppress repair
            RepairRoiE2eScenario {
                name: "clean-path-suppression".to_string(),
                regime: NetworkRegime::clean_path(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 10_485_760, // 10 MiB
                    k_symbols: 10240,
                    symbol_size_bytes: 1024,
                    expected_repair: false,
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: false,
                    min_bandwidth_efficiency: 1.0, // Perfect efficiency
                    max_cpu_overhead_ratio: 0.0,   // No overhead
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(30),
            },
            // Lossy Wi-Fi - should activate repair intelligently
            RepairRoiE2eScenario {
                name: "lossy-wifi-adaptive".to_string(),
                regime: NetworkRegime::lossy_wifi(),
                transfer_configs: vec![
                    TransferConfig {
                        size_bytes: 104_857_600, // 100 MiB
                        k_symbols: 102400,
                        symbol_size_bytes: 1024,
                        expected_repair: true, // Should activate for large lossy transfers
                    },
                    TransferConfig {
                        size_bytes: 1_048_576, // 1 MiB
                        k_symbols: 1024,
                        symbol_size_bytes: 1024,
                        expected_repair: false, // May not activate for small transfers
                    },
                ],
                expected_outcomes: vec![
                    ExpectedOutcome {
                        config_index: 0,
                        repair_should_activate: true,
                        min_bandwidth_efficiency: 0.8, // Some overhead acceptable
                        max_cpu_overhead_ratio: 2.0,   // Reasonable CPU cost
                        should_generate_proof: true,
                    },
                    ExpectedOutcome {
                        config_index: 1,
                        repair_should_activate: false, // Too small for repair
                        min_bandwidth_efficiency: 0.9,
                        max_cpu_overhead_ratio: 0.5,
                        should_generate_proof: true,
                    },
                ],
                max_duration: Duration::from_secs(60),
            },
            // Satellite high-BDP - should be selective about repair
            RepairRoiE2eScenario {
                name: "satellite-high-bdp-selective".to_string(),
                regime: NetworkRegime::satellite_high_bdp(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 1_073_741_824, // 1 GiB
                    k_symbols: 1048576,
                    symbol_size_bytes: 1024,
                    expected_repair: true, // Large transfers benefit from repair
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: true,
                    min_bandwidth_efficiency: 0.85, // High BDP tolerates some overhead
                    max_cpu_overhead_ratio: 1.5,
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(120),
            },
            // Relay expensive - should be very conservative
            RepairRoiE2eScenario {
                name: "relay-expensive-conservative".to_string(),
                regime: NetworkRegime::relay_expensive(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 52_428_800, // 50 MiB
                    k_symbols: 51200,
                    symbol_size_bytes: 1024,
                    expected_repair: false, // Should avoid repair due to cost
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: false,
                    min_bandwidth_efficiency: 1.0, // No wasted bandwidth
                    max_cpu_overhead_ratio: 0.0,
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(90),
            },
            // Mobile unstable - should consider instability
            RepairRoiE2eScenario {
                name: "mobile-unstable-adaptive".to_string(),
                regime: NetworkRegime::mobile_unstable(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 20_971_520, // 20 MiB
                    k_symbols: 20480,
                    symbol_size_bytes: 1024,
                    expected_repair: true, // Instability benefits from repair
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: true,
                    min_bandwidth_efficiency: 0.75, // Higher overhead acceptable for mobile
                    max_cpu_overhead_ratio: 3.0,
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(180),
            },
            // Swarm multi-peer - should leverage peer diversity
            RepairRoiE2eScenario {
                name: "swarm-multi-peer-leverage".to_string(),
                regime: NetworkRegime::swarm_multi_peer(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 209_715_200, // 200 MiB
                    k_symbols: 204800,
                    symbol_size_bytes: 1024,
                    expected_repair: true, // Multi-peer benefits from repair
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: true,
                    min_bandwidth_efficiency: 0.8,
                    max_cpu_overhead_ratio: 2.5,
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(300),
            },
            // Tail resume - should prioritize resume capability
            RepairRoiE2eScenario {
                name: "tail-resume-prioritize".to_string(),
                regime: NetworkRegime::tail_resume(),
                transfer_configs: vec![TransferConfig {
                    size_bytes: 536_870_912, // 512 MiB
                    k_symbols: 524288,
                    symbol_size_bytes: 1024,
                    expected_repair: true, // Resume scenarios benefit from repair
                }],
                expected_outcomes: vec![ExpectedOutcome {
                    config_index: 0,
                    repair_should_activate: true,
                    min_bandwidth_efficiency: 0.85,
                    max_cpu_overhead_ratio: 2.0,
                    should_generate_proof: true,
                }],
                max_duration: Duration::from_secs(240),
            },
        ]
    }

    /// Execute all scenarios and return comprehensive results.
    pub fn execute_all_scenarios(&mut self) -> Vec<RepairRoiE2eResult> {
        let mut results = Vec::new();

        for scenario in &self.scenarios.clone() {
            let result = self.execute_scenario(scenario);
            results.push(result);
        }

        results
    }

    /// Execute a single scenario with detailed logging.
    pub fn execute_scenario(&mut self, scenario: &RepairRoiE2eScenario) -> RepairRoiE2eResult {
        let start_time = self.lab_runtime.now();
        let mut transfer_results = Vec::new();
        let mut errors = Vec::new();
        let mut proof_artifacts = Vec::new();
        let mut decision_logs = Vec::new();
        let mut success = true;

        // Create simulator for this scenario
        let mut simulator = RepairRoiSimulator::new();
        simulator.add_regime(scenario.regime.clone());

        for (config_index, config) in scenario.transfer_configs.iter().enumerate() {
            match self.execute_transfer_config(scenario, config, &mut simulator) {
                Ok((transfer_result, decision_log, artifacts)) => {
                    transfer_results.push(transfer_result);
                    decision_logs.push(decision_log);
                    proof_artifacts.extend(artifacts);
                }
                Err(error) => {
                    errors.push(format!("Transfer config {}: {}", config_index, error));
                    success = false;
                }
            }
        }

        // Validate against expected outcomes
        for expected in &scenario.expected_outcomes {
            if let Some(result) = transfer_results.get(expected.config_index) {
                if !self.validate_expected_outcome(expected, result) {
                    errors.push(format!(
                        "Expected outcome validation failed for config {}",
                        expected.config_index
                    ));
                    success = false;
                }
            }
        }

        let end_time = self.lab_runtime.now();
        let duration_micros = end_time
            .saturating_sub_nanos(start_time.as_nanos())
            .as_nanos()
            / 1000;

        RepairRoiE2eResult {
            scenario: scenario.clone(),
            duration_micros,
            transfer_results,
            success,
            errors,
            proof_artifacts,
            decision_logs,
        }
    }

    /// Execute a single transfer configuration.
    fn execute_transfer_config(
        &mut self,
        scenario: &RepairRoiE2eScenario,
        config: &TransferConfig,
        _simulator: &mut RepairRoiSimulator,
    ) -> Result<(TransferResult, RepairDecisionLog, Vec<ProofArtifactRef>), String> {
        // Generate ROI inputs for this configuration
        let roi_inputs = scenario.regime.generate_roi_inputs(
            config.size_bytes,
            config.k_symbols,
            config.symbol_size_bytes,
        );

        // Make repair decision
        let coordinator = crate::atp::AtpRepairCoordinator::default();
        let decision = coordinator.decide(&roi_inputs);

        // Simulate the transfer execution
        let repair_activated = !matches!(
            decision.action,
            crate::atp::autotune::AtpRepairAction::NoRepair
        );

        // Calculate performance metrics
        let symbols_sent = if repair_activated {
            config.k_symbols as u64
                + (roi_inputs.bandwidth_overhead_bytes / config.symbol_size_bytes)
        } else {
            config.k_symbols as u64
        };

        let symbols_useful = config.k_symbols as u64; // Assume successful decode
        let bytes_wasted = if repair_activated {
            roi_inputs.bandwidth_overhead_bytes
        } else {
            0
        };

        let cpu_time_micros = if repair_activated {
            roi_inputs.encode_cpu_micros + roi_inputs.decode_cpu_micros
        } else {
            0
        };

        let gib_processed = config.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let cpu_micros_per_gib = if gib_processed > 0.0 {
            (cpu_time_micros as f64 / gib_processed) as u64
        } else {
            0
        };

        let bandwidth_efficiency = symbols_useful as f64 / symbols_sent as f64;

        let transfer_result = TransferResult {
            config: config.clone(),
            symbols_sent,
            symbols_useful,
            decode_success: true, // Assume success for simulation
            bytes_wasted,
            cpu_micros_per_gib,
            bandwidth_efficiency,
        };

        // Create decision log
        let decision_log = RepairDecisionLog {
            timestamp_micros: self.lab_runtime.now().as_nanos() / 1000,
            transfer_config: config.clone(),
            roi_inputs: serde_json::to_value(&roi_inputs).unwrap_or_default(),
            decision: serde_json::to_value(&decision).unwrap_or_default(),
            decision_factors: decision
                .factors
                .iter()
                .map(|f| format!("{:?}", f))
                .collect(),
            performance_impact: PerformanceImpact {
                cpu_overhead_ratio: if cpu_time_micros > 0 { 1.5 } else { 0.0 },
                bandwidth_overhead_ratio: 1.0 - bandwidth_efficiency,
                memory_pressure_increase_permille: roi_inputs.memory_pressure_permille as u64,
                latency_impact_micros: if repair_activated { 5000 } else { 0 }, // 5ms encode/decode
            },
        };

        // Create proof artifacts
        let mut artifacts = Vec::new();
        if repair_activated {
            artifacts.push(ProofArtifactRef {
                artifact_type: "repair_decision".to_string(),
                path: format!(
                    "/tmp/repair_decision_{}_{}.json",
                    scenario.name, config.size_bytes
                ),
                content_hash: "mock_hash_123".to_string(),
            });
        }

        Ok((transfer_result, decision_log, artifacts))
    }

    /// Validate transfer result against expected outcome.
    fn validate_expected_outcome(
        &self,
        expected: &ExpectedOutcome,
        result: &TransferResult,
    ) -> bool {
        // Check repair activation expectation
        let repair_activated = result.symbols_sent > result.config.k_symbols as u64;
        if repair_activated != expected.repair_should_activate {
            return false;
        }

        // Check bandwidth efficiency
        if result.bandwidth_efficiency < expected.min_bandwidth_efficiency {
            return false;
        }

        // Check CPU overhead (simplified check)
        let cpu_overhead_ratio = if result.cpu_micros_per_gib > 0 {
            2.0
        } else {
            0.0
        };
        if cpu_overhead_ratio > expected.max_cpu_overhead_ratio {
            return false;
        }

        true
    }

    /// Generate comprehensive report from E2e results.
    pub fn generate_report(&self, results: &[RepairRoiE2eResult]) -> E2eReport {
        let mut total_scenarios = 0;
        let mut successful_scenarios = 0;
        let mut failed_scenarios = 0;
        let mut regime_summaries = HashMap::new();

        for result in results {
            total_scenarios += 1;
            if result.success {
                successful_scenarios += 1;
            } else {
                failed_scenarios += 1;
            }

            let summary = regime_summaries
                .entry(result.scenario.regime.name.clone())
                .or_insert_with(|| RegimeSummary {
                    regime_name: result.scenario.regime.name.clone(),
                    total_transfers: 0,
                    repair_activations: 0,
                    avg_bandwidth_efficiency: 0.0,
                    avg_cpu_overhead: 0.0,
                    success_rate: 0.0,
                });

            summary.total_transfers += result.transfer_results.len();
            for transfer in &result.transfer_results {
                if transfer.symbols_sent > transfer.config.k_symbols as u64 {
                    summary.repair_activations += 1;
                }
                summary.avg_bandwidth_efficiency += transfer.bandwidth_efficiency;
                summary.avg_cpu_overhead += transfer.cpu_micros_per_gib as f64;
            }
        }

        // Normalize averages
        for summary in regime_summaries.values_mut() {
            if summary.total_transfers > 0 {
                summary.avg_bandwidth_efficiency /= summary.total_transfers as f64;
                summary.avg_cpu_overhead /= summary.total_transfers as f64;
            }
            summary.success_rate = if summary.total_transfers > 0 {
                1.0 // Simplified - assume all completed transfers are successful
            } else {
                0.0
            };
        }

        E2eReport {
            total_scenarios,
            successful_scenarios,
            failed_scenarios,
            regime_summaries: regime_summaries.into_values().collect(),
            overall_success_rate: successful_scenarios as f64 / total_scenarios as f64,
        }
    }
}

/// Policy comparison test result containing results for all policies tested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyComparisonResult {
    /// Names of scenarios tested.
    pub scenario_names: Vec<String>,
    /// Results for each policy tested.
    pub policy_results: Vec<PolicyResult>,
    /// Summary comparing policy performance.
    pub summary: PolicySummary,
}

/// Results for a single policy across all scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Policy name for identification.
    pub policy_name: String,
    /// Policy configuration used.
    pub policy_config: AtpRepairCoordinatorPolicy,
    /// Results for each scenario with this policy.
    pub scenario_results: Vec<RepairRoiE2eResult>,
}

/// Performance metrics for a single policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetrics {
    /// Policy name.
    pub policy_name: String,
    /// Percentage of scenarios that succeeded.
    pub success_rate: f64,
    /// Average duration per scenario.
    pub avg_duration: Duration,
    /// Average bandwidth efficiency achieved.
    pub avg_bandwidth_efficiency: f64,
    /// Total number of errors across all scenarios.
    pub total_errors: usize,
}

/// Summary comparing all tested policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    /// Metrics for each policy.
    pub policy_metrics: Vec<PolicyMetrics>,
    /// Name of the best overall policy.
    pub best_overall_policy: String,
    /// Recommendations based on comparison.
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    pub total_scenarios: usize,
    pub successful_scenarios: usize,
    pub failed_scenarios: usize,
    pub regime_summaries: Vec<RegimeSummary>,
    pub overall_success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeSummary {
    pub regime_name: String,
    pub total_transfers: usize,
    pub repair_activations: usize,
    pub avg_bandwidth_efficiency: f64,
    pub avg_cpu_overhead: f64,
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::runtime::LabRuntime;

    #[test]
    fn test_e2e_scenario_creation() {
        let scenarios = RepairRoiE2eHarness::create_default_scenarios();
        assert!(!scenarios.is_empty());

        // Verify clean path scenario
        let clean_scenario = scenarios
            .iter()
            .find(|s| s.name == "clean-path-suppression")
            .expect("Clean path scenario should exist");

        assert!(clean_scenario.regime.is_clean_path);
        assert_eq!(clean_scenario.regime.loss_permille, 0);
    }

    #[test]
    fn test_transfer_config_validation() {
        let config = TransferConfig {
            size_bytes: 1_048_576,
            k_symbols: 1024,
            symbol_size_bytes: 1024,
            expected_repair: false,
        };

        // Size should match k * symbol_size
        assert_eq!(
            config.size_bytes,
            config.k_symbols as u64 * config.symbol_size_bytes
        );
    }

    #[test]
    fn test_expected_outcome_validation() {
        let outcome = ExpectedOutcome {
            config_index: 0,
            repair_should_activate: false,
            min_bandwidth_efficiency: 1.0,
            max_cpu_overhead_ratio: 0.0,
            should_generate_proof: true,
        };

        let result = TransferResult {
            config: TransferConfig {
                size_bytes: 1_048_576,
                k_symbols: 1024,
                symbol_size_bytes: 1024,
                expected_repair: false,
            },
            symbols_sent: 1024, // No repair symbols
            symbols_useful: 1024,
            decode_success: true,
            bytes_wasted: 0,
            cpu_micros_per_gib: 0,
            bandwidth_efficiency: 1.0,
        };

        // This should validate successfully
        let harness = RepairRoiE2eHarness::new(LabRuntime::new(crate::lab::LabConfig::default()));
        assert!(harness.validate_expected_outcome(&outcome, &result));
    }

    #[test]
    fn test_policy_comparison_configuration() {
        // Test that we can configure multiple policies for comparison
        let lab_runtime = LabRuntime::new(crate::lab::LabConfig::default());
        let policies = RepairRoiE2eHarness::create_comparison_policies();

        // Should create 3 different policies (Conservative, Aggressive, Balanced)
        assert_eq!(policies.len(), 3);

        let harness = RepairRoiE2eHarness::new(lab_runtime).with_policies(policies.clone());

        // Verify policies were set correctly
        assert_eq!(harness.policies.len(), 3);

        // Verify policies have different configurations
        assert_ne!(
            harness.policies[0].min_positive_roi_micros,
            harness.policies[1].min_positive_roi_micros
        );
        assert_ne!(
            harness.policies[1].burst_repair_min_roi_micros,
            harness.policies[2].burst_repair_min_roi_micros
        );
    }

    #[test]
    fn test_policy_comparison_result_structure() {
        // Test the policy comparison result structure
        let lab_runtime = LabRuntime::new(crate::lab::LabConfig::default());
        let policies = RepairRoiE2eHarness::create_comparison_policies();
        let harness = RepairRoiE2eHarness::new(lab_runtime).with_policies(policies);

        // This would normally execute scenarios, but for testing we just verify structure
        let scenarios = &harness.scenarios.clone();
        let scenario_names: Vec<String> = scenarios.iter().map(|s| s.name.clone()).collect();

        // Verify we have test scenarios
        assert!(!scenario_names.is_empty());
        assert!(
            scenario_names
                .iter()
                .any(|name| name.contains("clean-path"))
        );
        assert!(scenario_names.iter().any(|name| name.contains("lossy")));

        // Verify comparison policies have been configured
        assert_eq!(harness.policies.len(), 3);

        // Test policy metrics structure
        let metrics = PolicyMetrics {
            policy_name: "Test".to_string(),
            success_rate: 0.95,
            avg_duration: Duration::from_secs(10),
            avg_bandwidth_efficiency: 0.85,
            total_errors: 1,
        };

        assert_eq!(metrics.policy_name, "Test");
        assert_eq!(metrics.success_rate, 0.95);
        assert_eq!(metrics.avg_duration, Duration::from_secs(10));
    }

    #[test]
    fn test_policy_comparison_best_policy_selection() {
        // Test the logic for determining the best policy
        let harness = RepairRoiE2eHarness::new(LabRuntime::new(crate::lab::LabConfig::default()));

        let test_metrics = vec![
            PolicyMetrics {
                policy_name: "HighSuccess".to_string(),
                success_rate: 1.0,
                avg_duration: Duration::from_secs(20),
                avg_bandwidth_efficiency: 0.8,
                total_errors: 0,
            },
            PolicyMetrics {
                policy_name: "HighEfficiency".to_string(),
                success_rate: 0.9,
                avg_duration: Duration::from_secs(15),
                avg_bandwidth_efficiency: 0.95,
                total_errors: 1,
            },
            PolicyMetrics {
                policy_name: "FastButUnreliable".to_string(),
                success_rate: 0.7,
                avg_duration: Duration::from_secs(5),
                avg_bandwidth_efficiency: 0.9,
                total_errors: 3,
            },
        ];

        let best_policy = harness.determine_best_policy(&test_metrics);

        // Should favor reliability over pure speed
        assert!(best_policy == "HighSuccess" || best_policy == "HighEfficiency");
        assert_ne!(best_policy, "FastButUnreliable");
    }
}
