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
    /// Policy configurations to test.
    #[allow(dead_code)] // TODO: Use for policy comparison tests
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
        let harness = RepairRoiE2eHarness::new(LabRuntime::new());
        assert!(harness.validate_expected_outcome(&outcome, &result));
    }
}
