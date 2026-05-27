//! Repair ROI simulator and deterministic fixtures for network regimes.
//!
//! This module provides evidence-based evaluation of when RaptorQ repair helps,
//! when it hurts, and when exact retransmit is better across various network
//! conditions. The simulator computes expected time saved versus costs to guide
//! adaptive repair policy thresholds.

use crate::atp::autotune::{
    AtpRepairAction, AtpRepairCoordinator, AtpRepairCoordinatorDecision,
    AtpRepairCoordinatorPolicy, AtpRepairPathMode, AtpRepairRoiInputs,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network regime characteristics for deterministic simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkRegime {
    /// Name of the network regime for logging and identification.
    pub name: String,
    /// Average round-trip time in microseconds.
    pub rtt_micros: u64,
    /// Loss rate in packets per thousand.
    pub loss_permille: u64,
    /// Bandwidth in bytes per second.
    pub bandwidth_bps: u64,
    /// Path stability (low = frequent migrations).
    pub stability_permille: u64,
    /// Relay cost multiplier (1000 = normal, higher = more expensive).
    pub relay_cost_multiplier_permille: u64,
    /// Mobile/unstable connection characteristics.
    pub mobile_unstable: bool,
    /// High bandwidth-delay product characteristics.
    pub high_bdp: bool,
    /// Asymmetric uplink (slower upload).
    pub asymmetric_uplink_ratio: f64,
    /// Multi-peer swarm characteristics.
    pub swarm_peer_count: u32,
    /// Clean path (no loss, low latency).
    pub is_clean_path: bool,
}

impl NetworkRegime {
    /// Create a clean, high-performance path regime.
    pub fn clean_path() -> Self {
        Self {
            name: "clean-path".to_string(),
            rtt_micros: 10_000,                   // 10ms
            loss_permille: 0,                     // No loss
            bandwidth_bps: 100_000_000,           // 100 Mbps
            stability_permille: 1000,             // Very stable
            relay_cost_multiplier_permille: 1000, // Normal cost
            mobile_unstable: false,
            high_bdp: false,
            asymmetric_uplink_ratio: 1.0, // Symmetric
            swarm_peer_count: 1,
            is_clean_path: true,
        }
    }

    /// Create a lossy Wi-Fi regime with packet loss.
    pub fn lossy_wifi() -> Self {
        Self {
            name: "lossy-wifi".to_string(),
            rtt_micros: 25_000,        // 25ms
            loss_permille: 50,         // 5% loss
            bandwidth_bps: 50_000_000, // 50 Mbps
            stability_permille: 800,   // Moderately stable
            relay_cost_multiplier_permille: 1000,
            mobile_unstable: false,
            high_bdp: false,
            asymmetric_uplink_ratio: 0.8, // Slightly asymmetric
            swarm_peer_count: 1,
            is_clean_path: false,
        }
    }

    /// Create a satellite high-BDP regime.
    pub fn satellite_high_bdp() -> Self {
        Self {
            name: "satellite-high-bdp".to_string(),
            rtt_micros: 600_000,                  // 600ms
            loss_permille: 10,                    // 1% loss
            bandwidth_bps: 25_000_000,            // 25 Mbps
            stability_permille: 900,              // Stable
            relay_cost_multiplier_permille: 2000, // Expensive
            mobile_unstable: false,
            high_bdp: true,
            asymmetric_uplink_ratio: 0.3, // Heavily asymmetric
            swarm_peer_count: 1,
            is_clean_path: false,
        }
    }

    /// Create a mobile unstable regime with frequent handoffs.
    pub fn mobile_unstable() -> Self {
        Self {
            name: "mobile-unstable".to_string(),
            rtt_micros: 80_000,                   // 80ms
            loss_permille: 100,                   // 10% loss
            bandwidth_bps: 10_000_000,            // 10 Mbps
            stability_permille: 300,              // Very unstable
            relay_cost_multiplier_permille: 1500, // More expensive
            mobile_unstable: true,
            high_bdp: false,
            asymmetric_uplink_ratio: 0.5, // Asymmetric
            swarm_peer_count: 1,
            is_clean_path: false,
        }
    }

    /// Create a relay-expensive regime.
    pub fn relay_expensive() -> Self {
        Self {
            name: "relay-expensive".to_string(),
            rtt_micros: 150_000,                  // 150ms via relay
            loss_permille: 5,                     // 0.5% loss
            bandwidth_bps: 20_000_000,            // 20 Mbps
            stability_permille: 700,              // Moderately stable
            relay_cost_multiplier_permille: 5000, // Very expensive
            mobile_unstable: false,
            high_bdp: false,
            asymmetric_uplink_ratio: 1.0,
            swarm_peer_count: 1,
            is_clean_path: false,
        }
    }

    /// Create a swarm multi-peer regime.
    pub fn swarm_multi_peer() -> Self {
        Self {
            name: "swarm-multi-peer".to_string(),
            rtt_micros: 40_000,                   // 40ms average
            loss_permille: 30,                    // 3% loss
            bandwidth_bps: 80_000_000,            // 80 Mbps aggregate
            stability_permille: 600,              // Unstable (peers come/go)
            relay_cost_multiplier_permille: 1200, // Slightly expensive
            mobile_unstable: false,
            high_bdp: false,
            asymmetric_uplink_ratio: 0.9,
            swarm_peer_count: 5, // Multiple peers
            is_clean_path: false,
        }
    }

    /// Create a tail/resume scenario with sparse gaps.
    pub fn tail_resume() -> Self {
        Self {
            name: "tail-resume".to_string(),
            rtt_micros: 30_000,        // 30ms
            loss_permille: 20,         // 2% loss
            bandwidth_bps: 40_000_000, // 40 Mbps
            stability_permille: 750,   // Moderately stable
            relay_cost_multiplier_permille: 1100,
            mobile_unstable: false,
            high_bdp: false,
            asymmetric_uplink_ratio: 0.85,
            swarm_peer_count: 1,
            is_clean_path: false,
        }
    }

    /// Generate ROI inputs for this network regime with given transfer parameters.
    pub fn generate_roi_inputs(
        &self,
        transfer_size_bytes: u64,
        k_symbols: usize,
        symbol_size_bytes: u64,
    ) -> AtpRepairRoiInputs {
        // Calculate expected time saved based on loss characteristics
        let expected_retransmit_rounds = if self.loss_permille == 0 {
            0
        } else {
            // Simple model: higher loss = more retransmit rounds
            1 + (self.loss_permille / 10).max(1)
        };

        let expected_time_saved_micros = expected_retransmit_rounds * self.rtt_micros;

        // Calculate bandwidth overhead (repair symbols needed)
        let repair_symbols_needed = if self.loss_permille == 0 {
            0
        } else {
            // Conservative estimate: 1.2x original for 5% loss, scaling
            let overhead_ratio = 1.0 + (self.loss_permille as f64 / 1000.0) * 2.5;
            ((k_symbols as f64 * overhead_ratio) - k_symbols as f64).ceil() as u64
        };

        let bandwidth_overhead_bytes = repair_symbols_needed * symbol_size_bytes;

        // Encode/decode costs scale with symbol count and processing
        let encode_cpu_micros = k_symbols as u64 * 2; // 2µs per source symbol
        let decode_cpu_micros = (k_symbols as u64 + repair_symbols_needed) * 3; // 3µs per symbol

        // Path-dependent pressures (convert to u16 and clamp to max 1000)
        let memory_pressure_permille = if transfer_size_bytes > 100_000_000 {
            200u16
        } else {
            50u16
        };
        let stream_contention_permille = if self.swarm_peer_count > 1 {
            150u16
        } else {
            30u16
        };

        let path_stability_permille = (self.stability_permille as u16).min(1000);

        // Resume value higher for tail scenarios and large transfers (convert to u16)
        let resume_value_permille =
            if self.name.contains("tail") || transfer_size_bytes > 500_000_000 {
                400u16
            } else {
                100u16
            };

        // Loss permille as u16
        let loss_permille = (self.loss_permille as u16).min(1000);

        // Available peer count
        let available_peer_count = (self.swarm_peer_count as u16).max(1);

        // Relay cost
        let relay_cost_micros_per_mib = (self.relay_cost_multiplier_permille * 100) / 1000; // Convert permille multiplier to micros/MiB

        AtpRepairRoiInputs {
            trace_id: format!("repair-sim-{}", self.name),
            workload_id: format!("transfer-{}-{}", transfer_size_bytes, k_symbols),
            expected_time_saved_micros,
            encode_cpu_micros,
            decode_cpu_micros,
            bandwidth_overhead_bytes,
            memory_pressure_permille,
            stream_contention_permille,
            relay_cost_micros_per_mib,
            path_stability_permille,
            resume_value_permille,
            loss_permille,
            available_peer_count,
            path_mode: AtpRepairPathMode::Direct, // Default to direct path
            requested_mode: None,                 // Let coordinator decide
            missing_tail_chunks: if self.name.contains("tail") { 10 } else { 0 },
            rtt_micros: self.rtt_micros,
            path_migration_events: if self.mobile_unstable { 3 } else { 0 },
            broadcast_peer_count: if self.swarm_peer_count > 1 {
                self.swarm_peer_count as u16
            } else {
                0
            },
        }
    }
}

/// Repair ROI simulation result for a specific scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairRoiSimulationResult {
    /// Network regime used for simulation.
    pub regime: NetworkRegime,
    /// Transfer parameters.
    pub transfer_size_bytes: u64,
    pub k_symbols: usize,
    pub symbol_size_bytes: u64,
    /// ROI inputs generated for this scenario.
    pub roi_inputs: AtpRepairRoiInputs,
    /// Decision made by the coordinator.
    pub decision: AtpRepairCoordinatorDecision,
    /// Calculated metrics.
    pub gross_benefit_micros: u64,
    pub total_cost_micros: u64,
    pub net_roi_micros: i64,
    pub repair_recommended: bool,
    /// Performance impact assessment.
    pub bandwidth_efficiency: f64, // Useful bytes / total bytes sent
    pub cpu_efficiency: f64,        // Time saved / CPU time spent
    pub relay_cost_efficiency: f64, // Time saved / relay cost
}

impl RepairRoiSimulationResult {
    /// Calculate efficiency metrics for this simulation result.
    fn calculate_efficiency_metrics(&mut self) {
        let useful_bytes = self.k_symbols as u64 * self.symbol_size_bytes;
        let total_bytes_sent = useful_bytes + self.roi_inputs.bandwidth_overhead_bytes;

        self.bandwidth_efficiency = if total_bytes_sent > 0 {
            useful_bytes as f64 / total_bytes_sent as f64
        } else {
            1.0
        };

        let total_cpu_micros =
            self.roi_inputs.encode_cpu_micros + self.roi_inputs.decode_cpu_micros;
        self.cpu_efficiency = if total_cpu_micros > 0 {
            self.roi_inputs.expected_time_saved_micros as f64 / total_cpu_micros as f64
        } else {
            0.0
        };

        let relay_cost_micros = mul_div_u64(
            self.roi_inputs.bandwidth_overhead_bytes,
            self.roi_inputs.relay_cost_micros_per_mib,
            1_048_576,
        );
        self.relay_cost_efficiency = if relay_cost_micros > 0 {
            self.roi_inputs.expected_time_saved_micros as f64 / relay_cost_micros as f64
        } else {
            0.0
        };
    }
}

/// Repair ROI simulator for evidence-based policy tuning.
#[derive(Debug, Clone)]
pub struct RepairRoiSimulator {
    /// Available network regimes for simulation.
    regimes: Vec<NetworkRegime>,
    /// Policy configurations to test.
    policies: Vec<AtpRepairCoordinatorPolicy>,
}

impl Default for RepairRoiSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl RepairRoiSimulator {
    /// Create a new repair ROI simulator with default regimes.
    pub fn new() -> Self {
        let regimes = vec![
            NetworkRegime::clean_path(),
            NetworkRegime::lossy_wifi(),
            NetworkRegime::satellite_high_bdp(),
            NetworkRegime::mobile_unstable(),
            NetworkRegime::relay_expensive(),
            NetworkRegime::swarm_multi_peer(),
            NetworkRegime::tail_resume(),
        ];

        let policies = vec![AtpRepairCoordinatorPolicy::default()];

        Self { regimes, policies }
    }

    /// Add a custom network regime to the simulation.
    pub fn add_regime(&mut self, regime: NetworkRegime) {
        self.regimes.push(regime);
    }

    /// Add a custom policy configuration to test.
    pub fn add_policy(&mut self, policy: AtpRepairCoordinatorPolicy) {
        self.policies.push(policy);
    }

    /// Configure the simulator to use a specific policy, replacing any existing policies.
    /// This differs from add_policy which appends to the list - configure_policy
    /// sets a single policy as the only policy to test.
    pub fn configure_policy(&mut self, policy: AtpRepairCoordinatorPolicy) {
        self.policies.clear();
        self.policies.push(policy);
    }

    /// Run simulation across all regimes and transfer sizes.
    pub fn run_comprehensive_simulation(&self) -> HashMap<String, Vec<RepairRoiSimulationResult>> {
        let mut results = HashMap::new();

        // Test different transfer sizes
        let transfer_sizes = vec![
            1_048_576,     // 1 MiB
            10_485_760,    // 10 MiB
            104_857_600,   // 100 MiB
            1_073_741_824, // 1 GiB
        ];

        let k_symbol_configs = vec![
            (1024, 1024), // 1024 symbols, 1 KiB each
            (8192, 1024), // 8192 symbols, 1 KiB each
            (1024, 8192), // 1024 symbols, 8 KiB each
        ];

        for regime in &self.regimes {
            let mut regime_results = Vec::new();

            for &transfer_size in &transfer_sizes {
                for &(k_symbols, symbol_size) in &k_symbol_configs {
                    // Skip combinations that don't match transfer size
                    let expected_size = k_symbols as u64 * symbol_size;
                    if expected_size != transfer_size {
                        continue;
                    }

                    let roi_inputs =
                        regime.generate_roi_inputs(transfer_size, k_symbols, symbol_size);

                    for policy in &self.policies {
                        let coordinator = AtpRepairCoordinator::new(*policy);
                        let decision = coordinator.decide(&roi_inputs);

                        let repair_recommended =
                            !matches!(decision.action, AtpRepairAction::NoRepair);

                        let mut result = RepairRoiSimulationResult {
                            regime: regime.clone(),
                            transfer_size_bytes: transfer_size,
                            k_symbols,
                            symbol_size_bytes: symbol_size,
                            roi_inputs: roi_inputs.clone(),
                            decision: decision.clone(),
                            gross_benefit_micros: 0, // Will be calculated
                            total_cost_micros: 0,    // Will be calculated
                            net_roi_micros: 0,       // Will be calculated
                            repair_recommended,
                            bandwidth_efficiency: 0.0,
                            cpu_efficiency: 0.0,
                            relay_cost_efficiency: 0.0,
                        };

                        // Calculate the metrics that coordinator uses internally
                        result.gross_benefit_micros = roi_inputs
                            .expected_time_saved_micros
                            .saturating_add(self.permille_of(
                                roi_inputs.expected_time_saved_micros,
                                roi_inputs.resume_value_permille as u64,
                            ));

                        let bandwidth_cost = mul_div_u64(
                            roi_inputs.bandwidth_overhead_bytes,
                            policy.bandwidth_cost_micros_per_mib,
                            1_048_576,
                        );
                        let memory_cost = permille_of(
                            result.gross_benefit_micros,
                            u64::from(roi_inputs.memory_pressure_permille),
                        );
                        let stream_cost = permille_of(
                            result.gross_benefit_micros,
                            u64::from(roi_inputs.stream_contention_permille),
                        );

                        result.total_cost_micros = roi_inputs
                            .encode_cpu_micros
                            .saturating_add(roi_inputs.decode_cpu_micros)
                            .saturating_add(bandwidth_cost)
                            .saturating_add(memory_cost)
                            .saturating_add(stream_cost);

                        let net_roi = i128::from(result.gross_benefit_micros)
                            - i128::from(result.total_cost_micros);
                        result.net_roi_micros =
                            net_roi.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;

                        result.calculate_efficiency_metrics();
                        regime_results.push(result);
                    }
                }
            }

            results.insert(regime.name.clone(), regime_results);
        }

        results
    }

    /// Analyze simulation results to generate policy recommendations.
    pub fn analyze_results(
        &self,
        results: &HashMap<String, Vec<RepairRoiSimulationResult>>,
    ) -> PolicyAnalysis {
        let mut analysis = PolicyAnalysis {
            total_scenarios: 0,
            repair_recommended_scenarios: 0,
            clean_path_false_positives: 0,
            high_loss_false_negatives: 0,
            regime_performance: HashMap::new(),
            efficiency_stats: EfficiencyStats::default(),
            recommendations: Vec::new(),
        };

        for (regime_name, regime_results) in results {
            let mut regime_stats = RegimeStats {
                total_scenarios: regime_results.len(),
                repair_recommended: 0,
                avg_bandwidth_efficiency: 0.0,
                avg_cpu_efficiency: 0.0,
                avg_net_roi: 0.0,
                false_positives: 0,
                false_negatives: 0,
            };

            let mut total_bandwidth_eff = 0.0;
            let mut total_cpu_eff = 0.0;
            let mut total_net_roi = 0.0;

            for result in regime_results {
                analysis.total_scenarios += 1;

                if result.repair_recommended {
                    analysis.repair_recommended_scenarios += 1;
                    regime_stats.repair_recommended += 1;
                }

                total_bandwidth_eff += result.bandwidth_efficiency;
                total_cpu_eff += result.cpu_efficiency;
                total_net_roi += result.net_roi_micros as f64;

                // Check for clean path false positives
                if result.regime.is_clean_path && result.repair_recommended {
                    analysis.clean_path_false_positives += 1;
                    regime_stats.false_positives += 1;
                }

                // Check for high loss false negatives
                if result.regime.loss_permille >= 50 && !result.repair_recommended {
                    analysis.high_loss_false_negatives += 1;
                    regime_stats.false_negatives += 1;
                }

                // Update global efficiency stats
                analysis.efficiency_stats.update(result);
            }

            if !regime_results.is_empty() {
                regime_stats.avg_bandwidth_efficiency =
                    total_bandwidth_eff / regime_results.len() as f64;
                regime_stats.avg_cpu_efficiency = total_cpu_eff / regime_results.len() as f64;
                regime_stats.avg_net_roi = total_net_roi / regime_results.len() as f64;
            }

            analysis
                .regime_performance
                .insert(regime_name.clone(), regime_stats);
        }

        analysis.generate_recommendations();
        analysis
    }

    /// Helper function for permille calculations.
    fn permille_of(&self, value: u64, permille: u64) -> u64 {
        permille_of(value, permille)
    }
}

fn permille_of(value: u64, permille: u64) -> u64 {
    value.saturating_mul(permille) / 1000
}

fn mul_div_u64(value: u64, mul: u64, div: u64) -> u64 {
    if div == 0 {
        0
    } else {
        value.saturating_mul(mul) / div
    }
}

/// Analysis results from repair ROI simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAnalysis {
    pub total_scenarios: usize,
    pub repair_recommended_scenarios: usize,
    pub clean_path_false_positives: usize,
    pub high_loss_false_negatives: usize,
    pub regime_performance: HashMap<String, RegimeStats>,
    pub efficiency_stats: EfficiencyStats,
    pub recommendations: Vec<String>,
}

impl PolicyAnalysis {
    fn generate_recommendations(&mut self) {
        // Generate evidence-based recommendations
        if self.clean_path_false_positives > 0 {
            self.recommendations.push(format!(
                "Consider increasing thresholds to reduce {} false positives on clean paths",
                self.clean_path_false_positives
            ));
        }

        if self.high_loss_false_negatives > 0 {
            self.recommendations.push(format!(
                "Consider decreasing thresholds to reduce {} false negatives on high-loss paths",
                self.high_loss_false_negatives
            ));
        }

        let repair_rate = self.repair_recommended_scenarios as f64 / self.total_scenarios as f64;
        if repair_rate > 0.8 {
            self.recommendations.push(
                "High repair activation rate - consider more conservative thresholds".to_string(),
            );
        } else if repair_rate < 0.2 {
            self.recommendations.push(
                "Low repair activation rate - consider more aggressive thresholds".to_string(),
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeStats {
    pub total_scenarios: usize,
    pub repair_recommended: usize,
    pub avg_bandwidth_efficiency: f64,
    pub avg_cpu_efficiency: f64,
    pub avg_net_roi: f64,
    pub false_positives: usize,
    pub false_negatives: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EfficiencyStats {
    pub min_bandwidth_efficiency: f64,
    pub max_bandwidth_efficiency: f64,
    pub avg_bandwidth_efficiency: f64,
    pub min_cpu_efficiency: f64,
    pub max_cpu_efficiency: f64,
    pub avg_cpu_efficiency: f64,
    pub scenarios_analyzed: usize,
}

impl EfficiencyStats {
    fn update(&mut self, result: &RepairRoiSimulationResult) {
        if self.scenarios_analyzed == 0 {
            self.min_bandwidth_efficiency = result.bandwidth_efficiency;
            self.max_bandwidth_efficiency = result.bandwidth_efficiency;
            self.avg_bandwidth_efficiency = result.bandwidth_efficiency;
            self.min_cpu_efficiency = result.cpu_efficiency;
            self.max_cpu_efficiency = result.cpu_efficiency;
            self.avg_cpu_efficiency = result.cpu_efficiency;
        } else {
            self.min_bandwidth_efficiency = self
                .min_bandwidth_efficiency
                .min(result.bandwidth_efficiency);
            self.max_bandwidth_efficiency = self
                .max_bandwidth_efficiency
                .max(result.bandwidth_efficiency);
            self.min_cpu_efficiency = self.min_cpu_efficiency.min(result.cpu_efficiency);
            self.max_cpu_efficiency = self.max_cpu_efficiency.max(result.cpu_efficiency);

            let n = self.scenarios_analyzed as f64;
            self.avg_bandwidth_efficiency =
                (self.avg_bandwidth_efficiency * n + result.bandwidth_efficiency) / (n + 1.0);
            self.avg_cpu_efficiency =
                (self.avg_cpu_efficiency * n + result.cpu_efficiency) / (n + 1.0);
        }

        self.scenarios_analyzed += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_regimes() {
        let clean = NetworkRegime::clean_path();
        assert_eq!(clean.name, "clean-path");
        assert_eq!(clean.loss_permille, 0);
        assert!(clean.is_clean_path);

        let lossy = NetworkRegime::lossy_wifi();
        assert_eq!(lossy.name, "lossy-wifi");
        assert_eq!(lossy.loss_permille, 50);
        assert!(!lossy.is_clean_path);

        let satellite = NetworkRegime::satellite_high_bdp();
        assert!(satellite.high_bdp);
        assert!(satellite.rtt_micros > 500_000);
    }

    #[test]
    fn test_roi_inputs_generation() {
        let regime = NetworkRegime::lossy_wifi();
        let inputs = regime.generate_roi_inputs(1_048_576, 1024, 1024);

        assert!(inputs.expected_time_saved_micros > 0);
        assert!(inputs.bandwidth_overhead_bytes > 0);
        assert!(inputs.encode_cpu_micros > 0);
        assert!(inputs.decode_cpu_micros > 0);
    }

    #[test]
    fn test_clean_path_suppression() {
        let regime = NetworkRegime::clean_path();
        let inputs = regime.generate_roi_inputs(1_048_576, 1024, 1024);

        // Clean path should have minimal overhead
        assert_eq!(inputs.expected_time_saved_micros, 0);
        assert_eq!(inputs.bandwidth_overhead_bytes, 0);
    }

    #[test]
    fn test_simulator_initialization() {
        let simulator = RepairRoiSimulator::new();
        assert_eq!(simulator.regimes.len(), 7);
        assert_eq!(simulator.policies.len(), 1);
    }

    #[test]
    fn test_comprehensive_simulation() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        assert!(!results.is_empty());
        assert!(results.contains_key("clean-path"));
        assert!(results.contains_key("lossy-wifi"));

        // Verify clean path results
        let clean_results = &results["clean-path"];
        assert!(!clean_results.is_empty());

        // Clean path should generally not recommend repair
        let repair_recommended_count = clean_results
            .iter()
            .filter(|r| r.repair_recommended)
            .count();

        // Most clean path scenarios should not recommend repair
        assert!(repair_recommended_count <= clean_results.len() / 2);
    }

    #[test]
    fn test_policy_analysis() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();
        let analysis = simulator.analyze_results(&results);

        assert!(analysis.total_scenarios > 0);
        assert!(!analysis.regime_performance.is_empty());
        assert!(analysis.efficiency_stats.scenarios_analyzed > 0);
    }

    #[test]
    fn test_efficiency_calculations() {
        let regime = NetworkRegime::lossy_wifi();
        let inputs = regime.generate_roi_inputs(1_048_576, 1024, 1024);
        let coordinator = AtpRepairCoordinator::default();
        let decision = coordinator.decide(&inputs);

        let mut result = RepairRoiSimulationResult {
            regime,
            transfer_size_bytes: 1_048_576,
            k_symbols: 1024,
            symbol_size_bytes: 1024,
            roi_inputs: inputs,
            decision,
            gross_benefit_micros: 50000,
            total_cost_micros: 30000,
            net_roi_micros: 20000,
            repair_recommended: true,
            bandwidth_efficiency: 0.0,
            cpu_efficiency: 0.0,
            relay_cost_efficiency: 0.0,
        };

        result.calculate_efficiency_metrics();

        assert!(result.bandwidth_efficiency > 0.0);
        assert!(result.bandwidth_efficiency <= 1.0);
        assert!(result.cpu_efficiency >= 0.0);
    }
}
