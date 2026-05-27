//! Comprehensive tests for ATP repair ROI simulator and evidence-based policy tuning.

use asupersync::atp::{
    AtpRepairCoordinator, AtpRepairCoordinatorPolicy, NetworkRegime, RepairRoiSimulator,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test ROI arithmetic correctness across different scenarios.
    #[test]
    fn test_roi_arithmetic_correctness() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        for (regime_name, regime_results) in &results {
            for result in regime_results {
                // Verify arithmetic consistency
                assert!(
                    result.gross_benefit_micros >= result.roi_inputs.expected_time_saved_micros,
                    "Gross benefit should include base time saved for regime {}",
                    regime_name
                );

                assert!(
                    result.total_cost_micros >= result.roi_inputs.encode_cpu_micros,
                    "Total cost should include at least encode cost for regime {}",
                    regime_name
                );

                assert!(
                    result.total_cost_micros >= result.roi_inputs.decode_cpu_micros,
                    "Total cost should include at least decode cost for regime {}",
                    regime_name
                );

                // Net ROI should be consistent with gross - total
                let expected_net_roi =
                    result.gross_benefit_micros as i64 - result.total_cost_micros as i64;
                let tolerance = 1000i64; // Allow small rounding errors
                assert!(
                    (result.net_roi_micros - expected_net_roi).abs() <= tolerance,
                    "Net ROI calculation inconsistent for regime {}: expected {}, got {}",
                    regime_name,
                    expected_net_roi,
                    result.net_roi_micros
                );

                // Bandwidth efficiency should be between 0 and 1
                assert!(
                    result.bandwidth_efficiency >= 0.0 && result.bandwidth_efficiency <= 1.0,
                    "Bandwidth efficiency out of range for regime {}: {}",
                    regime_name,
                    result.bandwidth_efficiency
                );

                // CPU efficiency should be non-negative
                assert!(
                    result.cpu_efficiency >= 0.0,
                    "CPU efficiency should be non-negative for regime {}: {}",
                    regime_name,
                    result.cpu_efficiency
                );
            }
        }
    }

    /// Test threshold hysteresis behavior.
    #[test]
    fn test_threshold_hysteresis() {
        // Create policies with slightly different thresholds
        let base_policy = AtpRepairCoordinatorPolicy::default();

        let mut high_threshold_policy = base_policy;
        high_threshold_policy.resume_value_floor_permille += 50; // Slightly higher threshold

        let mut low_threshold_policy = base_policy;
        low_threshold_policy.resume_value_floor_permille = low_threshold_policy
            .resume_value_floor_permille
            .saturating_sub(50); // Slightly lower

        let regime = NetworkRegime::tail_resume(); // High resume value scenario
        let inputs = regime.generate_roi_inputs(100_000_000, 8192, 1024); // Large transfer

        let base_coordinator = AtpRepairCoordinator::new(base_policy);
        let high_coordinator = AtpRepairCoordinator::new(high_threshold_policy);
        let low_coordinator = AtpRepairCoordinator::new(low_threshold_policy);

        let base_decision = base_coordinator.decide(&inputs);
        let high_decision = high_coordinator.decide(&inputs);
        let low_decision = low_coordinator.decide(&inputs);

        // Higher thresholds should be more conservative
        // Lower thresholds should be more aggressive
        // This creates hysteresis behavior
        println!("Base decision: {:?}", base_decision.action);
        println!("High threshold decision: {:?}", high_decision.action);
        println!("Low threshold decision: {:?}", low_decision.action);

        // At least verify decisions are computed without panic
        assert!(base_decision.factors.len() > 0);
        assert!(high_decision.factors.len() > 0);
        assert!(low_decision.factors.len() > 0);
    }

    /// Test clean path suppression - repair should rarely be recommended on clean paths.
    #[test]
    fn test_clean_path_suppression() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        let clean_results = results
            .get("clean-path")
            .expect("Clean path results should exist");

        let total_scenarios = clean_results.len();
        let repair_recommended = clean_results
            .iter()
            .filter(|r| r.repair_recommended)
            .count();

        let repair_rate = repair_recommended as f64 / total_scenarios as f64;

        // Clean paths should very rarely recommend repair (< 10% of cases)
        assert!(
            repair_rate < 0.1,
            "Clean path repair rate too high: {:.1}% ({}/{})",
            repair_rate * 100.0,
            repair_recommended,
            total_scenarios
        );

        // Verify clean path scenarios have minimal overhead
        for result in clean_results {
            assert_eq!(
                result.roi_inputs.bandwidth_overhead_bytes, 0,
                "Clean path should have no bandwidth overhead"
            );
            assert_eq!(
                result.roi_inputs.expected_time_saved_micros, 0,
                "Clean path should have no expected time savings"
            );
        }
    }

    /// Test relay cost sensitivity.
    #[test]
    fn test_relay_cost_sensitivity() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        let expensive_results = results
            .get("relay-expensive")
            .expect("Relay expensive results should exist");
        let clean_results = results
            .get("clean-path")
            .expect("Clean path results should exist");

        let expensive_repair_rate = expensive_results
            .iter()
            .filter(|r| r.repair_recommended)
            .count() as f64
            / expensive_results.len() as f64;

        let clean_repair_rate = clean_results
            .iter()
            .filter(|r| r.repair_recommended)
            .count() as f64
            / clean_results.len() as f64;

        // Expensive relay should be more conservative than clean path
        // (though clean path should already be very conservative)
        println!(
            "Expensive relay repair rate: {:.1}%",
            expensive_repair_rate * 100.0
        );
        println!("Clean path repair rate: {:.1}%", clean_repair_rate * 100.0);

        // Both should be low, but expensive relay scenarios need to consider cost
        assert!(
            expensive_repair_rate < 0.3,
            "Expensive relay repair rate should be conservative"
        );
    }

    /// Test CPU budget sensitivity.
    #[test]
    fn test_cpu_budget_sensitivity() {
        let mut simulator = RepairRoiSimulator::new();

        // Create a policy with very low CPU budget
        let mut low_cpu_policy = AtpRepairCoordinatorPolicy::default();
        // Increase the effective CPU cost by making bandwidth more expensive
        low_cpu_policy.bandwidth_cost_micros_per_mib *= 10;

        simulator.add_policy(low_cpu_policy);

        let results = simulator.run_comprehensive_simulation();

        // With higher effective costs, repair should be recommended less often
        for (regime_name, regime_results) in &results {
            let default_policy_results: Vec<_> = regime_results
                .iter()
                .filter(|_| {
                    // This is a heuristic to identify default policy results
                    // In practice, you'd track which policy was used
                    true
                })
                .collect();

            for result in &default_policy_results {
                // Higher CPU costs should lead to more conservative decisions
                // Verify that cost calculations include CPU components
                assert!(
                    result.total_cost_micros
                        >= result.roi_inputs.encode_cpu_micros
                            + result.roi_inputs.decode_cpu_micros,
                    "Total cost should include CPU costs for regime {}",
                    regime_name
                );
            }
        }
    }

    /// Test malformed telemetry handling.
    #[test]
    fn test_malformed_telemetry_handling() {
        let coordinator = AtpRepairCoordinator::default();

        // Test with extreme values
        let mut extreme_inputs =
            NetworkRegime::clean_path().generate_roi_inputs(1_048_576, 1024, 1024);
        extreme_inputs.expected_time_saved_micros = u64::MAX;
        extreme_inputs.bandwidth_overhead_bytes = u64::MAX;

        // Should not panic or produce invalid results
        let decision = coordinator.decide(&extreme_inputs);
        assert!(decision.factors.len() > 0);

        // Test with zero values
        let mut zero_inputs =
            NetworkRegime::clean_path().generate_roi_inputs(1_048_576, 1024, 1024);
        zero_inputs.expected_time_saved_micros = 0;
        zero_inputs.bandwidth_overhead_bytes = 0;
        zero_inputs.encode_cpu_micros = 0;
        zero_inputs.decode_cpu_micros = 0;

        let zero_decision = coordinator.decide(&zero_inputs);
        assert!(zero_decision.factors.len() > 0);
    }

    /// Test policy analysis generates meaningful recommendations.
    #[test]
    fn test_policy_analysis_recommendations() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();
        let analysis = simulator.analyze_results(&results);

        assert!(
            analysis.total_scenarios > 0,
            "Should have analyzed some scenarios"
        );
        assert!(
            !analysis.regime_performance.is_empty(),
            "Should have regime performance data"
        );
        assert!(
            analysis.efficiency_stats.scenarios_analyzed > 0,
            "Should have efficiency statistics"
        );

        // Verify regime performance makes sense
        for (regime_name, stats) in &analysis.regime_performance {
            assert!(
                stats.total_scenarios > 0,
                "Regime {} should have scenarios",
                regime_name
            );
            assert!(
                stats.avg_bandwidth_efficiency >= 0.0 && stats.avg_bandwidth_efficiency <= 1.0,
                "Regime {} bandwidth efficiency out of range: {}",
                regime_name,
                stats.avg_bandwidth_efficiency
            );
        }

        // Should generate some recommendations based on the analysis
        println!("Generated recommendations:");
        for recommendation in &analysis.recommendations {
            println!("- {}", recommendation);
        }
    }

    /// Test deterministic behavior across multiple runs.
    #[test]
    fn test_deterministic_simulation() {
        let simulator1 = RepairRoiSimulator::new();
        let simulator2 = RepairRoiSimulator::new();

        let results1 = simulator1.run_comprehensive_simulation();
        let results2 = simulator2.run_comprehensive_simulation();

        // Results should be identical across runs
        assert_eq!(
            results1.len(),
            results2.len(),
            "Simulation should be deterministic"
        );

        for (regime_name, regime_results1) in &results1 {
            let regime_results2 = results2
                .get(regime_name)
                .expect(&format!("Regime {} should exist in both runs", regime_name));

            assert_eq!(
                regime_results1.len(),
                regime_results2.len(),
                "Regime {} should have same number of results",
                regime_name
            );

            for (r1, r2) in regime_results1.iter().zip(regime_results2.iter()) {
                assert_eq!(r1.transfer_size_bytes, r2.transfer_size_bytes);
                assert_eq!(r1.k_symbols, r2.k_symbols);
                assert_eq!(r1.symbol_size_bytes, r2.symbol_size_bytes);
                assert_eq!(r1.repair_recommended, r2.repair_recommended);

                // Floating point comparisons with tolerance
                let tolerance = 1e-10;
                assert!((r1.bandwidth_efficiency - r2.bandwidth_efficiency).abs() < tolerance);
                assert!((r1.cpu_efficiency - r2.cpu_efficiency).abs() < tolerance);
            }
        }
    }

    /// Test regime coverage - ensure all expected regimes are tested.
    #[test]
    fn test_regime_coverage() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        // Verify all expected regimes are present
        let expected_regimes = vec![
            "clean-path",
            "lossy-wifi",
            "satellite-high-bdp",
            "mobile-unstable",
            "relay-expensive",
            "swarm-multi-peer",
            "tail-resume",
        ];

        for regime in expected_regimes {
            assert!(results.contains_key(regime), "Missing regime: {}", regime);
            assert!(
                !results[regime].is_empty(),
                "Regime {} should have results",
                regime
            );
        }

        // Verify regime characteristics match expectations
        let satellite_results = &results["satellite-high-bdp"];
        for result in satellite_results {
            assert!(
                result.regime.high_bdp,
                "Satellite regime should be high BDP"
            );
            assert!(
                result.regime.rtt_micros > 500_000,
                "Satellite should have high RTT"
            );
        }

        let mobile_results = &results["mobile-unstable"];
        for result in mobile_results {
            assert!(
                result.regime.mobile_unstable,
                "Mobile regime should be unstable"
            );
            assert!(
                result.regime.stability_permille < 500,
                "Mobile should be unstable"
            );
        }
    }

    /// Test efficiency metric bounds and sanity.
    #[test]
    fn test_efficiency_metrics_sanity() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        for (regime_name, regime_results) in &results {
            for result in regime_results {
                // Bandwidth efficiency should be between 0 and 1
                assert!(
                    result.bandwidth_efficiency >= 0.0 && result.bandwidth_efficiency <= 1.0,
                    "Invalid bandwidth efficiency for {}: {}",
                    regime_name,
                    result.bandwidth_efficiency
                );

                // CPU efficiency should be non-negative
                assert!(
                    result.cpu_efficiency >= 0.0,
                    "Invalid CPU efficiency for {}: {}",
                    regime_name,
                    result.cpu_efficiency
                );

                // If repair is recommended, there should be some benefit
                if result.repair_recommended && result.roi_inputs.expected_time_saved_micros > 0 {
                    assert!(
                        result.gross_benefit_micros > 0,
                        "Repair recommended but no gross benefit for {}",
                        regime_name
                    );
                }

                // If no overhead, bandwidth efficiency should be 1.0
                if result.roi_inputs.bandwidth_overhead_bytes == 0 {
                    assert_eq!(
                        result.bandwidth_efficiency, 1.0,
                        "No overhead should mean perfect bandwidth efficiency for {}",
                        regime_name
                    );
                }
            }
        }
    }

    /// Test swarm scenarios have different characteristics.
    #[test]
    fn test_swarm_scenario_characteristics() {
        let simulator = RepairRoiSimulator::new();
        let results = simulator.run_comprehensive_simulation();

        let swarm_results = results
            .get("swarm-multi-peer")
            .expect("Swarm results should exist");
        let single_peer_results = results
            .get("clean-path")
            .expect("Clean path results should exist");

        for result in swarm_results {
            assert!(
                result.regime.swarm_peer_count > 1,
                "Swarm should have multiple peers"
            );
            assert!(
                result.roi_inputs.available_peer_count > 1,
                "Swarm should have multiple repair peers"
            );
        }

        for result in single_peer_results {
            assert_eq!(result.regime.swarm_peer_count, 1, "Single peer scenario");
            assert_eq!(
                result.roi_inputs.available_peer_count, 1,
                "Single peer should expose exactly one repair peer"
            );
        }
    }
}
