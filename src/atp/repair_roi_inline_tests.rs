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
