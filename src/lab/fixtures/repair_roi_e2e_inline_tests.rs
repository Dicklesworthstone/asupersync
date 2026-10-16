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
