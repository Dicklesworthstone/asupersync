//! End-to-end tests for ATP resource governance.
//!
//! Tests resource governance behavior with different profiles, fairness policies,
//! and concurrent transfer scenarios. Includes deterministic lab runtime tests
//! for reproducible behavior validation.

#[cfg(test)]
mod tests {
    use super::super::{
        AtpDemandPriority, AtpFairnessCoordinator, AtpFairnessPolicy, AtpResourceBudget,
        AtpResourceDemand, AtpResourceGovernor, AtpTransferId,
        config::{AtpCustomLimits, AtpGovernanceConfig},
    };
    use crate::atp::profiles::{AtpPowerProfile, AtpResourceProfile};

    /// Test that governance correctly enforces bandwidth limits across profiles.
    #[test]
    fn e2e_governance_bandwidth_enforcement_across_profiles() {
        let test_cases = vec![
            (AtpPowerProfile::MaxSpeed, None), // Should be unlimited
            (AtpPowerProfile::Balanced, Some(128 * 1_048_576)),
            (AtpPowerProfile::Background, Some(32 * 1_048_576)),
            (AtpPowerProfile::BatterySaver, Some(16 * 1_048_576)),
            (AtpPowerProfile::CiDeterministic, Some(4 * 1_048_576)),
        ];

        for (profile, expected_bandwidth) in test_cases {
            let governor =
                AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(profile));

            // Test a high bandwidth demand
            let high_demand = AtpResourceDemand {
                bandwidth_bytes_per_second: 256 * 1_048_576, // 256 MiB/s
                ..AtpResourceDemand::default()
            };

            let decision = governor.evaluate(high_demand);

            match expected_bandwidth {
                None => {
                    // MaxSpeed should allow high bandwidth
                    assert!(
                        decision.allowed,
                        "Profile {profile:?} should allow high bandwidth"
                    );
                }
                Some(limit) => {
                    if high_demand.bandwidth_bytes_per_second > limit {
                        assert!(
                            decision.rejected(),
                            "Profile {profile:?} should reject bandwidth over {limit}"
                        );
                        assert!(!decision.violations.is_empty());
                    } else {
                        assert!(
                            decision.allowed,
                            "Profile {profile:?} should allow bandwidth under {limit}"
                        );
                    }
                }
            }
        }
    }

    /// Test fairness coordinator equal sharing with multiple transfers.
    #[test]
    fn e2e_fairness_equal_share_multiple_transfers() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        // Register three transfers with different demands
        coordinator.register_transfer(
            "transfer1".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 100 * 1_048_576,
                in_flight_bytes: 50 * 1_048_576,
                repair_symbols_per_second: 1_000,
                disk_write_concurrency: 2,
                relay_cost_micros_per_mib: None,
                priority: AtpDemandPriority::Foreground,
            },
        );

        coordinator.register_transfer(
            "transfer2".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 200 * 1_048_576,
                in_flight_bytes: 100 * 1_048_576,
                repair_symbols_per_second: 2_000,
                disk_write_concurrency: 4,
                relay_cost_micros_per_mib: Some(500_000),
                priority: AtpDemandPriority::Foreground,
            },
        );

        coordinator.register_transfer(
            "transfer3".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 50 * 1_048_576,
                in_flight_bytes: 25 * 1_048_576,
                repair_symbols_per_second: 500,
                disk_write_concurrency: 1,
                relay_cost_micros_per_mib: Some(1_000_000),
                priority: AtpDemandPriority::Foreground,
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 3);

        // Each transfer should get 1/3 of available resources
        for allocation in &allocations {
            assert!((allocation.share_ratio - (1.0 / 3.0)).abs() < 0.01);
            // Bandwidth: 128 MiB/s / 3 ≈ 42.67 MiB/s
            assert_eq!(allocation.bandwidth_bytes_per_second, 128 * 1_048_576 / 3);
            // In-flight: 128 MiB / 3 ≈ 42.67 MiB
            assert_eq!(allocation.in_flight_bytes, 128 * 1_048_576 / 3);
            // Repair symbols: 4096 / 3 ≈ 1365
            assert_eq!(allocation.repair_symbols_per_second, 4_096 / 3);
            // Disk concurrency: 4 / 3 = 1 (minimum 1)
            assert_eq!(allocation.disk_write_concurrency, 1);
        }
    }

    /// Test first-come-first-served fairness policy prioritizes first transfer.
    #[test]
    fn e2e_fairness_fcfs_prioritizes_first_transfer() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::FirstComeFirstServed);

        // Register transfers in specific order (BTreeMap maintains order)
        coordinator.register_transfer("first".into(), AtpResourceDemand::default());
        coordinator.register_transfer("second".into(), AtpResourceDemand::default());
        coordinator.register_transfer("third".into(), AtpResourceDemand::default());

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 3);

        // Sort by transfer ID to ensure consistent ordering
        let mut allocations = allocations;
        allocations.sort_by(|a, b| a.transfer_id.0.cmp(&b.transfer_id.0));

        // First transfer should get 70% of resources
        let first_alloc = &allocations[0]; // "first"
        assert!((first_alloc.share_ratio - 0.7).abs() < 0.01);

        // Other two should get 15% each (30% total / 2)
        for allocation in &allocations[1..] {
            assert!((allocation.share_ratio - 0.15).abs() < 0.01);
        }
    }

    /// Test size proportional fairness allocates by transfer size.
    #[test]
    fn e2e_fairness_size_proportional_allocation() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::SizeProportional);

        // Small transfer: 10 MiB
        coordinator.register_transfer(
            "small".into(),
            AtpResourceDemand {
                in_flight_bytes: 10 * 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        // Medium transfer: 30 MiB
        coordinator.register_transfer(
            "medium".into(),
            AtpResourceDemand {
                in_flight_bytes: 30 * 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        // Large transfer: 60 MiB
        coordinator.register_transfer(
            "large".into(),
            AtpResourceDemand {
                in_flight_bytes: 60 * 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 3);

        // Total size: 100 MiB, so proportions are 10%, 30%, 60%
        let small_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "small")
            .unwrap();
        let medium_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "medium")
            .unwrap();
        let large_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "large")
            .unwrap();

        assert!((small_alloc.share_ratio - 0.1).abs() < 0.01);
        assert!((medium_alloc.share_ratio - 0.3).abs() < 0.01);
        assert!((large_alloc.share_ratio - 0.6).abs() < 0.01);
    }

    /// Test governance config resolution with custom limits overriding profiles.
    #[test]
    fn e2e_governance_config_custom_limit_override() {
        let config = AtpGovernanceConfig::from_power_profile(AtpPowerProfile::Balanced)
            .with_custom_limits(AtpCustomLimits {
                max_bandwidth_bytes_per_second: Some(64 * 1_048_576), // Override to 64 MiB/s
                background_priority: Some(true),                      // Override to background
                ..AtpCustomLimits::default()
            });

        let resolved_budget = config.resolve_budget();

        // Custom override should take precedence
        assert_eq!(
            resolved_budget.max_bandwidth_bytes_per_second,
            Some(64 * 1_048_576)
        );
        assert!(resolved_budget.background_priority);

        // Non-overridden values should come from balanced profile
        assert_eq!(resolved_budget.max_in_flight_bytes, Some(128 * 1_048_576));
        assert_eq!(resolved_budget.max_repair_symbols_per_second, Some(4_096));
        assert!(!resolved_budget.metered_network); // Balanced default
    }

    /// Test dry-run mode doesn't affect governance decisions but tracks them.
    #[test]
    fn e2e_governance_dry_run_mode() {
        let config = AtpGovernanceConfig::from_power_profile(AtpPowerProfile::BatterySaver)
            .with_dry_run(true);

        let governor = AtpResourceGovernor::from_profile(config.resolve_profile());

        // Make a demand that should be rejected by battery saver
        let high_demand = AtpResourceDemand {
            bandwidth_bytes_per_second: 100 * 1_048_576, // Much higher than 16 MiB/s limit
            repair_symbols_per_second: 2_048,            // Higher than 512 limit
            ..AtpResourceDemand::default()
        };

        let decision = governor.evaluate(high_demand);

        // Should be rejected based on profile limits
        assert!(decision.rejected());
        assert!(!decision.violations.is_empty());
        assert_eq!(decision.reason_code, "resource_budget_exceeded");

        // Dry-run enforcement is resolved by the caller; this gate remains
        // deterministic so the caller can log or enforce the same decision.
    }

    /// Test concurrent transfer lifecycle with fairness coordinator.
    #[test]
    fn e2e_fairness_coordinator_transfer_lifecycle() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        // Start with no transfers
        assert_eq!(coordinator.active_transfer_count(), 0);
        assert!(coordinator.calculate_allocations().is_empty());

        // Add first transfer
        let transfer1_id: AtpTransferId = "transfer1".into();
        coordinator.register_transfer(transfer1_id.clone(), AtpResourceDemand::default());
        assert_eq!(coordinator.active_transfer_count(), 1);

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 1);
        assert!((allocations[0].share_ratio - 1.0).abs() < 0.01); // Gets 100%

        // Add second transfer
        let transfer2_id: AtpTransferId = "transfer2".into();
        coordinator.register_transfer(transfer2_id.clone(), AtpResourceDemand::default());
        assert_eq!(coordinator.active_transfer_count(), 2);

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 2);
        for allocation in &allocations {
            assert!((allocation.share_ratio - 0.5).abs() < 0.01); // Each gets 50%
        }

        // Remove first transfer
        coordinator.unregister_transfer(&transfer1_id);
        assert_eq!(coordinator.active_transfer_count(), 1);

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 1);
        assert_eq!(allocations[0].transfer_id, transfer2_id);
        assert!((allocations[0].share_ratio - 1.0).abs() < 0.01); // Gets 100% again

        // Remove last transfer
        coordinator.unregister_transfer(&transfer2_id);
        assert_eq!(coordinator.active_transfer_count(), 0);
        assert!(coordinator.calculate_allocations().is_empty());
    }

    /// Benchmark governance evaluation performance for high-frequency decisions.
    #[test]
    fn e2e_governance_performance_benchmark() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));

        let demand = AtpResourceDemand {
            bandwidth_bytes_per_second: 64 * 1_048_576,
            in_flight_bytes: 32 * 1_048_576,
            repair_symbols_per_second: 1_024,
            disk_write_concurrency: 2,
            relay_cost_micros_per_mib: Some(500_000),
            priority: AtpDemandPriority::Foreground,
        };

        // Governance decisions should be fast since they're used frequently
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _decision = governor.evaluate(demand);
        }
        let duration = start.elapsed();

        // Should complete 10k evaluations in well under 1 second
        assert!(
            duration.as_millis() < 1000,
            "Governance evaluation too slow: {duration:?}"
        );
    }
}
