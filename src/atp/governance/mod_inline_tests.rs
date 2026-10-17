    use super::{
        AtpDemandPriority, AtpFairnessCoordinator, AtpFairnessPolicy, AtpGovernanceViolationKind,
        AtpResourceBudget, AtpResourceDemand, AtpResourceGovernor, AtpTransferId,
    };
    use crate::atp::profiles::{AtpPowerProfile, AtpResourceProfile};

    #[test]
    fn balanced_governor_allows_demand_inside_budget() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: 64 * 1_048_576,
            in_flight_bytes: 64 * 1_048_576,
            repair_symbols_per_second: 512,
            disk_write_concurrency: 2,
            relay_cost_micros_per_mib: Some(100_000),
            priority: AtpDemandPriority::Foreground,
        });

        assert!(decision.allowed);
        assert!(!decision.rejected());
        assert_eq!(decision.reason_code, "within_resource_budget");
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn battery_saver_rejects_over_budget_repair_and_relay_cost() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::BatterySaver,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: 8 * 1_048_576,
            in_flight_bytes: 8 * 1_048_576,
            repair_symbols_per_second: 2_048,
            disk_write_concurrency: 1,
            relay_cost_micros_per_mib: Some(900_000),
            priority: AtpDemandPriority::Foreground,
        });

        assert!(decision.rejected());
        assert_eq!(decision.reason_code, "resource_budget_exceeded");
        assert_eq!(decision.violations.len(), 2);
        assert_eq!(
            decision.violations[0].kind,
            AtpGovernanceViolationKind::RepairSymbolsPerSecond
        );
        assert_eq!(decision.violations[0].requested, 2_048);
        assert_eq!(decision.violations[0].limit, 512);
        assert_eq!(
            decision.violations[1].kind.as_str(),
            "atp.governance.relay_cost_micros_per_mib"
        );
    }

    #[test]
    fn custom_profile_is_unrestricted_until_callers_set_caps() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Custom,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: u64::MAX,
            in_flight_bytes: u64::MAX,
            repair_symbols_per_second: u32::MAX,
            disk_write_concurrency: u16::MAX,
            relay_cost_micros_per_mib: Some(u64::MAX),
            priority: AtpDemandPriority::Foreground,
        });

        assert!(decision.allowed);
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn fairness_coordinator_equal_share_distributes_resources() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        // Register two transfers
        coordinator.register_transfer(
            "transfer1".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 64 * 1_048_576,
                in_flight_bytes: 32 * 1_048_576,
                repair_symbols_per_second: 1_024,
                disk_write_concurrency: 2,
                relay_cost_micros_per_mib: None,
                priority: AtpDemandPriority::Foreground,
            },
        );
        coordinator.register_transfer(
            "transfer2".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 32 * 1_048_576,
                in_flight_bytes: 16 * 1_048_576,
                repair_symbols_per_second: 512,
                disk_write_concurrency: 1,
                relay_cost_micros_per_mib: None,
                priority: AtpDemandPriority::Foreground,
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 2);

        // Each should get 50% of resources
        for allocation in &allocations {
            assert!((allocation.share_ratio - 0.5).abs() < 0.01);
            assert_eq!(allocation.bandwidth_bytes_per_second, 64 * 1_048_576); // 128/2
            assert_eq!(allocation.in_flight_bytes, 64 * 1_048_576); // 128/2
            assert_eq!(allocation.repair_symbols_per_second, 2_048); // 4096/2
            assert_eq!(allocation.disk_write_concurrency, 2); // 4/2
        }
    }

    #[test]
    fn fairness_coordinator_priority_weighted_uses_demand_priority() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::PriorityWeighted);

        coordinator.register_transfer(
            "interactive".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Interactive,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "foreground".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Foreground,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "background".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Background,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "best_effort".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::BestEffort,
                ..AtpResourceDemand::default()
            },
        );

        let allocations = coordinator.calculate_allocations();
        let interactive = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "interactive")
            .unwrap();
        let foreground = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "foreground")
            .unwrap();
        let background = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "background")
            .unwrap();
        let best_effort = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "best_effort")
            .unwrap();

        assert!(interactive.share_ratio > foreground.share_ratio);
        assert!(foreground.share_ratio > background.share_ratio);
        assert!(background.share_ratio > best_effort.share_ratio);
        assert!(
            (allocations
                .iter()
                .map(|allocation| allocation.share_ratio)
                .sum::<f64>()
                - 1.0)
                .abs()
                < 0.000_001
        );
    }

    #[test]
    fn fairness_coordinator_fcfs_gives_priority_to_first_transfer() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::FirstComeFirstServed);

        // Register transfers in order
        coordinator.register_transfer("first".into(), AtpResourceDemand::default());
        coordinator.register_transfer("second".into(), AtpResourceDemand::default());
        coordinator.register_transfer("third".into(), AtpResourceDemand::default());

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 3);

        // First transfer should get 70% of resources
        assert!((allocations[0].share_ratio - 0.7).abs() < 0.01);
        assert_eq!(allocations[0].transfer_id.0, "first");

        // Others should share the remaining 30% (15% each)
        for allocation in &allocations[1..] {
            assert!((allocation.share_ratio - 0.15).abs() < 0.01);
        }
    }

    #[test]
    fn fairness_coordinator_size_proportional_allocates_by_transfer_size() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::SizeProportional);

        // Small transfer: 1 MiB
        coordinator.register_transfer(
            "small".into(),
            AtpResourceDemand {
                in_flight_bytes: 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        // Large transfer: 9 MiB
        coordinator.register_transfer(
            "large".into(),
            AtpResourceDemand {
                in_flight_bytes: 9 * 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 2);

        // Small transfer should get ~10% (1/10)
        let small_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "small")
            .unwrap();
        assert!((small_alloc.share_ratio - 0.1).abs() < 0.01);

        // Large transfer should get ~90% (9/10)
        let large_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "large")
            .unwrap();
        assert!((large_alloc.share_ratio - 0.9).abs() < 0.01);
    }

    #[test]
    fn fairness_coordinator_unregister_transfer_removes_from_tracking() {
        let budget = AtpResourceBudget::default();
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        let transfer_id: AtpTransferId = "test_transfer".into();
        coordinator.register_transfer(transfer_id.clone(), AtpResourceDemand::default());
        assert_eq!(coordinator.active_transfer_count(), 1);

        coordinator.unregister_transfer(&transfer_id);
        assert_eq!(coordinator.active_transfer_count(), 0);
        assert!(coordinator.calculate_allocations().is_empty());
    }

    #[test]
    fn fairness_coordinator_budget_and_policy_updates() {
        let initial_budget = AtpResourceBudget::default();
        let mut coordinator =
            AtpFairnessCoordinator::new(initial_budget, AtpFairnessPolicy::EqualShare);

        assert_eq!(coordinator.policy(), AtpFairnessPolicy::EqualShare);

        // Update policy
        coordinator.update_policy(AtpFairnessPolicy::FirstComeFirstServed);
        assert_eq!(
            coordinator.policy(),
            AtpFairnessPolicy::FirstComeFirstServed
        );

        // Update budget
        let new_budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::MaxSpeed,
        ));
        coordinator.update_budget(new_budget);
        assert_eq!(*coordinator.budget(), new_budget);
    }

    #[test]
    fn fairness_policy_default_is_equal_share() {
        assert_eq!(AtpFairnessPolicy::default(), AtpFairnessPolicy::EqualShare);
    }

    #[test]
    fn transfer_id_conversions_work() {
        let id1: AtpTransferId = "test".into();
        let id2: AtpTransferId = String::from("test").into();
        assert_eq!(id1, id2);
        assert_eq!(id1.0, "test");
    }
