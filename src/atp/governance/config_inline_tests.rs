    use super::*;

    #[test]
    fn governance_config_defaults_are_reasonable() {
        let config = AtpGovernanceConfig::default();
        assert_eq!(config.power_profile, AtpPowerProfile::Balanced);
        assert_eq!(config.fairness_policy, AtpFairnessPolicy::EqualShare);
        assert!(!config.dry_run);
        assert!(!config.has_custom_limits());
        assert_eq!(config.metadata.source, "default");
    }

    #[test]
    fn resolve_budget_applies_custom_limits() {
        let config = AtpGovernanceConfig::from_power_profile(AtpPowerProfile::Balanced)
            .with_custom_limits(AtpCustomLimits {
                max_bandwidth_bytes_per_second: Some(1_048_576), // 1 MiB/s
                background_priority: Some(true),
                ..AtpCustomLimits::default()
            });

        let budget = config.resolve_budget();
        assert_eq!(budget.max_bandwidth_bytes_per_second, Some(1_048_576));
        assert!(budget.background_priority);
        // Other limits should come from the balanced profile.
        assert_eq!(budget.max_in_flight_bytes, Some(128 * 1_048_576));
    }

    #[test]
    fn parse_power_profile_handles_variations() {
        assert_eq!(
            parse_power_profile("max-speed").unwrap(),
            AtpPowerProfile::MaxSpeed
        );
        assert_eq!(
            parse_power_profile("Max_Speed").unwrap(),
            AtpPowerProfile::MaxSpeed
        );
        assert_eq!(
            parse_power_profile("BALANCED").unwrap(),
            AtpPowerProfile::Balanced
        );
        assert_eq!(
            parse_power_profile("battery").unwrap(),
            AtpPowerProfile::BatterySaver
        );

        assert!(parse_power_profile("invalid").is_err());
    }

    #[test]
    fn parse_fairness_policy_handles_variations() {
        assert_eq!(
            parse_fairness_policy("equal").unwrap(),
            AtpFairnessPolicy::EqualShare
        );
        assert_eq!(
            parse_fairness_policy("Priority_Weighted").unwrap(),
            AtpFairnessPolicy::PriorityWeighted
        );
        assert_eq!(
            parse_fairness_policy("fcfs").unwrap(),
            AtpFairnessPolicy::FirstComeFirstServed
        );

        assert!(parse_fairness_policy("invalid").is_err());
    }

    #[test]
    fn parse_size_string_handles_units() {
        assert_eq!(parse_size_string("1024").unwrap(), 1_024);
        assert_eq!(parse_size_string("1K").unwrap(), 1_024);
        assert_eq!(parse_size_string("64m").unwrap(), 64 * 1_048_576);
        assert_eq!(parse_size_string("2G").unwrap(), 2 * 1_073_741_824);
        assert_eq!(parse_size_string("1 T").unwrap(), 1_099_511_627_776);

        assert!(parse_size_string("invalid").is_err());
        assert!(parse_size_string("64X").is_err());
    }

    #[test]
    fn parse_size_string_rejects_byte_overflow() {
        let too_large_kib = format!("{}K", u64::MAX / 1_024 + 1);
        let too_large_tib = format!("{}T", u64::MAX / 1_099_511_627_776 + 1);

        assert!(parse_size_string(&too_large_kib).is_err());
        assert!(parse_size_string(&too_large_tib).is_err());
        assert_eq!(
            parse_size_string(&format!("{}B", u64::MAX)).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn cli_args_parse_config_rejects_relay_cost_overflow() {
        let args = AtpGovernanceCliArgs {
            relay_cost_ms_per_mib: Some(u64::MAX),
            ..AtpGovernanceCliArgs::default()
        };

        assert!(args.parse_config().is_err());
        assert_eq!(
            parse_relay_cost_millis(u64::MAX / 1_000).unwrap(),
            (u64::MAX / 1_000) * 1_000
        );
    }

    #[test]
    fn cli_args_parse_config_works() {
        let args = AtpGovernanceCliArgs {
            profile: Some("battery-saver".to_string()),
            bandwidth: Some("32M".to_string()),
            fairness: Some("fcfs".to_string()),
            background: true,
            dry_run: true,
            ..AtpGovernanceCliArgs::default()
        };

        let config = args.parse_config().unwrap();
        assert_eq!(config.power_profile, AtpPowerProfile::BatterySaver);
        assert_eq!(
            config.custom_limits.max_bandwidth_bytes_per_second,
            Some(32 * 1_048_576)
        );
        assert_eq!(
            config.fairness_policy,
            AtpFairnessPolicy::FirstComeFirstServed
        );
        assert_eq!(config.custom_limits.background_priority, Some(true));
        assert!(config.dry_run);
        assert_eq!(config.metadata.source, "cli");
    }
