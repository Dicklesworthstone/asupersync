    use super::{AtpPowerProfile, AtpResourceProfile};

    #[test]
    fn profile_keys_are_stable() {
        assert_eq!(AtpPowerProfile::BatterySaver.as_str(), "battery_saver");
        assert_eq!(
            AtpPowerProfile::RelayConservative.as_str(),
            "relay_conservative"
        );
    }

    #[test]
    fn battery_saver_is_stricter_than_balanced_for_local_pressure() {
        let balanced = AtpResourceProfile::for_power_profile(AtpPowerProfile::Balanced);
        let battery = AtpResourceProfile::for_power_profile(AtpPowerProfile::BatterySaver);

        assert!(battery.background_priority);
        assert!(battery.max_in_flight_bytes < balanced.max_in_flight_bytes);
        assert!(battery.max_repair_symbols_per_second < balanced.max_repair_symbols_per_second);
        assert!(battery.max_disk_write_concurrency < balanced.max_disk_write_concurrency);
    }

    #[test]
    fn all_power_profiles_have_descriptions() {
        for &power_profile in AtpPowerProfile::all() {
            let description = power_profile.description();
            assert!(!description.is_empty());
            assert!(description.len() > 10); // Should be meaningful
        }
    }

    #[test]
    fn max_speed_profile_is_mostly_unlimited() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::MaxSpeed);
        assert_eq!(profile.profile, AtpPowerProfile::MaxSpeed);
        assert!(profile.max_bandwidth_bytes_per_second.is_none()); // Unlimited bandwidth
        assert!(profile.max_relay_cost_micros_per_mib.is_none()); // Unlimited relay cost
        assert!(!profile.is_background_priority());
        assert!(!profile.is_metered_network());
        // But should still have some limits for safety
        assert!(profile.max_in_flight_bytes.is_some());
    }

    #[test]
    fn balanced_profile_has_reasonable_limits() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::Balanced);
        assert_eq!(profile.profile, AtpPowerProfile::Balanced);
        assert!(profile.has_limits());
        assert_eq!(
            profile.max_bandwidth_bytes_per_second,
            Some(128 * 1_048_576)
        );
        assert_eq!(profile.max_in_flight_bytes, Some(128 * 1_048_576));
        assert_eq!(profile.max_repair_symbols_per_second, Some(4_096));
        assert_eq!(profile.max_disk_write_concurrency, Some(4));
        assert!(!profile.is_background_priority());
        assert!(!profile.is_metered_network());
    }

    #[test]
    fn battery_saver_profile_is_very_conservative() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::BatterySaver);
        assert_eq!(profile.profile, AtpPowerProfile::BatterySaver);
        assert!(profile.has_limits());
        assert_eq!(profile.max_bandwidth_bytes_per_second, Some(16 * 1_048_576));
        assert_eq!(profile.max_repair_symbols_per_second, Some(512));
        assert_eq!(profile.max_disk_write_concurrency, Some(1));
        assert!(profile.is_background_priority());
        assert!(!profile.is_metered_network()); // Not metered, just battery conscious
    }

    #[test]
    fn metered_profile_is_network_cost_conscious() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::Metered);
        assert_eq!(profile.profile, AtpPowerProfile::Metered);
        assert!(profile.is_metered_network());
        assert!(profile.is_background_priority());
        // Should have very low relay cost limits
        assert_eq!(profile.max_relay_cost_micros_per_mib, Some(250_000));
    }

    #[test]
    fn relay_conservative_profile_limits_relay_cost() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::RelayConservative);
        assert_eq!(profile.profile, AtpPowerProfile::RelayConservative);
        assert_eq!(profile.max_relay_cost_micros_per_mib, Some(150_000)); // Very aggressive limit
        assert!(!profile.is_background_priority());
        assert!(!profile.is_metered_network());
    }

    #[test]
    fn ci_deterministic_profile_is_predictable() {
        let profile = AtpResourceProfile::for_power_profile(AtpPowerProfile::CiDeterministic);
        assert_eq!(profile.profile, AtpPowerProfile::CiDeterministic);
        assert!(profile.is_background_priority());
        assert!(profile.is_metered_network());
        // Should have very low, predictable limits
        assert_eq!(profile.max_bandwidth_bytes_per_second, Some(4 * 1_048_576));
        assert_eq!(profile.max_disk_write_concurrency, Some(1));
        assert_eq!(profile.max_relay_cost_micros_per_mib, Some(1)); // Essentially disables relay
    }

    #[test]
    fn custom_profile_allows_user_configuration() {
        let profile = AtpResourceProfile::custom(
            Some(1_048_576), // 1 MiB/s
            Some(512_000),   // 512 KB
            Some(64),        // 64 symbols/s
            Some(1),         // 1 write
            Some(10_000),    // 10ms per MiB
            true,            // background
            true,            // metered
        );
        assert_eq!(profile.profile, AtpPowerProfile::Custom);
        assert!(profile.has_limits());
        assert!(profile.is_background_priority());
        assert!(profile.is_metered_network());
        assert_eq!(profile.max_bandwidth_bytes_per_second, Some(1_048_576));
        assert_eq!(profile.max_relay_cost_micros_per_mib, Some(10_000));
    }

    #[test]
    fn power_profile_default_is_balanced() {
        assert_eq!(AtpPowerProfile::default(), AtpPowerProfile::Balanced);
    }

    #[test]
    fn resource_profile_default_is_balanced_preset() {
        let profile = AtpResourceProfile::default();
        let balanced = AtpResourceProfile::for_power_profile(AtpPowerProfile::Balanced);
        assert_eq!(profile, balanced);
    }
