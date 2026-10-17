    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn lab_provider_selects_fast_policy() {
        init_test("lab_provider_selects_fast_policy");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let report = build_atp_platform_capability_report(&provider);

        assert_eq!(
            report.degradation_policy.disk_writer_mode,
            "sparse-preallocated"
        );
        assert_eq!(
            report.degradation_policy.atomic_commit_mode,
            "sync-temp-rename-sync-parent"
        );
        assert_eq!(
            report.degradation_policy.endpoint_mode,
            "ipv6-ipv4-direct-first"
        );
        assert_eq!(report.degradation_policy.packaging_mode, "managed-service");
        assert!(report.caveats.is_empty());
        crate::test_complete!("lab_provider_selects_fast_policy");
    }

    #[test]
    fn lab_provider_selects_conservative_policy() {
        init_test("lab_provider_selects_conservative_policy");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let report = build_atp_platform_capability_report(&provider);

        assert_eq!(
            report.degradation_policy.disk_writer_mode,
            "contiguous-verified-quarantine"
        );
        assert_eq!(
            report.degradation_policy.atomic_commit_mode,
            "rename-with-journal-replay-guard"
        );
        assert_eq!(
            report.degradation_policy.endpoint_mode,
            "ipv4-or-relay-first"
        );
        assert_eq!(
            report.degradation_policy.packaging_mode,
            "foreground-or-user-service"
        );
        assert!(
            report
                .suggested_recovery_commands
                .contains(&"enable IPv6 loopback/networking on this host".to_string())
        );
        crate::test_complete!("lab_provider_selects_conservative_policy");
    }

    #[test]
    fn current_family_has_stable_label() {
        init_test("current_family_has_stable_label");
        let label = PlatformProbeFamily::current().as_str();
        assert!(!label.is_empty());
        assert!(!label.contains('-'));
        crate::test_complete!("current_family_has_stable_label");
    }
