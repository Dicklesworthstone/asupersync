    use super::*;

    #[derive(Clone, Debug)]
    struct DeterministicPlatformCapabilityProvider {
        target: PlatformTarget,
        sparse_files: CapabilityProbe,
        preallocation: CapabilityProbe,
        atomic_rename: CapabilityProbe,
        fsync_durability: CapabilityProbe,
        max_path_length: CapabilityProbe,
        case_sensitive_paths: CapabilityProbe,
        symlink_behavior: CapabilityProbe,
        socket_buffers: CapabilityProbe,
        ipv6: CapabilityProbe,
        router_assist: CapabilityProbe,
        service_manager: CapabilityProbe,
    }

    impl DeterministicPlatformCapabilityProvider {
        fn fully_supported() -> Self {
            Self {
                target: PlatformTarget {
                    os: "testos".to_string(),
                    family: "test".to_string(),
                    arch: "testarch".to_string(),
                    pointer_width: 64,
                },
                sparse_files: supported("sparse_files"),
                preallocation: supported("preallocation"),
                atomic_rename: supported("atomic_rename"),
                fsync_durability: supported("fsync_durability"),
                max_path_length: supported("max_path_length"),
                case_sensitive_paths: supported("case_sensitive_paths"),
                symlink_behavior: supported("symlink_behavior"),
                socket_buffers: supported("socket_buffers"),
                ipv6: supported("ipv6"),
                router_assist: supported("router_assist"),
                service_manager: supported("service_manager"),
            }
        }
    }

    impl PlatformCapabilityProvider for DeterministicPlatformCapabilityProvider {
        fn target(&self) -> PlatformTarget {
            self.target.clone()
        }

        fn sparse_files(&self) -> CapabilityProbe {
            self.sparse_files.clone()
        }

        fn preallocation(&self) -> CapabilityProbe {
            self.preallocation.clone()
        }

        fn atomic_rename(&self) -> CapabilityProbe {
            self.atomic_rename.clone()
        }

        fn fsync_durability(&self) -> CapabilityProbe {
            self.fsync_durability.clone()
        }

        fn max_path_length(&self) -> CapabilityProbe {
            self.max_path_length.clone()
        }

        fn case_sensitive_paths(&self) -> CapabilityProbe {
            self.case_sensitive_paths.clone()
        }

        fn symlink_behavior(&self) -> CapabilityProbe {
            self.symlink_behavior.clone()
        }

        fn socket_buffers(&self) -> CapabilityProbe {
            self.socket_buffers.clone()
        }

        fn ipv6(&self) -> CapabilityProbe {
            self.ipv6.clone()
        }

        fn router_assist(&self) -> CapabilityProbe {
            self.router_assist.clone()
        }

        fn service_manager(&self) -> CapabilityProbe {
            self.service_manager.clone()
        }
    }

    fn supported(name: &'static str) -> CapabilityProbe {
        CapabilityProbe::new(
            name,
            CapabilityStatus::Supported,
            ProbeSource::Measured,
            format!("{name} supported"),
        )
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn fully_supported_provider_selects_fast_policy() {
        init_test("fully_supported_provider_selects_fast_policy");
        let provider = DeterministicPlatformCapabilityProvider::fully_supported();
        let report = build_platform_capability_report(&provider);

        assert_eq!(
            report.schema_version,
            PLATFORM_CAPABILITY_REPORT_SCHEMA.to_string()
        );
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
        assert!(report.suggested_recovery_commands.is_empty());
        crate::test_complete!("fully_supported_provider_selects_fast_policy");
    }

    #[test]
    fn failed_probes_select_conservative_degradation() {
        init_test("failed_probes_select_conservative_degradation");
        let mut provider = DeterministicPlatformCapabilityProvider::fully_supported();
        provider.sparse_files = CapabilityProbe::new(
            "sparse_files",
            CapabilityStatus::Unsupported,
            ProbeSource::Measured,
            "sparse write probe failed",
        )
        .with_degradation_reason("write into quarantine before verified exposure");
        provider.fsync_durability = CapabilityProbe::new(
            "fsync_durability",
            CapabilityStatus::Degraded,
            ProbeSource::Measured,
            "directory fsync failed",
        )
        .with_degradation_reason("replay journal after every restart");
        provider.ipv6 = CapabilityProbe::new(
            "ipv6",
            CapabilityStatus::Degraded,
            ProbeSource::Measured,
            "IPv6 unavailable",
        )
        .with_degradation_reason("prefer IPv4")
        .with_recovery_command("enable IPv6 loopback/networking on this host");

        let report = build_platform_capability_report(&provider);

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
        assert!(report.caveats.iter().any(|caveat| {
            caveat.contains("sparse_files")
                && caveat.contains("write into quarantine before verified exposure")
        }));
        assert_eq!(
            report.suggested_recovery_commands,
            vec!["enable IPv6 loopback/networking on this host".to_string()]
        );
        crate::test_complete!("failed_probes_select_conservative_degradation");
    }

    #[test]
    fn supported_probe_recovery_commands_are_ignored() {
        init_test("supported_probe_recovery_commands_are_ignored");
        let mut provider = DeterministicPlatformCapabilityProvider::fully_supported();
        provider.preallocation = CapabilityProbe::new(
            "preallocation",
            CapabilityStatus::Supported,
            ProbeSource::Measured,
            "preallocation supported",
        )
        .with_recovery_command("do not suggest this for supported probes");

        let report = build_platform_capability_report(&provider);

        assert!(report.suggested_recovery_commands.is_empty());
        crate::test_complete!("supported_probe_recovery_commands_are_ignored");
    }

    #[test]
    fn native_report_has_stable_sections() {
        init_test("native_report_has_stable_sections");
        let report = detect_platform_capabilities();

        assert_eq!(report.schema_version, PLATFORM_CAPABILITY_REPORT_SCHEMA);
        assert_eq!(report.filesystem.sparse_files.name, "sparse_files");
        assert_eq!(report.filesystem.atomic_rename.name, "atomic_rename");
        assert_eq!(report.network.ipv6.name, "ipv6");
        assert_eq!(report.service.service_manager.name, "service_manager");
        assert!(!report.degradation_policy.disk_writer_mode.is_empty());
        assert!(!report.degradation_policy.atomic_commit_mode.is_empty());
        crate::test_complete!("native_report_has_stable_sections");
    }
