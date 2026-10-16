    use super::*;
    use crate::lab::AtpLabScenario;

    #[tokio::test]
    async fn test_lan_ipv6_harness_basic_execution() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("easy-nat-direct", 0xA7F0_0001)
            .with_regime(AtpLabRegime::LanMulticast)
            .with_regime(AtpLabRegime::EasyNat)
            .with_regime(AtpLabRegime::Ipv6Direct);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.transfer_succeeded());
        assert!(result.path_validation.lan_multicast_succeeded);
        assert!(result.path_validation.nat_punch_succeeded);
        assert!(result.path_validation.ipv6_direct_succeeded);
        assert_eq!(result.candidates_evaluated, 3);
    }

    #[tokio::test]
    async fn test_path_validation_has_direct_path() {
        let mut validation = AtpPathValidation::failed();
        validation.ipv6_direct_succeeded = true;
        validation.selected_path_kind = Some(PathKind::PublicIpv6);

        assert!(validation.has_direct_path());
        assert!(validation.transfer_succeeded());
    }

    #[tokio::test]
    async fn test_udp_blocked_forces_relay() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario =
            AtpLabScenario::new("udp-blocked", 0xA7F0_0003).with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(!result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::UdpBlocked
        );
    }

    #[tokio::test]
    async fn test_masque_connect_udp_relay_adapter_path() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario = AtpLabScenario::new("masque-proxy", 0xA7F0_0007)
            .with_regime(AtpLabRegime::MasqueConnectUdpProxy);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(result.path_validation.masque_connect_udp_succeeded);
        assert!(!result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::MasqueConnectUdp)
        );
        assert!(result.trace_events.iter().any(|event| matches!(
            &event.event,
            AtpPathEventKind::ConnectionAttempt {
                path_kind: PathKind::MasqueConnectUdp,
                target_endpoint,
            } if target_endpoint == "masque-connect-udp-proxy:443"
        )));
    }

    #[tokio::test]
    async fn test_path_migration_lan_to_ipv6() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("path-migration", 0xA7F0_0008)
            .with_regime(AtpLabRegime::PathMigration);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.migration_preserved_transfer);
        assert!(result.path_validation.lan_multicast_succeeded);
        assert!(result.path_validation.ipv6_direct_succeeded);
        assert_eq!(result.candidates_evaluated, 2);

        // Verify migration trace events
        let migration_event = result
            .trace_events
            .iter()
            .find(|event| matches!(&event.event, AtpPathEventKind::MigrationTriggered { .. }));
        assert!(migration_event.is_some());

        if let Some(event) = migration_event {
            if let AtpPathEventKind::MigrationTriggered { from_path, to_path } = &event.event {
                assert_eq!(*from_path, PathKind::LanMulticast);
                assert_eq!(*to_path, PathKind::PublicIpv6);
            }
        }
    }

    #[tokio::test]
    async fn test_hard_symmetric_nat_behavior() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario =
            AtpLabScenario::new("hard-nat", 0xA7F0_0009).with_regime(AtpLabRegime::SymmetricNat);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::HardSymmetricNat
        );
        assert!(!result.path_validation.nat_punch_succeeded);
        assert!(!result.path_validation.has_direct_path());

        // Verify failure trace event for NAT punching
        let failure_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::PathFailed {
                    path_kind: PathKind::NatPunchedUdp,
                    reason,
                } if reason.contains("Hard or symmetric NAT prevented hole punching")
            )
        });
        assert!(failure_event.is_some());
    }

    #[tokio::test]
    async fn test_relay_tcp_tls_443_fallback() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario =
            AtpLabScenario::new("relay-tls", 0xA7F0_000A).with_regime(AtpLabRegime::RelayTcpTls443);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.relay_succeeded);
        assert!(result.path_validation.relay_tcp_tls_443_succeeded);
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::AtpRelayTcpTls443)
        );

        // Verify connection attempt to correct path
        let connection_attempt = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::ConnectionAttempt {
                    path_kind: PathKind::AtpRelayTcpTls443,
                    ..
                }
            )
        });
        assert!(connection_attempt.is_some());
    }

    #[tokio::test]
    async fn test_tailscale_private_route_success() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("tailscale", 0xA7F0_000B)
            .with_regime(AtpLabRegime::TailscalePrivateRoute);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.tailscale_private_route_succeeded);
        assert!(result.path_validation.transfer_succeeded());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::TailscaleIp)
        );
    }

    #[tokio::test]
    async fn test_offline_mailbox_store_and_forward() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

        let scenario = AtpLabScenario::new("offline-mailbox", 0xA7F0_000C)
            .with_regime(AtpLabRegime::OfflineMailbox);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.offline_mailbox_succeeded);
        assert!(result.path_validation.transfer_succeeded());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::OfflineMailbox)
        );

        // Verify transfer completion event
        let transfer_complete = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::TransferCompleted {
                    selected_path: PathKind::OfflineMailbox,
                    bytes_transferred: 1048576, // 1MB
                }
            )
        });
        assert!(transfer_complete.is_some());
    }

    #[tokio::test]
    async fn test_explicit_public_udp_direct_path() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("explicit-udp", 0xA7F0_000D)
            .with_regime(AtpLabRegime::ExplicitPublicUdp);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert!(result.path_validation.explicit_public_udp_succeeded);
        assert!(result.path_validation.has_direct_path());
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(PathKind::ExplicitPublicUdp)
        );
    }

    #[tokio::test]
    async fn test_udp_blocked_fallback_with_loser_drain() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("udp-blocked-drain", 0xA7F0_000E)
            .with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::UdpBlocked
        );
        assert!(result.path_validation.relay_succeeded);

        // Verify fallback selection event
        let fallback_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::FallbackSelected {
                    from_path: PathKind::NatPunchedUdp,
                    to_path: PathKind::AtpRelayUdp,
                    reason,
                    relay_cost_micros: Some(55_000),
                } if reason == "udp_blocked_direct_datagrams"
            )
        });
        assert!(fallback_event.is_some());

        // Verify loser drain event
        let drain_event = result.trace_events.iter().find(|event| {
            matches!(
                &event.event,
                AtpPathEventKind::LoserPathDrained {
                    path_kind: PathKind::NatPunchedUdp,
                    reason,
                } if reason == "direct_udp_candidate_failed_before_relay_selection"
            )
        });
        assert!(drain_event.is_some());
    }

    #[tokio::test]
    async fn test_path_selection_priority_order() {
        // Test that best path selection prioritizes direct paths over relay paths
        let validation = AtpPathValidation {
            ipv6_direct_succeeded: true,
            lan_multicast_succeeded: true,
            explicit_public_udp_succeeded: true,
            nat_punch_succeeded: true,
            relay_succeeded: true,
            relay_tcp_tls_443_succeeded: true,
            masque_connect_udp_succeeded: true,
            tailscale_private_route_succeeded: true,
            offline_mailbox_succeeded: true,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::Ipv6Direct,
        };

        let harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());
        let selected = harness.select_best_path(&validation);

        // IPv6 direct should be preferred over all other paths
        assert_eq!(selected, Some(PathKind::PublicIpv6));
    }

    #[tokio::test]
    async fn test_path_selection_relay_fallback_priority() {
        // Test relay path priority when no direct paths succeed
        let validation = AtpPathValidation {
            ipv6_direct_succeeded: false,
            lan_multicast_succeeded: false,
            explicit_public_udp_succeeded: false,
            nat_punch_succeeded: false,
            relay_succeeded: true,
            relay_tcp_tls_443_succeeded: true,
            masque_connect_udp_succeeded: true,
            tailscale_private_route_succeeded: true,
            offline_mailbox_succeeded: true,
            migration_preserved_transfer: false,
            selected_path_kind: None,
            detected_nat_profile: NatProfile::UdpBlocked,
        };

        let harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());
        let selected = harness.select_best_path(&validation);

        // Tailscale private route should be preferred over relay paths
        assert_eq!(selected, Some(PathKind::TailscaleIp));
    }

    #[tokio::test]
    async fn test_target_endpoint_selection() {
        // Test endpoint selection for different path kinds
        assert_eq!(
            target_endpoint_for_path(PathKind::MasqueConnectUdp),
            "masque-connect-udp-proxy:443"
        );
        assert_eq!(
            target_endpoint_for_path(PathKind::LanMulticast),
            "virtual-endpoint"
        );
        assert_eq!(
            target_endpoint_for_path(PathKind::AtpRelayUdp),
            "virtual-endpoint"
        );
    }

    #[tokio::test]
    async fn test_trace_event_deterministic_timestamps() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

        let scenario = AtpLabScenario::new("timestamp-test", 0xA7F0_000F)
            .with_regime(AtpLabRegime::LanMulticast);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Verify timestamps are monotonically increasing
        let mut prev_timestamp = Time::from_nanos(0);
        for event in &result.trace_events {
            assert!(event.timestamp >= prev_timestamp);
            prev_timestamp = event.timestamp;
        }

        // Verify all events have unique trace IDs
        let trace_ids: Vec<_> = result.trace_events.iter().map(|e| e.trace_id).collect();
        let mut unique_trace_ids = trace_ids.clone();
        unique_trace_ids.sort();
        unique_trace_ids.dedup();
        assert_eq!(trace_ids.len(), unique_trace_ids.len());
    }

    #[tokio::test]
    async fn test_comprehensive_trace_event_coverage() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("comprehensive-trace", 0xA7F0_0010)
            .with_regime(AtpLabRegime::UdpBlocked);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Verify we have all expected trace event types
        // Should have discovery started, connection attempt, path failed,
        // fallback selected, loser drained, and transfer completed events
        assert!(result.trace_events.len() >= 6);

        // Verify we have discovery started events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::DiscoveryStarted { .. }))
        );

        // Verify we have connection attempt events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::ConnectionAttempt { .. }))
        );

        // Verify we have path failed events
        assert!(
            result
                .trace_events
                .iter()
                .any(|e| matches!(&e.event, AtpPathEventKind::PathFailed { .. }))
        );
    }

    #[tokio::test]
    async fn test_multi_regime_scenario_execution() {
        let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

        let scenario = AtpLabScenario::new("multi-regime", 0xA7F0_0011)
            .with_regime(AtpLabRegime::LanMulticast)
            .with_regime(AtpLabRegime::EasyNat)
            .with_regime(AtpLabRegime::HardNat)
            .with_regime(AtpLabRegime::RelayOnly);

        let result = harness.execute_scenario(&scenario).await.unwrap();

        // Should have evaluated candidates from all regimes
        assert_eq!(result.candidates_evaluated, 4);

        // Should have succeeded with some paths
        assert!(result.path_validation.transfer_succeeded());

        // Verify NAT profile was detected from hard NAT regime
        assert_eq!(
            result.path_validation.detected_nat_profile,
            NatProfile::HardSymmetricNat
        );
    }

    #[tokio::test]
    async fn test_config_variations() {
        // Test different configuration presets
        let lan_config = AtpPathTestConfig::lan_ipv6();
        assert!(lan_config.enable_path_tracing);
        assert_eq!(lan_config.path_discovery_timeout, Duration::from_secs(30));
        assert!(!lan_config.enable_migration);

        let nat_config = AtpPathTestConfig::nat_stress();
        assert!(nat_config.enable_path_tracing);
        assert_eq!(nat_config.path_discovery_timeout, Duration::from_secs(60));
        assert!(nat_config.enable_migration);

        let relay_config = AtpPathTestConfig::relay_only();
        assert!(relay_config.enable_path_tracing);
        assert_eq!(relay_config.path_discovery_timeout, Duration::from_secs(45));
        assert!(!relay_config.enable_migration);
    }

    #[tokio::test]
    async fn test_path_validation_edge_cases() {
        // Test failed validation
        let failed = AtpPathValidation::failed();
        assert!(!failed.has_direct_path());
        assert!(!failed.transfer_succeeded());
        assert_eq!(failed.selected_path_kind, None);
        assert_eq!(failed.detected_nat_profile, NatProfile::Unknown);

        // Test partial success scenarios
        let mut partial = AtpPathValidation::failed();
        partial.relay_succeeded = true;
        partial.selected_path_kind = Some(PathKind::AtpRelayUdp);
        assert!(!partial.has_direct_path());
        assert!(partial.transfer_succeeded());

        // Test migration success
        let mut with_migration = AtpPathValidation::failed();
        with_migration.lan_multicast_succeeded = true;
        with_migration.ipv6_direct_succeeded = true;
        with_migration.migration_preserved_transfer = true;
        with_migration.selected_path_kind = Some(PathKind::PublicIpv6);
        assert!(with_migration.has_direct_path());
        assert!(with_migration.transfer_succeeded());
    }
