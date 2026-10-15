//! ATP Path Lab Integration Tests
//!
//! Tests the ATP path lab harness against the required coverage matrix
//! for deterministic NAT/path validation scenarios.

use asupersync::atp::path::PathKind;
use asupersync::lab::atp_path::{AtpPathEventKind, AtpPathLabHarness, AtpPathTestConfig};
use asupersync::lab::{AtpLabRegime, AtpLabScenario};
use asupersync::net::atp::path::NatProfile;
use std::collections::BTreeSet;

#[tokio::test]
async fn test_atp_path_lab_lan_ipv6_scenario() -> Result<(), Box<dyn std::error::Error>> {
    // Test the first scenario from AtpLabScenario::required_matrix()
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());

    let scenario = AtpLabScenario::new("easy-nat-direct", 0xA7F0_0001)
        .with_regime(AtpLabRegime::LanMulticast)
        .with_regime(AtpLabRegime::EasyNat)
        .with_regime(AtpLabRegime::Ipv6Direct);

    let result = harness.execute_scenario(&scenario).await?;

    // Verify path validation results
    assert!(
        result.path_validation.transfer_succeeded(),
        "Transfer should succeed with LAN+IPv6 paths"
    );

    assert!(
        result.path_validation.lan_multicast_succeeded,
        "LAN multicast should succeed for LanMulticast regime"
    );

    assert!(
        result.path_validation.nat_punch_succeeded,
        "NAT hole punching should succeed for EasyNat regime"
    );

    assert!(
        result.path_validation.ipv6_direct_succeeded,
        "IPv6 direct should succeed for Ipv6Direct regime"
    );

    assert!(
        result.path_validation.has_direct_path(),
        "Should have at least one direct path"
    );

    // Check selected path preference (IPv6 should be preferred over LAN)
    assert_eq!(
        result.path_validation.selected_path_kind,
        Some(PathKind::PublicIpv6),
        "IPv6 direct should be selected as the best path"
    );

    // Verify trace events were captured
    assert!(
        result.trace_events.len() >= 4,
        "Should have trace events for both path discoveries"
    );

    // Verify scenario execution
    assert!(
        result.scenario_matched_expected,
        "Scenario should execute as expected"
    );

    assert_eq!(
        result.candidates_evaluated, 3,
        "Should evaluate exactly 3 path candidates"
    );

    println!(
        "✅ LAN+IPv6 scenario completed in {:?} with {} trace events",
        result.execution_time,
        result.trace_events.len()
    );

    Ok(())
}

#[tokio::test]
async fn test_atp_path_lab_udp_blocked_relay_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

    let scenario =
        AtpLabScenario::new("udp-blocked-relay", 0xA7F0_0003).with_regime(AtpLabRegime::UdpBlocked);

    let result = harness.execute_scenario(&scenario).await?;

    // Verify UDP blocked detection and relay fallback
    assert_eq!(
        result.path_validation.detected_nat_profile,
        NatProfile::UdpBlocked,
        "Should detect UDP blocked NAT profile"
    );

    assert!(
        !result.path_validation.has_direct_path(),
        "Should not have any direct paths when UDP is blocked"
    );

    assert!(
        result.path_validation.relay_succeeded,
        "Relay path should succeed as fallback"
    );

    assert!(
        result.path_validation.transfer_succeeded(),
        "Transfer should succeed via relay"
    );

    assert_eq!(
        result.path_validation.selected_path_kind,
        Some(PathKind::AtpRelayUdp),
        "Should select ATP relay as the path"
    );
    assert_eq!(
        result.candidates_evaluated, 2,
        "UDP-blocked fallback should first evaluate the failed direct UDP candidate"
    );
    assert!(result.trace_events.iter().any(|event| matches!(
        &event.event,
        AtpPathEventKind::PathFailed {
            path_kind: PathKind::NatPunchedUdp,
            reason,
        } if reason.contains("UDP blocked")
    )));
    assert!(result.trace_events.iter().any(|event| matches!(
        &event.event,
        AtpPathEventKind::FallbackSelected {
            from_path: PathKind::NatPunchedUdp,
            to_path: PathKind::AtpRelayUdp,
            reason,
            relay_cost_micros: Some(55_000),
        } if reason == "udp_blocked_direct_datagrams"
    )));
    assert!(result.trace_events.iter().any(|event| matches!(
        &event.event,
        AtpPathEventKind::LoserPathDrained {
            path_kind: PathKind::NatPunchedUdp,
            reason,
        } if reason.contains("direct_udp_candidate_failed")
    )));
    assert!(result.trace_events.iter().any(|event| matches!(
        &event.event,
        AtpPathEventKind::TransferCompleted {
            selected_path: PathKind::AtpRelayUdp,
            bytes_transferred: 1_048_576,
        }
    )));

    Ok(())
}

#[tokio::test]
async fn test_masque_connect_udp_relay_adapter() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::relay_only());

    let scenario = AtpLabScenario::new("enterprise-masque-connect-udp", 0xA7F0_0007)
        .with_regime(AtpLabRegime::UdpBlocked)
        .with_regime(AtpLabRegime::MasqueConnectUdpProxy);

    let result = harness.execute_scenario(&scenario).await?;

    assert_eq!(
        result.path_validation.detected_nat_profile,
        NatProfile::UdpBlocked,
        "MASQUE proxy scenario should preserve the UDP-blocked observation"
    );
    assert!(
        !result.path_validation.has_direct_path(),
        "MASQUE proxy must not be reported as a direct peer-to-peer path"
    );
    assert!(
        result.path_validation.relay_succeeded,
        "MASQUE proxy is an online relay-family adapter"
    );
    assert!(
        result.path_validation.masque_connect_udp_succeeded,
        "CONNECT-UDP relay adapter path should validate"
    );
    assert_eq!(
        result.path_validation.selected_path_kind,
        Some(PathKind::MasqueConnectUdp),
        "Enterprise egress scenario should select the MASQUE adapter"
    );
    assert!(
        result.path_validation.transfer_succeeded(),
        "Transfer should complete over the MASQUE relay adapter model"
    );
    assert!(
        result.trace_events.iter().any(|event| matches!(
            &event.event,
            asupersync::lab::atp_path::AtpPathEventKind::ConnectionAttempt {
                path_kind: PathKind::MasqueConnectUdp,
                target_endpoint,
            } if target_endpoint == "masque-connect-udp-proxy:443"
        )),
        "Trace should expose the MASQUE relay adapter endpoint"
    );

    Ok(())
}

#[tokio::test]
async fn test_atp_path_lab_hard_nat_punch_failure() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

    let scenario = AtpLabScenario::new("hard-nat-test", 0xA7F0_0002)
        .with_regime(AtpLabRegime::HardNat)
        .with_regime(AtpLabRegime::SymmetricNat);

    let result = harness.execute_scenario(&scenario).await?;

    // Hard NAT should prevent hole punching
    assert_eq!(
        result.path_validation.detected_nat_profile,
        NatProfile::HardSymmetricNat,
        "Should detect hard symmetric NAT"
    );

    assert!(
        !result.path_validation.nat_punch_succeeded,
        "NAT hole punching should fail with hard symmetric NAT"
    );

    // But scenario should still execute properly
    assert!(
        result.scenario_matched_expected,
        "Scenario should execute as expected even with failures"
    );

    assert_eq!(
        result.candidates_evaluated, 2,
        "Should evaluate 2 candidates"
    );

    Ok(())
}

#[tokio::test]
async fn test_atp_path_lab_migration_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());

    let scenario = AtpLabScenario::new("path-migration-test", 0xA7F0_0004)
        .with_regime(AtpLabRegime::PathMigration);

    let result = harness.execute_scenario(&scenario).await?;

    // Migration should preserve transfer correctness
    assert!(
        result.path_validation.migration_preserved_transfer,
        "Path migration should preserve transfer correctness"
    );

    // Should have migration events in trace
    let migration_events = result
        .trace_events
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                asupersync::lab::atp_path::AtpPathEventKind::MigrationTriggered { .. }
            )
        })
        .count();

    assert!(
        migration_events >= 1,
        "Should have at least one migration event in trace"
    );

    Ok(())
}

#[tokio::test]
async fn test_atp_path_lab_coverage_matrix() -> Result<(), Box<dyn std::error::Error>> {
    // Each PathKind should have at least one deterministic lab scenario.
    let harness_config = AtpPathTestConfig::lan_ipv6();

    let path_matrix = [
        (AtpLabRegime::LanMulticast, PathKind::LanMulticast),
        (AtpLabRegime::ExplicitPublicUdp, PathKind::ExplicitPublicUdp),
        (AtpLabRegime::Ipv6Direct, PathKind::PublicIpv6),
        (AtpLabRegime::EasyNat, PathKind::NatPunchedUdp),
        (AtpLabRegime::TailscalePrivateRoute, PathKind::TailscaleIp),
        (AtpLabRegime::RelayOnly, PathKind::AtpRelayUdp),
        (AtpLabRegime::RelayTcpTls443, PathKind::AtpRelayTcpTls443),
        (
            AtpLabRegime::MasqueConnectUdpProxy,
            PathKind::MasqueConnectUdp,
        ),
        (AtpLabRegime::OfflineMailbox, PathKind::OfflineMailbox),
    ];

    let mut covered = BTreeSet::new();
    for (regime, expected_kind) in path_matrix {
        let mut harness = AtpPathLabHarness::new(harness_config.clone());

        let scenario = AtpLabScenario::new(format!("test-{}", regime.label()), 0xA7F0_0000)
            .with_regime(regime);

        let result = harness.execute_scenario(&scenario).await?;

        assert!(
            result.path_validation.transfer_succeeded(),
            "Path regime {:?} should complete a transfer",
            regime
        );
        assert_eq!(
            result.path_validation.selected_path_kind,
            Some(expected_kind),
            "Path regime {:?} should select {:?}",
            regime,
            expected_kind
        );
        assert!(
            result.trace_events.iter().any(|event| matches!(
                &event.event,
                AtpPathEventKind::ConnectionAttempt { path_kind, .. } if *path_kind == expected_kind
            )),
            "Path regime {:?} should trace a {:?} connection attempt",
            regime,
            expected_kind
        );

        covered.insert(expected_kind);
    }

    let all_path_kinds = BTreeSet::from(PathKind::ALL);
    assert_eq!(covered, all_path_kinds);

    Ok(())
}
