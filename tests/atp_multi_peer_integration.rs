//! ATP Multi-Peer Integration Tests
//!
//! Integration tests for the ATP multi-peer test infrastructure framework.
//! Tests the framework itself rather than ATP implementations.

use asupersync::atp::multi_peer::{
    MultiPeerScenario, ScenarioType, PeerRole, MULTI_PEER_REPORT_SCHEMA,
    scenarios::AllScenarios,
    contracts::{MailboxContract, SwarmContract, CacheContract},
    harness::{MultiPeerHarness, TestReportGenerator, ScenarioExecutor},
};
use std::time::Duration;

#[test]
fn test_scenario_collection_completeness() {
    let all_scenarios = AllScenarios::all();

    // Should have scenarios from each major type
    let has_mailbox = all_scenarios.iter()
        .any(|s| matches!(s.scenario_type, ScenarioType::Mailbox));
    let has_swarm = all_scenarios.iter()
        .any(|s| matches!(s.scenario_type, ScenarioType::Swarm));
    let has_cache = all_scenarios.iter()
        .any(|s| matches!(s.scenario_type, ScenarioType::Cache));

    assert!(has_mailbox, "Should have mailbox scenarios");
    assert!(has_swarm, "Should have swarm scenarios");
    assert!(has_cache, "Should have cache scenarios");

    // All scenarios should be valid
    for scenario in &all_scenarios {
        assert!(scenario.validate().is_ok(),
            "Scenario {} should be valid: {:?}",
            scenario.scenario_id,
            scenario.validate()
        );
    }

    println!("✅ Validated {} multi-peer scenarios", all_scenarios.len());
}

#[test]
fn test_mailbox_scenarios_validation() {
    let mailbox_scenarios = AllScenarios::mailbox();
    let contract = MailboxContract;

    for scenario in &mailbox_scenarios {
        assert!(matches!(scenario.scenario_type, ScenarioType::Mailbox | ScenarioType::Adversarial),
            "Mailbox scenario should have appropriate type: {}", scenario.scenario_id);

        // Should pass contract validation
        let validation_result = contract.validate_scenario(scenario);
        assert!(validation_result.is_ok(),
            "Mailbox scenario {} should pass contract validation: {:?}",
            scenario.scenario_id,
            validation_result
        );
    }

    println!("✅ Validated {} mailbox scenarios", mailbox_scenarios.len());
}

#[test]
fn test_swarm_scenarios_validation() {
    let swarm_scenarios = AllScenarios::swarm();
    let contract = SwarmContract;

    for scenario in &swarm_scenarios {
        // Most should be swarm type, some may be peer churn or adversarial
        assert!(matches!(scenario.scenario_type,
            ScenarioType::Swarm | ScenarioType::PeerChurn | ScenarioType::Adversarial),
            "Swarm scenario should have appropriate type: {}", scenario.scenario_id);

        // Should have multiple peers for swarm behavior
        assert!(scenario.peers.len() >= 3,
            "Swarm scenario {} should have at least 3 peers", scenario.scenario_id);

        // Should have at least one receiver
        let has_receiver = scenario.peers.iter()
            .any(|p| matches!(p.role, PeerRole::Receiver));
        assert!(has_receiver,
            "Swarm scenario {} should have receiver", scenario.scenario_id);

        // Should pass contract validation if it's a swarm type
        if matches!(scenario.scenario_type, ScenarioType::Swarm | ScenarioType::PeerChurn) {
            let validation_result = contract.validate_scenario(scenario);
            assert!(validation_result.is_ok(),
                "Swarm scenario {} should pass contract validation: {:?}",
                scenario.scenario_id,
                validation_result
            );
        }
    }

    println!("✅ Validated {} swarm scenarios", swarm_scenarios.len());
}

#[test]
fn test_cache_scenarios_validation() {
    let cache_scenarios = AllScenarios::cache();
    let contract = CacheContract;

    for scenario in &cache_scenarios {
        assert!(matches!(scenario.scenario_type, ScenarioType::Cache),
            "Cache scenario should have cache type: {}", scenario.scenario_id);

        // Should have at least one peer with cache enabled
        let has_cache_peer = scenario.peers.iter()
            .any(|p| p.capabilities.cache_enabled);
        assert!(has_cache_peer,
            "Cache scenario {} should have peer with cache enabled", scenario.scenario_id);

        // Should pass contract validation
        let validation_result = contract.validate_scenario(scenario);
        assert!(validation_result.is_ok(),
            "Cache scenario {} should pass contract validation: {:?}",
            scenario.scenario_id,
            validation_result
        );
    }

    println!("✅ Validated {} cache scenarios", cache_scenarios.len());
}

#[test]
fn test_smoke_test_scenario_selection() {
    let smoke_scenarios = AllScenarios::smoke_test();

    // Should have reasonable number for smoke testing
    assert!(smoke_scenarios.len() >= 3 && smoke_scenarios.len() <= 10,
        "Smoke test should have reasonable number of scenarios: {}", smoke_scenarios.len());

    // Should have representation from different scenario types
    let types: std::collections::HashSet<_> = smoke_scenarios.iter()
        .map(|s| std::mem::discriminant(&s.scenario_type))
        .collect();
    assert!(types.len() >= 2, "Smoke test should cover multiple scenario types");

    // All should be relatively quick
    for scenario in &smoke_scenarios {
        assert!(scenario.timeout <= Duration::from_secs(600),
            "Smoke test scenario {} should be reasonably quick", scenario.scenario_id);
    }

    println!("✅ Validated {} smoke test scenarios", smoke_scenarios.len());
}

#[test]
fn test_scenario_id_uniqueness() {
    let all_scenarios = AllScenarios::all();
    let mut seen_ids = std::collections::HashSet::new();

    for scenario in &all_scenarios {
        assert!(seen_ids.insert(&scenario.scenario_id),
            "Scenario ID should be unique: {}", scenario.scenario_id);
    }

    println!("✅ Verified {} unique scenario IDs", all_scenarios.len());
}

#[test]
fn test_scenario_naming_conventions() {
    let all_scenarios = AllScenarios::all();

    for scenario in &all_scenarios {
        // ID should be kebab-case
        assert!(scenario.scenario_id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "Scenario ID should be kebab-case: {}", scenario.scenario_id);

        // Should contain at least one hyphen
        assert!(scenario.scenario_id.contains('-'),
            "Scenario ID should contain hyphen: {}", scenario.scenario_id);

        // Description should be meaningful
        assert!(scenario.description.len() >= 20,
            "Scenario description should be meaningful: {}", scenario.scenario_id);

        // Should end with period
        assert!(scenario.description.ends_with('.'),
            "Scenario description should end with period: {}", scenario.scenario_id);
    }

    println!("✅ Validated naming conventions for {} scenarios", all_scenarios.len());
}

#[tokio::test]
async fn test_harness_infrastructure() {
    let harness = MultiPeerHarness::new();
    assert!(harness.is_ok(), "Should create test harness");

    let harness = harness.unwrap();
    assert!(harness.work_dir().exists(), "Work directory should exist");

    // Test workspace creation with a simple scenario
    let simple_scenario = MultiPeerScenario {
        scenario_id: "test-harness-validation".to_string(),
        description: "Simple scenario for testing harness infrastructure.".to_string(),
        scenario_type: ScenarioType::Swarm,
        peers: vec![
            asupersync::atp::multi_peer::PeerConfig {
                peer_id: "receiver".to_string(),
                role: PeerRole::Receiver,
                availability: asupersync::atp::multi_peer::AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![],
                },
                capabilities: asupersync::atp::multi_peer::PeerCapabilities {
                    storage_quota: Some(10 * 1024 * 1024),
                    bandwidth_limit: Some(1024 * 1024),
                    cache_enabled: true,
                    seeding_enabled: false,
                    relay_enabled: false,
                },
                work_dir: None,
            },
            asupersync::atp::multi_peer::PeerConfig {
                peer_id: "seed1".to_string(),
                role: PeerRole::Seed,
                availability: asupersync::atp::multi_peer::AvailabilitySchedule {
                    initially_online: true,
                    schedule: vec![],
                },
                capabilities: asupersync::atp::multi_peer::PeerCapabilities {
                    storage_quota: Some(5 * 1024 * 1024),
                    bandwidth_limit: Some(512 * 1024),
                    cache_enabled: true,
                    seeding_enabled: true,
                    relay_enabled: false,
                },
                work_dir: None,
            },
        ],
        ..Default::default()
    };

    // Execute scenario (will fail since ATP not implemented, but should return result)
    let result = harness.execute_scenario(&simple_scenario).await;
    assert!(result.is_ok(), "Harness should return result even if execution fails");

    let result = result.unwrap();
    assert_eq!(result.schema_version, MULTI_PEER_REPORT_SCHEMA);
    assert_eq!(result.scenario.scenario_id, "test-harness-validation");
    assert!(!result.success, "Should fail since ATP not implemented");
    assert!(result.error.is_some(), "Should have error message about unimplemented features");

    println!("✅ Verified test harness infrastructure");
}

#[tokio::test]
async fn test_scenario_executor_smoke_test() {
    // This will fail since ATP features aren't implemented, but should test the infrastructure
    let result = ScenarioExecutor::smoke_test().await;
    assert!(result.is_err(), "Should fail since ATP features not implemented");

    let error = result.unwrap_err();
    assert!(error.contains("not yet implemented") || error.contains("waiting for"),
        "Error should indicate features not implemented: {}", error);

    println!("✅ Verified scenario executor handles unimplemented features gracefully");
}

#[test]
fn test_schema_validation() {
    // Test that our scenario schemas are valid
    let scenarios = AllScenarios::smoke_test();

    for scenario in &scenarios {
        // Should serialize/deserialize correctly
        let json = serde_json::to_string(scenario);
        assert!(json.is_ok(), "Scenario should serialize: {}", scenario.scenario_id);

        let json = json.unwrap();
        let deserialized: Result<MultiPeerScenario, _> = serde_json::from_str(&json);
        assert!(deserialized.is_ok(), "Scenario should deserialize: {}", scenario.scenario_id);

        let deserialized = deserialized.unwrap();
        assert_eq!(deserialized.scenario_id, scenario.scenario_id);
    }

    println!("✅ Validated schema serialization/deserialization");
}

#[test]
fn test_report_generation() {
    // Create some mock results for testing report generation
    let scenarios = AllScenarios::smoke_test();
    let mut mock_results = Vec::new();

    for (i, scenario) in scenarios.iter().enumerate() {
        let result = asupersync::atp::multi_peer::MultiPeerResult {
            schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
            scenario: scenario.clone(),
            executed_at: std::time::SystemTime::now(),
            success: i % 2 == 0, // Alternate success/failure
            error: if i % 2 == 0 { None } else { Some("Test error".to_string()) },
            duration: Duration::from_secs(30 + i as u64 * 10),
            peer_results: std::collections::HashMap::new(),
            network_events: Vec::new(),
            transfer_metrics: asupersync::atp::multi_peer::TransferMetrics {
                total_bytes: (i + 1) as u64 * 1024 * 1024, // 1MB, 2MB, 3MB, etc.
                verified_bytes: if i % 2 == 0 { (i + 1) as u64 * 1024 * 1024 } else { 0 },
                chunks_transferred: (i + 1) as u32 * 16,
                repair_blocks_used: 0,
                peer_rejections: 0,
                source_selections: Vec::new(),
            },
            cache_metrics: std::collections::HashMap::new(),
            verification_results: asupersync::atp::multi_peer::VerificationResults {
                crypto_verified: i % 2 == 0,
                manifest_verified: i % 2 == 0,
                proof_verified: i % 2 == 0,
                failures: Vec::new(),
            },
            artifacts: asupersync::atp::multi_peer::ArtifactPaths {
                report: std::path::PathBuf::from("/tmp/report.json"),
                logs: std::path::PathBuf::from("/tmp/logs"),
                traces: Vec::new(),
                sources: Vec::new(),
                destinations: Vec::new(),
            },
        };
        mock_results.push(result);
    }

    // Generate report
    let report = TestReportGenerator::generate_report(&mock_results);

    assert_eq!(report.total_scenarios, scenarios.len());
    assert!(report.successful > 0, "Should have some successful scenarios");
    assert!(report.failed > 0, "Should have some failed scenarios");
    assert!(report.success_rate > 0.0 && report.success_rate < 1.0, "Should have mixed results");

    // Generate summary text
    let summary = TestReportGenerator::summary_text(&report);
    assert!(summary.contains("Multi-Peer Test Report"), "Should contain header");
    assert!(summary.contains("Total Scenarios:"), "Should contain summary stats");
    assert!(summary.contains("Success Rate:"), "Should contain success rate");

    println!("✅ Verified test report generation");
}

#[test]
fn test_framework_completeness() {
    // Verify we have comprehensive coverage of ATP-NR12 requirements
    let all_scenarios = AllScenarios::all();

    // Check for required scenario types from ATP-NR12
    let has_offline_mailbox = all_scenarios.iter()
        .any(|s| s.scenario_id.contains("offline"));
    let has_swarm_multi_source = all_scenarios.iter()
        .any(|s| s.scenario_id.contains("multi-source"));
    let has_cache_eviction = all_scenarios.iter()
        .any(|s| s.scenario_id.contains("eviction"));
    let has_peer_churn = all_scenarios.iter()
        .any(|s| matches!(s.scenario_type, ScenarioType::PeerChurn));
    let has_malicious_peers = all_scenarios.iter()
        .any(|s| s.peers.iter().any(|p| matches!(p.role, PeerRole::Malicious)));

    assert!(has_offline_mailbox, "Should have offline mailbox scenarios");
    assert!(has_swarm_multi_source, "Should have multi-source swarm scenarios");
    assert!(has_cache_eviction, "Should have cache eviction scenarios");
    assert!(has_peer_churn, "Should have peer churn scenarios");
    assert!(has_malicious_peers, "Should have malicious peer scenarios");

    // Check for encryption requirements
    let encrypted_count = all_scenarios.iter()
        .filter(|s| s.transfer.encrypted)
        .count();
    assert!(encrypted_count > 0, "Should have encrypted transfer scenarios");

    // Check for verification requirements
    let verification_count = all_scenarios.iter()
        .filter(|s| s.transfer.verification.crypto_verification &&
                    s.transfer.verification.manifest_verification)
        .count();
    assert!(verification_count > 0, "Should have verification scenarios");

    println!("✅ Verified framework covers ATP-NR12 requirements:");
    println!("   - {} total scenarios", all_scenarios.len());
    println!("   - Offline mailbox: {}", has_offline_mailbox);
    println!("   - Multi-source swarm: {}", has_swarm_multi_source);
    println!("   - Cache eviction: {}", has_cache_eviction);
    println!("   - Peer churn: {}", has_peer_churn);
    println!("   - Malicious peers: {}", has_malicious_peers);
    println!("   - {} encrypted scenarios", encrypted_count);
    println!("   - {} verification scenarios", verification_count);
}