//! Combined multi-peer scenario collection and utilities
//!
//! Provides access to all scenario types and utilities for scenario management.

use crate::atp::multi_peer::cache::CacheScenarios;
use crate::atp::multi_peer::mailbox::MailboxScenarios;
use crate::atp::multi_peer::swarm::SwarmScenarios;
use crate::atp::multi_peer::*;

/// Collection of all multi-peer scenarios
pub struct AllScenarios;

impl AllScenarios {
    /// Get all mailbox scenarios
    pub fn mailbox() -> Vec<MultiPeerScenario> {
        MailboxScenarios::all_scenarios()
    }

    /// Get all swarm scenarios
    pub fn swarm() -> Vec<MultiPeerScenario> {
        SwarmScenarios::all_scenarios()
    }

    /// Get all cache scenarios
    pub fn cache() -> Vec<MultiPeerScenario> {
        CacheScenarios::all_scenarios()
    }

    /// Get all scenarios across all types
    pub fn all() -> Vec<MultiPeerScenario> {
        let mut scenarios = Vec::new();
        scenarios.extend(Self::mailbox());
        scenarios.extend(Self::swarm());
        scenarios.extend(Self::cache());
        scenarios
    }

    /// Get scenarios by type
    pub fn by_type(scenario_type: &ScenarioType) -> Vec<MultiPeerScenario> {
        Self::all()
            .into_iter()
            .filter(|s| {
                std::mem::discriminant(&s.scenario_type) == std::mem::discriminant(scenario_type)
            })
            .collect()
    }

    /// Get smoke test scenarios (quick validation subset)
    pub fn smoke_test() -> Vec<MultiPeerScenario> {
        vec![
            MailboxScenarios::receiver_offline_then_online(),
            SwarmScenarios::multi_source_verified_transfer(),
            CacheScenarios::local_cache_hit_miss(),
        ]
    }

    /// Get adversarial scenarios for security testing
    pub fn adversarial() -> Vec<MultiPeerScenario> {
        Self::all()
            .into_iter()
            .filter(|s| matches!(s.scenario_type, ScenarioType::Adversarial))
            .collect()
    }

    /// Get scenarios by expected completion time (for CI selection)
    pub fn by_completion_time(max_duration: Duration) -> Vec<MultiPeerScenario> {
        Self::all()
            .into_iter()
            .filter(|s| s.timeout <= max_duration)
            .collect()
    }

    /// Get scenario by ID
    pub fn by_id(scenario_id: &str) -> Option<MultiPeerScenario> {
        Self::all()
            .into_iter()
            .find(|s| s.scenario_id == scenario_id)
    }

    /// List all scenario IDs
    pub fn list_ids() -> Vec<String> {
        Self::all().into_iter().map(|s| s.scenario_id).collect()
    }
}

/// Scenario filters and utilities
pub struct ScenarioFilters;

impl ScenarioFilters {
    /// Filter scenarios that require specific peer counts
    pub fn min_peer_count(
        scenarios: Vec<MultiPeerScenario>,
        min_peers: usize,
    ) -> Vec<MultiPeerScenario> {
        scenarios
            .into_iter()
            .filter(|s| s.peers.len() >= min_peers)
            .collect()
    }

    /// Filter scenarios by network complexity
    pub fn network_complexity(
        scenarios: Vec<MultiPeerScenario>,
        max_latency_ms: u64,
    ) -> Vec<MultiPeerScenario> {
        scenarios
            .into_iter()
            .filter(|s| {
                s.network
                    .latency_ms
                    .values()
                    .all(|&latency| latency <= max_latency_ms)
            })
            .collect()
    }

    /// Filter scenarios by data size
    pub fn by_data_size(
        scenarios: Vec<MultiPeerScenario>,
        max_size: u64,
    ) -> Vec<MultiPeerScenario> {
        scenarios
            .into_iter()
            .filter(|s| {
                match &s.transfer.source {
                    SourceSpec::RandomBytes(size) => *size <= max_size,
                    SourceSpec::SparseFile { size, .. } => *size <= max_size,
                    _ => true, // Don't filter non-size-based specs
                }
            })
            .collect()
    }

    /// Filter scenarios that don't require unimplemented features
    pub fn implementable_now(scenarios: Vec<MultiPeerScenario>) -> Vec<MultiPeerScenario> {
        // For now, all scenarios require unimplemented ATP features
        // This filter will be updated as features are implemented
        scenarios
            .into_iter()
            .filter(|s| {
                // Currently all multi-peer scenarios depend on unimplemented features
                // This is a placeholder that will be updated as ATP-J* features are implemented
                match s.scenario_type {
                    ScenarioType::Mailbox => false,     // Requires ATP-J1
                    ScenarioType::Swarm => false,       // Requires ATP-J2
                    ScenarioType::Cache => false,       // Requires ATP-J3
                    ScenarioType::PeerChurn => false,   // Requires swarm infrastructure
                    ScenarioType::Adversarial => false, // Requires verification infrastructure
                    ScenarioType::Hybrid(_) => false,   // Requires multiple features
                }
            })
            .collect()
    }

    /// Filter scenarios suitable for CI/automated testing
    pub fn ci_suitable(scenarios: Vec<MultiPeerScenario>) -> Vec<MultiPeerScenario> {
        scenarios
            .into_iter()
            .filter(|s| {
                // Criteria for CI suitability:
                // 1. Reasonable timeout
                // 2. Not too many peers (resource constraints)
                // 3. Not adversarial (may be flaky)
                s.timeout <= Duration::from_secs(300)
                    && s.peers.len() <= 5
                    && !matches!(s.scenario_type, ScenarioType::Adversarial)
            })
            .collect()
    }
}

/// Scenario validation utilities
pub struct ScenarioValidation;

impl ScenarioValidation {
    /// Validate all scenarios in collection
    pub fn validate_all(scenarios: &[MultiPeerScenario]) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for scenario in scenarios {
            if let Err(error) = scenario.validate() {
                errors.push(format!("{}: {}", scenario.scenario_id, error));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check for duplicate scenario IDs
    pub fn check_unique_ids(scenarios: &[MultiPeerScenario]) -> Result<(), Vec<String>> {
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicates = Vec::new();

        for scenario in scenarios {
            if !seen_ids.insert(&scenario.scenario_id) {
                duplicates.push(scenario.scenario_id.clone());
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate scenario naming conventions
    pub fn validate_naming(scenarios: &[MultiPeerScenario]) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for scenario in scenarios {
            // Check ID format: type-description
            if !scenario.scenario_id.contains('-') {
                errors.push(format!(
                    "{}: ID should contain hyphen",
                    scenario.scenario_id
                ));
            }

            // Check ID matches scenario type
            let type_prefix = match scenario.scenario_type {
                ScenarioType::Mailbox => "mailbox",
                ScenarioType::Swarm => "swarm",
                ScenarioType::Cache => "cache",
                ScenarioType::PeerChurn => "swarm", // Peer churn is a swarm variant
                ScenarioType::Adversarial => "",    // Can be any type with malicious behavior
                ScenarioType::Hybrid(_) => "hybrid",
            };

            if !type_prefix.is_empty() && !scenario.scenario_id.starts_with(type_prefix) {
                errors.push(format!(
                    "{}: ID should start with '{}'",
                    scenario.scenario_id, type_prefix
                ));
            }

            // Check description is meaningful
            if scenario.description.len() < 20 {
                errors.push(format!("{}: Description too short", scenario.scenario_id));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Scenario statistics and reporting
pub struct ScenarioStats;

impl ScenarioStats {
    /// Generate statistics about scenario collection
    pub fn generate_stats(scenarios: &[MultiPeerScenario]) -> ScenarioStatistics {
        let total_count = scenarios.len();

        let by_type = scenarios
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, s| {
                let type_name = match s.scenario_type {
                    ScenarioType::Mailbox => "Mailbox",
                    ScenarioType::Swarm => "Swarm",
                    ScenarioType::Cache => "Cache",
                    ScenarioType::PeerChurn => "PeerChurn",
                    ScenarioType::Adversarial => "Adversarial",
                    ScenarioType::Hybrid(_) => "Hybrid",
                };
                *acc.entry(type_name.to_string()).or_insert(0) += 1;
                acc
            });

        let peer_counts: Vec<usize> = scenarios.iter().map(|s| s.peers.len()).collect();
        let avg_peers = if peer_counts.is_empty() {
            0.0
        } else {
            peer_counts.iter().sum::<usize>() as f64 / peer_counts.len() as f64
        };

        let timeouts: Vec<Duration> = scenarios.iter().map(|s| s.timeout).collect();
        let avg_timeout = if timeouts.is_empty() {
            Duration::ZERO
        } else {
            let total_secs: u64 = timeouts.iter().map(|d| d.as_secs()).sum();
            Duration::from_secs(total_secs / timeouts.len() as u64)
        };

        let transfer_sizes: Vec<u64> = scenarios
            .iter()
            .filter_map(|s| match &s.transfer.source {
                SourceSpec::RandomBytes(size) => Some(*size),
                SourceSpec::SparseFile { size, .. } => Some(*size),
                _ => None,
            })
            .collect();

        let avg_transfer_size = if transfer_sizes.is_empty() {
            0
        } else {
            transfer_sizes.iter().sum::<u64>() / transfer_sizes.len() as u64
        };

        let adversarial_count = scenarios
            .iter()
            .filter(|s| matches!(s.scenario_type, ScenarioType::Adversarial))
            .count();

        let encrypted_count = scenarios.iter().filter(|s| s.transfer.encrypted).count();

        ScenarioStatistics {
            total_count,
            by_type,
            avg_peers,
            avg_timeout,
            avg_transfer_size,
            adversarial_count,
            encrypted_count,
        }
    }

    /// Generate coverage report
    pub fn coverage_report(scenarios: &[MultiPeerScenario]) -> CoverageReport {
        let mut covered_features = std::collections::HashSet::new();
        let mut missing_features = std::collections::HashSet::new();

        // Define features that should be covered
        let all_features = vec![
            "mailbox_upload",
            "mailbox_download",
            "mailbox_offline_sender",
            "mailbox_offline_receiver",
            "swarm_multi_source",
            "swarm_verification",
            "swarm_rarest_first",
            "swarm_peer_churn",
            "cache_hit",
            "cache_miss",
            "cache_eviction",
            "cache_quota",
            "cache_relay",
            "adversarial_malicious_peers",
            "adversarial_tampered_chunks",
            "peer_rejection",
            "encrypted_transfer",
            "repair_coding",
            "verification_failure",
            "network_partitions",
        ];

        // Check which features are covered by scenarios
        for scenario in scenarios {
            match scenario.scenario_type {
                ScenarioType::Mailbox => {
                    covered_features.insert("mailbox_upload");
                    covered_features.insert("mailbox_download");
                    if scenario
                        .peers
                        .iter()
                        .any(|p| !p.availability.initially_online)
                    {
                        covered_features.insert("mailbox_offline_receiver");
                    }
                    if scenario
                        .peers
                        .iter()
                        .any(|p| !p.availability.schedule.is_empty())
                    {
                        covered_features.insert("mailbox_offline_sender");
                    }
                }
                ScenarioType::Swarm => {
                    covered_features.insert("swarm_multi_source");
                    covered_features.insert("swarm_verification");
                    if scenario.scenario_id.contains("rarest") {
                        covered_features.insert("swarm_rarest_first");
                    }
                }
                ScenarioType::PeerChurn => {
                    covered_features.insert("swarm_peer_churn");
                }
                ScenarioType::Cache => {
                    covered_features.insert("cache_hit");
                    covered_features.insert("cache_miss");
                    if scenario.scenario_id.contains("eviction") {
                        covered_features.insert("cache_eviction");
                        covered_features.insert("cache_quota");
                    }
                    if scenario
                        .peers
                        .iter()
                        .any(|p| matches!(p.role, PeerRole::Relay))
                    {
                        covered_features.insert("cache_relay");
                    }
                }
                ScenarioType::Adversarial => {
                    covered_features.insert("adversarial_malicious_peers");
                    if scenario.scenario_id.contains("tampered") {
                        covered_features.insert("adversarial_tampered_chunks");
                    }
                    if scenario.expectations.peer_rejections.unwrap_or(0) > 0 {
                        covered_features.insert("peer_rejection");
                    }
                }
                _ => {}
            }

            if scenario.transfer.encrypted {
                covered_features.insert("encrypted_transfer");
            }

            if scenario.transfer.repair_config.is_some() {
                covered_features.insert("repair_coding");
            }

            if !scenario.network.partitions.is_empty() {
                covered_features.insert("network_partitions");
            }
        }

        // Find missing features
        for feature in &all_features {
            if !covered_features.contains(*feature) {
                missing_features.insert(feature.to_string());
            }
        }

        let coverage_percentage =
            (covered_features.len() as f64 / all_features.len() as f64) * 100.0;

        CoverageReport {
            total_features: all_features.len(),
            covered_features: covered_features.len(),
            coverage_percentage,
            missing_features: missing_features.into_iter().collect(),
        }
    }
}

/// Statistics about scenario collection
#[derive(Debug)]
pub struct ScenarioStatistics {
    pub total_count: usize,
    pub by_type: std::collections::HashMap<String, usize>,
    pub avg_peers: f64,
    pub avg_timeout: Duration,
    pub avg_transfer_size: u64,
    pub adversarial_count: usize,
    pub encrypted_count: usize,
}

/// Coverage report for scenario features
#[derive(Debug)]
pub struct CoverageReport {
    pub total_features: usize,
    pub covered_features: usize,
    pub coverage_percentage: f64,
    pub missing_features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_scenarios_collection() {
        let scenarios = AllScenarios::all();
        assert!(!scenarios.is_empty(), "Should have scenarios");

        // Should have scenarios from each type
        let has_mailbox = scenarios
            .iter()
            .any(|s| matches!(s.scenario_type, ScenarioType::Mailbox));
        let has_swarm = scenarios
            .iter()
            .any(|s| matches!(s.scenario_type, ScenarioType::Swarm));
        let has_cache = scenarios
            .iter()
            .any(|s| matches!(s.scenario_type, ScenarioType::Cache));

        assert!(has_mailbox, "Should have mailbox scenarios");
        assert!(has_swarm, "Should have swarm scenarios");
        assert!(has_cache, "Should have cache scenarios");
    }

    #[test]
    fn test_scenario_filtering() {
        let all_scenarios = AllScenarios::all();
        assert!(
            !all_scenarios.is_empty(),
            "Should have scenarios before filtering"
        );

        // Test by type filtering
        let mailbox_scenarios = AllScenarios::by_type(&ScenarioType::Mailbox);
        assert!(
            !mailbox_scenarios.is_empty(),
            "Should have mailbox scenarios"
        );

        // Test completion time filtering
        let quick_scenarios = AllScenarios::by_completion_time(Duration::from_secs(300));
        assert!(!quick_scenarios.is_empty(), "Should have quick scenarios");

        // Test smoke test selection
        let smoke_scenarios = AllScenarios::smoke_test();
        assert_eq!(
            smoke_scenarios.len(),
            3,
            "Should have 3 smoke test scenarios"
        );
    }

    #[test]
    fn test_scenario_validation() {
        let scenarios = AllScenarios::all();

        // Test validation
        assert!(
            ScenarioValidation::validate_all(&scenarios).is_ok(),
            "All scenarios should be valid"
        );

        // Test unique IDs
        assert!(
            ScenarioValidation::check_unique_ids(&scenarios).is_ok(),
            "All scenario IDs should be unique"
        );

        // Test naming conventions
        assert!(
            ScenarioValidation::validate_naming(&scenarios).is_ok(),
            "All scenarios should follow naming conventions"
        );
    }

    #[test]
    fn test_scenario_filters() {
        let scenarios = AllScenarios::all();

        // Test peer count filter
        let multi_peer_scenarios = ScenarioFilters::min_peer_count(scenarios.clone(), 3);
        for scenario in &multi_peer_scenarios {
            assert!(scenario.peers.len() >= 3, "Should have at least 3 peers");
        }

        // Test data size filter
        let small_scenarios = ScenarioFilters::by_data_size(scenarios.clone(), 5 * 1024 * 1024); // 5MB
        for scenario in &small_scenarios {
            if let SourceSpec::RandomBytes(size) = scenario.transfer.source {
                assert!(size <= 5 * 1024 * 1024, "Should be <= 5MB");
            }
        }

        // Test CI suitability
        let ci_scenarios = ScenarioFilters::ci_suitable(scenarios);
        for scenario in &ci_scenarios {
            assert!(
                scenario.timeout <= Duration::from_secs(300),
                "Should have reasonable timeout"
            );
            assert!(scenario.peers.len() <= 5, "Should not have too many peers");
            assert!(
                !matches!(scenario.scenario_type, ScenarioType::Adversarial),
                "Should not include adversarial scenarios"
            );
        }
    }

    #[test]
    fn test_scenario_stats() {
        let scenarios = AllScenarios::all();
        let stats = ScenarioStats::generate_stats(&scenarios);

        assert!(stats.total_count > 0, "Should have scenarios");
        assert!(stats.avg_peers > 0.0, "Should have average peer count");
        assert!(!stats.by_type.is_empty(), "Should have type breakdown");

        // Test coverage report
        let coverage = ScenarioStats::coverage_report(&scenarios);
        assert!(coverage.total_features > 0, "Should have features to cover");
        assert!(
            coverage.coverage_percentage >= 0.0 && coverage.coverage_percentage <= 100.0,
            "Coverage should be valid percentage"
        );
    }

    #[test]
    fn test_scenario_by_id_lookup() {
        let scenarios = AllScenarios::all();
        let ids = AllScenarios::list_ids();

        assert!(!ids.is_empty(), "Should have scenario IDs");
        assert_eq!(
            scenarios.len(),
            ids.len(),
            "ID list should include every scenario"
        );

        // Test lookup by ID
        for id in &ids {
            let scenario = AllScenarios::by_id(id);
            assert!(scenario.is_some(), "Should find scenario by ID: {}", id);
            assert_eq!(
                scenario.unwrap().scenario_id,
                *id,
                "Should return correct scenario"
            );
        }

        // Test non-existent ID
        assert!(
            AllScenarios::by_id("non-existent").is_none(),
            "Should not find non-existent scenario"
        );
    }
}
