//! Cache scenario test definitions
//!
//! Tests for relay cache and local cache scenarios as specified in ATP-NR12.

use crate::atp::multi_peer::*;
use std::time::Duration;

/// Create cache scenarios for testing relay and local cache behavior
pub struct CacheScenarios;

impl CacheScenarios {
    /// Relay cache handoff scenario - data cached at relay for later retrieval
    pub fn relay_cache_handoff() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "cache-relay-handoff".to_string(),
            description: "Sender uploads to relay cache. Receiver downloads from cache later."
                .to_string(),
            scenario_type: ScenarioType::Cache,
            peers: vec![
                PeerConfig {
                    peer_id: "sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(90), false), // Goes offline after caching
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024), // 10MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: false,
                        schedule: vec![
                            (Duration::from_secs(120), true), // Comes online after sender is offline
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(15 * 1024 * 1024),  // 15MB
                        bandwidth_limit: Some(2 * 1024 * 1024), // 2MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "relay-cache".to_string(),
                    role: PeerRole::Relay,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![], // Always online
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(100 * 1024 * 1024), // 100MB cache
                        bandwidth_limit: Some(5 * 1024 * 1024), // 5MB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("sender".to_string(), "relay-cache".to_string()), 25),
                    (("receiver".to_string(), "relay-cache".to_string()), 30),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: [
                    (("sender".to_string(), "relay-cache".to_string()), 0.001),
                    (("receiver".to_string(), "relay-cache".to_string()), 0.002),
                ]
                .iter()
                .cloned()
                .collect(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(8 * 1024 * 1024), // 8MB transfer
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 16,
                    n: 24,
                    threshold: 0.75,
                }),
                chunk_size: 128 * 1024, // 128KB chunks
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: Some(Duration::from_secs(300)),
                bytes_transferred: Some(8 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: Some(CacheMetrics {
                    hits: Some(64),     // Expected cache hits (8MB / 128KB = 64 chunks)
                    misses: Some(0),    // Should be all hits from cache
                    evictions: Some(0), // No evictions expected
                }),
                log_events: vec![
                    LogEventExpectation {
                        event_type: "cache_store".to_string(),
                        required_fields: vec![
                            "chunk_hash".to_string(),
                            "cache_key".to_string(),
                            "ttl".to_string(),
                        ],
                        count: None, // Multiple stores expected
                    },
                    LogEventExpectation {
                        event_type: "cache_hit".to_string(),
                        required_fields: vec!["chunk_hash".to_string(), "cache_key".to_string()],
                        count: None,
                    },
                ],
            },
            timeout: Duration::from_secs(400),
        }
    }

    /// Local cache hit/miss scenario
    pub fn local_cache_hit_miss() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "cache-local-hit-miss".to_string(),
            description: "Test local cache behavior with cache hits, misses, and policy decisions."
                .to_string(),
            scenario_type: ScenarioType::Cache,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),  // 20MB
                        bandwidth_limit: Some(2 * 1024 * 1024), // 2MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed1".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(30 * 1024 * 1024), // 30MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed2".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(25 * 1024 * 1024), // 25MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("receiver".to_string(), "seed1".to_string()), 20),
                    (("receiver".to_string(), "seed2".to_string()), 40),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(12 * 1024 * 1024), // 12MB transfer
                encrypted: true,
                repair_config: None,
                chunk_size: 256 * 1024, // 256KB chunks (48 chunks total)
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: Some(Duration::from_secs(250)),
                bytes_transferred: Some(12 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: Some(CacheMetrics {
                    hits: Some(24),     // Expect some hits from repeated chunks
                    misses: Some(24),   // Some misses for new chunks
                    evictions: Some(0), // No evictions with sufficient cache space
                }),
                log_events: vec![
                    LogEventExpectation {
                        event_type: "cache_lookup".to_string(),
                        required_fields: vec!["chunk_hash".to_string(), "cache_result".to_string()],
                        count: None,
                    },
                    LogEventExpectation {
                        event_type: "cache_policy_decision".to_string(),
                        required_fields: vec![
                            "decision_type".to_string(),
                            "cache_key".to_string(),
                            "policy_reason".to_string(),
                        ],
                        count: None,
                    },
                ],
            },
            timeout: Duration::from_secs(400),
        }
    }

    /// Cache quota eviction scenario
    pub fn cache_quota_eviction() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "cache-quota-eviction".to_string(),
            description: "Test cache eviction behavior when quota is exceeded with LRU policy."
                .to_string(),
            scenario_type: ScenarioType::Cache,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(4 * 1024 * 1024), // Small 4MB cache to force eviction
                        bandwidth_limit: Some(1024 * 1024),   // 1MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed1".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024), // 20MB
                        bandwidth_limit: Some(512 * 1024),     // 512KB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "relay-cache".to_string(),
                    role: PeerRole::Relay,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(6 * 1024 * 1024), // Small 6MB cache for relay too
                        bandwidth_limit: Some(2 * 1024 * 1024), // 2MB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("receiver".to_string(), "seed1".to_string()), 50),
                    (("receiver".to_string(), "relay-cache".to_string()), 25),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(10 * 1024 * 1024), // 10MB transfer > cache size
                encrypted: true,
                repair_config: None,
                chunk_size: 128 * 1024, // 128KB chunks (80 chunks total)
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: Some(Duration::from_secs(400)),
                bytes_transferred: Some(10 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: Some(CacheMetrics {
                    hits: Some(0),       // Initial transfer - no hits expected
                    misses: Some(80),    // All chunks miss first time
                    evictions: Some(48), // ~48 evictions to fit in 4MB cache (32 chunks max)
                }),
                log_events: vec![
                    LogEventExpectation {
                        event_type: "cache_eviction".to_string(),
                        required_fields: vec![
                            "evicted_chunk_hash".to_string(),
                            "eviction_reason".to_string(),
                            "cache_utilization".to_string(),
                        ],
                        count: None, // Multiple evictions expected
                    },
                    LogEventExpectation {
                        event_type: "cache_quota_exceeded".to_string(),
                        required_fields: vec![
                            "quota_limit".to_string(),
                            "current_usage".to_string(),
                        ],
                        count: None,
                    },
                ],
            },
            timeout: Duration::from_secs(600),
        }
    }

    /// Seeding mode scenario - peer acts as cache and seed for others
    pub fn seed_mode() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "cache-seed-mode".to_string(),
            description: "Peer in seed mode caches and serves content to other peers efficiently."
                .to_string(),
            scenario_type: ScenarioType::Cache,
            peers: vec![
                PeerConfig {
                    peer_id: "original-sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(60), false), // Goes offline early
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024), // 10MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-cache".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![], // Always online
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(50 * 1024 * 1024),  // 50MB cache
                        bandwidth_limit: Some(3 * 1024 * 1024), // 3MB/s
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "receiver1".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(15 * 1024 * 1024), // 15MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "receiver2".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: false,
                        schedule: vec![
                            (Duration::from_secs(120), true), // Comes online later
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(15 * 1024 * 1024), // 15MB
                        bandwidth_limit: Some(1024 * 1024),    // 1MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (
                        ("original-sender".to_string(), "seed-cache".to_string()),
                        20,
                    ),
                    (("receiver1".to_string(), "seed-cache".to_string()), 15),
                    (("receiver2".to_string(), "seed-cache".to_string()), 25),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(6 * 1024 * 1024), // 6MB transfer
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 12,
                    n: 18,
                    threshold: 0.8,
                }),
                chunk_size: 128 * 1024, // 128KB chunks
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: Some(Duration::from_secs(300)),
                bytes_transferred: Some(6 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: Some(CacheMetrics {
                    hits: Some(48),     // Second receiver should get cache hits
                    misses: Some(48),   // First receiver gets misses
                    evictions: Some(0), // Sufficient cache space
                }),
                log_events: vec![LogEventExpectation {
                    event_type: "seed_cache_serve".to_string(),
                    required_fields: vec![
                        "served_chunk_hash".to_string(),
                        "requesting_peer".to_string(),
                        "cache_efficiency".to_string(),
                    ],
                    count: None,
                }],
            },
            timeout: Duration::from_secs(500),
        }
    }

    /// Get all predefined cache scenarios
    pub fn all_scenarios() -> Vec<MultiPeerScenario> {
        vec![
            Self::relay_cache_handoff(),
            Self::local_cache_hit_miss(),
            Self::cache_quota_eviction(),
            Self::seed_mode(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::multi_peer::contracts::{CacheContract, MultiPeerContract};

    #[test]
    fn test_relay_cache_handoff_validation() {
        let scenario = CacheScenarios::relay_cache_handoff();
        let contract = CacheContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert_eq!(scenario.scenario_id, "cache-relay-handoff");

        // Should have relay peer with cache enabled
        let has_relay_cache = scenario
            .peers
            .iter()
            .any(|p| matches!(p.role, PeerRole::Relay) && p.capabilities.cache_enabled);
        assert!(has_relay_cache, "Should have relay with cache enabled");
    }

    #[test]
    fn test_local_cache_hit_miss_validation() {
        let scenario = CacheScenarios::local_cache_hit_miss();
        let contract = CacheContract;

        assert!(contract.validate_scenario(&scenario).is_ok());

        // Should have cache metrics expectations
        assert!(scenario.expectations.cache_metrics.is_some());

        let cache_metrics = scenario.expectations.cache_metrics.unwrap();
        assert!(cache_metrics.hits.is_some());
        assert!(cache_metrics.misses.is_some());
    }

    #[test]
    fn test_cache_quota_eviction_validation() {
        let scenario = CacheScenarios::cache_quota_eviction();
        let contract = CacheContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert!(scenario.scenario_id.contains("eviction"));

        // Should have peers with storage quotas
        let has_quota = scenario
            .peers
            .iter()
            .any(|p| p.capabilities.storage_quota.is_some());
        assert!(has_quota, "Eviction scenario should have storage quotas");

        // Transfer size should exceed cache size to force eviction
        let min_cache_size = scenario
            .peers
            .iter()
            .filter_map(|p| p.capabilities.storage_quota)
            .min()
            .unwrap_or(0);

        if let SourceSpec::RandomBytes(transfer_size) = scenario.transfer.source {
            assert!(
                transfer_size > min_cache_size,
                "Transfer size should exceed smallest cache to force eviction"
            );
        }
    }

    #[test]
    fn test_shared_cache_rejects_plaintext_without_public_policy() {
        let mut scenario = CacheScenarios::relay_cache_handoff();
        scenario.transfer.encrypted = false;

        let contract = CacheContract;
        let error = contract
            .validate_scenario(&scenario)
            .expect_err("shared relay cache should reject plaintext transfers");

        assert!(
            error.contains("explicit public-data cache policy"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn test_shared_cache_accepts_plaintext_with_explicit_public_policy_marker() {
        let mut scenario = CacheScenarios::relay_cache_handoff();
        scenario.transfer.encrypted = false;
        scenario.expectations.log_events.push(LogEventExpectation {
            event_type: "cache_store".to_string(),
            required_fields: vec!["storage_class".to_string(), "public_policy_id".to_string()],
            count: None,
        });

        let contract = CacheContract;
        contract
            .validate_scenario(&scenario)
            .expect("explicit public policy marker should allow shared plaintext cache");
    }

    #[test]
    fn test_seed_mode_requires_cache_authorization() {
        let mut scenario = CacheScenarios::seed_mode();
        let seed_peer = scenario
            .peers
            .iter_mut()
            .find(|peer| matches!(peer.role, PeerRole::Seed))
            .expect("seed peer");
        seed_peer.capabilities.cache_enabled = false;

        let contract = CacheContract;
        let error = contract
            .validate_scenario(&scenario)
            .expect_err("seeding must require cache authorization");

        assert!(
            error.contains("must have cache enabled"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn test_cache_peer_requires_nonzero_storage_quota() {
        let mut scenario = CacheScenarios::local_cache_hit_miss();
        let receiver = scenario
            .peers
            .iter_mut()
            .find(|peer| matches!(peer.role, PeerRole::Receiver))
            .expect("receiver peer");
        receiver.capabilities.storage_quota = Some(0);

        let contract = CacheContract;
        let error = contract
            .validate_scenario(&scenario)
            .expect_err("cache-enabled peer should require nonzero quota");

        assert!(
            error.contains("nonzero storage quota"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn test_seed_mode_scenario() {
        let scenario = CacheScenarios::seed_mode();

        // Should have seed peer with cache and seeding enabled
        let seed_peer = scenario
            .peers
            .iter()
            .find(|p| matches!(p.role, PeerRole::Seed))
            .expect("Should have seed peer");

        assert!(
            seed_peer.capabilities.cache_enabled,
            "Seed should have cache enabled"
        );
        assert!(
            seed_peer.capabilities.seeding_enabled,
            "Seed should have seeding enabled"
        );

        // Should have multiple receivers
        let receiver_count = scenario
            .peers
            .iter()
            .filter(|p| matches!(p.role, PeerRole::Receiver))
            .count();
        assert!(
            receiver_count >= 2,
            "Seed mode should have multiple receivers"
        );
    }

    #[test]
    fn test_cache_log_events() {
        let scenarios = CacheScenarios::all_scenarios();

        for scenario in &scenarios {
            // All cache scenarios should have cache-related log events
            let has_cache_events = scenario
                .expectations
                .log_events
                .iter()
                .any(|event| event.event_type.contains("cache"));

            assert!(
                has_cache_events,
                "Cache scenario {} should have cache-related log events",
                scenario.scenario_id
            );
        }
    }

    #[test]
    fn test_all_scenarios_validate() {
        let scenarios = CacheScenarios::all_scenarios();
        assert!(!scenarios.is_empty());

        let contract = CacheContract;
        for scenario in &scenarios {
            assert!(
                scenario.validate().is_ok(),
                "Scenario {} should be valid",
                scenario.scenario_id
            );

            assert!(
                contract.validate_scenario(scenario).is_ok(),
                "Scenario {} should pass cache contract validation",
                scenario.scenario_id
            );
        }
    }
}
