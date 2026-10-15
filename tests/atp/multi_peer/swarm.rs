//! Swarm scenario test definitions
//!
//! Tests for multi-source swarm transfer scenarios as specified in ATP-NR12.

use crate::atp::multi_peer::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

/// Create swarm scenarios for testing multi-source transfers
pub struct SwarmScenarios;

/// Deterministic source-state row used by the swarm piece-picker contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmPieceSource {
    /// Stable peer identifier.
    pub peer_id: String,
    /// Chunks this peer can provide.
    pub chunks: Vec<String>,
    /// Whether this peer's advertised content has passed trust admission.
    pub verified_source: bool,
    /// Trust score after policy, identity, and prior verification evidence.
    pub trust_score: u8,
    /// Path-quality score; larger values are better.
    pub path_quality_score: u8,
    /// Remaining upload budget in bytes.
    pub upload_budget_remaining: u64,
    /// Expected decode usefulness for this peer's chunks.
    pub decode_usefulness_score: u8,
}

impl SwarmPieceSource {
    /// Construct a deterministic piece-source row for tests and fixtures.
    pub fn new(
        peer_id: impl Into<String>,
        chunks: impl IntoIterator<Item = impl Into<String>>,
        trust_score: u8,
        path_quality_score: u8,
        upload_budget_remaining: u64,
        decode_usefulness_score: u8,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            chunks: chunks.into_iter().map(Into::into).collect(),
            verified_source: true,
            trust_score,
            path_quality_score,
            upload_budget_remaining,
            decode_usefulness_score,
        }
    }

    /// Mark the source as failed trust admission.
    pub fn unverified(mut self) -> Self {
        self.verified_source = false;
        self
    }
}

/// Choose the next swarm piece without duplicating in-flight work unless hedging is allowed.
pub fn choose_next_swarm_piece(
    sources: &[SwarmPieceSource],
    completed_chunks: &[&str],
    in_flight_chunks: &[&str],
    allow_hedging: bool,
) -> Option<SourceSelection> {
    let completed: BTreeSet<_> = completed_chunks.iter().copied().collect();
    let in_flight: BTreeSet<_> = in_flight_chunks.iter().copied().collect();
    let mut available: BTreeMap<String, Vec<&SwarmPieceSource>> = BTreeMap::new();

    for source in sources {
        if !source.verified_source || source.trust_score == 0 || source.upload_budget_remaining == 0
        {
            continue;
        }

        for chunk in &source.chunks {
            if completed.contains(chunk.as_str()) {
                continue;
            }

            if in_flight.contains(chunk.as_str()) && !allow_hedging {
                continue;
            }

            available.entry(chunk.clone()).or_default().push(source);
        }
    }

    let (chunk_id, candidates) =
        available
            .iter()
            .min_by(|(left_chunk, left_sources), (right_chunk, right_sources)| {
                let left_usefulness = max_decode_usefulness(left_sources);
                let right_usefulness = max_decode_usefulness(right_sources);

                left_sources
                    .len()
                    .cmp(&right_sources.len())
                    .then_with(|| right_usefulness.cmp(&left_usefulness))
                    .then_with(|| left_chunk.cmp(right_chunk))
            })?;

    let selected = candidates.iter().copied().max_by(compare_piece_sources)?;
    let mut rejected_peers = HashMap::new();

    for source in sources {
        if source.peer_id == selected.peer_id
            || !source.chunks.iter().any(|chunk| chunk == chunk_id)
        {
            continue;
        }

        let reason = if !source.verified_source || source.trust_score == 0 {
            "trust_admission_failed"
        } else if source.upload_budget_remaining == 0 {
            "upload_budget_exhausted"
        } else if in_flight.contains(chunk_id.as_str()) && !allow_hedging {
            "duplicate_in_flight_suppressed"
        } else {
            "lower_piece_picker_score"
        };
        rejected_peers.insert(source.peer_id.clone(), reason.to_string());
    }

    Some(SourceSelection {
        chunk_id: chunk_id.clone(),
        selected_peer: selected.peer_id.clone(),
        reason: format!(
            "rarity={};decode_usefulness={};path_quality={};trust={}",
            candidates.len(),
            selected.decode_usefulness_score,
            selected.path_quality_score,
            selected.trust_score
        ),
        rejected_peers,
    })
}

fn max_decode_usefulness(sources: &[&SwarmPieceSource]) -> u8 {
    sources
        .iter()
        .map(|source| source.decode_usefulness_score)
        .max()
        .unwrap_or(0)
}

fn compare_piece_sources(
    left: &&SwarmPieceSource,
    right: &&SwarmPieceSource,
) -> std::cmp::Ordering {
    left.trust_score
        .cmp(&right.trust_score)
        .then_with(|| left.path_quality_score.cmp(&right.path_quality_score))
        .then_with(|| {
            left.upload_budget_remaining
                .cmp(&right.upload_budget_remaining)
        })
        .then_with(|| {
            left.decode_usefulness_score
                .cmp(&right.decode_usefulness_score)
        })
        .then_with(|| right.peer_id.cmp(&left.peer_id))
}

impl SwarmScenarios {
    /// Basic multi-source verified transfer from multiple seeds
    pub fn multi_source_verified_transfer() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "swarm-multi-source-verified".to_string(),
            description:
                "Receiver downloads from multiple seed peers, verifies all chunks against manifest."
                    .to_string(),
            scenario_type: ScenarioType::Swarm,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(50 * 1024 * 1024),  // 50MB
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
                        storage_quota: Some(20 * 1024 * 1024), // 20MB
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
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed3".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
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
                    (("receiver".to_string(), "seed2".to_string()), 35),
                    (("receiver".to_string(), "seed3".to_string()), 50),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: [
                    (("receiver".to_string(), "seed1".to_string()), 0.001),
                    (("receiver".to_string(), "seed2".to_string()), 0.005),
                    (("receiver".to_string(), "seed3".to_string()), 0.002),
                ]
                .iter()
                .cloned()
                .collect(),
                bandwidth: [
                    (
                        ("receiver".to_string(), "seed1".to_string()),
                        2 * 1024 * 1024,
                    ),
                    (("receiver".to_string(), "seed2".to_string()), 1024 * 1024),
                    (("receiver".to_string(), "seed3".to_string()), 1024 * 1024),
                ]
                .iter()
                .cloned()
                .collect(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(10 * 1024 * 1024), // 10MB transfer
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 20,
                    n: 30,
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
                bytes_transferred: Some(10 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![
                    LogEventExpectation {
                        event_type: "swarm_piece_selection".to_string(),
                        required_fields: vec![
                            "selected_peer".to_string(),
                            "rarity_score".to_string(),
                            "usefulness_score".to_string(),
                        ],
                        count: None, // Multiple selections expected
                    },
                    LogEventExpectation {
                        event_type: "chunk_verification_success".to_string(),
                        required_fields: vec!["chunk_hash".to_string(), "source_peer".to_string()],
                        count: None,
                    },
                ],
            },
            timeout: Duration::from_secs(600),
        }
    }

    /// Swarm with rarest-first piece selection algorithm
    pub fn rarest_first_selection() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "swarm-rarest-first-selection".to_string(),
            description:
                "Test rarest-first piece picker with uneven chunk distribution among seeds."
                    .to_string(),
            scenario_type: ScenarioType::Swarm,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(30 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-common".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(512 * 1024), // Slower seed
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-rare".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024), // Smaller cache = rarer pieces
                        bandwidth_limit: Some(256 * 1024),     // Even slower
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-fast".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(15 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024), // Fast but partial
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("receiver".to_string(), "seed-common".to_string()), 30),
                    (("receiver".to_string(), "seed-rare".to_string()), 100), // Higher latency for rare peer
                    (("receiver".to_string(), "seed-fast".to_string()), 15),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(8 * 1024 * 1024), // 8MB
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 16,
                    n: 24,
                    threshold: 0.8,
                }),
                chunk_size: 64 * 1024, // 64KB chunks
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
                bytes_transferred: Some(8 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![LogEventExpectation {
                    event_type: "piece_picker_rarity_decision".to_string(),
                    required_fields: vec![
                        "chunk_id".to_string(),
                        "rarity_score".to_string(),
                        "available_sources".to_string(),
                    ],
                    count: None,
                }],
            },
            timeout: Duration::from_secs(600),
        }
    }

    /// Peer churn scenario with seeds going offline/online
    pub fn peer_churn() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "swarm-peer-churn".to_string(),
            description:
                "Seeds go offline and come back online during transfer, testing adaptation."
                    .to_string(),
            scenario_type: ScenarioType::PeerChurn,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(40 * 1024 * 1024),
                        bandwidth_limit: Some(3 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-stable".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![], // Always online
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-flaky".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(60), false),  // Goes offline
                            (Duration::from_secs(120), true),  // Comes back
                            (Duration::from_secs(180), false), // Goes offline again
                            (Duration::from_secs(240), true),  // Comes back again
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(15 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024), // Fast when available
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-late".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: false,
                        schedule: vec![
                            (Duration::from_secs(90), true), // Joins later
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(25 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("receiver".to_string(), "seed-stable".to_string()), 25),
                    (("receiver".to_string(), "seed-flaky".to_string()), 40),
                    (("receiver".to_string(), "seed-late".to_string()), 30),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(12 * 1024 * 1024), // 12MB
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 24,
                    n: 36,
                    threshold: 0.7,
                }),
                chunk_size: 96 * 1024, // 96KB chunks
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: Some(Duration::from_secs(500)),
                bytes_transferred: Some(12 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![
                    LogEventExpectation {
                        event_type: "peer_disconnect".to_string(),
                        required_fields: vec!["peer_id".to_string()],
                        count: None,
                    },
                    LogEventExpectation {
                        event_type: "peer_connect".to_string(),
                        required_fields: vec!["peer_id".to_string()],
                        count: None,
                    },
                    LogEventExpectation {
                        event_type: "swarm_adaptation".to_string(),
                        required_fields: vec![
                            "available_sources".to_string(),
                            "transfer_strategy".to_string(),
                        ],
                        count: None,
                    },
                ],
            },
            timeout: Duration::from_secs(700),
        }
    }

    /// Malicious peers providing bad chunks
    pub fn malicious_peers_bad_chunks() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "swarm-malicious-bad-chunks".to_string(),
            description: "Malicious peers provide chunks with incorrect hashes. Receiver should detect and reject.".to_string(),
            scenario_type: ScenarioType::Adversarial,
            peers: vec![
                PeerConfig {
                    peer_id: "receiver".to_string(),
                    role: PeerRole::Receiver,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(30 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-honest1".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "seed-honest2".to_string(),
                    role: PeerRole::Seed,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: true,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "malicious1".to_string(),
                    role: PeerRole::Malicious,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024), // Fast to attract selection
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "malicious2".to_string(),
                    role: PeerRole::Malicious,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024),
                        bandwidth_limit: Some(3 * 1024 * 1024), // Even faster
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("receiver".to_string(), "seed-honest1".to_string()), 30),
                    (("receiver".to_string(), "seed-honest2".to_string()), 35),
                    (("receiver".to_string(), "malicious1".to_string()), 10), // Low latency to attract
                    (("receiver".to_string(), "malicious2".to_string()), 15),
                ].iter().cloned().collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(6 * 1024 * 1024), // 6MB
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
                success: true, // Should succeed with honest peers
                completion_time: Some(Duration::from_secs(400)),
                bytes_transferred: Some(6 * 1024 * 1024),
                peer_rejections: Some(2), // Both malicious peers should be rejected
                cache_metrics: None,
                log_events: vec![
                    LogEventExpectation {
                        event_type: "chunk_verification_failure".to_string(),
                        required_fields: vec![
                            "chunk_hash_expected".to_string(),
                            "chunk_hash_received".to_string(),
                            "source_peer".to_string(),
                        ],
                        count: None, // Multiple failures expected from malicious peers
                    },
                    LogEventExpectation {
                        event_type: "peer_rejection".to_string(),
                        required_fields: vec![
                            "peer_id".to_string(),
                            "rejection_reason".to_string(),
                        ],
                        count: Some(2), // Both malicious peers
                    },
                ],
            },
            timeout: Duration::from_secs(600),
        }
    }

    /// Get all predefined swarm scenarios
    pub fn all_scenarios() -> Vec<MultiPeerScenario> {
        vec![
            Self::multi_source_verified_transfer(),
            Self::rarest_first_selection(),
            Self::peer_churn(),
            Self::malicious_peers_bad_chunks(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::multi_peer::contracts::{
        AdversarialContract, MultiPeerContract, SwarmContract,
    };

    #[test]
    fn test_multi_source_scenario_validation() {
        let scenario = SwarmScenarios::multi_source_verified_transfer();
        let contract = SwarmContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert_eq!(scenario.scenario_id, "swarm-multi-source-verified");

        let seed_count = scenario
            .peers
            .iter()
            .filter(|p| matches!(p.role, PeerRole::Seed))
            .count();
        assert!(seed_count >= 2, "Should have multiple seeds");
    }

    #[test]
    fn test_rarest_first_scenario() {
        let scenario = SwarmScenarios::rarest_first_selection();

        // Should have different bandwidth limits to create rarity differences
        let seed_bandwidths: Vec<_> = scenario
            .peers
            .iter()
            .filter(|p| matches!(p.role, PeerRole::Seed))
            .map(|p| p.capabilities.bandwidth_limit)
            .collect();

        assert!(seed_bandwidths.len() >= 2, "Should have multiple seeds");

        // Should have variation in capabilities
        let min_bandwidth = seed_bandwidths.iter().min().unwrap();
        let max_bandwidth = seed_bandwidths.iter().max().unwrap();
        assert!(
            max_bandwidth > min_bandwidth,
            "Should have bandwidth variation"
        );
    }

    #[test]
    fn test_peer_churn_scenario() {
        let scenario = SwarmScenarios::peer_churn();

        assert!(matches!(scenario.scenario_type, ScenarioType::PeerChurn));

        // Check for peers with availability changes
        let has_churn = scenario
            .peers
            .iter()
            .any(|p| !p.availability.schedule.is_empty());
        assert!(
            has_churn,
            "Peer churn scenario should have availability changes"
        );

        // Should have stable peer
        let has_stable = scenario
            .peers
            .iter()
            .any(|p| p.availability.initially_online && p.availability.schedule.is_empty());
        assert!(has_stable, "Should have at least one stable peer");
    }

    #[test]
    fn test_malicious_peers_scenario() {
        let scenario = SwarmScenarios::malicious_peers_bad_chunks();
        let contract = AdversarialContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert!(matches!(scenario.scenario_type, ScenarioType::Adversarial));

        let malicious_count = scenario
            .peers
            .iter()
            .filter(|p| matches!(p.role, PeerRole::Malicious))
            .count();
        assert!(malicious_count >= 1, "Should have malicious peers");

        let honest_count = scenario
            .peers
            .iter()
            .filter(|p| !matches!(p.role, PeerRole::Malicious))
            .count();
        assert!(honest_count >= 2, "Should have honest peers");

        assert!(
            scenario.expectations.peer_rejections.unwrap_or(0) > 0,
            "Should expect peer rejections"
        );
    }

    #[test]
    fn piece_picker_prefers_rarest_verified_chunk() {
        let sources = vec![
            SwarmPieceSource::new("seed-a", ["chunk-common", "chunk-rare"], 90, 70, 16_384, 80),
            SwarmPieceSource::new("seed-b", ["chunk-common"], 95, 90, 16_384, 70),
            SwarmPieceSource::new("seed-c", ["chunk-common"], 80, 60, 16_384, 60),
        ];

        let decision = choose_next_swarm_piece(&sources, &[], &[], false)
            .expect("piece picker should choose a chunk");

        assert_eq!(decision.chunk_id, "chunk-rare");
        assert_eq!(decision.selected_peer, "seed-a");
        assert!(
            decision.reason.contains("rarity=1"),
            "decision should preserve rarity evidence: {}",
            decision.reason
        );
    }

    #[test]
    fn piece_picker_suppresses_duplicate_inflight_work_without_hedge() {
        let sources = vec![
            SwarmPieceSource::new("seed-a", ["chunk-inflight"], 90, 70, 16_384, 80),
            SwarmPieceSource::new("seed-b", ["chunk-next"], 80, 90, 16_384, 70),
        ];

        let decision = choose_next_swarm_piece(&sources, &[], &["chunk-inflight"], false)
            .expect("piece picker should choose non-duplicate work");

        assert_eq!(decision.chunk_id, "chunk-next");
        assert_eq!(decision.selected_peer, "seed-b");
    }

    #[test]
    fn piece_picker_allows_explicit_hedge_for_inflight_work() {
        let sources = vec![
            SwarmPieceSource::new("seed-a", ["chunk-inflight"], 90, 70, 16_384, 80),
            SwarmPieceSource::new("seed-b", ["chunk-inflight"], 95, 90, 16_384, 70),
        ];

        let decision = choose_next_swarm_piece(&sources, &[], &["chunk-inflight"], true)
            .expect("explicit hedge should admit in-flight chunk");

        assert_eq!(decision.chunk_id, "chunk-inflight");
        assert_eq!(decision.selected_peer, "seed-b");
        assert_eq!(
            decision.rejected_peers.get("seed-a").map(String::as_str),
            Some("lower_piece_picker_score")
        );
    }

    #[test]
    fn piece_picker_rejects_untrusted_and_budget_exhausted_peers() {
        let sources = vec![
            SwarmPieceSource::new("seed-untrusted", ["chunk-a"], 90, 90, 16_384, 90).unverified(),
            SwarmPieceSource::new("seed-empty-budget", ["chunk-a"], 90, 90, 0, 90),
            SwarmPieceSource::new("seed-good", ["chunk-a"], 80, 80, 16_384, 80),
        ];

        let decision = choose_next_swarm_piece(&sources, &[], &[], false)
            .expect("trusted source should remain selectable");

        assert_eq!(decision.selected_peer, "seed-good");
        assert_eq!(
            decision
                .rejected_peers
                .get("seed-untrusted")
                .map(String::as_str),
            Some("trust_admission_failed")
        );
        assert_eq!(
            decision
                .rejected_peers
                .get("seed-empty-budget")
                .map(String::as_str),
            Some("upload_budget_exhausted")
        );
    }

    #[test]
    fn test_all_scenarios_validate() {
        let scenarios = SwarmScenarios::all_scenarios();
        assert!(!scenarios.is_empty());

        for scenario in &scenarios {
            assert!(
                scenario.validate().is_ok(),
                "Scenario {} should be valid",
                scenario.scenario_id
            );
        }
    }
}
