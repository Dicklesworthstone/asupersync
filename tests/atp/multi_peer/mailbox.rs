//! Mailbox scenario test definitions
//!
//! Tests for offline mailbox upload/download scenarios as specified in ATP-NR12.

use crate::atp::multi_peer::*;
use std::time::Duration;

/// Create mailbox scenarios for testing offline upload/download
pub struct MailboxScenarios;

impl MailboxScenarios {
    /// Sender uploads to mailbox, then goes offline. Receiver comes online later to download.
    pub fn sender_offline_after_upload() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "mailbox-sender-offline-after-upload".to_string(),
            description: "Sender uploads encrypted transfer to mailbox, then goes offline. Receiver downloads later.".to_string(),
            scenario_type: ScenarioType::Mailbox,
            peers: vec![
                PeerConfig {
                    peer_id: "sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(60), false), // Goes offline after upload
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
                        initially_online: false, // Starts offline
                        schedule: vec![
                            (Duration::from_secs(120), true), // Comes online after sender is offline
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
                    peer_id: "mailbox-relay".to_string(),
                    role: PeerRole::Mailbox,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![], // Always online
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(100 * 1024 * 1024), // 100MB mailbox quota
                        bandwidth_limit: Some(10 * 1024 * 1024), // 10MB/s
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 50),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 75),
                ].iter().cloned().collect(),
                packet_loss: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 0.001),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 0.001),
                ].iter().cloned().collect(),
                bandwidth: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 2 * 1024 * 1024),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 2 * 1024 * 1024),
                ].iter().cloned().collect(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(5 * 1024 * 1024), // 5MB transfer
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 16,
                    n: 20,
                    threshold: 0.8,
                }),
                chunk_size: 256 * 1024, // 256KB chunks
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
                bytes_transferred: Some(5 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![
                    LogEventExpectation {
                        event_type: "mailbox_upload_complete".to_string(),
                        required_fields: vec![
                            "mailbox_id".to_string(),
                            "encrypted_manifest_hash".to_string(),
                            "chunk_count".to_string(),
                        ],
                        count: Some(1),
                    },
                    LogEventExpectation {
                        event_type: "mailbox_download_start".to_string(),
                        required_fields: vec![
                            "mailbox_id".to_string(),
                            "receiver_peer_id".to_string(),
                        ],
                        count: Some(1),
                    },
                ],
            },
            timeout: Duration::from_secs(600), // 10 minutes
        }
    }

    /// Receiver is offline initially, sender uploads to mailbox, receiver comes online later
    pub fn receiver_offline_then_online() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "mailbox-receiver-offline-then-online".to_string(),
            description: "Receiver starts offline. Sender uploads to mailbox. Receiver comes online later to download.".to_string(),
            scenario_type: ScenarioType::Mailbox,
            peers: vec![
                PeerConfig {
                    peer_id: "sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![], // Stays online
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
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
                            (Duration::from_secs(180), true), // Comes online after upload
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(10 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "mailbox-relay".to_string(),
                    role: PeerRole::Mailbox,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(50 * 1024 * 1024),
                        bandwidth_limit: Some(5 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 25),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 40),
                ].iter().cloned().collect(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(2 * 1024 * 1024), // 2MB
                encrypted: true,
                repair_config: None, // No repair for this test
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
                completion_time: Some(Duration::from_secs(240)),
                bytes_transferred: Some(2 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![
                    LogEventExpectation {
                        event_type: "mailbox_storage".to_string(),
                        required_fields: vec!["encrypted_chunks".to_string()],
                        count: None, // Variable based on chunk count
                    },
                ],
            },
            timeout: Duration::from_secs(300),
        }
    }

    /// Mailbox relay restarts during transfer
    pub fn relay_restart() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "mailbox-relay-restart".to_string(),
            description:
                "Mailbox relay restarts during transfer, testing persistence and recovery."
                    .to_string(),
            scenario_type: ScenarioType::Mailbox,
            peers: vec![
                PeerConfig {
                    peer_id: "sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(5 * 1024 * 1024),
                        bandwidth_limit: Some(512 * 1024),
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
                            (Duration::from_secs(150), true), // Comes online after relay restart
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(5 * 1024 * 1024),
                        bandwidth_limit: Some(512 * 1024),
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "mailbox-relay".to_string(),
                    role: PeerRole::Mailbox,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(60), false), // Restart: goes offline
                            (Duration::from_secs(90), true),  // Comes back online
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 30),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 35),
                ]
                .iter()
                .cloned()
                .collect(),
                packet_loss: [
                    (("sender".to_string(), "mailbox-relay".to_string()), 0.002),
                    (("receiver".to_string(), "mailbox-relay".to_string()), 0.002),
                ]
                .iter()
                .cloned()
                .collect(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(3 * 1024 * 1024), // 3MB
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 8,
                    n: 12,
                    threshold: 0.75,
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
                completion_time: Some(Duration::from_secs(300)),
                bytes_transferred: Some(3 * 1024 * 1024),
                peer_rejections: Some(0),
                cache_metrics: None,
                log_events: vec![LogEventExpectation {
                    event_type: "mailbox_persistence_recovery".to_string(),
                    required_fields: vec![
                        "recovered_chunks".to_string(),
                        "restart_timestamp".to_string(),
                    ],
                    count: Some(1),
                }],
            },
            timeout: Duration::from_secs(400),
        }
    }

    /// Test tampered stored chunks detection
    pub fn tampered_chunks() -> MultiPeerScenario {
        MultiPeerScenario {
            scenario_id: "mailbox-tampered-chunks".to_string(),
            description:
                "Malicious actor tampers with stored chunks. Receiver should detect and reject."
                    .to_string(),
            scenario_type: ScenarioType::Adversarial,
            peers: vec![
                PeerConfig {
                    peer_id: "sender".to_string(),
                    role: PeerRole::Sender,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![
                            (Duration::from_secs(45), false), // Goes offline after upload
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(5 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
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
                            (Duration::from_secs(120), true), // Comes online after tampering
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(5 * 1024 * 1024),
                        bandwidth_limit: Some(1024 * 1024),
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "mailbox-relay".to_string(),
                    role: PeerRole::Mailbox,
                    availability: AvailabilitySchedule {
                        initially_online: true,
                        schedule: vec![],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: Some(20 * 1024 * 1024),
                        bandwidth_limit: Some(2 * 1024 * 1024),
                        cache_enabled: true,
                        seeding_enabled: false,
                        relay_enabled: true,
                    },
                    work_dir: None,
                },
                PeerConfig {
                    peer_id: "tamperer".to_string(),
                    role: PeerRole::Malicious,
                    availability: AvailabilitySchedule {
                        initially_online: false,
                        schedule: vec![
                            (Duration::from_secs(75), true),  // Comes online to tamper
                            (Duration::from_secs(90), false), // Goes offline before receiver
                        ],
                    },
                    capabilities: PeerCapabilities {
                        storage_quota: None,
                        bandwidth_limit: None,
                        cache_enabled: false,
                        seeding_enabled: false,
                        relay_enabled: false,
                    },
                    work_dir: None,
                },
            ],
            network: NetworkConfig {
                latency_ms: std::collections::HashMap::new(),
                packet_loss: std::collections::HashMap::new(),
                bandwidth: std::collections::HashMap::new(),
                partitions: vec![],
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(1024 * 1024), // 1MB
                encrypted: true,
                repair_config: Some(RepairConfig {
                    k: 6,
                    n: 10,
                    threshold: 0.8,
                }),
                chunk_size: 32 * 1024, // 32KB chunks
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: false, // Should fail due to tampered chunks
                completion_time: None,
                bytes_transferred: Some(0), // No verified bytes due to tampering
                peer_rejections: Some(1),   // Tamperer should be rejected
                cache_metrics: None,
                log_events: vec![LogEventExpectation {
                    event_type: "chunk_verification_failure".to_string(),
                    required_fields: vec![
                        "chunk_hash_mismatch".to_string(),
                        "mailbox_id".to_string(),
                    ],
                    count: None, // May be multiple depending on chunks tampered
                }],
            },
            timeout: Duration::from_secs(240),
        }
    }

    /// Get all predefined mailbox scenarios
    pub fn all_scenarios() -> Vec<MultiPeerScenario> {
        vec![
            Self::sender_offline_after_upload(),
            Self::receiver_offline_then_online(),
            Self::relay_restart(),
            Self::tampered_chunks(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::multi_peer::contracts::{MailboxContract, MultiPeerContract};

    #[test]
    fn test_sender_offline_scenario_validation() {
        let scenario = MailboxScenarios::sender_offline_after_upload();
        let contract = MailboxContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert_eq!(scenario.scenario_id, "mailbox-sender-offline-after-upload");
        assert_eq!(scenario.peers.len(), 3);
    }

    #[test]
    fn test_receiver_offline_scenario_validation() {
        let scenario = MailboxScenarios::receiver_offline_then_online();
        let contract = MailboxContract;

        assert!(contract.validate_scenario(&scenario).is_ok());
        assert!(!scenario.peers[1].availability.initially_online); // receiver starts offline
    }

    #[test]
    fn test_relay_restart_scenario() {
        let scenario = MailboxScenarios::relay_restart();

        // Find the mailbox peer
        let mailbox_peer = scenario
            .peers
            .iter()
            .find(|p| matches!(p.role, PeerRole::Mailbox))
            .unwrap();

        // Should have restart schedule (offline then online)
        assert!(!mailbox_peer.availability.schedule.is_empty());
        let has_offline = mailbox_peer
            .availability
            .schedule
            .iter()
            .any(|(_, online)| !online);
        let has_online = mailbox_peer
            .availability
            .schedule
            .iter()
            .any(|(_, online)| *online);

        assert!(
            has_offline && has_online,
            "Mailbox should have restart schedule"
        );
    }

    #[test]
    fn test_tampered_chunks_adversarial() {
        let scenario = MailboxScenarios::tampered_chunks();

        assert!(matches!(scenario.scenario_type, ScenarioType::Adversarial));
        assert!(!scenario.expectations.success); // Should expect failure

        let has_malicious = scenario
            .peers
            .iter()
            .any(|p| matches!(p.role, PeerRole::Malicious));
        assert!(has_malicious, "Should have malicious peer for tampering");
    }

    #[test]
    fn test_all_scenarios_validate() {
        let scenarios = MailboxScenarios::all_scenarios();
        assert!(!scenarios.is_empty());

        // Each scenario should be valid according to its type
        for scenario in &scenarios {
            assert!(
                scenario.validate().is_ok(),
                "Scenario {} should be valid",
                scenario.scenario_id
            );
        }
    }
}
