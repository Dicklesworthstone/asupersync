//! Golden artifact tests for STUN/ICE message types serialization.
//!
//! These tests verify that STUN/ICE structures serialize to consistent,
//! stable JSON and binary formats. Golden artifacts ensure protocol
//! compatibility and detect unexpected serialization changes.

use asupersync::net::stun::{IceCandidate, IceCandidateType, StunError, StunMessageType};
use serde_json;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Golden artifact test infrastructure.
mod golden_artifact_harness {
    use serde::Serialize;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Golden artifact directory for STUN/ICE artifacts.
    fn artifacts_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("artifacts")
            .join("stun_ice_golden")
    }

    /// Ensure artifacts directory exists.
    fn ensure_artifacts_dir() -> std::io::Result<()> {
        let dir = artifacts_dir();
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Write or verify golden artifact JSON.
    pub fn verify_golden_json<T: Serialize>(
        name: &str,
        value: &T,
        update_mode: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        ensure_artifacts_dir()?;

        let artifact_path = artifacts_dir().join(format!("{}.golden.json", name));
        let actual_json = serde_json::to_string_pretty(value)?;

        if update_mode {
            // Update mode: write new golden artifact
            fs::write(&artifact_path, &actual_json)?;
            eprintln!("Updated golden artifact: {}", artifact_path.display());
            Ok(())
        } else {
            // Verify mode: compare against existing golden artifact
            if !artifact_path.exists() {
                return Err(format!(
                    "Golden artifact missing: {}. Run with UPDATE_GOLDEN=1 to create.",
                    artifact_path.display()
                )
                .into());
            }

            let expected_json = fs::read_to_string(&artifact_path)?;
            if actual_json != expected_json {
                // Create diff file for debugging
                let diff_path = artifacts_dir().join(format!("{}.diff", name));
                fs::write(
                    &diff_path,
                    format!("EXPECTED:\n{}\n\nACTUAL:\n{}\n", expected_json, actual_json),
                )?;

                return Err(format!(
                    "Golden artifact mismatch: {}. Diff saved to: {}",
                    artifact_path.display(),
                    diff_path.display()
                )
                .into());
            }

            Ok(())
        }
    }

    /// Verify golden artifact with binary encoding.
    pub fn verify_golden_binary<T: Serialize>(
        name: &str,
        value: &T,
        update_mode: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        ensure_artifacts_dir()?;

        let artifact_path = artifacts_dir().join(format!("{}.golden.bin", name));
        let actual_binary = bincode::serialize(value)?;

        if update_mode {
            fs::write(&artifact_path, &actual_binary)?;
            eprintln!(
                "Updated binary golden artifact: {}",
                artifact_path.display()
            );
            Ok(())
        } else {
            if !artifact_path.exists() {
                return Err(format!(
                    "Golden binary artifact missing: {}. Run with UPDATE_GOLDEN=1 to create.",
                    artifact_path.display()
                )
                .into());
            }

            let expected_binary = fs::read(&artifact_path)?;
            if actual_binary != expected_binary {
                let hex_path = artifacts_dir().join(format!("{}.hex_diff", name));
                fs::write(
                    &hex_path,
                    format!(
                        "EXPECTED (hex): {}\nACTUAL (hex): {}\n",
                        hex::encode(&expected_binary),
                        hex::encode(&actual_binary)
                    ),
                )?;

                return Err(format!(
                    "Golden binary artifact mismatch: {}. Hex diff saved to: {}",
                    artifact_path.display(),
                    hex_path.display()
                )
                .into());
            }

            Ok(())
        }
    }

    /// Check if we're in update mode (UPDATE_GOLDEN=1 environment variable).
    pub fn is_update_mode() -> bool {
        std::env::var("UPDATE_GOLDEN").unwrap_or_default() == "1"
    }
}

/// Golden artifact tests for IceCandidateType enum.
mod ice_candidate_type_tests {
    use super::golden_artifact_harness::*;
    use super::*;

    #[test]
    fn ice_candidate_type_host_golden() {
        let candidate_type = IceCandidateType::Host;
        verify_golden_json("ice_candidate_type_host", &candidate_type, is_update_mode())
            .expect("Host candidate type golden artifact");
    }

    #[test]
    fn ice_candidate_type_server_reflexive_golden() {
        let candidate_type = IceCandidateType::ServerReflexive;
        verify_golden_json(
            "ice_candidate_type_server_reflexive",
            &candidate_type,
            is_update_mode(),
        )
        .expect("ServerReflexive candidate type golden artifact");
    }

    #[test]
    fn ice_candidate_type_peer_reflexive_golden() {
        let candidate_type = IceCandidateType::PeerReflexive;
        verify_golden_json(
            "ice_candidate_type_peer_reflexive",
            &candidate_type,
            is_update_mode(),
        )
        .expect("PeerReflexive candidate type golden artifact");
    }

    #[test]
    fn ice_candidate_type_relay_golden() {
        let candidate_type = IceCandidateType::Relay;
        verify_golden_json(
            "ice_candidate_type_relay",
            &candidate_type,
            is_update_mode(),
        )
        .expect("Relay candidate type golden artifact");
    }

    #[test]
    fn ice_candidate_type_all_variants_collection() {
        let all_types = vec![
            IceCandidateType::Host,
            IceCandidateType::ServerReflexive,
            IceCandidateType::PeerReflexive,
            IceCandidateType::Relay,
        ];
        verify_golden_json(
            "ice_candidate_type_all_variants",
            &all_types,
            is_update_mode(),
        )
        .expect("All ICE candidate types golden artifact");
    }
}

/// Golden artifact tests for IceCandidate struct.
mod ice_candidate_tests {
    use super::golden_artifact_harness::*;
    use super::*;

    fn create_host_candidate() -> IceCandidate {
        IceCandidate {
            foundation: "1".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 2113667326,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 54400)),
            candidate_type: IceCandidateType::Host,
            related_address: None,
        }
    }

    fn create_server_reflexive_candidate() -> IceCandidate {
        IceCandidate {
            foundation: "2".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 1686052606,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 45), 54401)),
            candidate_type: IceCandidateType::ServerReflexive,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 100),
                54400,
            ))),
        }
    }

    fn create_relay_candidate() -> IceCandidate {
        IceCandidate {
            foundation: "3".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 16777215,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 80), 49200)),
            candidate_type: IceCandidateType::Relay,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(203, 0, 113, 45),
                54401,
            ))),
        }
    }

    #[test]
    fn ice_candidate_host_golden() {
        let candidate = create_host_candidate();
        verify_golden_json("ice_candidate_host", &candidate, is_update_mode())
            .expect("Host ICE candidate golden artifact");
        verify_golden_binary("ice_candidate_host", &candidate, is_update_mode())
            .expect("Host ICE candidate binary golden artifact");
    }

    #[test]
    fn ice_candidate_server_reflexive_golden() {
        let candidate = create_server_reflexive_candidate();
        verify_golden_json(
            "ice_candidate_server_reflexive",
            &candidate,
            is_update_mode(),
        )
        .expect("ServerReflexive ICE candidate golden artifact");
        verify_golden_binary(
            "ice_candidate_server_reflexive",
            &candidate,
            is_update_mode(),
        )
        .expect("ServerReflexive ICE candidate binary golden artifact");
    }

    #[test]
    fn ice_candidate_relay_golden() {
        let candidate = create_relay_candidate();
        verify_golden_json("ice_candidate_relay", &candidate, is_update_mode())
            .expect("Relay ICE candidate golden artifact");
        verify_golden_binary("ice_candidate_relay", &candidate, is_update_mode())
            .expect("Relay ICE candidate binary golden artifact");
    }

    #[test]
    fn ice_candidate_collection_golden() {
        let candidates = vec![
            create_host_candidate(),
            create_server_reflexive_candidate(),
            create_relay_candidate(),
        ];
        verify_golden_json("ice_candidate_collection", &candidates, is_update_mode())
            .expect("ICE candidate collection golden artifact");
        verify_golden_binary("ice_candidate_collection", &candidates, is_update_mode())
            .expect("ICE candidate collection binary golden artifact");
    }

    #[test]
    fn ice_candidate_ipv6_golden() {
        let ipv6_candidate = IceCandidate {
            foundation: "4".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 2113667326,
            address: "[2001:db8::1]:54400".parse().expect("IPv6 address"),
            candidate_type: IceCandidateType::Host,
            related_address: None,
        };
        verify_golden_json("ice_candidate_ipv6", &ipv6_candidate, is_update_mode())
            .expect("IPv6 ICE candidate golden artifact");
    }

    #[test]
    fn ice_candidate_edge_cases_golden() {
        // Test edge cases: empty foundation, max priority, etc.
        let edge_case_candidate = IceCandidate {
            foundation: "".to_string(),  // Empty foundation
            component: 65535,            // Max component ID
            protocol: "tcp".to_string(), // TCP instead of UDP
            priority: 0,                 // Min priority
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            candidate_type: IceCandidateType::PeerReflexive,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(255, 255, 255, 255),
                65535,
            ))),
        };
        verify_golden_json(
            "ice_candidate_edge_cases",
            &edge_case_candidate,
            is_update_mode(),
        )
        .expect("Edge case ICE candidate golden artifact");
    }
}

/// Golden artifact tests for STUN protocol structures.
mod stun_protocol_tests {
    use super::golden_artifact_harness::*;
    use super::*;

    /// STUN message for golden testing (simplified representation).
    #[derive(serde::Serialize, serde::Deserialize)]
    struct StunMessage {
        message_type: String,
        transaction_id: [u8; 12],
        attributes: Vec<StunAttribute>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct StunAttribute {
        attr_type: u16,
        attr_name: String,
        value: Vec<u8>,
    }

    fn create_binding_request() -> StunMessage {
        StunMessage {
            message_type: "BindingRequest".to_string(),
            transaction_id: [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
            ],
            attributes: vec![],
        }
    }

    fn create_binding_response() -> StunMessage {
        StunMessage {
            message_type: "BindingResponse".to_string(),
            transaction_id: [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
            ],
            attributes: vec![
                StunAttribute {
                    attr_type: 0x0020, // XOR-MAPPED-ADDRESS
                    attr_name: "XOR-MAPPED-ADDRESS".to_string(),
                    value: vec![0x00, 0x01, 0xD4, 0xC1, 0xCB, 0x00, 0x71, 0x2D],
                },
                StunAttribute {
                    attr_type: 0x8022, // SOFTWARE
                    attr_name: "SOFTWARE".to_string(),
                    value: "asupersync-stun-0.3.2".as_bytes().to_vec(),
                },
            ],
        }
    }

    #[test]
    fn stun_binding_request_golden() {
        let request = create_binding_request();
        verify_golden_json("stun_binding_request", &request, is_update_mode())
            .expect("STUN binding request golden artifact");
        verify_golden_binary("stun_binding_request", &request, is_update_mode())
            .expect("STUN binding request binary golden artifact");
    }

    #[test]
    fn stun_binding_response_golden() {
        let response = create_binding_response();
        verify_golden_json("stun_binding_response", &response, is_update_mode())
            .expect("STUN binding response golden artifact");
        verify_golden_binary("stun_binding_response", &response, is_update_mode())
            .expect("STUN binding response binary golden artifact");
    }

    #[test]
    fn stun_message_types_golden() {
        let message_types = vec![
            "BindingRequest".to_string(),
            "BindingResponse".to_string(),
            "BindingError".to_string(),
        ];
        verify_golden_json("stun_message_types", &message_types, is_update_mode())
            .expect("STUN message types golden artifact");
    }
}

/// Golden artifact tests for error types and edge cases.
mod error_and_edge_case_tests {
    use super::golden_artifact_harness::*;
    use super::*;

    /// Serializable STUN error for golden testing.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SerializableStunError {
        error_type: String,
        message: String,
    }

    fn stun_error_to_serializable(error: &StunError) -> SerializableStunError {
        SerializableStunError {
            error_type: match error {
                StunError::NotImplemented => "NotImplemented".to_string(),
                StunError::Timeout => "Timeout".to_string(),
                StunError::InvalidResponse => "InvalidResponse".to_string(),
                StunError::Network(_) => "Network".to_string(),
            },
            message: error.to_string(),
        }
    }

    #[test]
    fn stun_errors_golden() {
        let errors = vec![
            stun_error_to_serializable(&StunError::NotImplemented),
            stun_error_to_serializable(&StunError::Timeout),
            stun_error_to_serializable(&StunError::InvalidResponse),
            stun_error_to_serializable(&StunError::Network("Connection refused".to_string())),
        ];
        verify_golden_json("stun_errors", &errors, is_update_mode())
            .expect("STUN errors golden artifact");
    }

    #[test]
    fn network_protocol_compatibility_golden() {
        // Test network protocol compatibility scenarios
        let compatibility_data = serde_json::json!({
            "stun_version": "RFC 5389",
            "ice_version": "RFC 8445",
            "supported_candidate_types": ["host", "srflx", "prflx", "relay"],
            "default_stun_port": 3478,
            "default_turn_port": 3478,
            "magic_cookie": "0x2112A442",
            "fingerprint_enabled": true,
            "software_attribute": "asupersync-stun-0.3.2"
        });

        verify_golden_json(
            "network_protocol_compatibility",
            &compatibility_data,
            is_update_mode(),
        )
        .expect("Network protocol compatibility golden artifact");
    }
}

/// Integration test verifying all golden artifacts together.
#[test]
fn comprehensive_stun_ice_golden_integration() {
    use golden_artifact_harness::*;

    // Comprehensive test data combining all STUN/ICE structures
    let comprehensive_data = serde_json::json!({
        "test_suite": "STUN/ICE Golden Artifacts",
        "version": "1.0.0",
        "timestamp": "2026-05-26T07:00:00Z",
        "ice_candidate_types": [
            IceCandidateType::Host,
            IceCandidateType::ServerReflexive,
            IceCandidateType::PeerReflexive,
            IceCandidateType::Relay
        ],
        "sample_ice_candidates": [
            {
                "foundation": "1",
                "component": 1,
                "protocol": "udp",
                "priority": 2113667326,
                "address": "192.168.1.100:54400",
                "candidate_type": IceCandidateType::Host,
                "related_address": null
            },
            {
                "foundation": "2",
                "component": 1,
                "protocol": "udp",
                "priority": 1686052606,
                "address": "203.0.113.45:54401",
                "candidate_type": IceCandidateType::ServerReflexive,
                "related_address": "192.168.1.100:54400"
            }
        ],
        "stun_message_types": ["BindingRequest", "BindingResponse", "BindingError"],
        "test_vectors": {
            "ipv4_host": "192.168.1.100:54400",
            "ipv4_reflexive": "203.0.113.45:54401",
            "ipv6_host": "[2001:db8::1]:54400",
            "stun_server": "stun.l.google.com:19302"
        }
    });

    verify_golden_json(
        "comprehensive_stun_ice_integration",
        &comprehensive_data,
        is_update_mode(),
    )
    .expect("Comprehensive STUN/ICE integration golden artifact");
}
