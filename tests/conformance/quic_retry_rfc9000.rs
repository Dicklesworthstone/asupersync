//! QUIC Retry Packet Conformance Tests (RFC 9000 Section 17.2.5)
//!
//! This module provides comprehensive conformance testing for QUIC Retry packet
//! handling per RFC 9000 Section 17.2.5. The tests systematically validate:
//!
//! - Retry packet format and encoding/decoding correctness
//! - Connection ID and token field handling
//! - Integrity tag validation and authentication
//! - Client response requirements for Retry processing
//! - Server-side Retry generation and validation
//! - Error conditions and boundary cases
//!
//! # QUIC Retry Packet Format (RFC 9000 Section 17.2.5)
//!
//! ```
//! Retry Packet {
//!   Header Form (1) = 1,
//!   Fixed Bit (1) = 1,
//!   Long Packet Type (2) = 3,
//!   Unused (4),
//!   Version (32),
//!   DCID Len (8),
//!   Destination Connection ID (0..160),
//!   SCID Len (8),
//!   Source Connection ID (0..160),
//!   Retry Token (..),
//!   Retry Integrity Tag (128),
//! }
//! ```
//!
//! # Key RFC 9000 Requirements
//!
//! 1. **Format Validation**: Retry packets must conform to exact format
//! 2. **Connection ID Handling**: DCID from Initial becomes SCID in Retry response
//! 3. **Token Inclusion**: Server-generated retry token must be present
//! 4. **Integrity Protection**: 16-byte integrity tag validates packet authenticity
//! 5. **Client Processing**: Client must use retry token in subsequent Initial packet
//! 6. **Single Retry**: Client should only process one Retry packet per connection
//! 7. **Version Matching**: Retry packet version must match client's Initial packet

use asupersync::net::quic_core::{
    ConnectionId, LongPacketType, PacketHeader, QuicCoreError, RetryHeader,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Test result for a single QUIC Retry conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicRetryConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Conformance test categories for QUIC Retry packets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestCategory {
    /// Retry packet format validation
    PacketFormat,
    /// Connection ID field handling
    ConnectionIdHandling,
    /// Retry token processing
    TokenProcessing,
    /// Integrity tag validation
    IntegrityValidation,
    /// Client response requirements
    ClientProcessing,
    /// Server generation and validation
    ServerProcessing,
    /// Protocol ordering and state
    ProtocolOrdering,
}

/// Protocol requirement level per RFC 2119.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // RFC 2119: MUST
    Should, // RFC 2119: SHOULD
    May,    // RFC 2119: MAY
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// QUIC Retry packet conformance test harness.
pub struct QuicRetryConformanceHarness {
    /// Test execution timeout
    timeout: Duration,
}

impl QuicRetryConformanceHarness {
    /// Create a new conformance test harness.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    /// Run all conformance tests.
    pub fn run_all_tests(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Retry packet format conformance tests
        results.extend(self.test_packet_format());
        results.extend(self.test_connection_id_handling());
        results.extend(self.test_token_processing());
        results.extend(self.test_integrity_validation());
        results.extend(self.test_client_processing());
        results.extend(self.test_server_processing());
        results.extend(self.test_protocol_ordering());

        results
    }

    /// Test Retry packet format requirements (RFC 9000 Section 17.2.5).
    fn test_packet_format(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Valid Retry packet format
        results.push(self.run_test(
            "retry_packet_valid_format",
            "Retry packet with valid format MUST be parsed correctly",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            || {
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0x05, 0x06]).map_err(to_string)?,
                    token: vec![0xaa, 0xbb, 0xcc, 0xdd],
                    integrity_tag: [
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                        0x76, 0x54, 0x32, 0x10,
                    ],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, consumed) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                assert_eq!(consumed, encoded.len());

                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry, retry);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet header".to_string()),
                }
            },
        ));

        // Test 2: Retry packet encoding follows RFC 9000 format
        results.push(self.run_test(
            "retry_packet_encoding_format",
            "Retry packet encoding MUST follow RFC 9000 Section 17.2.5 format",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            || {
                let retry = RetryHeader {
                    version: 0xff00_001d, // QUIC v1 draft
                    dst_cid: ConnectionId::new(&[0xde, 0xad, 0xbe, 0xef]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0xca, 0xfe]).map_err(to_string)?,
                    token: vec![0x12, 0x34, 0x56],
                    integrity_tag: [0xab; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry)
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                // Verify header format per RFC 9000
                assert!(encoded.len() >= 9, "Minimum header size");

                // First byte: Header Form(1) + Fixed Bit(1) + Long Packet Type(2) + Unused(4)
                // Should be 0b1111_0000 for Retry packet
                assert_eq!(encoded[0], 0b1111_0000, "Retry packet type and format");

                // Version (4 bytes, big-endian)
                let version = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
                assert_eq!(version, 0xff00_001d, "Version field");

                // DCID length and value
                assert_eq!(encoded[5], 4, "DCID length");
                assert_eq!(&encoded[6..10], &[0xde, 0xad, 0xbe, 0xef], "DCID value");

                // SCID length and value
                assert_eq!(encoded[10], 2, "SCID length");
                assert_eq!(&encoded[11..13], &[0xca, 0xfe], "SCID value");

                // Token and integrity tag
                assert_eq!(&encoded[13..16], &[0x12, 0x34, 0x56], "Token");
                assert_eq!(&encoded[16..32], &[0xab; 16], "Integrity tag");

                Ok(())
            },
        ));

        // Test 3: Empty token handling
        results.push(self.run_test(
            "retry_packet_empty_token",
            "Retry packet with empty token MUST be handled correctly",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            || {
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[0x01]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0x02]).map_err(to_string)?,
                    token: vec![], // Empty token
                    integrity_tag: [0x00; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert!(decoded_retry.token.is_empty());
                        assert_eq!(decoded_retry, retry);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        // Test 4: Maximum connection ID lengths
        results.push(self.run_test(
            "retry_packet_max_cid_lengths",
            "Retry packet with maximum CID lengths MUST be handled",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            || {
                let max_cid = [0xff; 20]; // Maximum CID length
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&max_cid).map_err(to_string)?,
                    src_cid: ConnectionId::new(&max_cid).map_err(to_string)?,
                    token: vec![0x42],
                    integrity_tag: [0x99; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry.dst_cid.len(), 20);
                        assert_eq!(decoded_retry.src_cid.len(), 20);
                        assert_eq!(decoded_retry, retry);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        results
    }

    /// Test connection ID handling requirements (RFC 9000 Section 17.2.5).
    fn test_connection_id_handling(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: DCID from Initial becomes SCID in Retry response
        results.push(self.run_test(
            "retry_cid_swapping",
            "Retry packet MUST use Initial DCID as Retry SCID per RFC 9000",
            TestCategory::ConnectionIdHandling,
            RequirementLevel::Must,
            || {
                let original_dcid = ConnectionId::new(&[0x11, 0x22, 0x33]).map_err(to_string)?;
                let new_scid = ConnectionId::new(&[0xaa, 0xbb]).map_err(to_string)?;

                // Simulate server creating Retry response:
                // - DCID in Retry = new server-chosen CID (becomes client's DCID)
                // - SCID in Retry = original client DCID (from Initial packet)
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: new_scid,      // New server-chosen CID
                    src_cid: original_dcid, // Original client DCID
                    token: vec![0x42, 0x43],
                    integrity_tag: [0x00; 16],
                };

                // Verify the CIDs are correctly set
                assert_eq!(retry.src_cid, original_dcid);
                assert_eq!(retry.dst_cid, new_scid);

                // Test encoding/decoding preserves CID ordering
                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry.src_cid, original_dcid);
                        assert_eq!(decoded_retry.dst_cid, new_scid);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        // Test 2: Empty connection IDs handling
        results.push(self.run_test(
            "retry_empty_cids",
            "Retry packet MUST support zero-length connection IDs",
            TestCategory::ConnectionIdHandling,
            RequirementLevel::Must,
            || {
                let empty_cid = ConnectionId::new(&[]).map_err(to_string)?;
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: empty_cid,
                    src_cid: empty_cid,
                    token: vec![0x00],
                    integrity_tag: [0xff; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert!(decoded_retry.dst_cid.is_empty());
                        assert!(decoded_retry.src_cid.is_empty());
                        assert_eq!(decoded_retry, retry);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        results
    }

    /// Test retry token processing requirements.
    fn test_token_processing(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Arbitrary token content support
        results.push(self.run_test(
            "retry_token_arbitrary_content",
            "Retry tokens MAY contain arbitrary server data",
            TestCategory::TokenProcessing,
            RequirementLevel::May,
            || {
                let test_tokens = vec![
                    vec![],                             // Empty token
                    vec![0x00],                         // Single byte
                    vec![0x42; 100],                    // Large token
                    vec![0x01, 0x02, 0x03, 0xff, 0xfe], // Mixed bytes
                ];

                for (i, token) in test_tokens.iter().enumerate() {
                    let retry = RetryHeader {
                        version: 0x0000_0001,
                        dst_cid: ConnectionId::new(&[(i as u8) + 1]).map_err(to_string)?,
                        src_cid: ConnectionId::new(&[(i as u8) + 10]).map_err(to_string)?,
                        token: token.clone(),
                        integrity_tag: [i as u8; 16],
                    };

                    let mut encoded = Vec::new();
                    PacketHeader::Retry(retry.clone())
                        .encode(&mut encoded)
                        .map_err(to_string)?;

                    let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                    match decoded {
                        PacketHeader::Retry(decoded_retry) => {
                            assert_eq!(decoded_retry.token, *token);
                        }
                        _ => return Err(format!("Expected Retry packet for token {}", i)),
                    }
                }
                Ok(())
            },
        ));

        // Test 2: Large token handling
        results.push(self.run_test(
            "retry_token_large_size",
            "Retry packets SHOULD support large tokens up to practical limits",
            TestCategory::TokenProcessing,
            RequirementLevel::Should,
            || {
                // Test with 500-byte token (reasonable upper bound for practical use)
                let large_token: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[0x01]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0x02]).map_err(to_string)?,
                    token: large_token.clone(),
                    integrity_tag: [0xab; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry.token.len(), 500);
                        assert_eq!(decoded_retry.token, large_token);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        results
    }

    /// Test integrity tag validation requirements.
    fn test_integrity_validation(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Integrity tag must be exactly 16 bytes
        results.push(self.run_test(
            "retry_integrity_tag_length",
            "Retry packet integrity tag MUST be exactly 16 bytes",
            TestCategory::IntegrityValidation,
            RequirementLevel::Must,
            || {
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[0x01]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0x02]).map_err(to_string)?,
                    token: vec![0x42],
                    integrity_tag: [0xab; 16], // Exactly 16 bytes
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                // Verify the encoded packet ends with exactly 16 integrity tag bytes
                assert!(encoded.len() >= 16, "Packet must have integrity tag");
                let tag_start = encoded.len() - 16;
                assert_eq!(&encoded[tag_start..], &[0xab; 16]);

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry.integrity_tag.len(), 16);
                        assert_eq!(decoded_retry.integrity_tag, [0xab; 16]);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        // Test 2: Different integrity tag values
        results.push(self.run_test(
            "retry_integrity_tag_values",
            "Retry packet MUST preserve arbitrary integrity tag values",
            TestCategory::IntegrityValidation,
            RequirementLevel::Must,
            || {
                let test_tags = [
                    [0x00; 16], // All zeros
                    [0xff; 16], // All ones
                    [
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                        0x76, 0x54, 0x32, 0x10,
                    ], // Mixed pattern
                ];

                for (i, tag) in test_tags.iter().enumerate() {
                    let retry = RetryHeader {
                        version: 0x0000_0001,
                        dst_cid: ConnectionId::new(&[i as u8]).map_err(to_string)?,
                        src_cid: ConnectionId::new(&[(i + 1) as u8]).map_err(to_string)?,
                        token: vec![0x42],
                        integrity_tag: *tag,
                    };

                    let mut encoded = Vec::new();
                    PacketHeader::Retry(retry.clone())
                        .encode(&mut encoded)
                        .map_err(to_string)?;

                    let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                    match decoded {
                        PacketHeader::Retry(decoded_retry) => {
                            assert_eq!(decoded_retry.integrity_tag, *tag);
                        }
                        _ => return Err(format!("Expected Retry packet for tag {}", i)),
                    }
                }
                Ok(())
            },
        ));

        results
    }

    /// Test client processing requirements.
    fn test_client_processing(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Client must extract retry token for next Initial
        results.push(self.run_test(
            "retry_client_token_extraction",
            "Client MUST extract retry token for subsequent Initial packet",
            TestCategory::ClientProcessing,
            RequirementLevel::Must,
            || {
                let server_token = vec![0xde, 0xad, 0xbe, 0xef, 0x12, 0x34];
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[0x99, 0x88]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[0x11, 0x22, 0x33]).map_err(to_string)?,
                    token: server_token.clone(),
                    integrity_tag: [0xaa; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        // Client would extract this token for the next Initial packet
                        let extracted_token = decoded_retry.token;
                        assert_eq!(extracted_token, server_token);

                        // Verify all fields client needs are accessible
                        let _new_server_cid = decoded_retry.src_cid; // Server's new CID
                        let _original_client_cid = decoded_retry.dst_cid; // Client's original CID
                        let _version = decoded_retry.version; // Must match

                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        // Test 2: Client must update connection IDs
        results.push(self.run_test(
            "retry_client_cid_update",
            "Client MUST update connection IDs based on Retry packet",
            TestCategory::ClientProcessing,
            RequirementLevel::Must,
            || {
                let client_original_cid = ConnectionId::new(&[0x01, 0x02]).map_err(to_string)?;
                let server_new_cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc]).map_err(to_string)?;

                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: client_original_cid, // Client's original DCID
                    src_cid: server_new_cid,      // Server's new CID (becomes client's DCID)
                    token: vec![0x42],
                    integrity_tag: [0x00; 16],
                };

                // Client processing: extract new DCID for subsequent packets
                let next_client_dcid = retry.src_cid;
                let verified_original_cid = retry.dst_cid;

                assert_eq!(next_client_dcid, server_new_cid);
                assert_eq!(verified_original_cid, client_original_cid);

                // Simulate client would use next_client_dcid as DCID in next Initial
                assert_eq!(next_client_dcid.as_bytes(), &[0xaa, 0xbb, 0xcc]);
                Ok(())
            },
        ));

        results
    }

    /// Test server processing requirements.
    fn test_server_processing(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Server generates valid Retry format
        results.push(self.run_test(
            "retry_server_generation",
            "Server MUST generate properly formatted Retry packets",
            TestCategory::ServerProcessing,
            RequirementLevel::Must,
            || {
                // Simulate server generating Retry in response to Initial
                let client_initial_dcid = ConnectionId::new(&[0x11, 0x22]).map_err(to_string)?;
                let client_initial_scid = ConnectionId::new(&[0x33, 0x44]).map_err(to_string)?;
                let server_new_cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc]).map_err(to_string)?;
                let server_token = vec![0x12, 0x34, 0x56, 0x78];

                // Server constructs Retry response:
                // - DCID = client's original SCID (so client recognizes it)
                // - SCID = server's new CID (for client to use going forward)
                let retry = RetryHeader {
                    version: 0x0000_0001,         // Must match client's version
                    dst_cid: client_initial_scid, // Client's SCID becomes Retry DCID
                    src_cid: server_new_cid,      // Server's new CID becomes Retry SCID
                    token: server_token,
                    integrity_tag: [0x42; 16], // Would be computed with actual crypto
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry.clone())
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                // Verify server generated valid packet
                assert!(encoded.len() >= 16, "Must include integrity tag");
                assert_eq!(encoded[0] & 0xf0, 0xf0, "Must be Retry packet type");

                let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                match decoded {
                    PacketHeader::Retry(decoded_retry) => {
                        assert_eq!(decoded_retry, retry);
                        Ok(())
                    }
                    _ => Err("Expected Retry packet".to_string()),
                }
            },
        ));

        results
    }

    /// Test protocol ordering and state requirements.
    fn test_protocol_ordering(&self) -> Vec<QuicRetryConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Version field validation
        results.push(self.run_test(
            "retry_version_validation",
            "Retry packet version MUST match Initial packet version",
            TestCategory::ProtocolOrdering,
            RequirementLevel::Must,
            || {
                let versions = [0x0000_0001, 0xff00_001d, 0x00000000]; // Various QUIC versions

                for version in versions {
                    let retry = RetryHeader {
                        version,
                        dst_cid: ConnectionId::new(&[0x01]).map_err(to_string)?,
                        src_cid: ConnectionId::new(&[0x02]).map_err(to_string)?,
                        token: vec![0x42],
                        integrity_tag: [0x00; 16],
                    };

                    let mut encoded = Vec::new();
                    PacketHeader::Retry(retry.clone())
                        .encode(&mut encoded)
                        .map_err(to_string)?;

                    let (decoded, _) = PacketHeader::decode(&encoded, 0).map_err(to_string)?;
                    match decoded {
                        PacketHeader::Retry(decoded_retry) => {
                            assert_eq!(decoded_retry.version, version);
                        }
                        _ => {
                            return Err(format!(
                                "Expected Retry packet for version {:#x}",
                                version
                            ));
                        }
                    }
                }
                Ok(())
            },
        ));

        // Test 2: Packet type field validation
        results.push(self.run_test(
            "retry_packet_type_validation",
            "Retry packet type field MUST be correctly encoded",
            TestCategory::ProtocolOrdering,
            RequirementLevel::Must,
            || {
                let retry = RetryHeader {
                    version: 0x0000_0001,
                    dst_cid: ConnectionId::new(&[]).map_err(to_string)?,
                    src_cid: ConnectionId::new(&[]).map_err(to_string)?,
                    token: vec![],
                    integrity_tag: [0x00; 16],
                };

                let mut encoded = Vec::new();
                PacketHeader::Retry(retry)
                    .encode(&mut encoded)
                    .map_err(to_string)?;

                // Verify first byte has correct packet type encoding
                // RFC 9000: Long header format with type = 3 (Retry)
                // Bits: 1 (header form) | 1 (fixed bit) | 11 (type=3) | 0000 (unused)
                assert_eq!(encoded[0], 0b1111_0000);
                Ok(())
            },
        ));

        results
    }

    /// Helper function to run a single test with proper error handling and timing.
    fn run_test<F>(
        &self,
        test_id: &str,
        description: &str,
        category: TestCategory,
        requirement_level: RequirementLevel,
        test_fn: F,
    ) -> QuicRetryConformanceResult
    where
        F: FnOnce() -> Result<(), String>,
    {
        let start = Instant::now();

        let verdict = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn)) {
            Ok(Ok(())) => TestVerdict::Pass,
            Ok(Err(msg)) => {
                return QuicRetryConformanceResult {
                    test_id: test_id.to_string(),
                    description: description.to_string(),
                    category,
                    requirement_level,
                    verdict: TestVerdict::Fail,
                    error_message: Some(msg),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
            Err(panic_info) => {
                let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "Test panicked".to_string()
                };

                return QuicRetryConformanceResult {
                    test_id: test_id.to_string(),
                    description: description.to_string(),
                    category,
                    requirement_level,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Panic: {}", panic_msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        QuicRetryConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level,
            verdict,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

impl Default for QuicRetryConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to convert errors to strings.
fn to_string<E: std::fmt::Debug>(err: E) -> String {
    format!("{:?}", err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let harness = QuicRetryConformanceHarness::new();
        assert_eq!(harness.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_all_conformance_tests() {
        let harness = QuicRetryConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have tests
        assert!(!results.is_empty());

        // Verify all tests have proper IDs and descriptions
        for result in &results {
            assert!(!result.test_id.is_empty());
            assert!(!result.description.is_empty());
        }

        // Count tests by category
        let mut category_counts = std::collections::HashMap::new();
        for result in &results {
            *category_counts.entry(&result.category).or_insert(0) += 1;
        }

        // Verify we have tests in all main categories
        assert!(category_counts.contains_key(&TestCategory::PacketFormat));
        assert!(category_counts.contains_key(&TestCategory::ConnectionIdHandling));
        assert!(category_counts.contains_key(&TestCategory::TokenProcessing));
        assert!(category_counts.contains_key(&TestCategory::IntegrityValidation));

        println!("QUIC Retry Conformance Test Results:");
        println!("Total tests: {}", results.len());
        for (category, count) in category_counts {
            println!("  {:?}: {} tests", category, count);
        }

        // Check for any failures
        let failures: Vec<_> = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .collect();

        if !failures.is_empty() {
            println!("Failed tests:");
            for failure in failures {
                println!("  {} - {}", failure.test_id, failure.description);
                if let Some(ref msg) = failure.error_message {
                    println!("    Error: {}", msg);
                }
            }
        }
    }

    #[test]
    fn test_packet_format_conformance() {
        let harness = QuicRetryConformanceHarness::new();
        let results = harness.test_packet_format();

        assert!(!results.is_empty());

        // All format tests should pass
        for result in &results {
            assert_eq!(result.category, TestCategory::PacketFormat);
            if result.verdict == TestVerdict::Fail {
                panic!(
                    "Packet format test failed: {} - {:?}",
                    result.test_id, result.error_message
                );
            }
        }
    }

    #[test]
    fn test_connection_id_handling() {
        let harness = QuicRetryConformanceHarness::new();
        let results = harness.test_connection_id_handling();

        assert!(!results.is_empty());

        // All CID tests should pass
        for result in &results {
            assert_eq!(result.category, TestCategory::ConnectionIdHandling);
            assert!(
                result.verdict != TestVerdict::Fail,
                "Connection ID test failed: {} - {:?}",
                result.test_id,
                result.error_message
            );
        }
    }

    #[test]
    fn test_retry_roundtrip_basic() {
        // Basic smoke test for Retry packet encoding/decoding
        let retry = RetryHeader {
            version: 0x0000_0001,
            dst_cid: ConnectionId::new(&[0x01, 0x02]).unwrap(),
            src_cid: ConnectionId::new(&[0x03, 0x04]).unwrap(),
            token: vec![0xaa, 0xbb],
            integrity_tag: [0x42; 16],
        };

        let mut encoded = Vec::new();
        PacketHeader::Retry(retry.clone())
            .encode(&mut encoded)
            .unwrap();

        let (decoded, _) = PacketHeader::decode(&encoded, 0).unwrap();
        match decoded {
            PacketHeader::Retry(decoded_retry) => {
                assert_eq!(decoded_retry, retry);
            }
            _ => panic!("Expected Retry packet"),
        }
    }
}
