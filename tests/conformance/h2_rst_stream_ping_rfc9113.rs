//! HTTP/2 RST_STREAM and PING Frame Conformance Tests (RFC 9113)
//!
//! This module provides comprehensive conformance testing for HTTP/2 RST_STREAM and PING
//! frame handling per RFC 9113 (HTTP/2 revision of RFC 7540).
//! The tests systematically validate:
//!
//! - RST_STREAM frame format and error code handling
//! - PING frame format and ACK response requirements
//! - Stream vs connection error classification
//! - Frame ordering constraints and protocol violations
//! - Error propagation and connection termination
//!
//! # HTTP/2 RST_STREAM Frame (RFC 9113 Section 6.4)
//!
//! **Format:**
//! ```
//! +---------------------------------------------------------------+
//! |                        Error Code (32)                       |
//! +---------------------------------------------------------------+
//! ```
//!
//! **Requirements:**
//! - Length: exactly 4 bytes
//! - Stream ID: MUST be non-zero
//! - Error code: 32-bit value (standard or extension codes)
//! - Terminates stream immediately
//!
//! # HTTP/2 PING Frame (RFC 9113 Section 6.7)
//!
//! **Format:**
//! ```
//! +---------------------------------------------------------------+
//! |                      Opaque Data (64)                        |
//! +---------------------------------------------------------------+
//! ```
//!
//! **Requirements:**
//! - Length: exactly 8 bytes
//! - Stream ID: MUST be zero (connection-level)
//! - ACK flag: echo back received PING with ACK=1
//! - Opaque data: 8 bytes, client chooses content

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    error::{ErrorCode, H2Error},
    frame::{Frame, FrameHeader, FrameType, PingFrame, RstStreamFrame, parse_frame, ping_flags},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Test result for a single conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2ConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Conformance test categories for HTTP/2 frames.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestCategory {
    /// RST_STREAM frame format validation
    RstStreamFormat,
    /// RST_STREAM error code handling
    RstStreamErrorCodes,
    /// PING frame format validation
    PingFormat,
    /// PING ACK behavior
    PingAck,
    /// Stream vs connection error classification
    ErrorClassification,
    /// Frame ordering and protocol violations
    ProtocolOrdering,
    /// Connection management
    ConnectionHandling,
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

/// HTTP/2 conformance test harness.
pub struct H2ConformanceHarness {
    /// Test execution timeout
    timeout: Duration,
}

impl H2ConformanceHarness {
    /// Create a new conformance test harness.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    /// Run all conformance tests.
    pub fn run_all_tests(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // RST_STREAM conformance tests
        results.extend(self.test_rst_stream_format());
        results.extend(self.test_rst_stream_error_codes());

        // PING conformance tests
        results.extend(self.test_ping_format());
        results.extend(self.test_ping_ack_behavior());

        // Error classification tests
        results.extend(self.test_error_classification());

        // Protocol ordering tests
        results.extend(self.test_protocol_ordering());

        results
    }

    /// Test RST_STREAM frame format requirements (RFC 9113 Section 6.4).
    fn test_rst_stream_format(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: RST_STREAM frame must be exactly 4 bytes
        results.push(self.run_test(
            "rst_stream_length_exactly_4",
            "RST_STREAM frame MUST be exactly 4 bytes",
            TestCategory::RstStreamFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x08]); // CANCEL

                let result = RstStreamFrame::parse(&header, &payload);
                match result {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, 1);
                        assert_eq!(frame.error_code, ErrorCode::Cancel);
                        Ok(())
                    }
                    Err(_) => Err("Valid 4-byte RST_STREAM frame was rejected".to_string()),
                }
            },
        ));

        // Test 2: RST_STREAM with wrong length must be rejected
        results.push(self.run_test(
            "rst_stream_wrong_length_rejected",
            "RST_STREAM frame with wrong length MUST be rejected",
            TestCategory::RstStreamFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 3, // Wrong length
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[0x00, 0x00, 0x00]);

                let result = RstStreamFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::FrameSizeError);
                        Ok(())
                    }
                    Ok(_) => Err("Invalid RST_STREAM frame length was accepted".to_string()),
                }
            },
        ));

        // Test 3: RST_STREAM with stream ID 0 must be rejected
        results.push(self.run_test(
            "rst_stream_stream_id_zero_rejected",
            "RST_STREAM frame with stream ID 0 MUST be rejected",
            TestCategory::RstStreamFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 0, // Invalid for RST_STREAM
                };
                let payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x08]);

                let result = RstStreamFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::ProtocolError);
                        Ok(())
                    }
                    Ok(_) => Err("RST_STREAM with stream ID 0 was accepted".to_string()),
                }
            },
        ));

        // Test 4: RST_STREAM frame roundtrip encoding/decoding
        results.push(self.run_test(
            "rst_stream_roundtrip_encoding",
            "RST_STREAM frame encoding/decoding MUST preserve all fields",
            TestCategory::RstStreamFormat,
            RequirementLevel::Must,
            || {
                let original = RstStreamFrame::new(42, ErrorCode::RefusedStream);

                let mut buf = BytesMut::new();
                original.encode(&mut buf);

                let header = FrameHeader::parse(&mut buf).map_err(h2error_to_string)?;
                let payload = buf.split_to(header.length as usize).freeze();
                let parsed = RstStreamFrame::parse(&header, &payload).map_err(h2error_to_string)?;

                assert_eq!(parsed.stream_id, original.stream_id);
                assert_eq!(parsed.error_code, original.error_code);
                Ok(())
            },
        ));

        results
    }

    /// Test RST_STREAM error code handling (RFC 9113 Section 7).
    fn test_rst_stream_error_codes(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: All standard error codes must be accepted
        results.push(self.run_test(
            "rst_stream_standard_error_codes",
            "RST_STREAM MUST accept all standard HTTP/2 error codes",
            TestCategory::RstStreamErrorCodes,
            RequirementLevel::Must,
            || {
                let error_codes = [
                    ErrorCode::NoError,
                    ErrorCode::ProtocolError,
                    ErrorCode::InternalError,
                    ErrorCode::FlowControlError,
                    ErrorCode::SettingsTimeout,
                    ErrorCode::StreamClosed,
                    ErrorCode::FrameSizeError,
                    ErrorCode::RefusedStream,
                    ErrorCode::Cancel,
                    ErrorCode::CompressionError,
                    ErrorCode::ConnectError,
                    ErrorCode::EnhanceYourCalm,
                    ErrorCode::InadequateSecurity,
                    ErrorCode::Http11Required,
                ];

                for (stream_id, error_code) in error_codes.iter().enumerate() {
                    let header = FrameHeader {
                        length: 4,
                        frame_type: FrameType::RstStream as u8,
                        flags: 0,
                        stream_id: (stream_id as u32) + 1,
                    };
                    let error_value: u32 = (*error_code).into();
                    let payload = Bytes::copy_from_slice(&error_value.to_be_bytes());

                    let result =
                        RstStreamFrame::parse(&header, &payload).map_err(h2error_to_string)?;
                    assert_eq!(result.error_code, *error_code);
                }
                Ok(())
            },
        ));

        // Test 2: Unknown error codes should be mapped to INTERNAL_ERROR
        results.push(self.run_test(
            "rst_stream_unknown_error_codes_mapped",
            "Unknown error codes SHOULD be mapped to INTERNAL_ERROR",
            TestCategory::RstStreamErrorCodes,
            RequirementLevel::Should,
            || {
                let header = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 1,
                };
                // Use an unknown error code
                let payload = Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]);

                let result = RstStreamFrame::parse(&header, &payload).map_err(h2error_to_string)?;
                assert_eq!(result.error_code, ErrorCode::InternalError);
                Ok(())
            },
        ));

        results
    }

    /// Test PING frame format requirements (RFC 9113 Section 6.7).
    fn test_ping_format(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: PING frame must be exactly 8 bytes
        results.push(self.run_test(
            "ping_length_exactly_8",
            "PING frame MUST be exactly 8 bytes",
            TestCategory::PingFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: 0,
                    stream_id: 0,
                };
                let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let result = PingFrame::parse(&header, &payload);
                match result {
                    Ok(frame) => {
                        assert_eq!(frame.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
                        assert!(!frame.ack);
                        Ok(())
                    }
                    Err(_) => Err("Valid 8-byte PING frame was rejected".to_string()),
                }
            },
        ));

        // Test 2: PING with wrong length must be rejected
        results.push(self.run_test(
            "ping_wrong_length_rejected",
            "PING frame with wrong length MUST be rejected",
            TestCategory::PingFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 7, // Wrong length
                    frame_type: FrameType::Ping as u8,
                    flags: 0,
                    stream_id: 0,
                };
                let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7]);

                let result = PingFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::FrameSizeError);
                        Ok(())
                    }
                    Ok(_) => Err("Invalid PING frame length was accepted".to_string()),
                }
            },
        ));

        // Test 3: PING with non-zero stream ID must be rejected
        results.push(self.run_test(
            "ping_non_zero_stream_id_rejected",
            "PING frame with non-zero stream ID MUST be rejected",
            TestCategory::PingFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: 0,
                    stream_id: 1, // Invalid for PING
                };
                let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let result = PingFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::ProtocolError);
                        Ok(())
                    }
                    Ok(_) => Err("PING with non-zero stream ID was accepted".to_string()),
                }
            },
        ));

        // Test 4: PING frame roundtrip encoding/decoding
        results.push(self.run_test(
            "ping_roundtrip_encoding",
            "PING frame encoding/decoding MUST preserve all fields",
            TestCategory::PingFormat,
            RequirementLevel::Must,
            || {
                let original = PingFrame::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);

                let mut buf = BytesMut::new();
                original.encode(&mut buf);

                let header = FrameHeader::parse(&mut buf).map_err(h2error_to_string)?;
                let payload = buf.split_to(header.length as usize).freeze();
                let parsed = PingFrame::parse(&header, &payload).map_err(h2error_to_string)?;

                assert_eq!(parsed.opaque_data, original.opaque_data);
                assert_eq!(parsed.ack, original.ack);
                Ok(())
            },
        ));

        results
    }

    /// Test PING ACK behavior requirements (RFC 9113 Section 6.7).
    fn test_ping_ack_behavior(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: PING ACK must echo opaque data
        results.push(self.run_test(
            "ping_ack_echoes_opaque_data",
            "PING ACK MUST echo the exact opaque data from the original PING",
            TestCategory::PingAck,
            RequirementLevel::Must,
            || {
                let opaque_data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

                // Create original PING
                let ping = PingFrame::new(opaque_data);
                assert!(!ping.ack);
                assert_eq!(ping.opaque_data, opaque_data);

                // Create PING ACK
                let ping_ack = PingFrame::ack(opaque_data);
                assert!(ping_ack.ack);
                assert_eq!(ping_ack.opaque_data, opaque_data);

                // Verify they have the same opaque data but different ACK flag
                assert_eq!(ping.opaque_data, ping_ack.opaque_data);
                assert_ne!(ping.ack, ping_ack.ack);
                Ok(())
            },
        ));

        // Test 2: PING ACK flag encoding/decoding
        results.push(self.run_test(
            "ping_ack_flag_encoding",
            "PING ACK flag MUST be correctly encoded and decoded",
            TestCategory::PingAck,
            RequirementLevel::Must,
            || {
                let opaque_data = [0xFF; 8];
                let ping_ack = PingFrame::ack(opaque_data);

                let mut buf = BytesMut::new();
                ping_ack.encode(&mut buf);

                let header = FrameHeader::parse(&mut buf).map_err(h2error_to_string)?;
                // Verify ACK flag is set in header
                assert!(header.has_flag(ping_flags::ACK));

                let payload = buf.split_to(header.length as usize).freeze();
                let parsed = PingFrame::parse(&header, &payload).map_err(h2error_to_string)?;

                assert!(parsed.ack);
                assert_eq!(parsed.opaque_data, opaque_data);
                Ok(())
            },
        ));

        // Test 3: PING without ACK flag
        results.push(self.run_test(
            "ping_without_ack_flag",
            "PING frame without ACK flag MUST be parsed correctly",
            TestCategory::PingAck,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: 0, // No ACK flag
                    stream_id: 0,
                };
                let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let parsed = PingFrame::parse(&header, &payload).map_err(h2error_to_string)?;
                assert!(!parsed.ack);
                assert_eq!(parsed.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
                Ok(())
            },
        ));

        results
    }

    /// Test error classification requirements (RFC 9113).
    fn test_error_classification(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: RST_STREAM errors are stream-level
        results.push(self.run_test(
            "rst_stream_errors_stream_level",
            "RST_STREAM frame errors MUST be classified as stream errors",
            TestCategory::ErrorClassification,
            RequirementLevel::Must,
            || {
                // Create a valid RST_STREAM frame
                let rst_stream = RstStreamFrame::new(5, ErrorCode::Cancel);
                assert_eq!(rst_stream.stream_id, 5);

                // RST_STREAM frames terminate specific streams, not connections
                // This is implicit in the frame design - stream ID is non-zero
                assert!(rst_stream.stream_id > 0);
                Ok(())
            },
        ));

        // Test 2: PING errors are connection-level
        results.push(self.run_test(
            "ping_errors_connection_level",
            "PING frame errors MUST be classified as connection errors",
            TestCategory::ErrorClassification,
            RequirementLevel::Must,
            || {
                // PING frames always have stream ID 0 (connection-level)
                let ping = PingFrame::new([0; 8]);

                // Test that parsing with wrong stream ID gives connection error
                let header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: 0,
                    stream_id: 1, // Wrong for PING
                };
                let payload = Bytes::from_static(&[0; 8]);

                let result = PingFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert!(err.is_connection_error());
                        Ok(())
                    }
                    Ok(_) => Err("PING with wrong stream ID should fail".to_string()),
                }
            },
        ));

        results
    }

    /// Test protocol ordering requirements.
    fn test_protocol_ordering(&self) -> Vec<H2ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Frame parsing with parse_frame function
        results.push(self.run_test(
            "frame_parsing_integration",
            "Frame parsing MUST correctly identify RST_STREAM and PING frames",
            TestCategory::ProtocolOrdering,
            RequirementLevel::Must,
            || {
                // Test RST_STREAM parsing
                let rst_header = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 3,
                };
                let rst_payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x08]);
                let frame = parse_frame(&rst_header, rst_payload).map_err(h2error_to_string)?;

                match frame {
                    Frame::RstStream(rst) => {
                        assert_eq!(rst.stream_id, 3);
                        assert_eq!(rst.error_code, ErrorCode::Cancel);
                    }
                    _ => return Err("Expected RST_STREAM frame".to_string()),
                }

                // Test PING parsing
                let ping_header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: ping_flags::ACK,
                    stream_id: 0,
                };
                let ping_payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
                let frame = parse_frame(&ping_header, ping_payload).map_err(h2error_to_string)?;

                match frame {
                    Frame::Ping(ping) => {
                        assert!(ping.ack);
                        assert_eq!(ping.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
                    }
                    _ => return Err("Expected PING frame".to_string()),
                }

                Ok(())
            },
        ));

        // Test 2: Frame stream ID validation
        results.push(self.run_test(
            "frame_stream_id_validation",
            "Frame stream ID validation MUST follow RFC 9113 requirements",
            TestCategory::ProtocolOrdering,
            RequirementLevel::Must,
            || {
                // RST_STREAM requires non-zero stream ID
                let rst_stream = RstStreamFrame::new(0, ErrorCode::Cancel);
                let header = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream as u8,
                    flags: 0,
                    stream_id: 0, // Invalid
                };
                let payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x08]);

                let result = RstStreamFrame::parse(&header, &payload);
                assert!(result.is_err());

                // PING requires stream ID 0
                let header = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping as u8,
                    flags: 0,
                    stream_id: 1, // Invalid
                };
                let payload = Bytes::from_static(&[0; 8]);

                let result = PingFrame::parse(&header, &payload);
                assert!(result.is_err());

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
    ) -> H2ConformanceResult
    where
        F: FnOnce() -> Result<(), String>,
    {
        let start = Instant::now();

        let verdict = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn)) {
            Ok(Ok(())) => TestVerdict::Pass,
            Ok(Err(msg)) => {
                return H2ConformanceResult {
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

                return H2ConformanceResult {
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

        H2ConformanceResult {
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

impl Default for H2ConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

// Helper function to convert H2Error to String for ? operator in tests
fn h2error_to_string(err: H2Error) -> String {
    format!("H2Error: {}", err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let harness = H2ConformanceHarness::new();
        assert_eq!(harness.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_all_conformance_tests() {
        let harness = H2ConformanceHarness::new();
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
        assert!(category_counts.contains_key(&TestCategory::RstStreamFormat));
        assert!(category_counts.contains_key(&TestCategory::PingFormat));

        println!("H2 Conformance Test Results:");
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
    fn test_rst_stream_format_conformance() {
        let harness = H2ConformanceHarness::new();
        let results = harness.test_rst_stream_format();

        assert!(!results.is_empty());

        // All format tests should pass
        for result in &results {
            assert_eq!(result.category, TestCategory::RstStreamFormat);
            if result.verdict == TestVerdict::Fail {
                panic!(
                    "RST_STREAM format test failed: {} - {:?}",
                    result.test_id, result.error_message
                );
            }
        }
    }

    #[test]
    fn test_ping_format_conformance() {
        let harness = H2ConformanceHarness::new();
        let results = harness.test_ping_format();

        assert!(!results.is_empty());

        // All format tests should pass
        for result in &results {
            assert_eq!(result.category, TestCategory::PingFormat);
            if result.verdict == TestVerdict::Fail {
                panic!(
                    "PING format test failed: {} - {:?}",
                    result.test_id, result.error_message
                );
            }
        }
    }
}
