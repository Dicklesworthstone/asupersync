//! WebSocket RFC 6455 Close Frame Conformance Tests
//!
//! This module provides comprehensive conformance testing for WebSocket close frame
//! semantics and status codes per RFC 6455. The tests systematically validate:
//!
//! - Close frame format and payload structure (RFC 6455 §5.5.1)
//! - Status code semantics and validation (RFC 6455 §7.4)
//! - Close handshake protocol compliance (RFC 6455 §7.1.2-7.1.6)
//! - Control frame size limits (RFC 6455 §5.5)
//! - UTF-8 validation for close reason text
//! - Proper error handling for invalid close frames
//!
//! # RFC 6455 Close Frame Requirements
//!
//! **§7.4 Status Codes:**
//! - 1000: Normal closure
//! - 1001: Going away (endpoint going down)
//! - 1002: Protocol error
//! - 1003: Unsupported data type
//! - 1004: Reserved (never sent in frame)
//! - 1005: No status received (never sent in frame)
//! - 1006: Abnormal closure (never sent in frame)
//! - 1007: Invalid frame payload data (e.g., non-UTF-8)
//! - 1008: Policy violation
//! - 1009: Message too big
//! - 1010: Mandatory extension
//! - 1011: Internal server error
//! - 1015: TLS handshake (never sent in frame)
//!
//! **§7.1.2-7.1.6 Close Handshake:**
//! 1. Initiator sends Close frame with optional status code/reason
//! 2. Receiver echoes Close frame back (typically same status code)
//! 3. Both endpoints close underlying connection
//!
//! **§5.5.1 Close Frame Payload:**
//! - Empty: No status code or reason
//! - 2 bytes: Status code only (big-endian u16)
//! - 2+ bytes: Status code + UTF-8 reason text
//! - Maximum 125 bytes total (control frame limit)

use asupersync::net::websocket::{
    CloseCode, CloseHandshake, CloseReason, CloseState, Frame, FrameCodec, Opcode, WsError,
};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};

/// Test result for a single conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct WsConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub notes: Option<String>,
    pub elapsed_ms: u64,
}

/// Conformance test categories for WebSocket close frames.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TestCategory {
    FrameFormat,
    Handshake,
    ControlFrames,
    ConnectionClose,
    Extensions,
    Subprotocols,
    Masking,
    Fragmentation,
    ErrorHandling,
    DataFrames,
}

/// RFC conformance requirement level.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // RFC 2119 MUST
    Should, // RFC 2119 SHOULD
    May,    // RFC 2119 MAY
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// WebSocket RFC 6455 close frame conformance test harness.
#[allow(dead_code)]
pub struct WsConformanceHarness {
    results: Vec<WsConformanceResult>,
}

#[allow(dead_code)]

impl WsConformanceHarness {
    /// Create a new conformance test harness.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Execute all conformance tests.
    #[allow(dead_code)]
    pub fn run_all_tests(&mut self) -> Vec<WsConformanceResult> {
        // RFC 6455 §5.5.1 - Close Frame Format Tests
        self.test_close_frame_empty_payload();
        self.test_close_frame_code_only();
        self.test_close_frame_code_and_reason();
        self.test_close_frame_invalid_single_byte();
        self.test_close_frame_oversized_payload();

        // RFC 6455 §7.4 - Status Code Semantics Tests
        self.test_status_code_normal_closure();
        self.test_status_code_going_away();
        self.test_status_code_protocol_error();
        self.test_status_code_unsupported_data();
        self.test_status_code_invalid_payload();
        self.test_status_code_policy_violation();
        self.test_status_code_message_too_big();
        self.test_status_code_mandatory_extension();
        self.test_status_code_internal_error();

        // RFC 6455 §7.4 - Reserved Status Code Tests
        self.test_status_code_reserved_never_sent();
        self.test_status_code_no_status_received_never_sent();
        self.test_status_code_abnormal_never_sent();
        self.test_status_code_tls_handshake_never_sent();

        // RFC 6455 §7.4 - Status Code Range Validation
        self.test_status_code_range_validation();
        self.test_status_code_iana_registered();
        self.test_status_code_private_use();
        self.test_status_code_unassigned_acceptance();

        // RFC 6455 §7.1.2-7.1.6 - Close Handshake Protocol Tests
        self.test_handshake_initiator_flow();
        self.test_handshake_receiver_flow();
        self.test_handshake_echo_status_code();
        self.test_handshake_empty_close_echo();
        self.test_handshake_custom_code_echo();

        // RFC 6455 §5.5 - Control Frame Limits
        self.test_control_frame_125_byte_limit();
        self.test_control_frame_fin_bit_required();

        // Text Encoding Tests (RFC 6455 §5.6)
        self.test_close_reason_utf8_validation();
        self.test_close_reason_invalid_utf8_rejection();

        // Error Handling Tests
        self.test_invalid_opcode_rejection();
        self.test_malformed_payload_rejection();

        // Round-trip Encoding Tests
        self.test_close_frame_encode_decode_roundtrip();

        self.results.clone()
    }

    #[allow(dead_code)]

    fn record_result(&mut self, test_id: &str, description: &str, category: TestCategory,
                    requirement: RequirementLevel, verdict: TestVerdict, notes: Option<String>) {
        self.results.push(WsConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level: requirement,
            verdict,
            notes,
            elapsed_ms: 0, // TODO: Add timing if needed
        });
    }

    // ===== RFC 6455 §5.5.1 - Close Frame Format Tests =====

    #[allow(dead_code)]

    fn test_close_frame_empty_payload(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let reason = CloseReason::parse(&[]).expect("empty payload should parse");
            assert_eq!(reason.code, None);
            assert_eq!(reason.raw_code, None);
            assert_eq!(reason.text, None);

            let encoded = reason.encode();
            assert!(encoded.is_empty());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5.1-001",
            "Close frame with empty payload MUST be accepted",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_close_frame_code_only(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let payload = 1000u16.to_be_bytes();
            let reason = CloseReason::parse(&payload).expect("code-only payload should parse");

            assert_eq!(reason.code, Some(CloseCode::Normal));
            assert_eq!(reason.raw_code, Some(1000));
            assert_eq!(reason.text, None);

            let encoded = reason.encode();
            assert_eq!(encoded.as_ref(), &1000u16.to_be_bytes());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5.1-002",
            "Close frame with status code only MUST be accepted",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_close_frame_code_and_reason(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1001u16.to_be_bytes());
            payload.extend_from_slice(b"Going away");

            let reason = CloseReason::parse(&payload).expect("code+reason should parse");
            assert_eq!(reason.code, Some(CloseCode::GoingAway));
            assert_eq!(reason.raw_code, Some(1001));
            assert_eq!(reason.text.as_deref(), Some("Going away"));

            let encoded = reason.encode();
            assert_eq!(encoded.as_ref(), payload.as_slice());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5.1-003",
            "Close frame with status code and reason text MUST be accepted",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_close_frame_invalid_single_byte(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let result = CloseReason::parse(&[0x42]);
            assert!(result.is_err(), "single-byte payload should be rejected");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5.1-004",
            "Close frame with single-byte payload MUST be rejected",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_close_frame_oversized_payload(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // RFC 6455 §5.5: Control frames MUST have payload ≤ 125 bytes
            let reason_text = "a".repeat(124); // 2 bytes code + 124 bytes text = 126 bytes
            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1000), Some(&reason_text))
            });
            assert!(should_panic.is_err(), "oversized close frame should panic");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5.1-005",
            "Close frame payload exceeding 125 bytes MUST be rejected",
            TestCategory::ControlFrames,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== RFC 6455 §7.4 - Status Code Semantics Tests =====

    #[allow(dead_code)]

    fn test_status_code_normal_closure(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::Normal), 1000);
            assert!(CloseCode::Normal.is_sendable());

            let reason = CloseReason::new(CloseCode::Normal, None);
            assert!(reason.is_normal());
            assert!(!reason.is_error());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-001",
            "Status code 1000 (Normal) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_going_away(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::GoingAway), 1001);
            assert!(CloseCode::GoingAway.is_sendable());

            let reason = CloseReason::new(CloseCode::GoingAway, Some("Server shutdown"));
            assert!(!reason.is_normal());
            assert!(!reason.is_error());
            assert_eq!(reason.wire_code(), Some(1001));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-002",
            "Status code 1001 (Going Away) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_protocol_error(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::ProtocolError), 1002);
            assert!(CloseCode::ProtocolError.is_sendable());

            let reason = CloseReason::new(CloseCode::ProtocolError, Some("Invalid frame"));
            assert!(reason.is_error());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-003",
            "Status code 1002 (Protocol Error) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_unsupported_data(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::Unsupported), 1003);
            assert!(CloseCode::Unsupported.is_sendable());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-004",
            "Status code 1003 (Unsupported Data) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_invalid_payload(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::InvalidPayload), 1007);
            assert!(CloseCode::InvalidPayload.is_sendable());

            let reason = CloseReason::new(CloseCode::InvalidPayload, Some("Non-UTF-8 data"));
            assert!(reason.is_error());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-005",
            "Status code 1007 (Invalid Payload) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_policy_violation(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::PolicyViolation), 1008);
            assert!(CloseCode::PolicyViolation.is_sendable());

            let reason = CloseReason::new(CloseCode::PolicyViolation, Some("Rate limit exceeded"));
            assert!(reason.is_error());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-006",
            "Status code 1008 (Policy Violation) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_message_too_big(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::MessageTooBig), 1009);
            assert!(CloseCode::MessageTooBig.is_sendable());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-007",
            "Status code 1009 (Message Too Big) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_mandatory_extension(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::MandatoryExtension), 1010);
            assert!(CloseCode::MandatoryExtension.is_sendable());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-008",
            "Status code 1010 (Mandatory Extension) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_internal_error(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::InternalError), 1011);
            assert!(CloseCode::InternalError.is_sendable());

            let reason = CloseReason::new(CloseCode::InternalError, Some("Database error"));
            assert!(reason.is_error());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-009",
            "Status code 1011 (Internal Error) semantics MUST be correct",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Reserved Status Code Tests =====

    #[allow(dead_code)]

    fn test_status_code_reserved_never_sent(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::Reserved), 1004);
            assert!(!CloseCode::Reserved.is_sendable());

            // Should panic when trying to create frame with reserved code
            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1004), None)
            });
            assert!(should_panic.is_err(), "Frame::close should panic for reserved codes");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-010",
            "Status code 1004 (Reserved) MUST NOT be sent in close frame",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_no_status_received_never_sent(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::NoStatusReceived), 1005);
            assert!(!CloseCode::NoStatusReceived.is_sendable());

            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1005), None)
            });
            assert!(should_panic.is_err());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-011",
            "Status code 1005 (No Status Received) MUST NOT be sent in close frame",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_abnormal_never_sent(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::Abnormal), 1006);
            assert!(!CloseCode::Abnormal.is_sendable());

            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1006), None)
            });
            assert!(should_panic.is_err());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-012",
            "Status code 1006 (Abnormal Closure) MUST NOT be sent in close frame",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_tls_handshake_never_sent(&mut self) {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(u16::from(CloseCode::TlsHandshake), 1015);
            assert!(!CloseCode::TlsHandshake.is_sendable());

            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1015), None)
            });
            assert!(should_panic.is_err());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-013",
            "Status code 1015 (TLS Handshake) MUST NOT be sent in close frame",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Status Code Range Validation =====

    #[allow(dead_code)]

    fn test_status_code_range_validation(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Valid sendable codes
            assert!(CloseCode::is_valid_code(1000));
            assert!(CloseCode::is_valid_code(1001));
            assert!(CloseCode::is_valid_code(1002));
            assert!(CloseCode::is_valid_code(1003));
            assert!(CloseCode::is_valid_code(1007));
            assert!(CloseCode::is_valid_code(1008));
            assert!(CloseCode::is_valid_code(1009));
            assert!(CloseCode::is_valid_code(1010));
            assert!(CloseCode::is_valid_code(1011));
            assert!(CloseCode::is_valid_code(3000));
            assert!(CloseCode::is_valid_code(4999));

            // Invalid codes
            assert!(!CloseCode::is_valid_code(999));   // Below range
            assert!(!CloseCode::is_valid_code(1004));  // Reserved
            assert!(!CloseCode::is_valid_code(1005));  // Never sent
            assert!(!CloseCode::is_valid_code(1006));  // Never sent
            assert!(!CloseCode::is_valid_code(1015));  // Never sent
            assert!(!CloseCode::is_valid_code(5000));  // Above range
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-014",
            "Status code range validation MUST follow RFC 6455 specification",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_iana_registered(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // IANA registered codes should be valid
            assert!(CloseCode::is_valid_code(1012)); // Service restart
            assert!(CloseCode::is_valid_code(1013)); // Try again later
            assert!(CloseCode::is_valid_code(1014)); // Bad gateway
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-015",
            "IANA registered status codes MUST be accepted",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_private_use(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Private use range 4000-4999
            assert!(CloseCode::is_valid_code(4000));
            assert!(CloseCode::is_valid_code(4500));
            assert!(CloseCode::is_valid_code(4999));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-016",
            "Private use status codes (4000-4999) MUST be accepted",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_status_code_unassigned_acceptance(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // RFC 6455 §7.4.2: unassigned codes (1016-2999) must be accepted when received
            assert!(CloseCode::is_valid_received_code(1016));
            assert!(CloseCode::is_valid_received_code(2000));
            assert!(CloseCode::is_valid_received_code(2999));

            // But not valid for sending
            assert!(!CloseCode::is_valid_code(1016));
            assert!(!CloseCode::is_valid_code(2000));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.4-017",
            "Unassigned status codes MUST be accepted when received per §7.4.2",
            TestCategory::ConnectionClose,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Close Handshake Protocol Tests =====

    #[allow(dead_code)]

    fn test_handshake_initiator_flow(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();
            assert_eq!(handshake.state(), CloseState::Open);

            // 1. Initiate close
            let close_frame = handshake.initiate(CloseReason::normal()).unwrap();
            assert_eq!(close_frame.opcode, Opcode::Close);
            assert_eq!(handshake.state(), CloseState::CloseSent);

            // 2. Receive peer's close response
            let peer_response = Frame::close(Some(1000), None);
            let no_response = handshake.receive_close(&peer_response).unwrap();
            assert!(no_response.is_none()); // No response needed, handshake complete
            assert_eq!(handshake.state(), CloseState::Closed);
            assert!(handshake.is_closed());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.1.2-001",
            "Close handshake initiator flow MUST follow RFC 6455 protocol",
            TestCategory::Handshake,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_handshake_receiver_flow(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();
            assert_eq!(handshake.state(), CloseState::Open);

            // 1. Receive peer's close
            let peer_close = Frame::close(Some(1001), Some("going away"));
            let response = handshake.receive_close(&peer_close).unwrap().unwrap();
            assert_eq!(response.opcode, Opcode::Close);
            assert_eq!(handshake.state(), CloseState::CloseReceived);

            // 2. Send our close response (transition to Closed)
            handshake.mark_response_sent();
            assert_eq!(handshake.state(), CloseState::Closed);
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.1.2-002",
            "Close handshake receiver flow MUST follow RFC 6455 protocol",
            TestCategory::Handshake,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_handshake_echo_status_code(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();

            // Peer sends close with status code 1001
            let peer_close = Frame::close(Some(1001), Some("server shutdown"));
            let response = handshake.receive_close(&peer_close).unwrap().unwrap();

            // Response should echo the same status code
            assert_eq!(response.opcode, Opcode::Close);
            assert_eq!(&response.payload[..2], &1001u16.to_be_bytes());

            // Verify peer reason was captured
            let peer_reason = handshake.peer_reason().unwrap();
            assert_eq!(peer_reason.wire_code(), Some(1001));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.1.6-001",
            "Close handshake MUST echo peer's status code",
            TestCategory::Handshake,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_handshake_empty_close_echo(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();

            // Peer sends empty close frame
            let peer_close = Frame::close(None, None);
            let response = handshake.receive_close(&peer_close).unwrap().unwrap();

            // Response should also be empty
            assert_eq!(response.opcode, Opcode::Close);
            assert!(response.payload.is_empty());

            let peer_reason = handshake.peer_reason().unwrap();
            assert_eq!(peer_reason, &CloseReason::empty());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.1.6-002",
            "Empty close frame MUST be echoed as empty",
            TestCategory::Handshake,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_handshake_custom_code_echo(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();

            // Peer sends custom code in private use range
            let peer_close = Frame::close(Some(4000), Some("custom"));
            let response = handshake.receive_close(&peer_close).unwrap().unwrap();

            // Must echo custom code verbatim
            assert_eq!(response.opcode, Opcode::Close);
            assert_eq!(&response.payload[..2], &4000u16.to_be_bytes());

            let peer_reason = handshake.peer_reason().unwrap();
            assert_eq!(peer_reason.wire_code(), Some(4000));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-7.1.6-003",
            "Custom status codes MUST be echoed verbatim",
            TestCategory::Handshake,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Control Frame Limits =====

    #[allow(dead_code)]

    fn test_control_frame_125_byte_limit(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Maximum valid close frame: 2 bytes code + 123 bytes reason = 125 bytes
            let max_reason = "a".repeat(123);
            let frame = Frame::close(Some(1000), Some(&max_reason));
            assert_eq!(frame.payload.len(), 125);

            // One byte over should panic
            let over_reason = "a".repeat(124);
            let should_panic = std::panic::catch_unwind(|| {
                Frame::close(Some(1000), Some(&over_reason))
            });
            assert!(should_panic.is_err());
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5-001",
            "Control frames MUST NOT exceed 125-byte payload limit",
            TestCategory::ControlFrames,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_control_frame_fin_bit_required(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let frame = Frame::close(Some(1000), None);
            assert!(frame.fin, "Close frame must have FIN bit set");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.5-002",
            "Control frames MUST have FIN bit set",
            TestCategory::ControlFrames,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Text Encoding Tests =====

    #[allow(dead_code)]

    fn test_close_reason_utf8_validation(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1000u16.to_be_bytes());
            payload.extend_from_slice("Hello, 世界!".as_bytes()); // Valid UTF-8

            let reason = CloseReason::parse(&payload).expect("Valid UTF-8 should parse");
            assert_eq!(reason.text.as_deref(), Some("Hello, 世界!"));
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.6-001",
            "Close reason text MUST accept valid UTF-8",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_close_reason_invalid_utf8_rejection(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1000u16.to_be_bytes());
            payload.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8

            let result = CloseReason::parse(&payload);
            assert!(result.is_err(), "Invalid UTF-8 should be rejected");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-5.6-002",
            "Close reason text MUST reject invalid UTF-8",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Error Handling Tests =====

    #[allow(dead_code)]

    fn test_invalid_opcode_rejection(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let mut handshake = CloseHandshake::new();

            // Create a non-close frame
            let ping_frame = Frame::ping("test");
            let result = handshake.receive_close(&ping_frame);

            assert!(result.is_err(), "Non-close frame should be rejected");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-ERROR-001",
            "Non-close frames MUST be rejected by close handshake",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_malformed_payload_rejection(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Invalid reserved code
            let payload = 1004u16.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(result.is_err(), "Reserved code should be rejected");

            // Invalid range
            let payload = 999u16.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(result.is_err(), "Out-of-range code should be rejected");
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-ERROR-002",
            "Malformed close payloads MUST be rejected",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Round-trip Tests =====

    #[allow(dead_code)]

    fn test_close_frame_encode_decode_roundtrip(&mut self) {
        let result = std::panic::catch_unwind(|| {
            let test_cases = vec![
                CloseReason::empty(),
                CloseReason::normal(),
                CloseReason::going_away(),
                CloseReason::with_text(CloseCode::Normal, "goodbye"),
                CloseReason::with_text(CloseCode::GoingAway, "Server restart"),
                CloseReason::with_text(CloseCode::ProtocolError, "Invalid frame received"),
            ];

            for original in test_cases {
                let encoded = original.encode();
                let decoded = CloseReason::parse(&encoded).expect("Round-trip should succeed");

                assert_eq!(original.code, decoded.code, "Code should round-trip");
                assert_eq!(original.raw_code, decoded.raw_code, "Raw code should round-trip");
                assert_eq!(original.text, decoded.text, "Text should round-trip");
            }
        });

        let verdict = if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail };
        self.record_result(
            "RFC6455-ROUNDTRIP-001",
            "Close frame encoding/decoding MUST be symmetric",
            TestCategory::FrameFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }
}

impl Default for WsConformanceHarness {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_conformance_suite_completeness() {
        let mut harness = WsConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have comprehensive coverage
        assert!(!results.is_empty(), "Should have conformance test results");

        // Check categories are covered
        let categories: std::collections::HashSet<_> =
            results.iter().map(|r| &r.category).collect();

        assert!(categories.contains(&TestCategory::FrameFormat));
        assert!(categories.contains(&TestCategory::ConnectionClose));
        assert!(categories.contains(&TestCategory::Handshake));
        assert!(categories.contains(&TestCategory::ControlFrames));
        assert!(categories.contains(&TestCategory::ErrorHandling));

        // All MUST requirements should pass
        let must_failures: Vec<_> = results.iter()
            .filter(|r| r.requirement_level == RequirementLevel::Must && r.verdict == TestVerdict::Fail)
            .collect();

        if !must_failures.is_empty() {
            panic!("MUST requirements failed: {:#?}", must_failures);
        }

        println!("✅ WebSocket RFC 6455 close-frame conformance: {} tests passed", results.len());
    }

    #[test]
    #[allow(dead_code)]
    fn test_close_code_coverage() {
        // Verify we test all defined close codes
        assert_eq!(u16::from(CloseCode::Normal), 1000);
        assert_eq!(u16::from(CloseCode::GoingAway), 1001);
        assert_eq!(u16::from(CloseCode::ProtocolError), 1002);
        assert_eq!(u16::from(CloseCode::Unsupported), 1003);
        assert_eq!(u16::from(CloseCode::Reserved), 1004);
        assert_eq!(u16::from(CloseCode::NoStatusReceived), 1005);
        assert_eq!(u16::from(CloseCode::Abnormal), 1006);
        assert_eq!(u16::from(CloseCode::InvalidPayload), 1007);
        assert_eq!(u16::from(CloseCode::PolicyViolation), 1008);
        assert_eq!(u16::from(CloseCode::MessageTooBig), 1009);
        assert_eq!(u16::from(CloseCode::MandatoryExtension), 1010);
        assert_eq!(u16::from(CloseCode::InternalError), 1011);
        assert_eq!(u16::from(CloseCode::TlsHandshake), 1015);
    }

    #[test]
    #[allow(dead_code)]
    fn test_rfc_section_coverage() {
        // Verify key RFC sections are tested
        let mut harness = WsConformanceHarness::new();
        let results = harness.run_all_tests();

        let test_ids: std::collections::HashSet<String> =
            results.into_iter().map(|r| r.test_id).collect();

        // §5.5.1 Close frame format
        assert!(test_ids.contains("RFC6455-5.5.1-001"));
        assert!(test_ids.contains("RFC6455-5.5.1-002"));
        assert!(test_ids.contains("RFC6455-5.5.1-003"));

        // §7.4 Status codes
        assert!(test_ids.contains("RFC6455-7.4-001"));
        assert!(test_ids.contains("RFC6455-7.4-010"));

        // §7.1.2-7.1.6 Close handshake
        assert!(test_ids.contains("RFC6455-7.1.2-001"));
        assert!(test_ids.contains("RFC6455-7.1.6-001"));

        // §5.5 Control frame limits
        assert!(test_ids.contains("RFC6455-5.5-001"));
    }
}