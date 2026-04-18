#![no_main]

//! Fuzz target for src/net/websocket/client.rs close frame status code parsing.
//!
//! This fuzzer validates the security properties of WebSocket close frame parsing:
//! 1. Status code in allowed range per RFC 6455 Section 7.4.1
//! 2. Reason text UTF-8 validated
//! 3. Close codes 1005/1006 reserved (wire-only, not in sent frames)
//! 4. Close code + reason length bounds enforced
//! 5. Close code 1000 (Normal Closure) correctly handled

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::net::websocket::{
    close::{CloseCode, CloseReason},
    frame::{Frame, FrameCodec, Opcode, WsError},
};
use libfuzzer_sys::fuzz_target;

/// Structured input for controlled WebSocket close frame fuzzing scenarios.
#[derive(Arbitrary, Debug)]
enum CloseFuzzInput {
    /// Raw close frame payload bytes
    RawPayload(Vec<u8>),

    /// Structured close frame with known code and reason
    StructuredClose {
        code: Option<CloseCodeWrapper>,
        reason: Option<String>,
    },

    /// Edge case close frame scenarios
    EdgeCase(EdgeCaseScenario),

    /// Full frame fuzzing with close opcode
    FullFrame {
        payload: Vec<u8>,
        fin: bool,
        rsv1: bool,
        rsv2: bool,
        rsv3: bool,
    },

    /// UTF-8 boundary testing
    Utf8BoundaryTest {
        code: u16,
        utf8_bytes: Vec<u8>, // Potentially invalid UTF-8
    },

    /// Status code range testing
    StatusCodeRangeTest { code: u16, reason_valid_utf8: bool },
}

#[derive(Arbitrary, Debug)]
enum CloseCodeWrapper {
    Normal,
    GoingAway,
    ProtocolError,
    Unsupported,
    Reserved,
    NoStatusReceived, // 1005 - reserved
    Abnormal,         // 1006 - reserved
    InvalidPayload,
    PolicyViolation,
    MessageTooBig,
    MandatoryExtension,
    InternalError,
    ServiceRestart,
    TryAgainLater,
    BadGateway,
    TlsHandshake, // 1015 - reserved
    Custom(u16),  // 3000-4999
}

impl From<CloseCodeWrapper> for u16 {
    fn from(wrapper: CloseCodeWrapper) -> Self {
        match wrapper {
            CloseCodeWrapper::Normal => 1000,
            CloseCodeWrapper::GoingAway => 1001,
            CloseCodeWrapper::ProtocolError => 1002,
            CloseCodeWrapper::Unsupported => 1003,
            CloseCodeWrapper::Reserved => 1004,
            CloseCodeWrapper::NoStatusReceived => 1005,
            CloseCodeWrapper::Abnormal => 1006,
            CloseCodeWrapper::InvalidPayload => 1007,
            CloseCodeWrapper::PolicyViolation => 1008,
            CloseCodeWrapper::MessageTooBig => 1009,
            CloseCodeWrapper::MandatoryExtension => 1010,
            CloseCodeWrapper::InternalError => 1011,
            CloseCodeWrapper::ServiceRestart => 1012,
            CloseCodeWrapper::TryAgainLater => 1013,
            CloseCodeWrapper::BadGateway => 1014,
            CloseCodeWrapper::TlsHandshake => 1015,
            CloseCodeWrapper::Custom(code) => code.clamp(3000, 4999),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseScenario {
    /// Empty payload
    EmptyPayload,

    /// Single byte payload (invalid per RFC)
    SingleBytePayload(u8),

    /// Code only (no reason)
    CodeOnlyPayload(u16),

    /// Maximum length reason text
    MaxLengthReason(u16), // Code + maximum control frame payload

    /// Zero-length reason with valid code
    ZeroLengthReason(u16),

    /// Invalid UTF-8 sequences
    InvalidUtf8Sequences {
        code: u16,
        invalid_utf8: InvalidUtf8Pattern,
    },

    /// Reserved/forbidden codes
    ForbiddenCodes(ForbiddenCodeTest),

    /// Boundary codes (edge of valid ranges)
    BoundaryCodes(BoundaryCodeTest),

    /// Large payload stress test
    LargePayload {
        code: u16,
        text_size: u16, // Will be clamped to control frame limit
    },
}

#[derive(Arbitrary, Debug)]
enum InvalidUtf8Pattern {
    /// Invalid UTF-8 continuation bytes
    InvalidContinuation,
    /// Overlong encoding
    Overlong,
    /// Invalid start bytes
    InvalidStart,
    /// Truncated multibyte sequence
    TruncatedSequence,
    /// Surrogate pairs (invalid in UTF-8)
    SurrogatePairs,
    /// Raw invalid bytes
    RawBytes(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum ForbiddenCodeTest {
    /// 1004 - Reserved
    Reserved1004,
    /// 1005 - No Status Received (wire-only)
    NoStatusReceived1005,
    /// 1006 - Abnormal Closure (wire-only)
    AbnormalClosure1006,
    /// 1015 - TLS Handshake (wire-only)
    TlsHandshake1015,
    /// Out of range codes
    OutOfRange(OutOfRangeCode),
}

#[derive(Arbitrary, Debug)]
enum OutOfRangeCode {
    /// Below 1000
    TooLow(u16), // 0-999
    /// In unassigned range (but should be accepted per RFC 6455 §7.4.2)
    Unassigned(u16), // 1016-2999
    /// Above valid range
    TooHigh(u16), // 5000+
}

#[derive(Arbitrary, Debug)]
enum BoundaryCodeTest {
    /// Exactly 1000 (Normal)
    ExactlyNormal,
    /// Exactly 1003 (last standard before reserved gap)
    ExactlyBeforeReserved,
    /// Exactly 1007 (first after reserved gap)
    ExactlyAfterReserved,
    /// Exactly 1014 (last standard)
    ExactlyLastStandard,
    /// Exactly 1016 (first unassigned)
    ExactlyFirstUnassigned,
    /// Exactly 2999 (last unassigned)
    ExactlyLastUnassigned,
    /// Exactly 3000 (first IANA registered)
    ExactlyFirstIana,
    /// Exactly 3999 (last IANA registered)
    ExactlyLastIana,
    /// Exactly 4000 (first private)
    ExactlyFirstPrivate,
    /// Exactly 4999 (last private)
    ExactlyLastPrivate,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = CloseFuzzInput::arbitrary(&mut u) {
        fuzz_websocket_close_frame(input);
    }

    // Also fuzz raw bytes directly for maximum coverage
    if data.len() <= 127 {
        // Control frame payload limit
        fuzz_raw_close_payload(data);
    }
});

fn fuzz_websocket_close_frame(input: CloseFuzzInput) {
    match input {
        CloseFuzzInput::RawPayload(payload) => {
            fuzz_raw_close_payload(&payload);
        }

        CloseFuzzInput::StructuredClose { code, reason } => {
            fuzz_structured_close(code, reason);
        }

        CloseFuzzInput::EdgeCase(edge) => {
            fuzz_edge_case(edge);
        }

        CloseFuzzInput::FullFrame {
            payload,
            fin,
            rsv1,
            rsv2,
            rsv3,
        } => {
            fuzz_full_frame(payload, fin, rsv1, rsv2, rsv3);
        }

        CloseFuzzInput::Utf8BoundaryTest { code, utf8_bytes } => {
            fuzz_utf8_boundary_test(code, utf8_bytes);
        }

        CloseFuzzInput::StatusCodeRangeTest {
            code,
            reason_valid_utf8,
        } => {
            fuzz_status_code_range_test(code, reason_valid_utf8);
        }
    }
}

fn fuzz_raw_close_payload(payload: &[u8]) {
    // ASSERTION 1: Status code in allowed range per RFC 6455 Section 7.4.1
    // ASSERTION 2: Reason UTF-8 validated
    // ASSERTION 3: Close codes 1005/1006 reserved and rejected

    let parse_result = CloseReason::parse(payload);

    // Check basic payload structure requirements
    match payload.len() {
        0 => {
            // Empty payload should always succeed
            assert!(
                parse_result.is_ok(),
                "Empty close payload should parse successfully"
            );
            let reason = parse_result.unwrap();
            assert!(reason.code.is_none(), "Empty payload should have no code");
            assert!(
                reason.raw_code.is_none(),
                "Empty payload should have no raw code"
            );
            assert!(reason.text.is_none(), "Empty payload should have no text");
        }

        1 => {
            // Single byte payload is always invalid per RFC 6455
            assert!(
                parse_result.is_err(),
                "Single byte close payload should be rejected"
            );
            assert!(
                matches!(parse_result, Err(WsError::InvalidClosePayload)),
                "Single byte should return InvalidClosePayload error"
            );
        }

        _ => {
            // 2+ bytes: status code + optional reason
            let code_raw = u16::from_be_bytes([payload[0], payload[1]]);

            match parse_result {
                Ok(reason) => {
                    // ASSERTION 1: Status code must be in valid range
                    assert!(
                        is_valid_received_code(code_raw),
                        "Successfully parsed code {} should be in valid received range",
                        code_raw
                    );

                    assert_eq!(
                        reason.raw_code,
                        Some(code_raw),
                        "Raw code should match parsed value"
                    );

                    // ASSERTION 2: Reason text must be valid UTF-8
                    if payload.len() > 2 {
                        let reason_bytes = &payload[2..];
                        assert!(
                            std::str::from_utf8(reason_bytes).is_ok(),
                            "Successfully parsed reason should be valid UTF-8"
                        );

                        if let Some(text) = &reason.text {
                            assert_eq!(
                                text.as_bytes(),
                                reason_bytes,
                                "Parsed text should match original bytes"
                            );
                        }
                    }

                    // ASSERTION 5: Close code 1000 Normal Closure handled correctly
                    if code_raw == 1000 {
                        assert_eq!(
                            reason.code,
                            Some(CloseCode::Normal),
                            "Code 1000 should map to CloseCode::Normal"
                        );
                        assert!(
                            reason.is_normal(),
                            "Code 1000 should be recognized as normal"
                        );
                    }
                }

                Err(WsError::InvalidClosePayload) => {
                    // Should be invalid due to one of:
                    // 1. Invalid status code (reserved/forbidden)
                    // 2. Invalid UTF-8 in reason text

                    let code_valid = is_valid_received_code(code_raw);
                    let utf8_valid = if payload.len() > 2 {
                        std::str::from_utf8(&payload[2..]).is_ok()
                    } else {
                        true
                    };

                    // ASSERTION 3: Reserved codes 1005/1006 should be rejected
                    if code_raw == 1005 || code_raw == 1006 {
                        assert!(
                            !code_valid,
                            "Reserved codes 1005/1006 should not be valid for receiving"
                        );
                    }

                    assert!(
                        !code_valid || !utf8_valid,
                        "InvalidClosePayload should only occur for invalid code {} or invalid UTF-8",
                        code_raw
                    );
                }

                Err(other) => {
                    panic!("Unexpected error for close payload parsing: {:?}", other);
                }
            }
        }
    }

    // Test round-trip encoding if parsing succeeded
    if let Ok(reason) = parse_result {
        let encoded = reason.encode();

        // ASSERTION 4: Close code + reason length bounds
        // Control frames have a maximum payload of 125 bytes
        assert!(
            encoded.len() <= 125,
            "Encoded close frame payload should not exceed 125 bytes, got {}",
            encoded.len()
        );

        // Re-parsing should yield the same result
        let reparsed = CloseReason::parse(&encoded);
        assert!(reparsed.is_ok(), "Round-trip parsing should succeed");

        let reparsed_reason = reparsed.unwrap();
        assert_eq!(
            reason.raw_code, reparsed_reason.raw_code,
            "Raw code should round-trip"
        );
        assert_eq!(reason.text, reparsed_reason.text, "Text should round-trip");
    }
}

/// Check if a code is valid for receiving (more permissive than sending)
fn is_valid_received_code(code: u16) -> bool {
    // Per RFC 6455 §7.4.2 and CloseCode::is_valid_received_code()
    matches!(code, 1000..=1003 | 1007..=1014 | 1016..=4999)
}

fn fuzz_structured_close(code_wrapper: Option<CloseCodeWrapper>, reason: Option<String>) {
    let mut payload = Vec::new();

    // Build payload
    if let Some(code_wrap) = code_wrapper {
        let code: u16 = code_wrap.into();
        payload.extend_from_slice(&code.to_be_bytes());

        if let Some(text) = reason {
            // Clamp reason text to fit within control frame limit
            let max_text_len = 125 - 2; // 125 byte limit minus 2 bytes for code
            let clamped_text = if text.len() > max_text_len {
                text.chars().take(max_text_len).collect::<String>()
            } else {
                text
            };
            payload.extend_from_slice(clamped_text.as_bytes());
        }
    } else if reason.is_some() {
        // Reason without code - use 1000 (Normal)
        payload.extend_from_slice(&1000u16.to_be_bytes());
        if let Some(text) = reason {
            let max_text_len = 123;
            let clamped_text = if text.len() > max_text_len {
                text.chars().take(max_text_len).collect::<String>()
            } else {
                text
            };
            payload.extend_from_slice(clamped_text.as_bytes());
        }
    }

    fuzz_raw_close_payload(&payload);
}

fn fuzz_edge_case(edge: EdgeCaseScenario) {
    match edge {
        EdgeCaseScenario::EmptyPayload => {
            fuzz_raw_close_payload(&[]);
        }

        EdgeCaseScenario::SingleBytePayload(byte) => {
            fuzz_raw_close_payload(&[byte]);
        }

        EdgeCaseScenario::CodeOnlyPayload(code) => {
            let payload = code.to_be_bytes();
            fuzz_raw_close_payload(&payload);
        }

        EdgeCaseScenario::MaxLengthReason(code) => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&code.to_be_bytes());

            // Fill with maximum valid reason text (125 - 2 = 123 bytes)
            let reason_text = "A".repeat(123);
            payload.extend_from_slice(reason_text.as_bytes());

            fuzz_raw_close_payload(&payload);
        }

        EdgeCaseScenario::ZeroLengthReason(code) => {
            // Code with empty reason (just the code bytes)
            let payload = code.to_be_bytes();
            fuzz_raw_close_payload(&payload);
        }

        EdgeCaseScenario::InvalidUtf8Sequences { code, invalid_utf8 } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&code.to_be_bytes());

            let invalid_bytes = generate_invalid_utf8(invalid_utf8);
            payload.extend_from_slice(&invalid_bytes);

            // Should be rejected due to invalid UTF-8
            let result = CloseReason::parse(&payload);
            if is_valid_received_code(code) {
                // Code is valid, so failure should be due to UTF-8
                assert!(result.is_err(), "Invalid UTF-8 should be rejected");
            }
        }

        EdgeCaseScenario::ForbiddenCodes(forbidden) => {
            fuzz_forbidden_codes(forbidden);
        }

        EdgeCaseScenario::BoundaryCodes(boundary) => {
            fuzz_boundary_codes(boundary);
        }

        EdgeCaseScenario::LargePayload { code, text_size } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&code.to_be_bytes());

            // Generate large but valid UTF-8 text (clamped to control frame limit)
            let actual_size = (text_size as usize).min(123); // 125 - 2 bytes for code
            let large_text = "X".repeat(actual_size);
            payload.extend_from_slice(large_text.as_bytes());

            fuzz_raw_close_payload(&payload);
        }
    }
}

fn generate_invalid_utf8(pattern: InvalidUtf8Pattern) -> Vec<u8> {
    match pattern {
        InvalidUtf8Pattern::InvalidContinuation => {
            // Start byte followed by invalid continuation
            vec![0xC2, 0x20] // 0x20 is not a valid continuation byte
        }

        InvalidUtf8Pattern::Overlong => {
            // Overlong encoding of ASCII 'A' (should be 0x41, not 0xC1 0x81)
            vec![0xC1, 0x81]
        }

        InvalidUtf8Pattern::InvalidStart => {
            // Invalid UTF-8 start byte
            vec![0xFF, 0x80]
        }

        InvalidUtf8Pattern::TruncatedSequence => {
            // Start of 3-byte sequence but truncated
            vec![0xE0, 0x80] // Missing third byte
        }

        InvalidUtf8Pattern::SurrogatePairs => {
            // UTF-16 surrogate encoded in UTF-8 (invalid)
            vec![0xED, 0xA0, 0x80] // U+D800 (high surrogate)
        }

        InvalidUtf8Pattern::RawBytes(bytes) => {
            bytes.into_iter().take(50).collect() // Limit size
        }
    }
}

fn fuzz_forbidden_codes(forbidden: ForbiddenCodeTest) {
    let code = match forbidden {
        ForbiddenCodeTest::Reserved1004 => 1004,
        ForbiddenCodeTest::NoStatusReceived1005 => 1005,
        ForbiddenCodeTest::AbnormalClosure1006 => 1006,
        ForbiddenCodeTest::TlsHandshake1015 => 1015,
        ForbiddenCodeTest::OutOfRange(out_of_range) => match out_of_range {
            OutOfRangeCode::TooLow(code) => code.min(999),
            OutOfRangeCode::Unassigned(code) => code.clamp(1016, 2999),
            OutOfRangeCode::TooHigh(code) => code.max(5000),
        },
    };

    let payload = code.to_be_bytes();
    let result = CloseReason::parse(&payload);

    // ASSERTION 3: Reserved/forbidden codes should be handled appropriately
    match code {
        1005 | 1006 => {
            // These codes are reserved for wire-only use and should be rejected
            assert!(
                result.is_err(),
                "Reserved codes {} should be rejected",
                code
            );
        }

        1004 | 1015 => {
            // These are also reserved/forbidden
            assert!(
                result.is_err(),
                "Forbidden code {} should be rejected",
                code
            );
        }

        1016..=2999 => {
            // Unassigned codes should be accepted per RFC 6455 §7.4.2
            assert!(
                result.is_ok(),
                "Unassigned code {} should be accepted",
                code
            );
        }

        0..=999 | 5000.. => {
            // Out of valid range
            assert!(
                result.is_err(),
                "Out-of-range code {} should be rejected",
                code
            );
        }

        _ => {
            // Other codes in valid ranges
            if is_valid_received_code(code) {
                assert!(result.is_ok(), "Valid code {} should be accepted", code);
            } else {
                assert!(result.is_err(), "Invalid code {} should be rejected", code);
            }
        }
    }
}

fn fuzz_boundary_codes(boundary: BoundaryCodeTest) {
    let code = match boundary {
        BoundaryCodeTest::ExactlyNormal => 1000,
        BoundaryCodeTest::ExactlyBeforeReserved => 1003,
        BoundaryCodeTest::ExactlyAfterReserved => 1007,
        BoundaryCodeTest::ExactlyLastStandard => 1014,
        BoundaryCodeTest::ExactlyFirstUnassigned => 1016,
        BoundaryCodeTest::ExactlyLastUnassigned => 2999,
        BoundaryCodeTest::ExactlyFirstIana => 3000,
        BoundaryCodeTest::ExactlyLastIana => 3999,
        BoundaryCodeTest::ExactlyFirstPrivate => 4000,
        BoundaryCodeTest::ExactlyLastPrivate => 4999,
    };

    let payload = code.to_be_bytes();
    let result = CloseReason::parse(&payload);

    // All boundary codes should be valid for receiving
    assert!(result.is_ok(), "Boundary code {} should be valid", code);

    let reason = result.unwrap();
    assert_eq!(reason.raw_code, Some(code), "Raw code should match");

    // Check specific boundary expectations
    match code {
        1000 => {
            assert_eq!(
                reason.code,
                Some(CloseCode::Normal),
                "1000 should map to Normal"
            );
            assert!(reason.is_normal(), "1000 should be recognized as normal");
        }

        1003 => {
            assert_eq!(
                reason.code,
                Some(CloseCode::Unsupported),
                "1003 should map to Unsupported"
            );
        }

        1007 => {
            assert_eq!(
                reason.code,
                Some(CloseCode::InvalidPayload),
                "1007 should map to InvalidPayload"
            );
        }

        1014 => {
            assert_eq!(
                reason.code,
                Some(CloseCode::BadGateway),
                "1014 should map to BadGateway"
            );
        }

        1016..=2999 | 3000..=4999 => {
            // Unassigned or custom codes - should parse but not map to enum
            assert!(
                reason.code.is_none(),
                "Unassigned/custom codes should not map to enum variants"
            );
            assert_eq!(reason.raw_code, Some(code), "Raw code should be preserved");
        }

        _ => {}
    }
}

fn fuzz_full_frame(payload: Vec<u8>, fin: bool, rsv1: bool, rsv2: bool, rsv3: bool) {
    // Test full frame decoding with close opcode
    let frame = Frame {
        fin,
        rsv1,
        rsv2,
        rsv3,
        opcode: Opcode::Close,
        masked: false,
        mask_key: None,
        payload: payload.into(),
    };

    // ASSERTION 4: Close code + reason length bounds
    // Control frames must have payload ≤ 125 bytes
    if payload.len() > 125 {
        // Should be rejected during frame validation
        return;
    }

    // Try to extract close reason from frame
    let reason_result = CloseReason::parse(&frame.payload);

    // Test frame-to-message conversion
    let message_result = crate::net::websocket::client::Message::try_from(frame);

    match message_result {
        Ok(message) => {
            if let crate::net::websocket::client::Message::Close(reason_opt) = message {
                match reason_result {
                    Ok(expected_reason) => {
                        match reason_opt {
                            Some(actual_reason) => {
                                assert_eq!(
                                    actual_reason.raw_code, expected_reason.raw_code,
                                    "Frame conversion should preserve raw code"
                                );
                                assert_eq!(
                                    actual_reason.text, expected_reason.text,
                                    "Frame conversion should preserve text"
                                );
                            }
                            None => {
                                // Only acceptable if payload was empty
                                assert!(
                                    payload.is_empty(),
                                    "Empty reason only valid for empty payload"
                                );
                            }
                        }
                    }
                    Err(_) => {
                        // Parse failed, so message should have None reason or conversion should fail
                        // This is acceptable behavior
                    }
                }
            } else {
                panic!("Frame with Close opcode should convert to Close message");
            }
        }

        Err(_) => {
            // Frame conversion failed - acceptable if payload is invalid
        }
    }
}

fn fuzz_utf8_boundary_test(code: u16, utf8_bytes: Vec<u8>) {
    let mut payload = Vec::new();
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(&utf8_bytes);

    let result = CloseReason::parse(&payload);

    // Check UTF-8 validity
    let is_valid_utf8 = std::str::from_utf8(&utf8_bytes).is_ok();
    let is_valid_code = is_valid_received_code(code);

    if is_valid_code && is_valid_utf8 {
        assert!(
            result.is_ok(),
            "Valid code {} with valid UTF-8 should parse",
            code
        );
    } else if !is_valid_code {
        assert!(result.is_err(), "Invalid code {} should be rejected", code);
    } else if !is_valid_utf8 {
        assert!(result.is_err(), "Invalid UTF-8 should be rejected");
    }
}

fn fuzz_status_code_range_test(code: u16, reason_valid_utf8: bool) {
    let mut payload = Vec::new();
    payload.extend_from_slice(&code.to_be_bytes());

    if reason_valid_utf8 {
        payload.extend_from_slice(b"valid reason");
    } else {
        // Add invalid UTF-8
        payload.extend_from_slice(&[0xFF, 0xFE]);
    }

    let result = CloseReason::parse(&payload);

    let is_valid_code = is_valid_received_code(code);

    if is_valid_code && reason_valid_utf8 {
        assert!(
            result.is_ok(),
            "Valid code {} with valid UTF-8 should parse",
            code
        );

        let reason = result.unwrap();
        assert_eq!(reason.raw_code, Some(code), "Raw code should match");

        // ASSERTION 5: Normal closure handling
        if code == 1000 {
            assert_eq!(
                reason.code,
                Some(CloseCode::Normal),
                "Code 1000 should be Normal"
            );
            assert!(reason.is_normal(), "Code 1000 should be normal");
        }
    } else {
        assert!(
            result.is_err(),
            "Invalid code {} or UTF-8 should be rejected",
            code
        );
    }
}

/// Stress test with comprehensive edge cases
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_standard_close_codes() {
        let standard_codes = [
            1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014,
        ];

        for &code in &standard_codes {
            let payload = code.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(result.is_ok(), "Standard code {} should parse", code);

            let reason = result.unwrap();
            assert_eq!(reason.raw_code, Some(code));

            if code == 1000 {
                assert!(reason.is_normal(), "Code 1000 should be normal");
            }
        }
    }

    #[test]
    fn test_reserved_codes_rejected() {
        let reserved_codes = [1004, 1005, 1006, 1015];

        for &code in &reserved_codes {
            let payload = code.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(result.is_err(), "Reserved code {} should be rejected", code);
        }
    }

    #[test]
    fn test_utf8_validation() {
        // Valid UTF-8
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice("Hello 🌍".as_bytes());

        let result = CloseReason::parse(&payload);
        assert!(result.is_ok(), "Valid UTF-8 should parse");

        // Invalid UTF-8
        let mut invalid_payload = Vec::new();
        invalid_payload.extend_from_slice(&1000u16.to_be_bytes());
        invalid_payload.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8

        let invalid_result = CloseReason::parse(&invalid_payload);
        assert!(invalid_result.is_err(), "Invalid UTF-8 should be rejected");
    }

    #[test]
    fn test_length_bounds() {
        // Maximum control frame payload
        let mut max_payload = Vec::new();
        max_payload.extend_from_slice(&1000u16.to_be_bytes());
        max_payload.extend_from_slice("A".repeat(123).as_bytes()); // 125 total

        assert_eq!(
            max_payload.len(),
            125,
            "Should be exactly at control frame limit"
        );

        let result = CloseReason::parse(&max_payload);
        assert!(result.is_ok(), "Maximum length payload should parse");
    }

    #[test]
    fn test_unassigned_codes_accepted() {
        // RFC 6455 §7.4.2: codes 1016-2999 should be accepted
        let unassigned_codes = [1016, 1500, 2000, 2999];

        for &code in &unassigned_codes {
            let payload = code.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(
                result.is_ok(),
                "Unassigned code {} should be accepted",
                code
            );

            let reason = result.unwrap();
            assert_eq!(reason.raw_code, Some(code));
            assert!(
                reason.code.is_none(),
                "Unassigned codes should not map to enum"
            );
        }
    }

    #[test]
    fn test_custom_codes_accepted() {
        // Custom codes 3000-4999 should be accepted
        let custom_codes = [3000, 3500, 4000, 4999];

        for &code in &custom_codes {
            let payload = code.to_be_bytes();
            let result = CloseReason::parse(&payload);
            assert!(result.is_ok(), "Custom code {} should be accepted", code);
        }
    }
}
