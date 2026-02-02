//! Security invariant tests for Asupersync.
//!
//! These tests verify that critical security properties hold across the codebase.
//! They are designed to catch regressions in security-sensitive code.

#![allow(clippy::similar_names)]

use asupersync::bytes::BytesMut;
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder, Settings, SettingsBuilder};
use asupersync::net::websocket::{CloseReason, Frame, Opcode, WsError};

// =============================================================================
// HTTP/2 SECURITY INVARIANTS
// =============================================================================

mod http2_security {
    use super::*;

    /// Verify that max_concurrent_streams has a reasonable default.
    #[test]
    fn invariant_max_concurrent_streams_bounded() {
        let settings = Settings::default();
        assert!(
            settings.max_concurrent_streams <= 1000,
            "max_concurrent_streams should be bounded to prevent stream exhaustion"
        );
        assert!(
            settings.max_concurrent_streams >= 1,
            "max_concurrent_streams should allow at least one stream"
        );
    }

    /// Verify that max_header_list_size is bounded.
    #[test]
    fn invariant_max_header_list_size_bounded() {
        let settings = Settings::default();
        assert!(
            settings.max_header_list_size <= 1024 * 1024, // 1 MB
            "max_header_list_size should be bounded to prevent memory exhaustion"
        );
    }

    /// Verify that max_frame_size is within RFC 7540 limits.
    #[test]
    fn invariant_max_frame_size_rfc_compliant() {
        let settings = Settings::default();
        // RFC 7540: SETTINGS_MAX_FRAME_SIZE must be between 2^14 and 2^24-1
        assert!(
            settings.max_frame_size >= 16384,
            "max_frame_size must be at least 16384 (2^14) per RFC 7540"
        );
        assert!(
            settings.max_frame_size <= 16_777_215,
            "max_frame_size must not exceed 16777215 (2^24-1) per RFC 7540"
        );
    }

    /// Verify that initial_window_size doesn't exceed RFC 7540 limits.
    #[test]
    fn invariant_initial_window_size_bounded() {
        let settings = Settings::default();
        // RFC 7540: SETTINGS_INITIAL_WINDOW_SIZE must be <= 2^31-1
        assert!(
            settings.initial_window_size <= 2_147_483_647,
            "initial_window_size must not exceed 2^31-1 per RFC 7540"
        );
    }

    /// Verify settings can be constructed safely.
    #[test]
    fn invariant_settings_builder_creates_valid_settings() {
        // Valid settings should work
        let settings = SettingsBuilder::new()
            .max_concurrent_streams(100)
            .max_header_list_size(65536)
            .build();

        assert_eq!(settings.max_concurrent_streams, 100);
        assert_eq!(settings.max_header_list_size, 65536);
    }

    /// Verify continuation timeout is set.
    #[test]
    fn invariant_continuation_timeout_set() {
        let settings = Settings::default();
        assert!(
            settings.continuation_timeout_ms > 0,
            "CONTINUATION timeout should be non-zero"
        );
        assert!(
            settings.continuation_timeout_ms <= 30_000,
            "CONTINUATION timeout should be reasonable (<=30s)"
        );
    }
}

// =============================================================================
// WEBSOCKET SECURITY INVARIANTS
// =============================================================================

mod websocket_security {
    use super::*;

    /// Verify that invalid opcodes are rejected.
    #[test]
    fn invariant_invalid_opcode_rejected() {
        // Reserved opcodes should be rejected
        for opcode in [0x03, 0x04, 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F] {
            let result = Opcode::from_u8(opcode);
            assert!(
                result.is_err(),
                "Reserved opcode {:#x} should be rejected",
                opcode
            );
        }
    }

    /// Verify that valid opcodes are accepted.
    #[test]
    fn invariant_valid_opcode_accepted() {
        // Valid opcodes per RFC 6455
        let valid_opcodes = [
            (0x0, Opcode::Continuation),
            (0x1, Opcode::Text),
            (0x2, Opcode::Binary),
            (0x8, Opcode::Close),
            (0x9, Opcode::Ping),
            (0xA, Opcode::Pong),
        ];

        for (byte, expected) in valid_opcodes {
            let result = Opcode::from_u8(byte);
            assert!(
                result.is_ok(),
                "Valid opcode {:#x} should be accepted",
                byte
            );
            assert_eq!(result.unwrap(), expected);
        }
    }

    /// Verify control frames are correctly identified.
    #[test]
    fn invariant_control_frame_identification() {
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(!Opcode::Continuation.is_control());
    }

    /// Verify data frames are correctly identified.
    #[test]
    fn invariant_data_frame_identification() {
        assert!(Opcode::Text.is_data());
        assert!(Opcode::Binary.is_data());
        assert!(Opcode::Continuation.is_data());
        assert!(!Opcode::Close.is_data());
        assert!(!Opcode::Ping.is_data());
        assert!(!Opcode::Pong.is_data());
    }

    /// Verify close reason parsing for valid payloads.
    #[test]
    fn invariant_close_reason_valid_parsed() {
        // Valid close reason: status code 1000 (normal closure) + "Goodbye"
        let valid_payload = vec![0x03, 0xE8, b'G', b'o', b'o', b'd', b'b', b'y', b'e'];
        let result = CloseReason::parse(&valid_payload);
        assert!(result.is_ok(), "Valid close reason should parse");

        // Empty payload is also valid (no code, no reason)
        let empty_payload: Vec<u8> = vec![];
        let result = CloseReason::parse(&empty_payload);
        assert!(result.is_ok(), "Empty close payload should be valid");
    }

    /// Verify WsError types are distinguishable.
    #[test]
    fn invariant_ws_error_distinct() {
        let invalid_opcode = WsError::InvalidOpcode(0xFF);
        let invalid_utf8 = WsError::InvalidUtf8;
        let reserved_bits = WsError::ReservedBitsSet;

        // Different error kinds should be distinguishable
        assert!(!matches!(invalid_opcode, WsError::InvalidUtf8));
        assert!(!matches!(invalid_utf8, WsError::InvalidOpcode(_)));
        assert!(!matches!(reserved_bits, WsError::InvalidOpcode(_)));
    }
}

// =============================================================================
// HPACK SECURITY INVARIANTS
// =============================================================================

mod hpack_security {
    use super::*;

    /// Verify that HPACK encoder produces bounded output.
    #[test]
    fn invariant_hpack_encoding_bounded() {
        let mut encoder = HpackEncoder::new();
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        let mut buf = BytesMut::with_capacity(4096);
        encoder.encode(&headers, &mut buf);

        // Output should be reasonable for typical headers
        // HPACK can compress or expand depending on table state
        assert!(
            buf.len() <= 4096,
            "HPACK encoding should not produce unbounded output"
        );
    }

    /// Verify decode-encode roundtrip preserves headers.
    #[test]
    fn invariant_hpack_roundtrip() {
        let original_headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/api/v1/data"),
            Header::new("content-type", "application/json"),
        ];

        // Encode
        let mut encoder = HpackEncoder::new();
        let mut buf = BytesMut::with_capacity(256);
        encoder.encode(&original_headers, &mut buf);
        let encoded = buf.freeze();

        // Decode
        let mut decoder = HpackDecoder::new();
        let mut encoded_copy = encoded.clone();
        let decoded = decoder.decode(&mut encoded_copy).expect("decode should succeed");

        // Verify count matches
        assert_eq!(
            decoded.len(),
            original_headers.len(),
            "Decoded header count should match"
        );

        // Verify header content matches (using field access)
        for (orig, dec) in original_headers.iter().zip(decoded.iter()) {
            assert_eq!(&orig.name, &dec.name);
            assert_eq!(&orig.value, &dec.value);
        }
    }

    /// Verify HPACK decoder handles empty input.
    #[test]
    fn invariant_hpack_empty_input() {
        let mut decoder = HpackDecoder::new();
        let mut empty = asupersync::bytes::Bytes::new();
        let result = decoder.decode(&mut empty);
        assert!(result.is_ok(), "Empty input should decode to empty headers");
        assert!(result.unwrap().is_empty());
    }
}

// =============================================================================
// FLOW CONTROL INVARIANTS
// =============================================================================

mod flow_control_security {
    use super::*;

    /// Verify that window sizes respect RFC 7540 limits.
    #[test]
    fn invariant_window_size_limits() {
        // RFC 7540 Section 6.9.1: Window size cannot exceed 2^31-1
        const MAX_WINDOW_SIZE: u32 = 2_147_483_647;

        let settings = Settings::default();
        assert!(
            settings.initial_window_size <= MAX_WINDOW_SIZE,
            "Initial window size must not exceed 2^31-1"
        );
    }
}

// =============================================================================
// STRESS TEST MARKERS
// =============================================================================

/// Stress test for HPACK decoder with malformed input.
/// Marked as ignored for normal test runs.
#[test]
#[ignore]
fn stress_hpack_malformed_input() {
    use asupersync::bytes::Bytes;

    let mut decoder = HpackDecoder::new();

    // Test with various malformed inputs
    let malformed_inputs: Vec<Vec<u8>> = vec![
        vec![0xFF; 100],                    // All 0xFF bytes
        vec![0x00; 1000],                   // All zeros
        (0..255).cycle().take(500).collect(), // Cycling bytes
        vec![0x80; 50],                     // Incomplete integer encoding
    ];

    for input in malformed_inputs {
        let mut bytes = Bytes::from(input.clone());
        let result = decoder.decode(&mut bytes);
        // Should either succeed or return an error, never panic
        match result {
            Ok(_) => { /* Valid decode */ }
            Err(_) => { /* Expected for malformed input */ }
        }
    }
}

/// Stress test for WebSocket frame construction.
#[test]
#[ignore]
fn stress_websocket_frame_sizes() {
    use asupersync::bytes::Bytes;

    // Test with various frame sizes and patterns
    for size in [0, 1, 125, 126, 127, 1024, 65535, 65536] {
        let payload = vec![0xAB; size];

        // Valid frame construction
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: true,
            mask_key: Some([0x12, 0x34, 0x56, 0x78]),
            payload: Bytes::from(payload),
        };

        // Frame should be valid
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Binary);
    }
}

/// Stress test for settings builder with edge cases.
#[test]
#[ignore]
fn stress_settings_edge_cases() {
    // Test with maximum values
    let settings = SettingsBuilder::new()
        .max_concurrent_streams(u32::MAX)
        .max_frame_size(16_777_215) // Max per RFC 7540
        .initial_window_size(2_147_483_647) // Max per RFC 7540
        .build();

    assert_eq!(settings.max_concurrent_streams, u32::MAX);
    assert_eq!(settings.max_frame_size, 16_777_215);
    assert_eq!(settings.initial_window_size, 2_147_483_647);

    // Test with minimum values
    let settings = SettingsBuilder::new()
        .max_concurrent_streams(0)
        .max_frame_size(16384) // Min per RFC 7540
        .initial_window_size(0)
        .build();

    assert_eq!(settings.max_concurrent_streams, 0);
    assert_eq!(settings.max_frame_size, 16384);
}
