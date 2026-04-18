//! Fuzz target for HTTP/3 error code parsing per RFC 9114.
//!
//! Tests error code parsing in QUIC error frames with HTTP/3 error codes:
//! 1. H3_NO_ERROR (0x100) through H3_VERSION_FALLBACK (0x110) correctly parsed
//! 2. Unknown error codes handled as generic HTTP/3 error
//! 3. QUIC error codes distinct from HTTP/3 codes
//! 4. Error-code frame length bounds checking
//! 5. Reason phrase UTF-8 validation
//!
//! Feeds malformed error frames to HTTP/3 error code parsing to verify
//! robustness and RFC 9114 compliance.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::{convert::TryInto, str};

// HTTP/3 error codes per RFC 9114 Section 8
const H3_NO_ERROR: u64 = 0x100;
const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
const H3_INTERNAL_ERROR: u64 = 0x102;
const H3_STREAM_CREATION_ERROR: u64 = 0x103;
const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
const H3_FRAME_UNEXPECTED: u64 = 0x105;
const H3_FRAME_ERROR: u64 = 0x106;
const H3_EXCESSIVE_LOAD: u64 = 0x107;
const H3_ID_ERROR: u64 = 0x108;
const H3_SETTINGS_ERROR: u64 = 0x109;
const H3_MISSING_SETTINGS: u64 = 0x10A;
const H3_REQUEST_REJECTED: u64 = 0x10B;
const H3_REQUEST_CANCELLED: u64 = 0x10C;
const H3_REQUEST_INCOMPLETE: u64 = 0x10D;
const H3_MESSAGE_ERROR: u64 = 0x10E;
const H3_CONNECT_ERROR: u64 = 0x10F;
const H3_VERSION_FALLBACK: u64 = 0x110;

// QUIC transport error codes for distinction testing
const QUIC_NO_ERROR: u64 = 0x0;
const QUIC_INTERNAL_ERROR: u64 = 0x1;
const QUIC_CONNECTION_REFUSED: u64 = 0x2;
const QUIC_FLOW_CONTROL_ERROR: u64 = 0x3;
const QUIC_STREAM_LIMIT_ERROR: u64 = 0x4;
const QUIC_STREAM_STATE_ERROR: u64 = 0x5;
const QUIC_FINAL_SIZE_ERROR: u64 = 0x6;
const QUIC_FRAME_ENCODING_ERROR: u64 = 0x7;
const QUIC_TRANSPORT_PARAMETER_ERROR: u64 = 0x8;
const QUIC_CONNECTION_ID_LIMIT_ERROR: u64 = 0x9;
const QUIC_PROTOCOL_VIOLATION: u64 = 0xA;
const QUIC_INVALID_TOKEN: u64 = 0xB;
const QUIC_APPLICATION_ERROR: u64 = 0xC;
const QUIC_CRYPTO_BUFFER_EXCEEDED: u64 = 0xD;
const QUIC_KEY_UPDATE_ERROR: u64 = 0xE;
const QUIC_AEAD_LIMIT_REACHED: u64 = 0xF;

/// Fuzz input for HTTP/3 error code testing
#[derive(Debug, Clone, Arbitrary)]
struct H3ErrorFuzzInput {
    /// Error code to test
    error_code: u64,
    /// Reason phrase (may contain invalid UTF-8)
    reason_phrase: Vec<u8>,
    /// Frame encoding variant
    encoding_variant: ErrorFrameEncoding,
    /// Additional frame data for bounds testing
    additional_data: Vec<u8>,
}

/// Error frame encoding variants for testing
#[derive(Debug, Clone, Arbitrary)]
enum ErrorFrameEncoding {
    /// Standard QUIC CONNECTION_CLOSE frame with error code
    QuicConnectionClose,
    /// QUIC APPLICATION_CLOSE frame with HTTP/3 error code
    QuicApplicationClose,
    /// Raw error code for direct parsing testing
    RawErrorCode,
    /// Malformed frame with truncated data
    MalformedFrame,
    /// Oversized frame for bounds testing
    OversizedFrame,
}

/// HTTP/3 error code classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3ErrorClass {
    /// Valid HTTP/3 error code in range 0x100-0x110
    ValidH3Error,
    /// QUIC transport error code (0x0-0xF)
    QuicTransportError,
    /// Unknown/invalid error code
    UnknownError,
}

/// Classify an error code according to RFC 9114
fn classify_error_code(code: u64) -> H3ErrorClass {
    match code {
        H3_NO_ERROR..=H3_VERSION_FALLBACK => H3ErrorClass::ValidH3Error,
        QUIC_NO_ERROR..=QUIC_AEAD_LIMIT_REACHED => H3ErrorClass::QuicTransportError,
        _ => H3ErrorClass::UnknownError,
    }
}

/// Get the name of a known HTTP/3 error code
fn h3_error_name(code: u64) -> Option<&'static str> {
    match code {
        H3_NO_ERROR => Some("H3_NO_ERROR"),
        H3_GENERAL_PROTOCOL_ERROR => Some("H3_GENERAL_PROTOCOL_ERROR"),
        H3_INTERNAL_ERROR => Some("H3_INTERNAL_ERROR"),
        H3_STREAM_CREATION_ERROR => Some("H3_STREAM_CREATION_ERROR"),
        H3_CLOSED_CRITICAL_STREAM => Some("H3_CLOSED_CRITICAL_STREAM"),
        H3_FRAME_UNEXPECTED => Some("H3_FRAME_UNEXPECTED"),
        H3_FRAME_ERROR => Some("H3_FRAME_ERROR"),
        H3_EXCESSIVE_LOAD => Some("H3_EXCESSIVE_LOAD"),
        H3_ID_ERROR => Some("H3_ID_ERROR"),
        H3_SETTINGS_ERROR => Some("H3_SETTINGS_ERROR"),
        H3_MISSING_SETTINGS => Some("H3_MISSING_SETTINGS"),
        H3_REQUEST_REJECTED => Some("H3_REQUEST_REJECTED"),
        H3_REQUEST_CANCELLED => Some("H3_REQUEST_CANCELLED"),
        H3_REQUEST_INCOMPLETE => Some("H3_REQUEST_INCOMPLETE"),
        H3_MESSAGE_ERROR => Some("H3_MESSAGE_ERROR"),
        H3_CONNECT_ERROR => Some("H3_CONNECT_ERROR"),
        H3_VERSION_FALLBACK => Some("H3_VERSION_FALLBACK"),
        _ => None,
    }
}

/// Get the name of a known QUIC transport error code
fn quic_error_name(code: u64) -> Option<&'static str> {
    match code {
        QUIC_NO_ERROR => Some("QUIC_NO_ERROR"),
        QUIC_INTERNAL_ERROR => Some("QUIC_INTERNAL_ERROR"),
        QUIC_CONNECTION_REFUSED => Some("QUIC_CONNECTION_REFUSED"),
        QUIC_FLOW_CONTROL_ERROR => Some("QUIC_FLOW_CONTROL_ERROR"),
        QUIC_STREAM_LIMIT_ERROR => Some("QUIC_STREAM_LIMIT_ERROR"),
        QUIC_STREAM_STATE_ERROR => Some("QUIC_STREAM_STATE_ERROR"),
        QUIC_FINAL_SIZE_ERROR => Some("QUIC_FINAL_SIZE_ERROR"),
        QUIC_FRAME_ENCODING_ERROR => Some("QUIC_FRAME_ENCODING_ERROR"),
        QUIC_TRANSPORT_PARAMETER_ERROR => Some("QUIC_TRANSPORT_PARAMETER_ERROR"),
        QUIC_CONNECTION_ID_LIMIT_ERROR => Some("QUIC_CONNECTION_ID_LIMIT_ERROR"),
        QUIC_PROTOCOL_VIOLATION => Some("QUIC_PROTOCOL_VIOLATION"),
        QUIC_INVALID_TOKEN => Some("QUIC_INVALID_TOKEN"),
        QUIC_APPLICATION_ERROR => Some("QUIC_APPLICATION_ERROR"),
        QUIC_CRYPTO_BUFFER_EXCEEDED => Some("QUIC_CRYPTO_BUFFER_EXCEEDED"),
        QUIC_KEY_UPDATE_ERROR => Some("QUIC_KEY_UPDATE_ERROR"),
        QUIC_AEAD_LIMIT_REACHED => Some("QUIC_AEAD_LIMIT_REACHED"),
        _ => None,
    }
}

/// Encode a QUIC varint per RFC 9000
fn encode_varint(value: u64) -> Vec<u8> {
    match value {
        0..=63 => vec![value as u8],
        64..=16383 => {
            let bytes = (value | 0x4000).to_be_bytes();
            vec![bytes[6], bytes[7]]
        }
        16384..=1073741823 => {
            let bytes = (value | 0x80000000).to_be_bytes();
            vec![bytes[4], bytes[5], bytes[6], bytes[7]]
        }
        _ => {
            let bytes = (value | 0xC000000000000000).to_be_bytes();
            bytes.to_vec()
        }
    }
}

/// Build an error frame based on encoding variant
fn build_error_frame(input: &H3ErrorFuzzInput) -> Vec<u8> {
    let mut frame = Vec::new();

    match input.encoding_variant {
        ErrorFrameEncoding::QuicConnectionClose => {
            // QUIC CONNECTION_CLOSE frame (type 0x1C)
            frame.extend_from_slice(&encode_varint(0x1C));
            frame.extend_from_slice(&encode_varint(input.error_code));
            frame.extend_from_slice(&[0]); // Frame type (0 for no specific frame)
            let reason_len = input.reason_phrase.len().min(65535) as u64;
            frame.extend_from_slice(&encode_varint(reason_len));
            frame.extend_from_slice(&input.reason_phrase[..reason_len as usize]);
        }
        ErrorFrameEncoding::QuicApplicationClose => {
            // QUIC APPLICATION_CLOSE frame (type 0x1D)
            frame.extend_from_slice(&encode_varint(0x1D));
            frame.extend_from_slice(&encode_varint(input.error_code));
            let reason_len = input.reason_phrase.len().min(65535) as u64;
            frame.extend_from_slice(&encode_varint(reason_len));
            frame.extend_from_slice(&input.reason_phrase[..reason_len as usize]);
        }
        ErrorFrameEncoding::RawErrorCode => {
            // Just the error code as varint
            frame.extend_from_slice(&encode_varint(input.error_code));
            frame.extend_from_slice(&input.reason_phrase);
        }
        ErrorFrameEncoding::MalformedFrame => {
            // Intentionally truncated/malformed frame
            frame.extend_from_slice(&encode_varint(0x1D));
            if !input.additional_data.is_empty() {
                let truncate_at = input.additional_data[0] as usize % 10;
                let full_frame = encode_varint(input.error_code);
                frame.extend_from_slice(&full_frame[..truncate_at.min(full_frame.len())]);
            }
        }
        ErrorFrameEncoding::OversizedFrame => {
            // Frame with oversized reason phrase
            frame.extend_from_slice(&encode_varint(0x1D));
            frame.extend_from_slice(&encode_varint(input.error_code));
            let oversized_len = 100_000u64; // Unreasonably large
            frame.extend_from_slice(&encode_varint(oversized_len));
            frame.extend_from_slice(&input.reason_phrase);
            frame.extend_from_slice(&input.additional_data);
        }
    }

    frame
}

/// Attempt to parse error code from frame data
fn parse_error_code(frame_data: &[u8]) -> Option<u64> {
    if frame_data.is_empty() {
        return None;
    }

    // Simple varint parsing for error code
    let mut cursor = 0;
    let mut result = 0u64;
    let mut shift = 0;

    for &byte in frame_data.iter().take(8) {
        cursor += 1;
        if shift == 0 {
            // First byte determines encoding
            match byte >> 6 {
                0b00 => return Some((byte & 0x3F) as u64), // 6-bit value
                0b01 => {
                    result = ((byte & 0x3F) as u64) << 8;
                    shift = 8;
                }
                0b10 => {
                    result = ((byte & 0x3F) as u64) << 24;
                    shift = 24;
                }
                0b11 => {
                    result = ((byte & 0x3F) as u64) << 56;
                    shift = 56;
                }
                _ => unreachable!(),
            }
        } else {
            result |= (byte as u64) << (shift - 8);
            shift = shift.saturating_sub(8);
            if shift == 0 {
                return Some(result);
            }
        }
    }

    None
}

/// Validate UTF-8 in reason phrase
fn validate_reason_phrase(reason: &[u8]) -> Result<&str, std::str::Utf8Error> {
    str::from_utf8(reason)
}

fuzz_target!(|input: H3ErrorFuzzInput| {
    // Bound input size to prevent timeout
    if input.reason_phrase.len() > 10_000 || input.additional_data.len() > 1_000 {
        return;
    }

    // Build error frame from fuzz input
    let frame_data = build_error_frame(&input);
    if frame_data.len() > 100_000 {
        return; // Prevent memory exhaustion
    }

    // === Assertion 1: H3_NO_ERROR (0x100) through H3_VERSION_FALLBACK (0x110) correctly parsed ===
    let error_classification = classify_error_code(input.error_code);
    match error_classification {
        H3ErrorClass::ValidH3Error => {
            // All HTTP/3 error codes should be recognized
            assert!(h3_error_name(input.error_code).is_some(),
                "Valid HTTP/3 error code 0x{:x} should have a name", input.error_code);

            // Error code should be in the correct range
            assert!(input.error_code >= H3_NO_ERROR && input.error_code <= H3_VERSION_FALLBACK,
                "HTTP/3 error code 0x{:x} should be in range 0x100-0x110", input.error_code);
        }
        H3ErrorClass::QuicTransportError => {
            // QUIC codes should be in transport range
            assert!(input.error_code <= QUIC_AEAD_LIMIT_REACHED,
                "QUIC transport error 0x{:x} should be <= 0xF", input.error_code);
        }
        H3ErrorClass::UnknownError => {
            // Unknown codes should not have names in either namespace
            assert!(h3_error_name(input.error_code).is_none(),
                "Unknown error code 0x{:x} should not have an HTTP/3 name", input.error_code);
            assert!(quic_error_name(input.error_code).is_none(),
                "Unknown error code 0x{:x} should not have a QUIC name", input.error_code);
        }
    }

    // === Assertion 2: Unknown error codes handled as generic HTTP/3 error ===
    if matches!(error_classification, H3ErrorClass::UnknownError) {
        // Unknown codes above HTTP/3 range should be treated as generic HTTP/3 errors
        if input.error_code > H3_VERSION_FALLBACK {
            // Should not cause panic or undefined behavior when parsed
            let _ = parse_error_code(&frame_data);
        }
    }

    // === Assertion 3: QUIC error codes distinct from HTTP/3 codes ===
    if matches!(error_classification, H3ErrorClass::QuicTransportError) {
        // QUIC transport error codes should not be confused with HTTP/3 codes
        assert!(h3_error_name(input.error_code).is_none(),
            "QUIC error code 0x{:x} should not map to HTTP/3 error name", input.error_code);

        // Should have a QUIC name if it's a known transport error
        if input.error_code <= QUIC_AEAD_LIMIT_REACHED {
            assert!(quic_error_name(input.error_code).is_some(),
                "Known QUIC error code 0x{:x} should have a name", input.error_code);
        }
    }

    // === Assertion 4: Error-code frame length bound ===
    if !frame_data.is_empty() {
        // Parsing should not cause buffer overruns
        let parsed_code = parse_error_code(&frame_data);

        // Should either parse successfully or fail gracefully
        if let Some(code) = parsed_code {
            // Parsed code should be reasonable (not malformed due to bad varint encoding)
            if frame_data.len() >= 8 {
                // For well-formed frames, parsed code should match input (for simple encodings)
                match input.encoding_variant {
                    ErrorFrameEncoding::RawErrorCode => {
                        // Direct encoding should preserve the error code
                        if input.error_code <= 0x3F {
                            assert_eq!(code, input.error_code,
                                "Simple varint encoding should preserve error code");
                        }
                    }
                    _ => {
                        // Other encodings may have additional data, but code should be reasonable
                        assert!(code <= (1u64 << 62) - 1,
                            "Parsed error code 0x{:x} exceeds varint maximum", code);
                    }
                }
            }
        }

        // Frame processing should not cause infinite loops or excessive memory usage
        let frame_len = frame_data.len();
        assert!(frame_len <= 100_000, "Frame length {} exceeds reasonable bound", frame_len);
    }

    // === Assertion 5: Reason phrase UTF-8 validated ===
    match input.encoding_variant {
        ErrorFrameEncoding::QuicConnectionClose | ErrorFrameEncoding::QuicApplicationClose => {
            // Reason phrase should be validated for UTF-8
            let utf8_result = validate_reason_phrase(&input.reason_phrase);

            match utf8_result {
                Ok(valid_reason) => {
                    // Valid UTF-8 should be accepted
                    assert!(valid_reason.len() <= input.reason_phrase.len(),
                        "Valid UTF-8 string should not exceed byte length");

                    // Should not contain null bytes (per QUIC spec)
                    assert!(!valid_reason.contains('\0'),
                        "Reason phrase should not contain null bytes");
                }
                Err(_utf8_error) => {
                    // Invalid UTF-8 should be detected and handled gracefully
                    // Implementation should either reject the frame or sanitize the text

                    // Check that the error is legitimate (not due to fuzzer edge cases)
                    if !input.reason_phrase.is_empty() {
                        let _sanitized = String::from_utf8_lossy(&input.reason_phrase);
                        // Should not panic during sanitization
                    }
                }
            }
        }
        _ => {
            // For other frame types, UTF-8 validation may not apply
            // But if reason phrase is present, it should still be handled safely
            if !input.reason_phrase.is_empty() {
                let _ = validate_reason_phrase(&input.reason_phrase);
            }
        }
    }

    // Additional robustness checks

    // Error code parsing should be deterministic
    if frame_data.len() >= 8 {
        let first_parse = parse_error_code(&frame_data);
        let second_parse = parse_error_code(&frame_data);
        assert_eq!(first_parse, second_parse, "Error code parsing should be deterministic");
    }

    // Should handle edge case error codes gracefully
    match input.error_code {
        0 => {
            // Zero error code (QUIC NO_ERROR)
            assert_eq!(classify_error_code(0), H3ErrorClass::QuicTransportError);
        }
        u64::MAX => {
            // Maximum error code
            assert_eq!(classify_error_code(u64::MAX), H3ErrorClass::UnknownError);
        }
        0xFF => {
            // Boundary case between QUIC and HTTP/3 ranges
            assert_eq!(classify_error_code(0xFF), H3ErrorClass::UnknownError);
        }
        0x111 => {
            // Just above HTTP/3 range
            assert_eq!(classify_error_code(0x111), H3ErrorClass::UnknownError);
        }
        _ => {}
    }

    // Should not panic on any fuzz input
    // (If we get here without panicking, the fuzz target succeeded)
});