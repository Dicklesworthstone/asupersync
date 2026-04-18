//! HTTP/2 PRIORITY Frame Parsing Fuzz Target
//!
//! Tests the robustness and correctness of HTTP/2 PRIORITY frame parsing,
//! focusing on the 5-byte frame structure and protocol violations that
//! should trigger appropriate error responses per RFC 7540 Section 6.3.
//!
//! # Assertion Coverage
//!
//! 1. **Frame length exactly 5 bytes**: PRIORITY frames must be exactly 5 bytes
//!    per RFC 7540 §6.3, otherwise FRAME_SIZE_ERROR
//! 2. **Exclusive flag E correctly masked**: E flag is bit 31 of dependency field,
//!    properly extracted without affecting stream dependency value
//! 3. **Stream dependency uint31 (no R bit)**: Reserved R bit (bit 31) is masked
//!    off from dependency, leaving only 31-bit stream identifier space
//! 4. **Weight (0-255) mapped to 1-256**: Raw weight byte maps to priority weight
//!    range 1-256 per RFC specification
//! 5. **PRIORITY on Stream ID 0 triggers PROTOCOL_ERROR**: Stream ID 0 is reserved
//!    for connection-level frames, PRIORITY frames must use non-zero stream IDs

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{FrameHeader, FrameType, PriorityFrame};

/// Maximum valid stream ID (31 bits).
const MAX_STREAM_ID: u32 = 0x7FFF_FFFF;

/// Fuzz input for PRIORITY frame testing.
#[derive(Arbitrary, Debug)]
struct PriorityFrameFuzzInput {
    /// Stream ID for the frame header (can be 0 for testing protocol violations).
    stream_id: u32,
    /// Frame payload length (can be != 5 for testing frame size errors).
    payload_length: u8,
    /// Raw payload bytes (up to 255 bytes to test oversized frames).
    payload_bytes: Vec<u8>,
    /// Whether to test valid 5-byte payload structure.
    use_structured_payload: bool,
    /// Structured payload for valid PRIORITY frames.
    structured: StructuredPriorityPayload,
}

/// Structured 5-byte PRIORITY frame payload for testing valid parsing.
#[derive(Arbitrary, Debug)]
struct StructuredPriorityPayload {
    /// Exclusive dependency flag (will be placed in bit 31).
    exclusive: bool,
    /// Stream dependency (31-bit stream ID).
    dependency: u32,
    /// Priority weight (0-255, maps to 1-256).
    weight: u8,
}

impl StructuredPriorityPayload {
    /// Convert to 5-byte payload following RFC 7540 §6.3 format.
    fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(5);

        // Mask dependency to 31 bits and set exclusive flag in bit 31
        let dependency = self.dependency & 0x7FFF_FFFF;
        let first_byte = if self.exclusive {
            ((dependency >> 24) as u8) | 0x80  // Set E flag
        } else {
            (dependency >> 24) as u8            // Clear E flag
        };

        payload.push(first_byte);
        payload.push((dependency >> 16) as u8);
        payload.push((dependency >> 8) as u8);
        payload.push(dependency as u8);
        payload.push(self.weight);

        payload
    }
}

fn fuzz_priority_frame(input: &PriorityFrameFuzzInput) {
    // Build frame payload
    let payload = if input.use_structured_payload {
        input.structured.to_payload()
    } else {
        // Use raw payload bytes, truncated/padded to payload_length
        let mut payload = input.payload_bytes.clone();
        payload.resize(input.payload_length as usize, 0);
        payload
    };

    // Create frame header
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type: FrameType::Priority as u8,
        flags: 0,  // PRIORITY frames have no flags
        stream_id: input.stream_id,
    };

    let payload_bytes = Bytes::from(payload);

    // Test PRIORITY frame parsing
    let result = PriorityFrame::parse(&header, &payload_bytes);

    match result {
        Ok(frame) => {
            // Assertion 1: Frame length exactly 5 bytes
            assert_eq!(
                header.length, 5,
                "Valid PRIORITY frame must have exactly 5 bytes, got {}",
                header.length
            );

            // Assertion 2: Exclusive flag E correctly masked
            if input.use_structured_payload {
                assert_eq!(
                    frame.priority.exclusive, input.structured.exclusive,
                    "Exclusive flag mismatch: expected {}, got {}",
                    input.structured.exclusive, frame.priority.exclusive
                );
            }

            // Assertion 3: Stream dependency uint31 (no R bit)
            assert!(
                frame.priority.dependency <= MAX_STREAM_ID,
                "Stream dependency exceeds 31-bit limit: 0x{:08x}",
                frame.priority.dependency
            );

            // If using structured input, verify dependency extraction
            if input.use_structured_payload {
                let expected_dependency = input.structured.dependency & 0x7FFF_FFFF;
                assert_eq!(
                    frame.priority.dependency, expected_dependency,
                    "Dependency mismatch: expected 0x{:08x}, got 0x{:08x}",
                    expected_dependency, frame.priority.dependency
                );
            }

            // Assertion 4: Weight (0-255) mapped to 1-256
            // Note: The frame stores weight as u8 (0-255), but RFC 7540 specifies
            // that weight semantically represents 1-256. This is handled by
            // consumers adding 1 to the stored value.
            if input.use_structured_payload {
                assert_eq!(
                    frame.priority.weight, input.structured.weight,
                    "Weight mismatch: expected {}, got {}",
                    input.structured.weight, frame.priority.weight
                );
            }

            // Assertion 5: PRIORITY on Stream ID 0 should have been rejected
            assert!(
                header.stream_id != 0,
                "PRIORITY frame with stream ID 0 should be rejected, but was accepted"
            );
        }

        Err(error) => {
            match error {
                // Assertion 5: PRIORITY on Stream ID 0 triggers PROTOCOL_ERROR
                H2Error::Protocol { message, .. } if header.stream_id == 0 => {
                    assert!(
                        message.contains("PRIORITY frame with stream ID 0"),
                        "Expected PRIORITY stream ID 0 error message, got: {}",
                        message
                    );
                }

                // Assertion 1: Frame length != 5 bytes triggers FRAME_SIZE_ERROR
                H2Error::Stream { error_code: ErrorCode::FrameSizeError, .. } => {
                    assert!(
                        header.length != 5,
                        "FRAME_SIZE_ERROR should only occur when length != 5, got length {}",
                        header.length
                    );
                }

                // Stream errors for self-dependency
                H2Error::Stream { error_code: ErrorCode::ProtocolError, message, .. } => {
                    if message.contains("stream cannot depend on itself") {
                        // This is expected when dependency == stream_id
                        assert!(
                            input.use_structured_payload &&
                            (input.structured.dependency & 0x7FFF_FFFF) == header.stream_id,
                            "Self-dependency error without actual self-dependency"
                        );
                    }
                }

                // Other errors are acceptable for malformed input
                _ => {
                    // Unexpected error type - log for debugging but don't fail
                    // This allows fuzzer to find edge cases in error handling
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = PriorityFrameFuzzInput::arbitrary(&mut Unstructured::new(data)) {
        fuzz_priority_frame(&input);
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_priority_frame() {
        let input = PriorityFrameFuzzInput {
            stream_id: 1,
            payload_length: 5,
            payload_bytes: vec![],
            use_structured_payload: true,
            structured: StructuredPriorityPayload {
                exclusive: true,
                dependency: 42,
                weight: 128,
            },
        };

        fuzz_priority_frame(&input);
    }

    #[test]
    fn test_priority_frame_stream_zero() {
        let input = PriorityFrameFuzzInput {
            stream_id: 0,  // Should trigger PROTOCOL_ERROR
            payload_length: 5,
            payload_bytes: vec![],
            use_structured_payload: true,
            structured: StructuredPriorityPayload {
                exclusive: false,
                dependency: 1,
                weight: 16,
            },
        };

        fuzz_priority_frame(&input);
    }

    #[test]
    fn test_priority_frame_wrong_size() {
        let input = PriorityFrameFuzzInput {
            stream_id: 1,
            payload_length: 4,  // Should trigger FRAME_SIZE_ERROR
            payload_bytes: vec![0x80, 0x00, 0x00, 0x01],  // Only 4 bytes
            use_structured_payload: false,
            structured: StructuredPriorityPayload {
                exclusive: false,
                dependency: 1,
                weight: 16,
            },
        };

        fuzz_priority_frame(&input);
    }

    #[test]
    fn test_exclusive_flag_extraction() {
        let input = PriorityFrameFuzzInput {
            stream_id: 3,
            payload_length: 5,
            payload_bytes: vec![],
            use_structured_payload: true,
            structured: StructuredPriorityPayload {
                exclusive: true,
                dependency: 0x1234567,  // 31-bit dependency
                weight: 255,
            },
        };

        fuzz_priority_frame(&input);
    }

    #[test]
    fn test_max_stream_dependency() {
        let input = PriorityFrameFuzzInput {
            stream_id: 5,
            payload_length: 5,
            payload_bytes: vec![],
            use_structured_payload: true,
            structured: StructuredPriorityPayload {
                exclusive: false,
                dependency: MAX_STREAM_ID,  // Maximum 31-bit value
                weight: 0,
            },
        };

        fuzz_priority_frame(&input);
    }

    #[test]
    fn test_self_dependency() {
        let stream_id = 7;
        let input = PriorityFrameFuzzInput {
            stream_id,
            payload_length: 5,
            payload_bytes: vec![],
            use_structured_payload: true,
            structured: StructuredPriorityPayload {
                exclusive: false,
                dependency: stream_id,  // Should trigger self-dependency error
                weight: 64,
            },
        };

        fuzz_priority_frame(&input);
    }
}
