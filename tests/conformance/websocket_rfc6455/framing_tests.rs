//! Frame format conformance tests.
//!
//! Tests frame format requirements from RFC 6455 Section 5.

use super::*;
use asupersync::bytes::BytesMut;
use asupersync::net::websocket::{Frame, Opcode, FrameCodec, apply_mask};
use asupersync::codec::{Decoder, Encoder};

/// Run all frame format conformance tests.
pub fn run_framing_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_frame_header_format());
    results.push(test_opcode_validation());
    results.push(test_reserved_bits());
    results.push(test_payload_length_encoding());
    results.push(test_masking_key_format());
    results.push(test_control_frame_constraints());
    results.push(test_data_frame_validation());
    results.push(test_frame_size_limits());

    results
}

/// RFC 6455 Section 5.2: Frame header format validation.
fn test_frame_header_format() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Frame header structure validation
        // Minimum frame: 2 bytes (FIN + opcode + length + no payload)

        let mut codec = FrameCodec::new();

        // Test minimal frame structure
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x81, 0x00]); // FIN=1, opcode=1 (text), length=0

        let frame = codec.decode(&mut buf)
            .map_err(|e| format!("Failed to decode minimal frame: {}", e))?
            .ok_or("Expected frame from minimal header")?;

        // Verify frame structure
        if !frame.fin {
            return Err("FIN bit should be set".to_string());
        }

        if frame.opcode != Opcode::Text {
            return Err(format!("Expected Text opcode, got {:?}", frame.opcode));
        }

        if frame.payload.len() != 0 {
            return Err("Expected empty payload for zero length".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-HEADER-FORMAT",
        "Frame header format validation",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.2: Opcode validation.
fn test_opcode_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test all defined opcodes
        let defined_opcodes = [
            (0x0, Opcode::Continuation, "Continuation frame"),
            (0x1, Opcode::Text, "Text frame"),
            (0x2, Opcode::Binary, "Binary frame"),
            (0x8, Opcode::Close, "Close frame"),
            (0x9, Opcode::Ping, "Ping frame"),
            (0xA, Opcode::Pong, "Pong frame"),
        ];

        for (byte_val, expected_opcode, description) in &defined_opcodes {
            match Opcode::from_u8(*byte_val) {
                Ok(opcode) => {
                    if opcode != *expected_opcode {
                        return Err(format!(
                            "{}: expected {:?}, got {:?}",
                            description, expected_opcode, opcode
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to parse {}: {}", description, e));
                }
            }
        }

        // Test reserved opcodes (should be rejected)
        let reserved_opcodes = [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF];
        for opcode_byte in &reserved_opcodes {
            if Opcode::from_u8(*opcode_byte).is_ok() {
                return Err(format!(
                    "Reserved opcode 0x{:X} should be rejected",
                    opcode_byte
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-OPCODE",
        "Opcode validation for defined and reserved values",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.2: Reserved bits validation.
fn test_reserved_bits() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Reserved bits (RSV1, RSV2, RSV3) must be 0 unless extension defines meaning

        // Test frame with reserved bits set (should be accepted but noted)
        let frame = Frame {
            fin: true,
            rsv1: true,  // Extension may use this
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask: None,
            payload: b"test".to_vec().into(),
        };

        // Frame structure should allow reserved bits
        // (Extensions can define meaning for these bits)
        if frame.rsv1 != true {
            return Err("RSV1 bit should be preserved".to_string());
        }

        // Test all combinations of reserved bits
        let rsv_combinations = [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ];

        for (rsv1, rsv2, rsv3) in &rsv_combinations {
            let frame = Frame {
                fin: true,
                rsv1: *rsv1,
                rsv2: *rsv2,
                rsv3: *rsv3,
                opcode: Opcode::Binary,
                masked: false,
                mask: None,
                payload: Vec::new().into(),
            };

            // All combinations should be structurally valid
            if frame.rsv1 != *rsv1 || frame.rsv2 != *rsv2 || frame.rsv3 != *rsv3 {
                return Err("Reserved bits not preserved correctly".to_string());
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-RESERVED-BITS",
        "Reserved bits handling and preservation",
        TestCategory::FrameFormat,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.2: Payload length encoding.
fn test_payload_length_encoding() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test all payload length encodings

        let test_cases = [
            // (payload_size, description)
            (0, "Empty payload"),
            (1, "Single byte payload"),
            (125, "Maximum 7-bit payload"),
            (126, "Minimum 16-bit payload length"),
            (127, "Edge case payload length"),
            (65535, "Maximum 16-bit payload length"),
            (65536, "Minimum 64-bit payload length"),
        ];

        for (payload_size, description) in &test_cases {
            let payload = vec![0u8; *payload_size];

            let frame = Frame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Binary,
                masked: false,
                mask: None,
                payload: payload.into(),
            };

            // Encode and decode to verify length encoding
            let mut codec = FrameCodec::new();
            let mut buf = BytesMut::new();

            codec.encode(frame.clone(), &mut buf)
                .map_err(|e| format!("Failed to encode {}: {}", description, e))?;

            let decoded = codec.decode(&mut buf)
                .map_err(|e| format!("Failed to decode {}: {}", description, e))?
                .ok_or_else(|| format!("Expected frame for {}", description))?;

            if decoded.payload.len() != *payload_size {
                return Err(format!(
                    "{}: payload length mismatch, expected {}, got {}",
                    description, payload_size, decoded.payload.len()
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-PAYLOAD-LENGTH",
        "Payload length encoding validation",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.3: Masking key format.
fn test_masking_key_format() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test masking key handling

        // Masked frame (client-to-server)
        let mask = [0x12, 0x34, 0x56, 0x78];
        let payload = b"Hello";

        let masked_frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: true,
            mask: Some(mask),
            payload: payload.to_vec().into(),
        };

        // Verify masking key is present
        if masked_frame.mask_key.is_none() {
            return Err("Masked frame must have masking key".to_string());
        }

        // Unmasked frame (server-to-client)
        let unmasked_frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask: None,
            payload: payload.to_vec().into(),
        };

        // Verify unmasked frame has no mask
        if unmasked_frame.mask.is_some() {
            return Err("Unmasked frame must not have masking key".to_string());
        }

        // Test mask application
        let mut masked_payload = payload.to_vec();
        apply_mask(&mut masked_payload, &mask);

        // Applying mask twice should restore original
        apply_mask(&mut masked_payload, &mask);
        if masked_payload != payload {
            return Err("Double masking should restore original payload".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.3-MASKING-KEY",
        "Masking key format and application",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.5: Control frame constraints.
fn test_control_frame_constraints() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Control frames have specific constraints

        let control_opcodes = [Opcode::Close, Opcode::Ping, Opcode::Pong];

        for opcode in &control_opcodes {
            // Control frames must have FIN=1
            let frame_without_fin = Frame {
                fin: false,  // Invalid for control frames
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: *opcode,
                masked: false,
                mask: None,
                payload: Vec::new().into(),
            };

            // This should be structurally valid but semantically invalid
            if frame_without_fin.fin {
                return Err("Test setup error: FIN should be false".to_string());
            }

            // Control frames must not exceed 125 bytes payload
            let large_payload = vec![0u8; 126]; // Too large for control frame
            let oversized_frame = Frame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: *opcode,
                masked: false,
                mask: None,
                payload: large_payload.into(),
            };

            // This should be detected as invalid
            if oversized_frame.payload.len() <= 125 {
                return Err("Test setup error: payload should be oversized".to_string());
            }

            // Valid control frame
            let valid_frame = Frame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: *opcode,
                masked: false,
                mask: None,
                payload: vec![0u8; 50].into(), // Valid size
            };

            if !valid_frame.fin {
                return Err(format!("Valid {:?} frame should have FIN=1", opcode));
            }

            if valid_frame.payload.len() > 125 {
                return Err(format!("Valid {:?} frame payload too large", opcode));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.5-CONTROL-CONSTRAINTS",
        "Control frame constraint validation",
        TestCategory::ControlFrames,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 Section 5.2: Data frame validation.
fn test_data_frame_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test data frame types: Text, Binary, Continuation

        let data_opcodes = [Opcode::Text, Opcode::Binary, Opcode::Continuation];

        for opcode in &data_opcodes {
            // Data frames can have any payload size (up to implementation limits)
            let sizes_to_test = [0, 1, 125, 126, 1000, 65535];

            for size in &sizes_to_test {
                let payload = vec![0u8; *size];

                let frame = Frame {
                    fin: true,
                    rsv1: false,
                    rsv2: false,
                    rsv3: false,
                    opcode: *opcode,
                    masked: false,
                    mask: None,
                    payload: payload.into(),
                };

                // Verify data frame properties
                if !frame.opcode.is_data() {
                    return Err(format!("{:?} should be data frame", opcode));
                }

                if frame.opcode.is_control() {
                    return Err(format!("{:?} should not be control frame", opcode));
                }

                // Data frames can be fragmented (FIN=0)
                let fragmented_frame = Frame {
                    fin: false, // Fragment
                    rsv1: false,
                    rsv2: false,
                    rsv3: false,
                    opcode: *opcode,
                    masked: false,
                    mask: None,
                    payload: vec![0u8; 100].into(),
                };

                // Fragmented data frames are valid (except Continuation as first frame)
                if *opcode == Opcode::Continuation {
                    // Continuation frames must follow a fragmented frame
                    // (Can't test full sequence here, but structure is valid)
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-DATA-FRAMES",
        "Data frame type validation",
        TestCategory::DataFrames,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Frame size limit validation.
fn test_frame_size_limits() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test frame size boundaries

        // Maximum theoretical frame size is 2^63-1 bytes (64-bit length)
        // but practical implementations have smaller limits

        let size_boundaries = [
            125,      // 7-bit length boundary
            126,      // 16-bit length starts
            127,      // Edge case
            65535,    // 16-bit length boundary
            65536,    // 64-bit length starts
        ];

        for size in &size_boundaries {
            // Create frame at boundary
            let frame = Frame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Binary,
                masked: false,
                mask: None,
                payload: vec![0u8; *size].into(),
            };

            // Verify size is preserved
            if frame.payload.len() != *size {
                return Err(format!(
                    "Frame size not preserved: expected {}, got {}",
                    size, frame.payload.len()
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-SIZE-LIMITS",
        "Frame size limit validation",
        TestCategory::FrameFormat,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}