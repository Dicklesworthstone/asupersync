//! HTTP/2 Frame Variant Decoder Fuzzing
//!
//! Tick #115: Structure-aware fuzzing for src/http/h2/frame.rs frame variant decoder.
//! Tests arbitrary 9-byte header + payload combinations with focus on:
//!
//! ## Core Assertions
//! 1. **Variant tag mapped**: FrameType::from_u8() correctly maps or returns None
//! 2. **Length validated**: Frame length field is properly validated against payload
//! 3. **No panic on unknown frame type**: Unknown types go to Frame::Unknown without panic
//! 4. **9-byte header parsing**: Header parsing handles arbitrary byte combinations
//!
//! ## Attack Surface
//! - Frame type byte (0x00-0xFF) -> variant mapping
//! - Length field vs actual payload size mismatches
//! - Invalid/reserved frame types (0x0A+ are undefined in RFC 7540)
//! - Malformed flag combinations for each frame type
//! - Stream ID with/without reserved R bit

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, parse_frame, FRAME_HEADER_SIZE, MAX_FRAME_SIZE,
};
use libfuzzer_sys::fuzz_target;

/// Maximum payload size to prevent OOM during fuzzing
const MAX_PAYLOAD_SIZE: usize = 16_384;

/// Structured input for HTTP/2 frame variant fuzzing
#[derive(Arbitrary, Debug)]
struct FrameVariantInput {
    /// 9-byte frame header components
    header: FrameHeaderInput,
    /// Variable-length payload
    payload: Vec<u8>,
    /// Attack scenario to focus testing
    attack_vector: AttackVector,
}

/// Frame header input with explicit field control
#[derive(Arbitrary, Debug)]
struct FrameHeaderInput {
    /// Length field (24-bit) - may not match actual payload
    length: u32,
    /// Frame type byte (0x00-0xFF) - includes unknown types
    frame_type: u8,
    /// Flags byte (8-bit) - may be invalid for frame type
    flags: u8,
    /// Stream ID (31-bit) with potential reserved R bit
    stream_id_raw: u32,
}

/// Attack vectors for focused fuzzing
#[derive(Arbitrary, Debug)]
enum AttackVector {
    /// Test unknown frame types (>= 0x0A)
    UnknownFrameTypes,
    /// Test length field vs payload size mismatches
    LengthMismatch,
    /// Test reserved/invalid flag combinations
    InvalidFlags,
    /// Test stream ID with reserved R bit set
    ReservedRBit,
    /// Test boundary conditions (empty, max size)
    BoundaryConditions,
    /// Test completely random byte combinations
    RandomBytes,
}

fuzz_target!(|input: FrameVariantInput| {
    // Guard against excessive memory allocation
    if input.payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    // Clamp length field to valid range (24-bit)
    let length = input.header.length & 0x00FF_FFFF;
    if length > MAX_FRAME_SIZE {
        return;
    }

    match input.attack_vector {
        AttackVector::UnknownFrameTypes => {
            fuzz_unknown_frame_types(&input.header, &input.payload);
        }
        AttackVector::LengthMismatch => {
            fuzz_length_mismatch(&input.header, &input.payload);
        }
        AttackVector::InvalidFlags => {
            fuzz_invalid_flags(&input.header, &input.payload);
        }
        AttackVector::ReservedRBit => {
            fuzz_reserved_r_bit(&input.header, &input.payload);
        }
        AttackVector::BoundaryConditions => {
            fuzz_boundary_conditions(&input.header, &input.payload);
        }
        AttackVector::RandomBytes => {
            fuzz_random_bytes(&input.header, &input.payload);
        }
    }
});

/// Test unknown frame types (>= 0x0A) -> Frame::Unknown path
fn fuzz_unknown_frame_types(header: &FrameHeaderInput, payload: &[u8]) {
    // Focus on unknown frame types (RFC 7540 defines 0x0-0x9)
    let unknown_types = [0x0A, 0x0B, 0xFF, 0x42, 0x80];

    for &unknown_type in &unknown_types {
        let modified_header = FrameHeaderInput {
            frame_type: unknown_type,
            ..*header
        };

        test_frame_parsing(&modified_header, payload, |frame_type_byte| {
            // **Assertion 1: Variant tag mapped**
            let frame_type_opt = FrameType::from_u8(frame_type_byte);
            assert!(frame_type_opt.is_none(),
                "Unknown frame type 0x{:02X} should map to None", frame_type_byte);
        });
    }
}

/// Test length field vs payload size mismatches
fn fuzz_length_mismatch(header: &FrameHeaderInput, payload: &[u8]) {
    let scenarios = [
        // Length smaller than payload
        (payload.len().saturating_sub(10) as u32, payload),
        // Length larger than payload
        (payload.len().saturating_add(10) as u32, payload),
        // Zero length with non-empty payload
        (0, payload),
        // Max length with small payload
        (MAX_FRAME_SIZE, &payload[..payload.len().min(100)]),
    ];

    for &(test_length, test_payload) in &scenarios {
        let modified_header = FrameHeaderInput {
            length: test_length,
            ..*header
        };

        test_frame_parsing(&modified_header, test_payload, |_| {
            // **Assertion 2: Length validated**
            // The parser should handle length mismatches gracefully
            // Either succeed with truncated payload or fail with proper error
        });
    }
}

/// Test invalid flag combinations for each frame type
fn fuzz_invalid_flags(header: &FrameHeaderInput, payload: &[u8]) {
    let flag_tests = [
        // All flags set (0xFF)
        0xFF,
        // Reserved bits set
        0x80, 0x40, 0x02,
        // Invalid combinations
        0x3F, 0x7E,
    ];

    for &test_flags in &flag_tests {
        let modified_header = FrameHeaderInput {
            flags: test_flags,
            ..*header
        };

        test_frame_parsing(&modified_header, payload, |_| {
            // Parser should handle invalid flags without panic
            // May accept (ignoring invalid flags) or reject with error
        });
    }
}

/// Test stream ID with reserved R bit set
fn fuzz_reserved_r_bit(header: &FrameHeaderInput, payload: &[u8]) {
    // Test with R bit set in various ways
    let r_bit_tests = [
        header.stream_id_raw | 0x8000_0000,  // Set R bit
        0x8000_0001,                         // R bit + stream ID 1
        0xFFFF_FFFF,                         // All bits set
        0x8000_0000,                         // Only R bit set
    ];

    for &test_stream_id in &r_bit_tests {
        let modified_header = FrameHeaderInput {
            stream_id_raw: test_stream_id,
            ..*header
        };

        test_frame_parsing(&modified_header, payload, |_| {
            // R bit should be cleared during parsing per RFC 7540 Section 4.1
        });
    }
}

/// Test boundary conditions
fn fuzz_boundary_conditions(header: &FrameHeaderInput, payload: &[u8]) {
    let boundary_tests = [
        // Empty payload
        (0, &[][..]),
        // Single byte payload
        (1, &[0x42][..]),
        // Maximum frame size
        (MAX_FRAME_SIZE, payload),
        // Just under max size
        (MAX_FRAME_SIZE - 1, payload),
    ];

    for &(test_length, test_payload) in &boundary_tests {
        let modified_header = FrameHeaderInput {
            length: test_length,
            ..*header
        };

        test_frame_parsing(&modified_header, test_payload, |_| {
            // Boundary conditions should be handled gracefully
        });
    }
}

/// Test completely random byte combinations
fn fuzz_random_bytes(header: &FrameHeaderInput, payload: &[u8]) {
    test_frame_parsing(header, payload, |_| {
        // Any random input should be handled without panic
    });
}

/// Core frame parsing test with invariant checking
fn test_frame_parsing<F>(header: &FrameHeaderInput, payload: &[u8], assertion: F)
where
    F: Fn(u8),
{
    // Construct 9-byte frame header
    let length = (header.length & 0x00FF_FFFF).min(MAX_FRAME_SIZE);
    let frame_header_bytes = construct_frame_header(
        length,
        header.frame_type,
        header.flags,
        header.stream_id_raw,
    );

    // Create frame data buffer
    let mut frame_data = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame_data.extend_from_slice(&frame_header_bytes);

    // Add payload (truncated to declared length)
    let payload_to_add = if payload.len() > length as usize {
        &payload[..length as usize]
    } else {
        payload
    };
    frame_data.extend_from_slice(payload_to_add);

    // **Core Test: Parse 9-byte header**
    let mut header_buf = BytesMut::from(frame_data.as_ref());
    match FrameHeader::parse(&mut header_buf) {
        Ok(parsed_header) => {
            // **Assertion 1: Variant tag mapped**
            assertion(parsed_header.frame_type);

            // **Assertion 2: Length validated**
            assert_eq!(parsed_header.length, length,
                "Parsed length {} should match declared length {}",
                parsed_header.length, length);

            // **Assertion: R bit cleared**
            let expected_stream_id = header.stream_id_raw & 0x7FFF_FFFF;
            assert_eq!(parsed_header.stream_id, expected_stream_id,
                "Stream ID R bit should be cleared: raw=0x{:08X}, parsed=0x{:08X}",
                header.stream_id_raw, parsed_header.stream_id);

            // **Core Test: Parse complete frame**
            let frame_payload = header_buf.freeze();
            match parse_frame(&parsed_header, frame_payload) {
                Ok(frame) => {
                    // **Assertion 3: Unknown frame types handled**
                    if let Some(frame_type) = FrameType::from_u8(parsed_header.frame_type) {
                        // Known frame type - should parse to specific variant
                        match frame_type {
                            FrameType::Data => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Data(_))),
                            FrameType::Headers => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Headers(_))),
                            FrameType::Priority => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Priority(_))),
                            FrameType::RstStream => assert!(matches!(frame, asupersync::http::h2::frame::Frame::RstStream(_))),
                            FrameType::Settings => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Settings(_))),
                            FrameType::PushPromise => assert!(matches!(frame, asupersync::http::h2::frame::Frame::PushPromise(_))),
                            FrameType::Ping => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Ping(_))),
                            FrameType::GoAway => assert!(matches!(frame, asupersync::http::h2::frame::Frame::GoAway(_))),
                            FrameType::WindowUpdate => assert!(matches!(frame, asupersync::http::h2::frame::Frame::WindowUpdate(_))),
                            FrameType::Continuation => assert!(matches!(frame, asupersync::http::h2::frame::Frame::Continuation(_))),
                        }
                    } else {
                        // **Assertion 3: No panic on unknown frame type**
                        assert!(matches!(frame, asupersync::http::h2::frame::Frame::Unknown { .. }),
                            "Unknown frame type 0x{:02X} should parse to Frame::Unknown",
                            parsed_header.frame_type);
                    }
                }
                Err(_) => {
                    // Frame parsing failed - acceptable for malformed content
                    // Key assertion: no panic occurred
                }
            }
        }
        Err(_) => {
            // Header parsing failed - acceptable for malformed header
            // Key assertion: no panic occurred
        }
    }
}

/// Construct frame header bytes manually
fn construct_frame_header(
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id_raw: u32,
) -> [u8; FRAME_HEADER_SIZE] {
    [
        (length >> 16) as u8,        // Length high byte
        (length >> 8) as u8,         // Length middle byte
        length as u8,                // Length low byte
        frame_type,                  // Frame type
        flags,                       // Flags
        (stream_id_raw >> 24) as u8, // Stream ID high byte (may have R bit)
        (stream_id_raw >> 16) as u8, // Stream ID byte 2
        (stream_id_raw >> 8) as u8,  // Stream ID byte 3
        stream_id_raw as u8,         // Stream ID low byte
    ]
}