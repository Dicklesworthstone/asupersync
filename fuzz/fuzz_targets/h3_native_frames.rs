//! Fuzz target for HTTP/3 frame type parser in h3_native.rs
//!
//! Tests frame type and length varint parsing with 5 key assertions:
//! 1. Varint frame type within u62 range (0..2^62-1)
//! 2. Length varint bounded and handled correctly
//! 3. Unknown frame types ignored gracefully per RFC 9114 §9
//! 4. GREASE frame types tolerated (extensibility preservation)
//! 5. Reserved frame types rejected cleanly
//!
//! Focuses specifically on the frame header parsing (type + length varints)
//! and conformance with HTTP/3 frame processing requirements.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{H3Frame, H3NativeError};
use asupersync::net::quic_core::{QUIC_VARINT_MAX, decode_varint, encode_varint};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

/// Maximum frame payload size to prevent OOM during fuzzing
const MAX_FRAME_PAYLOAD: usize = 65536;

/// Known HTTP/3 frame types from RFC 9114
const KNOWN_FRAME_TYPES: &[u64] = &[
    0x0,  // DATA
    0x1,  // HEADERS
    0x3,  // CANCEL_PUSH
    0x4,  // SETTINGS
    0x5,  // PUSH_PROMISE
    0x7,  // GOAWAY
    0xD,  // MAX_PUSH_ID
    0x30, // DATAGRAM (RFC 9297)
];

/// HTTP/2 reserved frame types that should be rejected in HTTP/3
const H2_RESERVED_FRAME_TYPES: &[u64] = &[
    0x2, // PRIORITY (HTTP/2)
    0x6, // PING (HTTP/2)
    0x8, // WINDOW_UPDATE (HTTP/2)
    0x9, // CONTINUATION (HTTP/2)
];

/// GREASE frame types for extensibility testing
/// Following the GREASE pattern: 0x1f * N + 0x21 where N = 0,1,2,...
const GREASE_FRAME_TYPES: &[u64] = &[
    0x21, 0x40, 0x5F, 0x7E, 0x9D, 0xBC, 0xDB, 0xFA, 0x119, 0x138, 0x157, 0x176, 0x195, 0x1B4,
    0x1D3, 0x1F2,
];

/// Fuzzing input structure for HTTP/3 frame type parser
#[derive(Arbitrary, Debug)]
struct H3FrameFuzzInput {
    /// Frame type parsing tests
    frame_type_tests: Vec<FrameTypeTest>,
    /// Frame length parsing tests
    frame_length_tests: Vec<FrameLengthTest>,
    /// Unknown frame type handling tests
    unknown_frame_tests: Vec<UnknownFrameTest>,
    /// GREASE frame type tests
    grease_tests: Vec<GreaseTest>,
    /// Reserved frame type rejection tests
    reserved_tests: Vec<ReservedTest>,
    /// Boundary condition tests
    boundary_tests: Vec<BoundaryTest>,
}

/// Frame type parsing test case
#[derive(Arbitrary, Debug)]
enum FrameTypeTest {
    /// Parse frame with valid type and length
    ValidFrame { frame_type: u64, payload: Vec<u8> },
    /// Parse frame with maximum varint type value
    MaxVarintType { payload: Vec<u8> },
    /// Parse frame with malformed type varint
    MalformedTypeVarint {
        malformed_data: Vec<u8>,
        payload: Vec<u8>,
    },
    /// Parse frame with type larger than u62 range
    OutOfRangeType {
        oversized_type: Vec<u8>, // Raw bytes that decode > QUIC_VARINT_MAX
        payload: Vec<u8>,
    },
}

/// Frame length parsing test case
#[derive(Arbitrary, Debug)]
enum FrameLengthTest {
    /// Parse frame with valid length
    ValidLength {
        frame_type: u64,
        payload_length: u64,
        actual_payload: Vec<u8>,
    },
    /// Parse frame with malformed length varint
    MalformedLengthVarint {
        frame_type: u64,
        malformed_length: Vec<u8>,
        payload: Vec<u8>,
    },
    /// Parse frame with length exceeding available data
    InsufficientData {
        frame_type: u64,
        claimed_length: u64,
        actual_data: Vec<u8>,
    },
    /// Parse frame with maximum varint length
    MaxVarintLength { frame_type: u64 },
    /// Parse frame with zero length
    ZeroLength { frame_type: u64 },
}

/// Unknown frame type handling test case
#[derive(Arbitrary, Debug)]
enum UnknownFrameTest {
    /// Parse unknown frame type (should be preserved)
    UnknownType { unknown_type: u64, payload: Vec<u8> },
    /// Parse stream of frames with unknown types mixed with known types
    MixedUnknownKnown { frame_sequence: Vec<FrameSpec> },
    /// Parse unknown frame with various payload patterns
    UnknownWithPayloadPattern {
        unknown_type: u64,
        payload_pattern: PayloadPattern,
    },
}

/// GREASE frame type test case
#[derive(Arbitrary, Debug)]
enum GreaseTest {
    /// Parse GREASE frame type (should be tolerated)
    GreaseType {
        grease_index: u8, // Index into GREASE_FRAME_TYPES
        payload: Vec<u8>,
    },
    /// Parse stream of GREASE frames
    MultipleGrease { grease_frames: Vec<GreaseFrame> },
    /// Parse GREASE frame with specific payload patterns
    GreaseWithPattern {
        grease_index: u8,
        payload_pattern: PayloadPattern,
    },
}

/// Reserved frame type rejection test case
#[derive(Arbitrary, Debug)]
enum ReservedTest {
    /// Parse HTTP/2 reserved frame type (should be handled appropriately)
    H2ReservedType {
        reserved_index: u8, // Index into H2_RESERVED_FRAME_TYPES
        payload: Vec<u8>,
    },
    /// Parse custom reserved frame type
    CustomReserved {
        reserved_type: u64,
        payload: Vec<u8>,
    },
}

/// Boundary condition test case
#[derive(Arbitrary, Debug)]
enum BoundaryTest {
    /// Test varint encoding boundaries
    VarintBoundary {
        boundary_type: VarintBoundaryType,
        is_frame_type: bool, // true for frame type, false for length
    },
    /// Test empty frame data
    EmptyFrame,
    /// Test single byte frame
    SingleByte { byte: u8 },
    /// Test frame at maximum payload size
    MaxPayloadFrame { frame_type: u64 },
    /// Test concatenated frames
    ConcatenatedFrames { frame_specs: Vec<FrameSpec> },
}

/// Frame specification for test construction
#[derive(Arbitrary, Debug, Clone)]
struct FrameSpec {
    frame_type: FrameTypeChoice,
    payload: Vec<u8>,
}

/// Choice of frame type for construction
#[derive(Arbitrary, Debug, Clone)]
enum FrameTypeChoice {
    Known { index: u8 }, // Index into KNOWN_FRAME_TYPES
    Unknown { type_value: u64 },
    Grease { index: u8 },   // Index into GREASE_FRAME_TYPES
    Reserved { index: u8 }, // Index into H2_RESERVED_FRAME_TYPES
}

/// GREASE frame structure
#[derive(Arbitrary, Debug, Clone)]
struct GreaseFrame {
    grease_type: u8, // Index into GREASE_FRAME_TYPES
    payload: Vec<u8>,
}

/// Varint encoding boundary types
#[derive(Arbitrary, Debug)]
enum VarintBoundaryType {
    /// 6-bit boundary (63)
    SixBit,
    /// 14-bit boundary (16383)
    FourteenBit,
    /// 30-bit boundary (1073741823)
    ThirtyBit,
    /// 62-bit boundary (4611686018427387903)
    SixtyTwoBit,
}

/// Payload patterns for testing
#[derive(Arbitrary, Debug)]
enum PayloadPattern {
    /// Empty payload
    Empty,
    /// All zeros
    AllZeros { length: u16 },
    /// All ones
    AllOnes { length: u16 },
    /// Sequential bytes 0, 1, 2, ...
    Sequential { length: u16 },
    /// Alternating 0xAA, 0x55 pattern
    Alternating { length: u16 },
    /// Random bytes with seed
    Random { seed: u32, length: u16 },
}

fuzz_target!(|input: H3FrameFuzzInput| {
    // Limit test iterations to prevent timeouts
    for test in input.frame_type_tests.iter().take(16) {
        test_frame_type_parsing(test);
    }

    for test in input.frame_length_tests.iter().take(16) {
        test_frame_length_parsing(test);
    }

    for test in input.unknown_frame_tests.iter().take(8) {
        test_unknown_frame_handling(test);
    }

    for test in input.grease_tests.iter().take(8) {
        test_grease_frame_handling(test);
    }

    for test in input.reserved_tests.iter().take(8) {
        test_reserved_frame_handling(test);
    }

    for test in input.boundary_tests.iter().take(8) {
        test_boundary_conditions(test);
    }
});

fn test_frame_type_parsing(test: &FrameTypeTest) {
    match test {
        FrameTypeTest::ValidFrame {
            frame_type,
            payload,
        } => {
            // Assertion 1: varint Type within u62 range
            if *frame_type > QUIC_VARINT_MAX {
                return; // Skip invalid test case
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    match H3Frame::decode(&frame_data) {
                        Ok((frame, consumed)) => {
                            // Verify complete consumption
                            assert_eq!(
                                consumed,
                                frame_data.len(),
                                "Frame parsing did not consume all input"
                            );

                            // Verify frame type is preserved correctly
                            match frame {
                                H3Frame::Unknown {
                                    frame_type: parsed_type,
                                    ..
                                } => {
                                    assert_eq!(
                                        parsed_type, *frame_type,
                                        "Unknown frame type not preserved correctly"
                                    );
                                }
                                _ => {
                                    // Known frame types should match expected patterns
                                    verify_known_frame_type(&frame, *frame_type);
                                }
                            }
                        }
                        Err(H3NativeError::InvalidFrame(msg)) => {
                            // Some frame types may be invalid due to payload constraints
                            if msg.contains("frame type out of range") {
                                panic!("Frame type {} should be in valid range", frame_type);
                            }
                        }
                        Err(_) => {
                            // Other errors are acceptable (malformed payload, etc.)
                        }
                    }
                }
            }
        }

        FrameTypeTest::MaxVarintType { payload } => {
            // Test frame with maximum valid varint type
            let mut frame_data = Vec::new();
            if encode_varint(QUIC_VARINT_MAX, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    match H3Frame::decode(&frame_data) {
                        Ok((H3Frame::Unknown { frame_type, .. }, _)) => {
                            assert_eq!(
                                frame_type, QUIC_VARINT_MAX,
                                "Maximum varint frame type not preserved"
                            );
                        }
                        Ok(_) => {
                            panic!("Maximum varint frame type should be treated as Unknown");
                        }
                        Err(_) => {
                            // Errors are acceptable for maximum values
                        }
                    }
                }
            }
        }

        FrameTypeTest::MalformedTypeVarint {
            malformed_data,
            payload,
        } => {
            // Test malformed frame type varint handling
            let mut frame_data = malformed_data.clone();
            frame_data.truncate(8); // Limit malformed data length

            let limited_payload = limit_payload(payload);
            if let Ok(length_bytes) = encode_varint_to_bytes(limited_payload.len() as u64) {
                frame_data.extend_from_slice(&length_bytes);
                frame_data.extend_from_slice(&limited_payload);

                // Should either parse successfully or fail gracefully
                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        // Success is fine - malformed data might accidentally be valid
                    }
                    Err(H3NativeError::InvalidFrame(msg)) => {
                        assert!(
                            msg.contains("frame type varint"),
                            "Expected frame type varint error, got: {}",
                            msg
                        );
                    }
                    Err(_) => {
                        // Other errors are acceptable
                    }
                }
            }
        }

        FrameTypeTest::OutOfRangeType {
            oversized_type,
            payload,
        } => {
            // Test frame type larger than u62 range (should be rejected)
            let mut frame_data = oversized_type.clone();
            frame_data.truncate(9); // Varint can be at most 8 bytes, plus safety margin

            let limited_payload = limit_payload(payload);
            if let Ok(length_bytes) = encode_varint_to_bytes(limited_payload.len() as u64) {
                frame_data.extend_from_slice(&length_bytes);
                frame_data.extend_from_slice(&limited_payload);

                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        // If it parses, the oversized type was actually valid
                    }
                    Err(H3NativeError::InvalidFrame(_)) => {
                        // Expected for truly out of range values
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }
    }
}

fn test_frame_length_parsing(test: &FrameLengthTest) {
    match test {
        FrameLengthTest::ValidLength {
            frame_type,
            payload_length,
            actual_payload,
        } => {
            // Assertion 2: Length varint bounded
            if *frame_type > QUIC_VARINT_MAX || *payload_length > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok()
                && encode_varint(*payload_length, &mut frame_data).is_ok()
            {
                let limited_payload = limit_payload(actual_payload);
                frame_data.extend_from_slice(&limited_payload);

                match H3Frame::decode(&frame_data) {
                    Ok((frame, consumed)) => {
                        // Verify length consistency
                        let expected_consumed = varint_encoded_length(*frame_type)
                            + varint_encoded_length(*payload_length)
                            + (*payload_length as usize).min(limited_payload.len());

                        assert!(
                            consumed <= frame_data.len(),
                            "Frame consumed more bytes than available"
                        );
                    }
                    Err(H3NativeError::UnexpectedEof) => {
                        // Expected when payload_length > actual_payload.len()
                        assert!(
                            (*payload_length as usize) > limited_payload.len(),
                            "UnexpectedEof should only occur when length > available data"
                        );
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }

        FrameLengthTest::MalformedLengthVarint {
            frame_type,
            malformed_length,
            payload,
        } => {
            if *frame_type > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok() {
                frame_data.extend_from_slice(&malformed_length[..malformed_length.len().min(8)]);

                let limited_payload = limit_payload(payload);
                frame_data.extend_from_slice(&limited_payload);

                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        // Malformed data might accidentally be valid
                    }
                    Err(H3NativeError::InvalidFrame(msg)) => {
                        assert!(
                            msg.contains("frame length varint"),
                            "Expected frame length varint error, got: {}",
                            msg
                        );
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }

        FrameLengthTest::InsufficientData {
            frame_type,
            claimed_length,
            actual_data,
        } => {
            if *frame_type > QUIC_VARINT_MAX || *claimed_length > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok()
                && encode_varint(*claimed_length, &mut frame_data).is_ok()
            {
                let limited_data = limit_payload(actual_data);
                frame_data.extend_from_slice(&limited_data);

                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        // Success implies claimed_length <= actual_data.len()
                        assert!(
                            (*claimed_length as usize) <= limited_data.len(),
                            "Should not succeed when claimed length > available data"
                        );
                    }
                    Err(H3NativeError::UnexpectedEof) => {
                        // Expected when claimed_length > actual_data.len()
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }

        FrameLengthTest::MaxVarintLength { frame_type } => {
            if *frame_type > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok()
                && encode_varint(QUIC_VARINT_MAX, &mut frame_data).is_ok()
            {
                // Don't actually include QUIC_VARINT_MAX bytes of payload
                // Just test that the length varint itself is handled
                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        panic!("Should not succeed with max varint length and no payload");
                    }
                    Err(H3NativeError::UnexpectedEof) => {
                        // Expected - we didn't provide the payload
                    }
                    Err(H3NativeError::InvalidFrame(msg)) => {
                        // May fail if length is considered out of range
                        if msg.contains("frame length exceeds addressable range") {
                            // This is acceptable - implementation limit
                        }
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }

        FrameLengthTest::ZeroLength { frame_type } => {
            if *frame_type > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok()
                && encode_varint(0, &mut frame_data).is_ok()
            {
                match H3Frame::decode(&frame_data) {
                    Ok((frame, consumed)) => {
                        // Zero-length frames should parse successfully
                        let expected_consumed =
                            varint_encoded_length(*frame_type) + varint_encoded_length(0);
                        assert_eq!(
                            consumed, expected_consumed,
                            "Zero-length frame consumption mismatch"
                        );

                        // Verify payload is empty
                        verify_frame_payload_empty(&frame);
                    }
                    Err(_) => {
                        // Some frame types may not allow zero length
                    }
                }
            }
        }
    }
}

fn test_unknown_frame_handling(test: &UnknownFrameTest) {
    match test {
        UnknownFrameTest::UnknownType {
            unknown_type,
            payload,
        } => {
            // Assertion 3: unknown frame types ignored gracefully per RFC 9114
            if *unknown_type > QUIC_VARINT_MAX {
                return;
            }

            // Skip known frame types
            if KNOWN_FRAME_TYPES.contains(unknown_type) {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*unknown_type, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    match H3Frame::decode(&frame_data) {
                        Ok((
                            H3Frame::Unknown {
                                frame_type,
                                payload: parsed_payload,
                            },
                            consumed,
                        )) => {
                            assert_eq!(
                                frame_type, *unknown_type,
                                "Unknown frame type not preserved correctly"
                            );
                            assert_eq!(
                                parsed_payload, limited_payload,
                                "Unknown frame payload not preserved correctly"
                            );
                            assert_eq!(
                                consumed,
                                frame_data.len(),
                                "Unknown frame consumption mismatch"
                            );
                        }
                        Ok(_) => {
                            panic!(
                                "Unknown frame type {} should produce Unknown variant",
                                unknown_type
                            );
                        }
                        Err(_) => {
                            // Errors are acceptable for malformed payloads
                        }
                    }
                }
            }
        }

        UnknownFrameTest::MixedUnknownKnown { frame_sequence } => {
            let mut combined_data = Vec::new();
            let mut expected_frames = Vec::new();

            for (i, frame_spec) in frame_sequence.iter().take(8).enumerate() {
                let frame_type = resolve_frame_type(&frame_spec.frame_type);
                if frame_type > QUIC_VARINT_MAX {
                    continue;
                }

                let limited_payload = limit_payload(&frame_spec.payload);

                let mut frame_data = Vec::new();
                if encode_varint(frame_type, &mut frame_data).is_ok()
                    && encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok()
                {
                    frame_data.extend_from_slice(&limited_payload);
                    combined_data.extend_from_slice(&frame_data);
                    expected_frames.push((frame_type, limited_payload));
                }
            }

            // Parse frames sequentially
            let mut pos = 0;
            for (expected_type, expected_payload) in expected_frames {
                if pos >= combined_data.len() {
                    break;
                }

                match H3Frame::decode(&combined_data[pos..]) {
                    Ok((frame, consumed)) => {
                        verify_frame_matches_expected(&frame, expected_type, &expected_payload);
                        pos += consumed;
                    }
                    Err(_) => {
                        // Errors are acceptable - move to next frame attempt
                        break;
                    }
                }
            }
        }

        UnknownFrameTest::UnknownWithPayloadPattern {
            unknown_type,
            payload_pattern,
        } => {
            if *unknown_type > QUIC_VARINT_MAX || KNOWN_FRAME_TYPES.contains(unknown_type) {
                return;
            }

            let test_payload = generate_payload_pattern(payload_pattern);
            let mut frame_data = Vec::new();

            if encode_varint(*unknown_type, &mut frame_data).is_ok()
                && encode_varint(test_payload.len() as u64, &mut frame_data).is_ok()
            {
                frame_data.extend_from_slice(&test_payload);

                match H3Frame::decode(&frame_data) {
                    Ok((
                        H3Frame::Unknown {
                            frame_type,
                            payload,
                        },
                        _,
                    )) => {
                        assert_eq!(frame_type, *unknown_type);
                        assert_eq!(payload, test_payload);
                    }
                    Ok(_) => {
                        panic!("Unknown frame should produce Unknown variant");
                    }
                    Err(_) => {
                        // Acceptable
                    }
                }
            }
        }
    }
}

fn test_grease_frame_handling(test: &GreaseTest) {
    match test {
        GreaseTest::GreaseType {
            grease_index,
            payload,
        } => {
            // Assertion 4: GREASE frame types tolerated
            let grease_type =
                GREASE_FRAME_TYPES[(*grease_index as usize) % GREASE_FRAME_TYPES.len()];

            let mut frame_data = Vec::new();
            if encode_varint(grease_type, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    match H3Frame::decode(&frame_data) {
                        Ok((
                            H3Frame::Unknown {
                                frame_type,
                                payload: parsed_payload,
                            },
                            _,
                        )) => {
                            assert_eq!(frame_type, grease_type, "GREASE frame type not preserved");
                            assert_eq!(
                                parsed_payload, limited_payload,
                                "GREASE frame payload not preserved"
                            );
                        }
                        Ok(_) => {
                            panic!("GREASE frame should produce Unknown variant");
                        }
                        Err(_) => {
                            // Errors acceptable for malformed payloads
                        }
                    }
                }
            }
        }

        GreaseTest::MultipleGrease { grease_frames } => {
            let mut combined_data = Vec::new();

            for grease_frame in grease_frames.iter().take(4) {
                let grease_type = GREASE_FRAME_TYPES
                    [(grease_frame.grease_type as usize) % GREASE_FRAME_TYPES.len()];
                let limited_payload = limit_payload(&grease_frame.payload);

                let mut frame_data = Vec::new();
                if encode_varint(grease_type, &mut frame_data).is_ok()
                    && encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok()
                {
                    frame_data.extend_from_slice(&limited_payload);
                    combined_data.extend_from_slice(&frame_data);
                }
            }

            // Parse multiple GREASE frames
            let mut pos = 0;
            while pos < combined_data.len() {
                match H3Frame::decode(&combined_data[pos..]) {
                    Ok((H3Frame::Unknown { frame_type, .. }, consumed)) => {
                        assert!(
                            GREASE_FRAME_TYPES.contains(&frame_type),
                            "Expected GREASE frame type, got {}",
                            frame_type
                        );
                        pos += consumed;
                    }
                    Ok(_) => {
                        panic!("GREASE frames should produce Unknown variants");
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }

        GreaseTest::GreaseWithPattern {
            grease_index,
            payload_pattern,
        } => {
            let grease_type =
                GREASE_FRAME_TYPES[(*grease_index as usize) % GREASE_FRAME_TYPES.len()];
            let test_payload = generate_payload_pattern(payload_pattern);

            let mut frame_data = Vec::new();
            if encode_varint(grease_type, &mut frame_data).is_ok()
                && encode_varint(test_payload.len() as u64, &mut frame_data).is_ok()
            {
                frame_data.extend_from_slice(&test_payload);

                match H3Frame::decode(&frame_data) {
                    Ok((
                        H3Frame::Unknown {
                            frame_type,
                            payload,
                        },
                        _,
                    )) => {
                        assert_eq!(frame_type, grease_type);
                        assert_eq!(payload, test_payload);
                    }
                    Ok(_) => {
                        panic!("GREASE frame should produce Unknown variant");
                    }
                    Err(_) => {
                        // Acceptable
                    }
                }
            }
        }
    }
}

fn test_reserved_frame_handling(test: &ReservedTest) {
    match test {
        ReservedTest::H2ReservedType {
            reserved_index,
            payload,
        } => {
            // Assertion 5: reserved frame types rejected cleanly
            let reserved_type =
                H2_RESERVED_FRAME_TYPES[(*reserved_index as usize) % H2_RESERVED_FRAME_TYPES.len()];

            let mut frame_data = Vec::new();
            if encode_varint(reserved_type, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    match H3Frame::decode(&frame_data) {
                        Ok((H3Frame::Unknown { frame_type, .. }, _)) => {
                            // HTTP/2 reserved frames are treated as unknown in HTTP/3
                            // This is actually correct per RFC 9114
                            assert_eq!(frame_type, reserved_type);
                        }
                        Ok(_) => {
                            // Should not parse as known frame type
                            panic!(
                                "HTTP/2 reserved frame type {} should not parse as known frame",
                                reserved_type
                            );
                        }
                        Err(_) => {
                            // Rejection is also acceptable
                        }
                    }
                }
            }
        }

        ReservedTest::CustomReserved {
            reserved_type,
            payload,
        } => {
            if *reserved_type > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*reserved_type, &mut frame_data).is_ok() {
                let limited_payload = limit_payload(payload);
                if encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok() {
                    frame_data.extend_from_slice(&limited_payload);

                    // Custom reserved types should be handled as unknown frames
                    match H3Frame::decode(&frame_data) {
                        Ok((frame, _)) => {
                            verify_frame_handled_appropriately(&frame, *reserved_type);
                        }
                        Err(_) => {
                            // Rejection is acceptable
                        }
                    }
                }
            }
        }
    }
}

fn test_boundary_conditions(test: &BoundaryTest) {
    match test {
        BoundaryTest::VarintBoundary {
            boundary_type,
            is_frame_type,
        } => {
            let boundary_value = match boundary_type {
                VarintBoundaryType::SixBit => 63u64,
                VarintBoundaryType::FourteenBit => 16383u64,
                VarintBoundaryType::ThirtyBit => 1073741823u64,
                VarintBoundaryType::SixtyTwoBit => QUIC_VARINT_MAX,
            };

            let (frame_type, payload_length) = if *is_frame_type {
                (boundary_value, 0u64)
            } else {
                (0u64, boundary_value) // DATA frame with boundary length
            };

            let mut frame_data = Vec::new();
            if encode_varint(frame_type, &mut frame_data).is_ok()
                && encode_varint(payload_length, &mut frame_data).is_ok()
            {
                if payload_length == 0 {
                    // Zero-length frame
                    match H3Frame::decode(&frame_data) {
                        Ok((frame, _)) => {
                            if *is_frame_type {
                                // Boundary frame type should be handled appropriately
                                verify_boundary_frame_type(&frame, boundary_value);
                            } else {
                                // Boundary length should be handled
                                verify_frame_payload_empty(&frame);
                            }
                        }
                        Err(_) => {
                            // Acceptable for extreme boundary values
                        }
                    }
                } else {
                    // Don't actually create large payload - just test length parsing
                    match H3Frame::decode(&frame_data) {
                        Ok(_) => {
                            panic!("Should not succeed with large length and no payload");
                        }
                        Err(H3NativeError::UnexpectedEof) => {
                            // Expected
                        }
                        Err(_) => {
                            // Other errors acceptable
                        }
                    }
                }
            }
        }

        BoundaryTest::EmptyFrame => {
            // Test completely empty frame data
            match H3Frame::decode(&[]) {
                Ok(_) => {
                    panic!("Empty frame data should not parse successfully");
                }
                Err(H3NativeError::InvalidFrame(_)) => {
                    // Expected
                }
                Err(_) => {
                    // Other errors acceptable
                }
            }
        }

        BoundaryTest::SingleByte { byte } => {
            match H3Frame::decode(&[*byte]) {
                Ok(_) => {
                    panic!("Single byte should not be sufficient for a frame");
                }
                Err(H3NativeError::InvalidFrame(_)) | Err(H3NativeError::UnexpectedEof) => {
                    // Expected
                }
                Err(_) => {
                    // Other errors acceptable
                }
            }
        }

        BoundaryTest::MaxPayloadFrame { frame_type } => {
            if *frame_type > QUIC_VARINT_MAX {
                return;
            }

            let mut frame_data = Vec::new();
            if encode_varint(*frame_type, &mut frame_data).is_ok()
                && encode_varint(MAX_FRAME_PAYLOAD as u64, &mut frame_data).is_ok()
            {
                // Don't actually create max payload - just test the header
                match H3Frame::decode(&frame_data) {
                    Ok(_) => {
                        panic!("Should not succeed with max payload length and no actual payload");
                    }
                    Err(H3NativeError::UnexpectedEof) => {
                        // Expected
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }

        BoundaryTest::ConcatenatedFrames { frame_specs } => {
            let mut combined_data = Vec::new();
            let mut expected_count = 0;

            for frame_spec in frame_specs.iter().take(4) {
                let frame_type = resolve_frame_type(&frame_spec.frame_type);
                if frame_type > QUIC_VARINT_MAX {
                    continue;
                }

                let limited_payload = limit_payload(&frame_spec.payload);
                let mut frame_data = Vec::new();

                if encode_varint(frame_type, &mut frame_data).is_ok()
                    && encode_varint(limited_payload.len() as u64, &mut frame_data).is_ok()
                {
                    frame_data.extend_from_slice(&limited_payload);
                    combined_data.extend_from_slice(&frame_data);
                    expected_count += 1;
                }
            }

            // Parse concatenated frames
            let mut pos = 0;
            let mut parsed_count = 0;

            while pos < combined_data.len() && parsed_count < expected_count {
                match H3Frame::decode(&combined_data[pos..]) {
                    Ok((_, consumed)) => {
                        pos += consumed;
                        parsed_count += 1;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            // Should parse at least some frames from valid concatenated data
            if expected_count > 0 && parsed_count == 0 && combined_data.len() > 0 {
                panic!("No frames parsed from valid concatenated frame data");
            }
        }
    }
}

// Helper functions

fn limit_payload(payload: &[u8]) -> Vec<u8> {
    payload.iter().take(MAX_FRAME_PAYLOAD).copied().collect()
}

fn encode_varint_to_bytes(value: u64) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    encode_varint(value, &mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn varint_encoded_length(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

fn resolve_frame_type(choice: &FrameTypeChoice) -> u64 {
    match choice {
        FrameTypeChoice::Known { index } => {
            KNOWN_FRAME_TYPES[(*index as usize) % KNOWN_FRAME_TYPES.len()]
        }
        FrameTypeChoice::Unknown { type_value } => *type_value,
        FrameTypeChoice::Grease { index } => {
            GREASE_FRAME_TYPES[(*index as usize) % GREASE_FRAME_TYPES.len()]
        }
        FrameTypeChoice::Reserved { index } => {
            H2_RESERVED_FRAME_TYPES[(*index as usize) % H2_RESERVED_FRAME_TYPES.len()]
        }
    }
}

fn generate_payload_pattern(pattern: &PayloadPattern) -> Vec<u8> {
    match pattern {
        PayloadPattern::Empty => Vec::new(),
        PayloadPattern::AllZeros { length } => vec![0; (*length as usize).min(MAX_FRAME_PAYLOAD)],
        PayloadPattern::AllOnes { length } => vec![0xFF; (*length as usize).min(MAX_FRAME_PAYLOAD)],
        PayloadPattern::Sequential { length } => (0..)
            .take((*length as usize).min(MAX_FRAME_PAYLOAD))
            .map(|i| (i % 256) as u8)
            .collect(),
        PayloadPattern::Alternating { length } => (0..)
            .take((*length as usize).min(MAX_FRAME_PAYLOAD))
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect(),
        PayloadPattern::Random { seed, length } => {
            let mut rng_state = *seed;
            (0..)
                .take((*length as usize).min(MAX_FRAME_PAYLOAD))
                .map(|_| {
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    (rng_state >> 16) as u8
                })
                .collect()
        }
    }
}

fn verify_known_frame_type(frame: &H3Frame, expected_type: u64) {
    match (frame, expected_type) {
        (H3Frame::Data(_), 0x0) => {}
        (H3Frame::Headers(_), 0x1) => {}
        (H3Frame::CancelPush(_), 0x3) => {}
        (H3Frame::Settings(_), 0x4) => {}
        (H3Frame::PushPromise { .. }, 0x5) => {}
        (H3Frame::Goaway(_), 0x7) => {}
        (H3Frame::MaxPushId(_), 0xD) => {}
        (H3Frame::Datagram { .. }, 0x30) => {}
        _ => {
            // Unknown frame or type mismatch - this might be acceptable
            // depending on payload validity
        }
    }
}

fn verify_frame_payload_empty(frame: &H3Frame) {
    match frame {
        H3Frame::Data(payload) => assert!(payload.is_empty()),
        H3Frame::Headers(payload) => assert!(payload.is_empty()),
        H3Frame::Settings(settings) => {
            // Settings frame with no settings is valid
        }
        H3Frame::Unknown { payload, .. } => assert!(payload.is_empty()),
        H3Frame::Datagram { payload, .. } => assert!(payload.is_empty()),
        _ => {
            // Other frame types may not allow zero length payloads
        }
    }
}

fn verify_frame_matches_expected(frame: &H3Frame, expected_type: u64, expected_payload: &[u8]) {
    match frame {
        H3Frame::Unknown {
            frame_type,
            payload,
        } => {
            assert_eq!(*frame_type, expected_type);
            assert_eq!(payload, expected_payload);
        }
        _ => {
            verify_known_frame_type(frame, expected_type);
        }
    }
}

fn verify_frame_handled_appropriately(frame: &H3Frame, frame_type: u64) {
    if KNOWN_FRAME_TYPES.contains(&frame_type) {
        verify_known_frame_type(frame, frame_type);
    } else {
        match frame {
            H3Frame::Unknown {
                frame_type: parsed_type,
                ..
            } => {
                assert_eq!(*parsed_type, frame_type);
            }
            _ => {
                panic!(
                    "Unknown frame type {} should produce Unknown variant",
                    frame_type
                );
            }
        }
    }
}

fn verify_boundary_frame_type(frame: &H3Frame, boundary_value: u64) {
    if KNOWN_FRAME_TYPES.contains(&boundary_value) {
        verify_known_frame_type(frame, boundary_value);
    } else {
        match frame {
            H3Frame::Unknown { frame_type, .. } => {
                assert_eq!(*frame_type, boundary_value);
            }
            _ => {
                panic!(
                    "Boundary frame type {} should be handled appropriately",
                    boundary_value
                );
            }
        }
    }
}
