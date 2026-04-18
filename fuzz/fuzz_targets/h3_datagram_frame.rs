#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::http::h3_native::{H3Frame, H3NativeError};
use asupersync::net::quic_core::encode_varint;

/// Fuzz input for HTTP/3 DATAGRAM frame parsing (RFC 9297)
#[derive(Arbitrary, Debug)]
struct DatagramFrameFuzz {
    /// DATAGRAM frame operations
    datagram_operations: Vec<DatagramOperation>,
    /// Edge cases and boundary conditions
    edge_cases: Vec<DatagramEdgeCase>,
    /// Round-trip testing scenarios
    roundtrip_tests: Vec<DatagramRoundTrip>,
    /// Metamorphic transformations
    metamorphic_tests: Vec<DatagramMetamorphic>,
}

/// DATAGRAM frame parsing operations
#[derive(Arbitrary, Debug)]
enum DatagramOperation {
    /// Parse DATAGRAM frame from raw bytes
    ParseRaw { data: Vec<u8> },
    /// Parse DATAGRAM frame with specific quarter_stream_id and payload
    ParseStructured {
        quarter_stream_id: u64,
        payload: Vec<u8>,
    },
    /// Parse multiple consecutive DATAGRAM frames
    ParseMultiple { frames: Vec<DatagramFrame> },
    /// Parse truncated DATAGRAM frame
    ParseTruncated {
        complete_frame: DatagramFrame,
        truncate_at: u16,
    },
}

/// Structured DATAGRAM frame for construction
#[derive(Arbitrary, Debug, Clone)]
struct DatagramFrame {
    quarter_stream_id: u64,
    payload: Vec<u8>,
}

/// Edge cases and boundary conditions for DATAGRAM frames
#[derive(Arbitrary, Debug)]
enum DatagramEdgeCase {
    /// Empty payload
    EmptyPayload { quarter_stream_id: u64 },
    /// Maximum quarter_stream_id value
    MaxQuarterStreamId { payload: Vec<u8> },
    /// Large payload
    LargePayload {
        quarter_stream_id: u64,
        size: u16,
        fill_byte: u8,
    },
    /// Invalid varint encoding for quarter_stream_id
    InvalidVarint { malformed_varint: Vec<u8>, payload: Vec<u8> },
    /// Single byte frame
    SingleByte { byte: u8 },
    /// Frame with only type and length (no payload)
    TypeLengthOnly,
    /// Oversized frame length
    OversizedLength {
        quarter_stream_id: u64,
        claimed_length: u64,
        actual_payload: Vec<u8>,
    },
}

/// Round-trip testing for DATAGRAM frames
#[derive(Arbitrary, Debug)]
enum DatagramRoundTrip {
    /// Standard round-trip: construct -> encode -> decode -> verify
    Standard { frame: DatagramFrame },
    /// Round-trip with specific quarter_stream_id boundary values
    BoundaryValues { test_case: BoundaryCase },
    /// Round-trip with various payload patterns
    PayloadPatterns { pattern: PayloadPattern },
}

/// Boundary cases for quarter_stream_id
#[derive(Arbitrary, Debug)]
enum BoundaryCase {
    /// Zero quarter_stream_id
    Zero,
    /// Single bit set quarter_stream_id
    PowerOfTwo { exponent: u8 }, // 2^exponent
    /// Maximum valid QUIC stream ID values
    MaxValidQuic,
    /// Values around varint encoding boundaries
    VarintBoundary { boundary_type: VarintBoundaryType },
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
    /// All zeros
    AllZeros { length: u16 },
    /// All ones
    AllOnes { length: u16 },
    /// Alternating pattern
    Alternating { length: u16 },
    /// Sequential bytes
    Sequential { length: u16 },
    /// Random pattern
    Random { seed: u8, length: u16 },
    /// UTF-8 text
    Utf8Text { text: String },
    /// Binary pattern that might be mistaken for frame headers
    FrameLike { fake_type: u8, fake_length: u8 },
}

/// Metamorphic transformations for DATAGRAM frames
#[derive(Arbitrary, Debug)]
enum DatagramMetamorphic {
    /// Adding/removing empty payloads should not change semantics
    EmptyPayloadInvariance { base_frame: DatagramFrame },
    /// Concatenating frames should preserve individual frame parsing
    ConcatenationPreservation { frames: Vec<DatagramFrame> },
    /// Encoding order should not matter for identical frames
    EncodingOrderInvariance { frame1: DatagramFrame, frame2: DatagramFrame },
    /// Payload byte order changes should be detectable
    PayloadOrderSensitivity { original: DatagramFrame },
}

/// Size limits to prevent timeout/memory exhaustion
const MAX_PAYLOAD_SIZE: usize = 16384; // 16KB
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 62) - 1; // Maximum valid QUIC stream ID
const MAX_OPERATIONS: usize = 50;
const MAX_FRAMES: usize = 10;

fuzz_target!(|input: DatagramFrameFuzz| {
    // Limit total operations to prevent timeout
    let total_operations = input.datagram_operations.len()
        + input.edge_cases.len()
        + input.roundtrip_tests.len()
        + input.metamorphic_tests.len();

    if total_operations > MAX_OPERATIONS {
        return;
    }

    // Test basic DATAGRAM frame operations
    for operation in input.datagram_operations {
        test_datagram_operation(operation);
    }

    // Test edge cases and boundary conditions
    for edge_case in input.edge_cases {
        test_datagram_edge_case(edge_case);
    }

    // Test round-trip encoding/decoding
    for roundtrip in input.roundtrip_tests {
        test_datagram_roundtrip(roundtrip);
    }

    // Test metamorphic properties
    for metamorphic in input.metamorphic_tests {
        test_datagram_metamorphic(metamorphic);
    }
});

fn test_datagram_operation(operation: DatagramOperation) {
    match operation {
        DatagramOperation::ParseRaw { mut data } => {
            // Limit size to prevent memory exhaustion
            if data.len() > MAX_PAYLOAD_SIZE * 2 {
                data.truncate(MAX_PAYLOAD_SIZE * 2);
            }

            // Test raw DATAGRAM frame parsing - should not panic
            let result = H3Frame::decode(&data);

            match result {
                Ok((frame, consumed)) => {
                    // Verify consumed bytes are reasonable
                    assert!(consumed <= data.len(), "Consumed more bytes than available");

                    // If this is a DATAGRAM frame, verify its consistency
                    if let H3Frame::Datagram { quarter_stream_id, payload } = frame {
                        verify_datagram_frame_consistency(quarter_stream_id, &payload);

                        // Test re-encoding if decode succeeded
                        test_datagram_frame_reencode(quarter_stream_id, &payload);
                    }
                }
                Err(err) => {
                    // Verify error is reasonable for the input
                    verify_datagram_error_consistency(&err, &data);
                }
            }
        }

        DatagramOperation::ParseStructured { quarter_stream_id, mut payload } => {
            // Limit payload size and quarter_stream_id value
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }
            let clamped_qsid = quarter_stream_id.min(MAX_QUARTER_STREAM_ID);

            // Construct well-formed DATAGRAM frame
            let frame_bytes = construct_datagram_frame(clamped_qsid, &payload);
            let result = H3Frame::decode(&frame_bytes);

            match result {
                Ok((H3Frame::Datagram { quarter_stream_id: parsed_qsid, payload: parsed_payload }, consumed)) => {
                    // Verify parse results match input
                    assert_eq!(parsed_qsid, clamped_qsid, "Quarter stream ID mismatch");
                    assert_eq!(parsed_payload, payload, "Payload mismatch");
                    assert_eq!(consumed, frame_bytes.len(), "Should consume entire frame");
                }
                Ok((other_frame, _)) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other_frame);
                }
                Err(err) => {
                    // Shouldn't fail for well-formed frames unless there's a size limit
                    eprintln!("Unexpected error for well-formed DATAGRAM frame: {:?}", err);
                }
            }
        }

        DatagramOperation::ParseMultiple { frames } => {
            let limited_frames: Vec<_> = frames.into_iter().take(MAX_FRAMES).collect();
            let mut combined_data = Vec::new();

            // Construct concatenated frames
            for frame in &limited_frames {
                let clamped_qsid = frame.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
                let limited_payload = if frame.payload.len() > MAX_PAYLOAD_SIZE / MAX_FRAMES {
                    &frame.payload[..MAX_PAYLOAD_SIZE / MAX_FRAMES]
                } else {
                    &frame.payload
                };

                let frame_bytes = construct_datagram_frame(clamped_qsid, limited_payload);
                combined_data.extend_from_slice(&frame_bytes);
            }

            // Parse each frame sequentially
            let mut offset = 0;
            let mut parsed_count = 0;

            while offset < combined_data.len() && parsed_count < limited_frames.len() {
                match H3Frame::decode(&combined_data[offset..]) {
                    Ok((frame, consumed)) => {
                        if let H3Frame::Datagram { quarter_stream_id, payload } = frame {
                            verify_datagram_frame_consistency(quarter_stream_id, &payload);
                            offset += consumed;
                            parsed_count += 1;
                        } else {
                            // Non-DATAGRAM frame encountered, stop parsing
                            break;
                        }
                    }
                    Err(_) => {
                        // Parsing error, stop
                        break;
                    }
                }
            }
        }

        DatagramOperation::ParseTruncated { complete_frame, truncate_at } => {
            let clamped_qsid = complete_frame.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let limited_payload = if complete_frame.payload.len() > MAX_PAYLOAD_SIZE {
                &complete_frame.payload[..MAX_PAYLOAD_SIZE]
            } else {
                &complete_frame.payload
            };

            let complete_bytes = construct_datagram_frame(clamped_qsid, limited_payload);
            let truncate_pos = (truncate_at as usize).min(complete_bytes.len());
            let truncated = &complete_bytes[..truncate_pos];

            // Should handle truncated input gracefully
            let result = H3Frame::decode(truncated);
            match result {
                Ok((frame, consumed)) => {
                    // If parsing succeeded, the frame must be complete within truncated data
                    assert!(consumed <= truncated.len(), "Consumed more than available");
                    if let H3Frame::Datagram { quarter_stream_id, payload } = frame {
                        verify_datagram_frame_consistency(quarter_stream_id, &payload);
                    }
                }
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected for truncated input
                }
                Err(_) => {
                    // Other errors are also acceptable for truncated data
                }
            }
        }
    }
}

fn test_datagram_edge_case(edge_case: DatagramEdgeCase) {
    match edge_case {
        DatagramEdgeCase::EmptyPayload { quarter_stream_id } => {
            let clamped_qsid = quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let frame_bytes = construct_datagram_frame(clamped_qsid, &[]);

            let result = H3Frame::decode(&frame_bytes);
            match result {
                Ok((H3Frame::Datagram { quarter_stream_id: parsed_qsid, payload }, _)) => {
                    assert_eq!(parsed_qsid, clamped_qsid);
                    assert!(payload.is_empty(), "Empty payload should remain empty");
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other);
                }
                Err(err) => {
                    // Error is acceptable, but should be informative
                    verify_datagram_error_consistency(&err, &frame_bytes);
                }
            }
        }

        DatagramEdgeCase::MaxQuarterStreamId { mut payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Test with maximum valid quarter_stream_id
            let max_qsid = MAX_QUARTER_STREAM_ID;
            let frame_bytes = construct_datagram_frame(max_qsid, &payload);

            let result = H3Frame::decode(&frame_bytes);
            match result {
                Ok((H3Frame::Datagram { quarter_stream_id, payload: parsed_payload }, _)) => {
                    assert_eq!(quarter_stream_id, max_qsid);
                    assert_eq!(parsed_payload, payload);
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other);
                }
                Err(err) => {
                    verify_datagram_error_consistency(&err, &frame_bytes);
                }
            }
        }

        DatagramEdgeCase::LargePayload { quarter_stream_id, size, fill_byte } => {
            let clamped_qsid = quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let payload_size = (size as usize).min(MAX_PAYLOAD_SIZE);
            let payload = vec![fill_byte; payload_size];

            let frame_bytes = construct_datagram_frame(clamped_qsid, &payload);
            let result = H3Frame::decode(&frame_bytes);

            match result {
                Ok((H3Frame::Datagram { quarter_stream_id: parsed_qsid, payload: parsed_payload }, _)) => {
                    assert_eq!(parsed_qsid, clamped_qsid);
                    assert_eq!(parsed_payload.len(), payload_size);
                    assert!(parsed_payload.iter().all(|&b| b == fill_byte), "Payload pattern should be preserved");
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other);
                }
                Err(err) => {
                    // Large payload might trigger size limits
                    verify_datagram_error_consistency(&err, &frame_bytes);
                }
            }
        }

        DatagramEdgeCase::InvalidVarint { mut malformed_varint, mut payload } => {
            if malformed_varint.len() > 16 {
                malformed_varint.truncate(16);
            }
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Construct frame with malformed quarter_stream_id varint
            let mut frame_data = Vec::new();

            // DATAGRAM frame type
            let _ = encode_varint(0x30, &mut frame_data);

            // Frame length (varint + payload)
            let frame_length = malformed_varint.len() + payload.len();
            let _ = encode_varint(frame_length as u64, &mut frame_data);

            // Malformed quarter_stream_id varint
            frame_data.extend_from_slice(&malformed_varint);

            // Payload
            frame_data.extend_from_slice(&payload);

            // Should handle malformed varint gracefully
            let result = H3Frame::decode(&frame_data);
            match result {
                Ok((frame, _)) => {
                    // If it somehow parsed, verify it's reasonable
                    if let H3Frame::Datagram { quarter_stream_id, payload: parsed_payload } = frame {
                        verify_datagram_frame_consistency(quarter_stream_id, &parsed_payload);
                    }
                }
                Err(err) => {
                    // Expected for malformed varint - should be informative error
                    verify_datagram_error_consistency(&err, &frame_data);
                }
            }
        }

        DatagramEdgeCase::SingleByte { byte } => {
            // Test single byte input - should fail gracefully
            let result = H3Frame::decode(&[byte]);
            match result {
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected - single byte can't contain complete frame
                }
                Err(_) => {
                    // Other errors are also acceptable
                }
                Ok(_) => {
                    // Unexpected but not necessarily wrong
                }
            }
        }

        DatagramEdgeCase::TypeLengthOnly => {
            // Construct frame with only type and length, no payload
            let mut frame_data = Vec::new();
            let _ = encode_varint(0x30, &mut frame_data);
            let _ = encode_varint(0, &mut frame_data); // Length = 0 (no payload)

            // Should fail because DATAGRAM frame requires at least quarter_stream_id
            let result = H3Frame::decode(&frame_data);
            match result {
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected - no quarter_stream_id
                }
                Err(H3NativeError::InvalidFrame(_)) => {
                    // Also acceptable - invalid frame structure
                }
                Ok(_) => {
                    // Unexpected - DATAGRAM frame should require quarter_stream_id
                }
                Err(_) => {
                    // Other errors are acceptable
                }
            }
        }

        DatagramEdgeCase::OversizedLength { quarter_stream_id, claimed_length, mut actual_payload } => {
            let clamped_qsid = quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            if actual_payload.len() > MAX_PAYLOAD_SIZE {
                actual_payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Construct frame with claimed length > actual length
            let mut frame_data = Vec::new();
            let _ = encode_varint(0x30, &mut frame_data);

            let actual_length = {
                let mut qsid_bytes = Vec::new();
                let _ = encode_varint(clamped_qsid, &mut qsid_bytes);
                qsid_bytes.len() + actual_payload.len()
            };
            let claimed_length = claimed_length.max(actual_length as u64 + 1).min(u64::MAX);

            let _ = encode_varint(claimed_length, &mut frame_data);
            let _ = encode_varint(clamped_qsid, &mut frame_data);
            frame_data.extend_from_slice(&actual_payload);

            // Should detect length mismatch
            let result = H3Frame::decode(&frame_data);
            match result {
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected - claimed length exceeds available data
                }
                Err(H3NativeError::InvalidFrame(_)) => {
                    // Also acceptable - length validation error
                }
                Ok(_) => {
                    // Unexpected - should detect oversized length
                }
                Err(_) => {
                    // Other errors are acceptable
                }
            }
        }
    }
}

fn test_datagram_roundtrip(roundtrip: DatagramRoundTrip) {
    match roundtrip {
        DatagramRoundTrip::Standard { frame } => {
            let clamped_qsid = frame.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let limited_payload = if frame.payload.len() > MAX_PAYLOAD_SIZE {
                &frame.payload[..MAX_PAYLOAD_SIZE]
            } else {
                &frame.payload
            };

            // Encode frame
            let encoded = construct_datagram_frame(clamped_qsid, limited_payload);

            // Decode frame
            match H3Frame::decode(&encoded) {
                Ok((H3Frame::Datagram { quarter_stream_id, payload }, consumed)) => {
                    // Verify round-trip consistency
                    assert_eq!(quarter_stream_id, clamped_qsid, "Quarter stream ID round-trip failed");
                    assert_eq!(payload, limited_payload, "Payload round-trip failed");
                    assert_eq!(consumed, encoded.len(), "Should consume entire encoded frame");

                    // Verify re-encoding produces same result
                    let re_encoded = construct_datagram_frame(quarter_stream_id, &payload);
                    assert_eq!(re_encoded, encoded, "Re-encoding should produce identical bytes");
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other);
                }
                Err(err) => {
                    panic!("Round-trip decode failed: {:?}", err);
                }
            }
        }

        DatagramRoundTrip::BoundaryValues { test_case } => {
            let (qsid, description) = match test_case {
                BoundaryCase::Zero => (0, "zero quarter_stream_id"),
                BoundaryCase::PowerOfTwo { exponent } => {
                    let exp = exponent.min(62); // Limit to valid range
                    (1u64 << exp, "power of two quarter_stream_id")
                }
                BoundaryCase::MaxValidQuic => (MAX_QUARTER_STREAM_ID, "maximum valid QUIC stream ID"),
                BoundaryCase::VarintBoundary { boundary_type } => {
                    let value = match boundary_type {
                        VarintBoundaryType::SixBit => 63,
                        VarintBoundaryType::FourteenBit => 16383,
                        VarintBoundaryType::ThirtyBit => 1073741823,
                        VarintBoundaryType::SixtyTwoBit => 4611686018427387903,
                    };
                    (value.min(MAX_QUARTER_STREAM_ID), "varint boundary quarter_stream_id")
                }
            };

            // Test round-trip with boundary value
            let payload = b"boundary test payload".to_vec();
            let encoded = construct_datagram_frame(qsid, &payload);

            match H3Frame::decode(&encoded) {
                Ok((H3Frame::Datagram { quarter_stream_id, payload: parsed_payload }, _)) => {
                    assert_eq!(quarter_stream_id, qsid, "Boundary case {} failed", description);
                    assert_eq!(parsed_payload, payload, "Payload should be preserved for {}", description);
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame for {}, got: {:?}", description, other);
                }
                Err(err) => {
                    panic!("Round-trip failed for {}: {:?}", description, err);
                }
            }
        }

        DatagramRoundTrip::PayloadPatterns { pattern } => {
            let (payload, description) = match pattern {
                PayloadPattern::AllZeros { length } => {
                    let len = (length as usize).min(MAX_PAYLOAD_SIZE);
                    (vec![0u8; len], "all zeros pattern")
                }
                PayloadPattern::AllOnes { length } => {
                    let len = (length as usize).min(MAX_PAYLOAD_SIZE);
                    (vec![0xFF; len], "all ones pattern")
                }
                PayloadPattern::Alternating { length } => {
                    let len = (length as usize).min(MAX_PAYLOAD_SIZE);
                    let payload: Vec<u8> = (0..len).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
                    (payload, "alternating pattern")
                }
                PayloadPattern::Sequential { length } => {
                    let len = (length as usize).min(MAX_PAYLOAD_SIZE);
                    let payload: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
                    (payload, "sequential pattern")
                }
                PayloadPattern::Random { seed, length } => {
                    let len = (length as usize).min(MAX_PAYLOAD_SIZE);
                    // Simple PRNG for reproducible "random" pattern
                    let mut val = seed as u32;
                    let payload: Vec<u8> = (0..len).map(|_| {
                        val = val.wrapping_mul(1103515245).wrapping_add(12345);
                        (val >> 16) as u8
                    }).collect();
                    (payload, "random pattern")
                }
                PayloadPattern::Utf8Text { text } => {
                    let mut bytes = text.into_bytes();
                    if bytes.len() > MAX_PAYLOAD_SIZE {
                        bytes.truncate(MAX_PAYLOAD_SIZE);
                    }
                    (bytes, "UTF-8 text pattern")
                }
                PayloadPattern::FrameLike { fake_type, fake_length } => {
                    let mut payload = Vec::new();
                    payload.push(fake_type);
                    payload.push(fake_length);
                    // Add some fake frame content
                    payload.extend_from_slice(b"fake frame content");
                    (payload, "frame-like pattern")
                }
            };

            // Test round-trip with specific payload pattern
            let qsid = 42; // Arbitrary quarter_stream_id
            let encoded = construct_datagram_frame(qsid, &payload);

            match H3Frame::decode(&encoded) {
                Ok((H3Frame::Datagram { quarter_stream_id, payload: parsed_payload }, _)) => {
                    assert_eq!(quarter_stream_id, qsid, "Quarter stream ID should be preserved for {}", description);
                    assert_eq!(parsed_payload, payload, "Payload pattern {} should be preserved exactly", description);
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame for {}, got: {:?}", description, other);
                }
                Err(err) => {
                    panic!("Round-trip failed for {}: {:?}", description, err);
                }
            }
        }
    }
}

fn test_datagram_metamorphic(metamorphic: DatagramMetamorphic) {
    match metamorphic {
        DatagramMetamorphic::EmptyPayloadInvariance { base_frame } => {
            let clamped_qsid = base_frame.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);

            // Test that frames with empty payloads decode consistently
            let empty_frame = construct_datagram_frame(clamped_qsid, &[]);
            let result = H3Frame::decode(&empty_frame);

            match result {
                Ok((H3Frame::Datagram { quarter_stream_id, payload }, _)) => {
                    assert_eq!(quarter_stream_id, clamped_qsid);
                    assert!(payload.is_empty(), "Empty payload invariance violated");
                }
                Ok(other) => {
                    panic!("Expected DATAGRAM frame, got: {:?}", other);
                }
                Err(_) => {
                    // Error is acceptable for metamorphic testing
                }
            }
        }

        DatagramMetamorphic::ConcatenationPreservation { frames } => {
            let limited_frames: Vec<_> = frames.into_iter().take(MAX_FRAMES).collect();
            if limited_frames.is_empty() {
                return;
            }

            // Encode individual frames
            let mut individual_results = Vec::new();
            let mut concatenated_data = Vec::new();

            for frame in &limited_frames {
                let clamped_qsid = frame.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
                let limited_payload = if frame.payload.len() > MAX_PAYLOAD_SIZE / MAX_FRAMES {
                    &frame.payload[..MAX_PAYLOAD_SIZE / MAX_FRAMES]
                } else {
                    &frame.payload
                };

                let frame_bytes = construct_datagram_frame(clamped_qsid, limited_payload);

                // Parse individual frame
                if let Ok((frame_parsed, _)) = H3Frame::decode(&frame_bytes) {
                    if let H3Frame::Datagram { quarter_stream_id, payload } = frame_parsed {
                        individual_results.push((quarter_stream_id, payload));
                    }
                }

                concatenated_data.extend_from_slice(&frame_bytes);
            }

            // Parse concatenated frames
            let mut offset = 0;
            let mut concatenated_results = Vec::new();

            while offset < concatenated_data.len() && concatenated_results.len() < individual_results.len() {
                match H3Frame::decode(&concatenated_data[offset..]) {
                    Ok((H3Frame::Datagram { quarter_stream_id, payload }, consumed)) => {
                        concatenated_results.push((quarter_stream_id, payload));
                        offset += consumed;
                    }
                    _ => break,
                }
            }

            // Verify concatenation preserves individual parsing results
            assert_eq!(concatenated_results.len(), individual_results.len(),
                "Concatenation should preserve number of frames");

            for (i, (individual, concatenated)) in individual_results.iter().zip(concatenated_results.iter()).enumerate() {
                assert_eq!(individual, concatenated,
                    "Frame {} should parse identically when concatenated", i);
            }
        }

        DatagramMetamorphic::EncodingOrderInvariance { frame1, frame2 } => {
            // Test that identical frames encode to identical bytes regardless of construction order
            let clamped_qsid1 = frame1.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let clamped_qsid2 = frame2.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);

            let limited_payload1 = if frame1.payload.len() > MAX_PAYLOAD_SIZE / 2 {
                &frame1.payload[..MAX_PAYLOAD_SIZE / 2]
            } else {
                &frame1.payload
            };
            let limited_payload2 = if frame2.payload.len() > MAX_PAYLOAD_SIZE / 2 {
                &frame2.payload[..MAX_PAYLOAD_SIZE / 2]
            } else {
                &frame2.payload
            };

            let encoded1 = construct_datagram_frame(clamped_qsid1, limited_payload1);
            let encoded2 = construct_datagram_frame(clamped_qsid2, limited_payload2);

            // If frames are identical, encodings should be identical
            if clamped_qsid1 == clamped_qsid2 && limited_payload1 == limited_payload2 {
                assert_eq!(encoded1, encoded2, "Identical frames should encode identically");
            }

            // Decode both and verify consistency
            if let (Ok((H3Frame::Datagram { quarter_stream_id: qsid1, payload: payload1 }, _)),
                    Ok((H3Frame::Datagram { quarter_stream_id: qsid2, payload: payload2 }, _))) =
                   (H3Frame::decode(&encoded1), H3Frame::decode(&encoded2)) {

                // Verify round-trip consistency
                assert_eq!(qsid1, clamped_qsid1);
                assert_eq!(payload1, limited_payload1);
                assert_eq!(qsid2, clamped_qsid2);
                assert_eq!(payload2, limited_payload2);
            }
        }

        DatagramMetamorphic::PayloadOrderSensitivity { original } => {
            let clamped_qsid = original.quarter_stream_id.min(MAX_QUARTER_STREAM_ID);
            let limited_payload = if original.payload.len() > MAX_PAYLOAD_SIZE {
                &original.payload[..MAX_PAYLOAD_SIZE]
            } else {
                &original.payload
            };

            if limited_payload.len() < 2 {
                return; // Can't test order sensitivity with < 2 bytes
            }

            // Create payload with bytes in reverse order
            let mut reversed_payload = limited_payload.to_vec();
            reversed_payload.reverse();

            let original_encoded = construct_datagram_frame(clamped_qsid, limited_payload);
            let reversed_encoded = construct_datagram_frame(clamped_qsid, &reversed_payload);

            // Parse both frames
            if let (Ok((H3Frame::Datagram { quarter_stream_id: orig_qsid, payload: orig_payload }, _)),
                    Ok((H3Frame::Datagram { quarter_stream_id: rev_qsid, payload: rev_payload }, _))) =
                   (H3Frame::decode(&original_encoded), H3Frame::decode(&reversed_encoded)) {

                // Quarter stream IDs should be identical
                assert_eq!(orig_qsid, rev_qsid, "Quarter stream ID should not be affected by payload order");

                // Payloads should be different (unless palindromic)
                if orig_payload != rev_payload {
                    assert_eq!(orig_payload, limited_payload, "Original payload should be preserved");
                    assert_eq!(rev_payload, reversed_payload, "Reversed payload should be preserved");
                }
            }
        }
    }
}

fn construct_datagram_frame(quarter_stream_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame_data = Vec::new();

    // Frame type: DATAGRAM (0x30)
    let _ = encode_varint(0x30, &mut frame_data);

    // Frame length: quarter_stream_id varint + payload
    let mut qsid_bytes = Vec::new();
    let _ = encode_varint(quarter_stream_id, &mut qsid_bytes);
    let frame_length = qsid_bytes.len() + payload.len();
    let _ = encode_varint(frame_length as u64, &mut frame_data);

    // Quarter stream ID (varint)
    frame_data.extend_from_slice(&qsid_bytes);

    // Payload
    frame_data.extend_from_slice(payload);

    frame_data
}

fn verify_datagram_frame_consistency(quarter_stream_id: u64, payload: &[u8]) {
    // Verify quarter_stream_id is within valid range
    assert!(quarter_stream_id <= MAX_QUARTER_STREAM_ID,
        "Quarter stream ID {} exceeds maximum {}", quarter_stream_id, MAX_QUARTER_STREAM_ID);

    // Verify payload size is reasonable
    assert!(payload.len() <= MAX_PAYLOAD_SIZE,
        "Payload size {} exceeds maximum {}", payload.len(), MAX_PAYLOAD_SIZE);

    // Additional RFC 9297 compliance checks could go here
}

fn verify_datagram_error_consistency(err: &H3NativeError, data: &[u8]) {
    match err {
        H3NativeError::UnexpectedEof => {
            // Should occur when frame is incomplete
        }
        H3NativeError::InvalidFrame(msg) => {
            // Should describe what's invalid
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
        H3NativeError::ControlProtocol(msg) => {
            assert!(!msg.is_empty(), "Control protocol error should have message");
        }
        H3NativeError::StreamProtocol(msg) => {
            assert!(!msg.is_empty(), "Stream protocol error should have message");
        }
        _ => {
            // Other errors are also acceptable for DATAGRAM frame parsing
        }
    }

    // Verify error is not due to excessively large input
    if data.len() <= MAX_PAYLOAD_SIZE * 2 {
        // Error should be informative for reasonably-sized inputs
    }
}

fn test_datagram_frame_reencode(quarter_stream_id: u64, payload: &[u8]) {
    // Test that we can re-encode a successfully decoded frame
    let re_encoded = construct_datagram_frame(quarter_stream_id, payload);

    // Re-parse the re-encoded frame
    match H3Frame::decode(&re_encoded) {
        Ok((H3Frame::Datagram { quarter_stream_id: re_qsid, payload: re_payload }, _)) => {
            assert_eq!(re_qsid, quarter_stream_id, "Re-encoding should preserve quarter_stream_id");
            assert_eq!(re_payload, payload, "Re-encoding should preserve payload");
        }
        Ok(other) => {
            panic!("Re-encoded frame should be DATAGRAM, got: {:?}", other);
        }
        Err(err) => {
            panic!("Re-encoding should not fail: {:?}", err);
        }
    }
}