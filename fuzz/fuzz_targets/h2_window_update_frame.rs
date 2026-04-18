#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{FrameHeader, FrameType};

/// Fuzz input for HTTP/2 WINDOW_UPDATE frame testing (RFC 7540 §6.9)
#[derive(Arbitrary, Debug)]
struct WindowUpdateFuzz {
    /// WINDOW_UPDATE frame operations
    window_update_operations: Vec<WindowUpdateOperation>,
    /// Edge cases and boundary conditions
    edge_cases: Vec<WindowUpdateEdgeCase>,
    /// Round-trip testing scenarios
    roundtrip_tests: Vec<WindowUpdateRoundTrip>,
    /// Flow control overflow scenarios
    overflow_tests: Vec<WindowUpdateOverflow>,
    /// Reserved bit manipulation tests
    reserved_bit_tests: Vec<ReservedBitTest>,
}

/// WINDOW_UPDATE frame parsing operations
#[derive(Arbitrary, Debug)]
enum WindowUpdateOperation {
    /// Parse WINDOW_UPDATE frame from raw bytes
    ParseRaw { data: Vec<u8> },
    /// Parse WINDOW_UPDATE with specific stream_id and increment
    ParseStructured { stream_id: u32, increment: u32 },
    /// Parse multiple WINDOW_UPDATE frames
    ParseMultiple { frames: Vec<WindowUpdateFrameData> },
    /// Parse truncated WINDOW_UPDATE frame
    ParseTruncated {
        complete_frame: WindowUpdateFrameData,
        truncate_at: u8,
    },
}

/// Edge cases and boundary conditions for WINDOW_UPDATE frames
#[derive(Arbitrary, Debug)]
enum WindowUpdateEdgeCase {
    /// Zero increment (must be rejected per RFC 7540 §6.9.1)
    ZeroIncrement { stream_id: u32 },
    /// Maximum increment value (2^31-1)
    MaxIncrement { stream_id: u32 },
    /// Connection-level vs stream-level behavior
    ConnectionVsStream {
        increment: u32,
        connection_level: bool,
    },
    /// Invalid payload length (not 4 bytes)
    InvalidPayloadLength {
        stream_id: u32,
        payload_length: u8,
        fill_byte: u8,
    },
    /// Stream ID boundary values
    StreamIdBoundary {
        stream_id_type: StreamIdType,
        increment: u32,
    },
}

/// Different stream ID types for boundary testing
#[derive(Arbitrary, Debug)]
enum StreamIdType {
    /// Connection level (stream ID 0)
    Connection,
    /// Minimum stream ID (1)
    MinStream,
    /// Maximum valid stream ID (2^31-1)
    MaxStream,
    /// Power of 2 stream IDs
    PowerOfTwo { exponent: u8 },
    /// Stream ID with reserved bit set (invalid)
    WithReservedBit { base_id: u32 },
}

/// Round-trip testing for WINDOW_UPDATE frames
#[derive(Arbitrary, Debug)]
enum WindowUpdateRoundTrip {
    /// Standard round-trip: construct -> encode -> decode -> verify
    Standard { frame: WindowUpdateFrameData },
    /// Round-trip with boundary increment values
    BoundaryIncrement { test_case: IncrementBoundary },
    /// Round-trip with various stream ID patterns
    StreamIdPattern { pattern: StreamIdPattern },
}

/// Increment boundary values for testing
#[derive(Arbitrary, Debug)]
enum IncrementBoundary {
    /// Minimum valid increment (1)
    Min,
    /// Powers of 2
    PowerOfTwo { exponent: u8 },
    /// Maximum valid increment (2^31-1)
    Max,
    /// Values around boundaries
    NearBoundary { offset: i8 },
}

/// Stream ID patterns for testing
#[derive(Arbitrary, Debug)]
enum StreamIdPattern {
    /// Sequential stream IDs
    Sequential { start: u32, count: u8 },
    /// Alternating even/odd stream IDs
    Alternating { start: u32, count: u8 },
    /// Random valid stream IDs
    Random { seed: u8, count: u8 },
}

/// Flow control overflow scenarios
#[derive(Arbitrary, Debug)]
enum WindowUpdateOverflow {
    /// Test window size overflow detection
    WindowOverflow {
        current_window_size: u32,
        increment: u32,
        stream_id: u32,
    },
    /// Cumulative increment overflow
    CumulativeOverflow {
        increments: Vec<u32>,
        stream_id: u32,
    },
    /// Large increment near max values
    LargeIncrement { base_increment: u32, stream_id: u32 },
}

/// Reserved bit manipulation tests
#[derive(Arbitrary, Debug)]
enum ReservedBitTest {
    /// Set reserved bit in increment field
    IncrementReservedBit { stream_id: u32, increment: u32 },
    /// Verify reserved bit is cleared during encoding
    EncodingReservedBitClear { frame: WindowUpdateFrameData },
    /// Multiple reserved bits set
    MultipleReservedBits {
        stream_id: u32,
        increment: u32,
        pattern: u8,
    },
}

/// Window update frame data for construction
#[derive(Arbitrary, Debug, Clone, Copy)]
struct WindowUpdateFrameData {
    stream_id: u32,
    increment: u32,
}

/// Size limits and constants from RFC 7540
const MAX_INCREMENT: u32 = 0x7FFF_FFFF; // 2^31-1
const MAX_WINDOW_SIZE: u64 = 0x7FFF_FFFF; // Maximum flow control window size
const WINDOW_UPDATE_PAYLOAD_SIZE: usize = 4;
const MAX_OPERATIONS: usize = 50;
const MAX_FRAMES: usize = 10;

fuzz_target!(|input: WindowUpdateFuzz| {
    // Limit operations to prevent timeout
    let total_operations = input.window_update_operations.len()
        + input.edge_cases.len()
        + input.roundtrip_tests.len()
        + input.overflow_tests.len()
        + input.reserved_bit_tests.len();

    if total_operations > MAX_OPERATIONS {
        return;
    }

    // Test basic WINDOW_UPDATE operations
    for operation in input.window_update_operations {
        test_window_update_operation(operation);
    }

    // Test edge cases and boundary conditions
    for edge_case in input.edge_cases {
        test_window_update_edge_case(edge_case);
    }

    // Test round-trip encoding/decoding
    for roundtrip in input.roundtrip_tests {
        test_window_update_roundtrip(roundtrip);
    }

    // Test flow control overflow scenarios
    for overflow in input.overflow_tests {
        test_window_update_overflow(overflow);
    }

    // Test reserved bit handling
    for reserved_bit in input.reserved_bit_tests {
        test_reserved_bit_handling(reserved_bit);
    }
});

fn test_window_update_operation(operation: WindowUpdateOperation) {
    match operation {
        WindowUpdateOperation::ParseRaw { mut data } => {
            // Limit size to prevent memory exhaustion
            if data.len() > 1024 {
                data.truncate(1024);
            }

            // Attempt to parse as HTTP/2 frame
            if data.len() >= 9 {
                let mut buf = BytesMut::from(&data[..]);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload_data = buf.split_to((header.length as usize).min(data.len() - 9));
                    let payload = payload_data.freeze();

                    // Test WINDOW_UPDATE parsing
                    if header.frame_type == FrameType::WindowUpdate as u8 {
                        let result = asupersync::http::h2::frame::WindowUpdateFrame::parse(
                            &header, &payload,
                        );
                        match result {
                            Ok(frame) => {
                                verify_window_update_consistency(frame.stream_id, frame.increment);
                                test_window_update_reencode(frame.stream_id, frame.increment);
                            }
                            Err(err) => {
                                verify_window_update_error_consistency(&err, &header, &payload);
                            }
                        }
                    }
                }
            }
        }

        WindowUpdateOperation::ParseStructured {
            stream_id,
            increment,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF; // Clear reserved bit
            let clamped_increment = increment & 0x7FFF_FFFF; // Clear reserved bit

            // Construct well-formed WINDOW_UPDATE frame
            if clamped_increment > 0 {
                // Valid increment
                let frame_bytes =
                    construct_window_update_frame(clamped_stream_id, clamped_increment);

                let mut buf = BytesMut::from(&frame_bytes[..]);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload = buf.split_to(header.length as usize).freeze();

                    match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                        Ok(parsed) => {
                            assert_eq!(parsed.stream_id, clamped_stream_id, "Stream ID mismatch");
                            assert_eq!(parsed.increment, clamped_increment, "Increment mismatch");
                        }
                        Err(err) => {
                            // Should only fail for zero increment or malformed data
                            verify_window_update_error_consistency(&err, &header, &payload);
                        }
                    }
                }
            }
        }

        WindowUpdateOperation::ParseMultiple { frames } => {
            let limited_frames: Vec<_> = frames.into_iter().take(MAX_FRAMES).collect();
            let mut combined_data = Vec::new();

            // Construct multiple WINDOW_UPDATE frames
            for frame in &limited_frames {
                let clamped_stream_id = frame.stream_id & 0x7FFF_FFFF;
                let clamped_increment = (frame.increment & 0x7FFF_FFFF).max(1); // Ensure non-zero

                let frame_bytes =
                    construct_window_update_frame(clamped_stream_id, clamped_increment);
                combined_data.extend_from_slice(&frame_bytes);
            }

            // Parse each frame sequentially
            let mut offset = 0;
            let mut parsed_count = 0;

            while offset < combined_data.len() && parsed_count < limited_frames.len() {
                if offset + 9 > combined_data.len() {
                    break;
                }

                let mut buf = BytesMut::from(&combined_data[offset..]);
                match FrameHeader::parse(&mut buf) {
                    Ok(header) => {
                        if header.frame_type == FrameType::WindowUpdate as u8 {
                            if header.length as usize <= buf.len() {
                                let payload = buf.split_to(header.length as usize).freeze();

                                if let Ok(frame) =
                                    asupersync::http::h2::frame::WindowUpdateFrame::parse(
                                        &header, &payload,
                                    )
                                {
                                    verify_window_update_consistency(
                                        frame.stream_id,
                                        frame.increment,
                                    );
                                    offset += 9 + header.length as usize;
                                    parsed_count += 1;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        WindowUpdateOperation::ParseTruncated {
            complete_frame,
            truncate_at,
        } => {
            let clamped_stream_id = complete_frame.stream_id & 0x7FFF_FFFF;
            let clamped_increment = (complete_frame.increment & 0x7FFF_FFFF).max(1);

            let complete_bytes =
                construct_window_update_frame(clamped_stream_id, clamped_increment);
            let truncate_pos = (truncate_at as usize).min(complete_bytes.len());
            let truncated = &complete_bytes[..truncate_pos];

            // Should handle truncated input gracefully
            if truncated.len() >= 9 {
                let mut buf = BytesMut::from(truncated);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload = buf.freeze();

                    let result =
                        asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload);
                    match result {
                        Ok(frame) => {
                            // If parsing succeeded, frame must be valid within truncated data
                            verify_window_update_consistency(frame.stream_id, frame.increment);
                        }
                        Err(_) => {
                            // Expected for truncated input
                        }
                    }
                }
            }
        }
    }
}

fn test_window_update_edge_case(edge_case: WindowUpdateEdgeCase) {
    match edge_case {
        WindowUpdateEdgeCase::ZeroIncrement { stream_id } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;

            // Construct WINDOW_UPDATE frame with zero increment (should be rejected)
            let frame_bytes = construct_window_update_frame_raw(clamped_stream_id, 0);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                let result =
                    asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload);
                match result {
                    Err(ref err) if clamped_stream_id == 0 => {
                        // Connection-level zero increment should be protocol error
                        assert!(
                            err.is_connection_error(),
                            "Should be connection-level error"
                        );
                        assert_eq!(
                            err.code,
                            ErrorCode::ProtocolError,
                            "Should be protocol error"
                        );
                        assert!(
                            err.message.contains("zero increment"),
                            "Error message should mention zero increment"
                        );
                    }
                    Err(ref err) if clamped_stream_id > 0 => {
                        // Stream-level zero increment should be stream error
                        assert!(!err.is_connection_error(), "Should be stream-level error");
                        assert_eq!(
                            err.stream_id.unwrap(),
                            clamped_stream_id,
                            "Error stream ID should match"
                        );
                        assert_eq!(
                            err.code,
                            ErrorCode::ProtocolError,
                            "Should be protocol error"
                        );
                        assert!(
                            err.message.contains("zero increment"),
                            "Error message should mention zero increment"
                        );
                    }
                    Ok(_) => {
                        panic!("Zero increment should be rejected per RFC 7540 §6.9.1");
                    }
                    Err(ref other) => {
                        // Other errors might be acceptable depending on implementation
                        eprintln!("Unexpected error for zero increment: {:?}", other);
                    }
                }
            }
        }

        WindowUpdateEdgeCase::MaxIncrement { stream_id } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let max_increment = MAX_INCREMENT;

            let frame_bytes = construct_window_update_frame(clamped_stream_id, max_increment);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, clamped_stream_id);
                        assert_eq!(frame.increment, max_increment);
                    }
                    Err(err) => {
                        panic!("Maximum increment should be valid: {:?}", err);
                    }
                }
            }
        }

        WindowUpdateEdgeCase::ConnectionVsStream {
            increment,
            connection_level,
        } => {
            let stream_id = if connection_level { 0 } else { 1 };
            let clamped_increment = (increment & 0x7FFF_FFFF).max(1);

            let frame_bytes = construct_window_update_frame(stream_id, clamped_increment);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, stream_id);
                        assert_eq!(frame.increment, clamped_increment);

                        // Both connection-level and stream-level should be valid for non-zero increments
                        verify_window_update_consistency(frame.stream_id, frame.increment);
                    }
                    Err(err) => {
                        // Should only fail for invalid increment
                        verify_window_update_error_consistency(&err, &header, &payload);
                    }
                }
            }
        }

        WindowUpdateEdgeCase::InvalidPayloadLength {
            stream_id,
            payload_length,
            fill_byte,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let length = (payload_length as usize).min(64); // Limit to prevent memory issues

            // Construct frame with invalid payload length
            let header = FrameHeader {
                length: length as u32,
                frame_type: FrameType::WindowUpdate as u8,
                flags: 0,
                stream_id: clamped_stream_id,
            };

            let mut frame_data = BytesMut::new();
            header.write(&mut frame_data);
            frame_data.extend_from_slice(&vec![fill_byte; length]);
            let frame_data = frame_data.to_vec();

            let mut buf = BytesMut::from(&frame_data[..]);
            if let Ok(parsed_header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(parsed_header.length as usize).freeze();

                let result =
                    asupersync::http::h2::frame::WindowUpdateFrame::parse(&parsed_header, &payload);
                if length != WINDOW_UPDATE_PAYLOAD_SIZE {
                    // Should fail for invalid payload length
                    match result {
                        Err(ref err) if err.code == ErrorCode::FrameSizeError => {
                            assert!(
                                err.message.contains("4 bytes"),
                                "Error should mention required 4 bytes"
                            );
                        }
                        Ok(_) => {
                            panic!("Invalid payload length should be rejected");
                        }
                        Err(ref other) => {
                            // Other errors might be acceptable
                            eprintln!("Unexpected error for invalid payload length: {:?}", other);
                        }
                    }
                }
            }
        }

        WindowUpdateEdgeCase::StreamIdBoundary {
            stream_id_type,
            increment,
        } => {
            let stream_id = match stream_id_type {
                StreamIdType::Connection => 0,
                StreamIdType::MinStream => 1,
                StreamIdType::MaxStream => 0x7FFF_FFFF,
                StreamIdType::PowerOfTwo { exponent } => {
                    let exp = (exponent & 0x1F).min(30); // Limit to valid range
                    (1u32 << exp) & 0x7FFF_FFFF
                }
                StreamIdType::WithReservedBit { base_id } => {
                    base_id | 0x8000_0000 // Set reserved bit
                }
            };

            let clamped_increment = (increment & 0x7FFF_FFFF).max(1);

            // For reserved bit test, use raw construction
            let frame_bytes = if matches!(stream_id_type, StreamIdType::WithReservedBit { .. }) {
                construct_window_update_frame_raw(stream_id, clamped_increment)
            } else {
                construct_window_update_frame(stream_id, clamped_increment)
            };

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                let result =
                    asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload);
                match result {
                    Ok(frame) => {
                        // Verify stream ID is properly handled (reserved bit should be cleared)
                        verify_window_update_consistency(frame.stream_id, frame.increment);

                        if matches!(stream_id_type, StreamIdType::WithReservedBit { .. }) {
                            // Stream ID should have reserved bit cleared
                            assert_eq!(
                                frame.stream_id & 0x8000_0000,
                                0,
                                "Reserved bit should be cleared"
                            );
                        }
                    }
                    Err(err) => {
                        verify_window_update_error_consistency(&err, &header, &payload);
                    }
                }
            }
        }
    }
}

fn test_window_update_roundtrip(roundtrip: WindowUpdateRoundTrip) {
    match roundtrip {
        WindowUpdateRoundTrip::Standard { frame } => {
            let clamped_stream_id = frame.stream_id & 0x7FFF_FFFF;
            let clamped_increment = (frame.increment & 0x7FFF_FFFF).max(1);

            // Encode frame
            let encoded = construct_window_update_frame(clamped_stream_id, clamped_increment);

            // Decode frame
            let mut buf = BytesMut::from(&encoded[..]);
            match FrameHeader::parse(&mut buf) {
                Ok(header) => {
                    let payload = buf.split_to(header.length as usize).freeze();

                    match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                        Ok(parsed) => {
                            // Verify round-trip consistency
                            assert_eq!(
                                parsed.stream_id, clamped_stream_id,
                                "Stream ID round-trip failed"
                            );
                            assert_eq!(
                                parsed.increment, clamped_increment,
                                "Increment round-trip failed"
                            );

                            // Verify re-encoding produces same result
                            let re_encoded =
                                construct_window_update_frame(parsed.stream_id, parsed.increment);
                            assert_eq!(
                                re_encoded, encoded,
                                "Re-encoding should produce identical bytes"
                            );
                        }
                        Err(err) => {
                            panic!("Round-trip decode failed: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    panic!("Round-trip header parse failed: {:?}", err);
                }
            }
        }

        WindowUpdateRoundTrip::BoundaryIncrement { test_case } => {
            let stream_id = 1; // Use stream-level for boundary testing
            let increment = match test_case {
                IncrementBoundary::Min => 1,
                IncrementBoundary::PowerOfTwo { exponent } => {
                    let exp = (exponent & 0x1F).min(30);
                    (1u32 << exp) & 0x7FFF_FFFF
                }
                IncrementBoundary::Max => MAX_INCREMENT,
                IncrementBoundary::NearBoundary { offset } => {
                    let base = MAX_INCREMENT / 2;
                    ((base as i64 + offset as i64).max(1) as u32).min(MAX_INCREMENT)
                }
            };

            // Test round-trip with boundary increment
            let encoded = construct_window_update_frame(stream_id, increment);

            let mut buf = BytesMut::from(&encoded[..]);
            match FrameHeader::parse(&mut buf) {
                Ok(header) => {
                    let payload = buf.split_to(header.length as usize).freeze();

                    match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                        Ok(parsed) => {
                            assert_eq!(parsed.stream_id, stream_id);
                            assert_eq!(parsed.increment, increment);
                        }
                        Err(err) => {
                            panic!("Boundary increment round-trip failed: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    panic!("Boundary increment header parse failed: {:?}", err);
                }
            }
        }

        WindowUpdateRoundTrip::StreamIdPattern { pattern } => {
            let stream_ids = match pattern {
                StreamIdPattern::Sequential { start, count } => {
                    let start = (start & 0x7FFF_FFFF).max(1); // Ensure valid stream ID
                    let count = count.min(20); // Limit iterations
                    (0..count)
                        .map(|i| start.saturating_add(i as u32 * 2))
                        .collect::<Vec<_>>()
                }
                StreamIdPattern::Alternating { start, count } => {
                    let start = (start & 0x7FFF_FFFF).max(1);
                    let count = count.min(20);
                    (0..count)
                        .map(|i| if i % 2 == 0 { start } else { start + 2 })
                        .collect::<Vec<_>>()
                }
                StreamIdPattern::Random { seed, count } => {
                    let count = count.min(20);
                    let mut val = seed as u32;
                    (0..count)
                        .map(|_| {
                            val = val.wrapping_mul(1103515245).wrapping_add(12345);
                            ((val >> 16) & 0x7FFF_FFFF).max(1)
                        })
                        .collect::<Vec<_>>()
                }
            };

            let increment = 1000; // Fixed increment for pattern testing

            // Test round-trip for each stream ID in pattern
            for stream_id in stream_ids {
                let encoded = construct_window_update_frame(stream_id, increment);

                let mut buf = BytesMut::from(&encoded[..]);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload = buf.split_to(header.length as usize).freeze();

                    if let Ok(parsed) =
                        asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload)
                    {
                        assert_eq!(parsed.stream_id, stream_id);
                        assert_eq!(parsed.increment, increment);
                    }
                }
            }
        }
    }
}

fn test_window_update_overflow(overflow: WindowUpdateOverflow) {
    match overflow {
        WindowUpdateOverflow::WindowOverflow {
            current_window_size,
            increment,
            stream_id,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let clamped_increment = (increment & 0x7FFF_FFFF).max(1);

            // Test if increment would cause window overflow
            let total = current_window_size as u64 + clamped_increment as u64;
            if total > MAX_WINDOW_SIZE {
                // This represents a flow control violation scenario
                // The frame itself should parse correctly, but application logic should detect overflow
                let frame_bytes =
                    construct_window_update_frame(clamped_stream_id, clamped_increment);

                let mut buf = BytesMut::from(&frame_bytes[..]);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload = buf.split_to(header.length as usize).freeze();

                    // Frame parsing should succeed even if increment causes overflow
                    match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                        Ok(frame) => {
                            verify_window_update_consistency(frame.stream_id, frame.increment);

                            // Application should detect overflow separately
                            assert!(
                                current_window_size as u64 + frame.increment as u64
                                    > MAX_WINDOW_SIZE
                            );
                        }
                        Err(err) => {
                            verify_window_update_error_consistency(&err, &header, &payload);
                        }
                    }
                }
            }
        }

        WindowUpdateOverflow::CumulativeOverflow {
            increments,
            stream_id,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let limited_increments: Vec<_> = increments
                .into_iter()
                .take(10)
                .map(|inc| (inc & 0x7FFF_FFFF).max(1))
                .collect();

            // Test cumulative increments
            let mut total_increment = 0u64;
            for increment in limited_increments {
                let frame_bytes = construct_window_update_frame(clamped_stream_id, increment);

                let mut buf = BytesMut::from(&frame_bytes[..]);
                if let Ok(header) = FrameHeader::parse(&mut buf) {
                    let payload = buf.split_to(header.length as usize).freeze();

                    if let Ok(frame) =
                        asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload)
                    {
                        total_increment += frame.increment as u64;

                        // Each individual frame should be valid
                        verify_window_update_consistency(frame.stream_id, frame.increment);

                        if total_increment > MAX_WINDOW_SIZE {
                            // Cumulative overflow detected
                            break;
                        }
                    }
                }
            }
        }

        WindowUpdateOverflow::LargeIncrement {
            base_increment,
            stream_id,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let large_increment = (base_increment | 0x4000_0000) & 0x7FFF_FFFF; // Large but valid

            let frame_bytes = construct_window_update_frame(clamped_stream_id, large_increment);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, clamped_stream_id);
                        assert_eq!(frame.increment, large_increment);
                        verify_window_update_consistency(frame.stream_id, frame.increment);
                    }
                    Err(err) => {
                        verify_window_update_error_consistency(&err, &header, &payload);
                    }
                }
            }
        }
    }
}

fn test_reserved_bit_handling(reserved_bit: ReservedBitTest) {
    match reserved_bit {
        ReservedBitTest::IncrementReservedBit {
            stream_id,
            increment,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;
            let increment_with_reserved_bit = increment | 0x8000_0000; // Set reserved bit

            // Construct frame with reserved bit set in increment
            let frame_bytes =
                construct_window_update_frame_raw(clamped_stream_id, increment_with_reserved_bit);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                    Ok(frame) => {
                        // Reserved bit should be cleared during parsing
                        let expected_increment = increment_with_reserved_bit & 0x7FFF_FFFF;
                        assert_eq!(
                            frame.increment, expected_increment,
                            "Reserved bit should be cleared"
                        );

                        if expected_increment == 0 {
                            panic!("Zero increment should have been rejected");
                        }

                        verify_window_update_consistency(frame.stream_id, frame.increment);
                    }
                    Err(err) => {
                        // Should only fail if increment becomes zero after clearing reserved bit
                        if (increment_with_reserved_bit & 0x7FFF_FFFF) == 0 {
                            // Expected to fail for zero increment
                        } else {
                            verify_window_update_error_consistency(&err, &header, &payload);
                        }
                    }
                }
            }
        }

        ReservedBitTest::EncodingReservedBitClear { frame } => {
            let clamped_stream_id = frame.stream_id & 0x7FFF_FFFF;
            let clamped_increment = (frame.increment & 0x7FFF_FFFF).max(1);

            // Create frame using library encoding
            let h2_frame = asupersync::http::h2::frame::WindowUpdateFrame::new(
                clamped_stream_id,
                clamped_increment,
            );

            let mut encoded_buf = BytesMut::new();
            h2_frame.encode(&mut encoded_buf);

            // Parse the encoded frame and verify reserved bit is clear
            let mut buf = encoded_buf;
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                // Check raw payload bytes - reserved bit should be clear
                if payload.len() == 4 {
                    let raw_increment =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    assert_eq!(
                        raw_increment & 0x8000_0000,
                        0,
                        "Encoded increment should have reserved bit clear"
                    );

                    // Also verify through parsing
                    if let Ok(parsed) =
                        asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload)
                    {
                        assert_eq!(
                            parsed.increment & 0x8000_0000,
                            0,
                            "Parsed increment should have reserved bit clear"
                        );
                    }
                }
            }
        }

        ReservedBitTest::MultipleReservedBits {
            stream_id,
            increment,
            pattern,
        } => {
            let clamped_stream_id = stream_id & 0x7FFF_FFFF;

            // Apply pattern to set various bits
            let modified_increment = increment ^ ((pattern as u32) << 24);

            let frame_bytes =
                construct_window_update_frame_raw(clamped_stream_id, modified_increment);

            let mut buf = BytesMut::from(&frame_bytes[..]);
            if let Ok(header) = FrameHeader::parse(&mut buf) {
                let payload = buf.split_to(header.length as usize).freeze();

                match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                    Ok(frame) => {
                        // All reserved bits should be cleared
                        let expected_increment = modified_increment & 0x7FFF_FFFF;
                        assert_eq!(
                            frame.increment, expected_increment,
                            "All reserved bits should be cleared"
                        );

                        if expected_increment > 0 {
                            verify_window_update_consistency(frame.stream_id, frame.increment);
                        }
                    }
                    Err(err) => {
                        // Should only fail if increment becomes zero after clearing reserved bits
                        let expected_increment = modified_increment & 0x7FFF_FFFF;
                        if expected_increment == 0 {
                            // Expected to fail for zero increment
                        } else {
                            verify_window_update_error_consistency(&err, &header, &payload);
                        }
                    }
                }
            }
        }
    }
}

fn construct_window_update_frame(stream_id: u32, increment: u32) -> Vec<u8> {
    let frame = asupersync::http::h2::frame::WindowUpdateFrame::new(stream_id, increment);
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    buf.to_vec()
}

fn construct_window_update_frame_raw(stream_id: u32, increment: u32) -> Vec<u8> {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::WindowUpdate as u8,
        flags: 0,
        stream_id,
    };

    let mut frame_data = BytesMut::new();
    header.write(&mut frame_data);
    frame_data.put_u32(increment); // Raw increment without reserved bit clearing
    frame_data.to_vec()
}

fn verify_window_update_consistency(stream_id: u32, increment: u32) {
    // Verify stream ID is valid (reserved bit clear)
    assert_eq!(
        stream_id & 0x8000_0000,
        0,
        "Stream ID reserved bit should be clear"
    );

    // Verify increment is valid and non-zero
    assert!(increment > 0, "Increment must be non-zero");
    assert!(
        increment <= MAX_INCREMENT,
        "Increment must not exceed 2^31-1"
    );
    assert_eq!(
        increment & 0x8000_0000,
        0,
        "Increment reserved bit should be clear"
    );
}

fn verify_window_update_error_consistency(err: &H2Error, header: &FrameHeader, payload: &Bytes) {
    match err.code {
        ErrorCode::FrameSizeError => {
            // Should occur for invalid payload length
            if payload.len() != WINDOW_UPDATE_PAYLOAD_SIZE {
                assert!(
                    err.message.contains("4 bytes"),
                    "Frame size error should mention 4 bytes"
                );
            }
        }
        ErrorCode::ProtocolError => {
            // Check if connection-level zero increment
            if header.stream_id == 0 && err.is_connection_error() {
                assert!(
                    err.message.contains("zero increment"),
                    "Protocol error should mention zero increment"
                );
            } else if header.stream_id > 0 && !err.is_connection_error() {
                // Stream-level zero increment
                assert_eq!(
                    err.stream_id.unwrap(),
                    header.stream_id,
                    "Error stream ID should match header"
                );
                assert!(
                    err.message.contains("zero increment"),
                    "Stream error should mention zero increment"
                );
            }
        }
        _ => {
            // Other errors might be acceptable depending on input
        }
    }
}

fn test_window_update_reencode(stream_id: u32, increment: u32) {
    // Test that we can re-encode a successfully parsed frame
    let frame = asupersync::http::h2::frame::WindowUpdateFrame::new(stream_id, increment);

    let mut encoded_buf = BytesMut::new();
    frame.encode(&mut encoded_buf);

    // Re-parse the encoded frame
    let mut buf = encoded_buf;
    match FrameHeader::parse(&mut buf) {
        Ok(header) => {
            let payload = buf.split_to(header.length as usize).freeze();

            match asupersync::http::h2::frame::WindowUpdateFrame::parse(&header, &payload) {
                Ok(re_parsed) => {
                    assert_eq!(
                        re_parsed.stream_id, stream_id,
                        "Re-encoding should preserve stream ID"
                    );
                    assert_eq!(
                        re_parsed.increment, increment,
                        "Re-encoding should preserve increment"
                    );
                }
                Err(err) => {
                    panic!("Re-encoding should not fail: {:?}", err);
                }
            }
        }
        Err(err) => {
            panic!("Re-encoded frame header parsing should not fail: {:?}", err);
        }
    }
}
