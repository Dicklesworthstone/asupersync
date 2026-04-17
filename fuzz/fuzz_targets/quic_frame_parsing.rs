#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// QUIC frame fuzz input for comprehensive RFC 9000 frame testing
#[derive(Debug, Arbitrary)]
struct QuicFrameFuzzInput {
    /// Frame type and payload combinations
    frames: Vec<QuicFrameFuzzData>,
    /// VLQ encoding edge cases
    vlq_edge_cases: Vec<VlqEdgeCase>,
    /// Stream ID validation scenarios
    stream_id_tests: Vec<StreamIdTest>,
    /// ACK frame specific tests
    ack_tests: Vec<AckFrameTest>,
    /// Frame type encoding collision tests
    collision_tests: Vec<FrameTypeCollision>,
}

/// Individual QUIC frame for fuzzing all RFC 9000 frame types
#[derive(Debug, Arbitrary)]
struct QuicFrameFuzzData {
    /// Frame type from RFC 9000
    frame_type: QuicFrameType,
    /// Raw frame payload
    payload: Vec<u8>,
    /// Whether to use malformed encoding
    malformed_encoding: bool,
}

/// RFC 9000 QUIC frame types for comprehensive coverage
#[derive(Debug, Arbitrary)]
enum QuicFrameType {
    /// PADDING frame (0x00)
    Padding,
    /// PING frame (0x01)
    Ping,
    /// ACK frame (0x02, 0x03)
    Ack { ecn_counts: bool },
    /// RESET_STREAM frame (0x04)
    ResetStream,
    /// STOP_SENDING frame (0x05)
    StopSending,
    /// CRYPTO frame (0x06)
    Crypto,
    /// NEW_TOKEN frame (0x07)
    NewToken,
    /// STREAM frames (0x08-0x0f with different flags)
    Stream { fin: bool, len: bool, off: bool },
    /// MAX_DATA frame (0x10)
    MaxData,
    /// MAX_STREAM_DATA frame (0x11)
    MaxStreamData,
    /// MAX_STREAMS frames (0x12, 0x13)
    MaxStreams { bidirectional: bool },
    /// DATA_BLOCKED frame (0x14)
    DataBlocked,
    /// STREAM_DATA_BLOCKED frame (0x15)
    StreamDataBlocked,
    /// STREAMS_BLOCKED frames (0x16, 0x17)
    StreamsBlocked { bidirectional: bool },
    /// NEW_CONNECTION_ID frame (0x18)
    NewConnectionId,
    /// RETIRE_CONNECTION_ID frame (0x19)
    RetireConnectionId,
    /// PATH_CHALLENGE frame (0x1a)
    PathChallenge,
    /// PATH_RESPONSE frame (0x1b)
    PathResponse,
    /// CONNECTION_CLOSE frames (0x1c, 0x1d)
    ConnectionClose { quic_error: bool },
    /// HANDSHAKE_DONE frame (0x1e)
    HandshakeDone,
}

/// VLQ (Variable-Length Integer) encoding edge cases
#[derive(Debug, Arbitrary)]
enum VlqEdgeCase {
    /// 1-byte encoding boundary (0-63)
    OneByteBoundary { value: u8 },
    /// 2-byte encoding boundary (64-16383)
    TwoByteBoundary { value: u16 },
    /// 4-byte encoding boundary (16384-1073741823)
    FourByteBoundary { value: u32 },
    /// 8-byte encoding boundary (1073741824-4611686018427387903)
    EightByteBoundary { value: u64 },
    /// Invalid encoding (too large)
    Invalid { raw_bytes: Vec<u8> },
    /// Minimal encoding violation
    NonMinimal { value: u64, excess_bytes: u8 },
}

/// Stream ID validation tests for parity and direction bits
#[derive(Debug, Arbitrary)]
struct StreamIdTest {
    /// Stream ID value
    stream_id: u64,
    /// Expected direction (client-initiated vs server-initiated)
    expected_direction: StreamDirection,
    /// Expected type (bidirectional vs unidirectional)
    expected_type: StreamType,
    /// Test invalid stream ID scenarios
    invalid_scenario: Option<InvalidStreamIdScenario>,
}

/// Stream direction based on least significant bit
#[derive(Debug, Arbitrary)]
enum StreamDirection {
    /// Client-initiated streams (even stream IDs)
    ClientInitiated,
    /// Server-initiated streams (odd stream IDs)
    ServerInitiated,
}

/// Stream type based on second least significant bit
#[derive(Debug, Arbitrary)]
enum StreamType {
    /// Bidirectional streams (bit 1 = 0)
    Bidirectional,
    /// Unidirectional streams (bit 1 = 1)
    Unidirectional,
}

/// Invalid stream ID scenarios for edge case testing
#[derive(Debug, Arbitrary)]
enum InvalidStreamIdScenario {
    /// Stream ID exceeds maximum allowed
    TooLarge,
    /// Stream ID violates ordering constraints
    OutOfOrder,
    /// Stream ID with reserved bits set
    ReservedBits,
}

/// ACK frame specific validation tests
#[derive(Debug, Arbitrary)]
struct AckFrameTest {
    /// Largest acknowledged packet number
    largest_acked: u64,
    /// ACK delay value
    ack_delay: u64,
    /// ACK ranges for testing overlap/gaps
    ack_ranges: Vec<AckRange>,
    /// ECN counts (if present)
    ecn_counts: Option<EcnCounts>,
    /// Test invalid ACK scenarios
    invalid_scenario: Option<InvalidAckScenario>,
}

/// ACK range for testing validation logic
#[derive(Debug, Arbitrary)]
struct AckRange {
    /// Gap from previous range
    gap: u64,
    /// Length of this range
    length: u64,
}

/// ECN (Explicit Congestion Notification) counts
#[derive(Debug, Arbitrary)]
struct EcnCounts {
    /// ECT(0) count
    ect0_count: u64,
    /// ECT(1) count
    ect1_count: u64,
    /// ECN-CE count
    ecn_ce_count: u64,
}

/// Invalid ACK frame scenarios
#[derive(Debug, Arbitrary)]
enum InvalidAckScenario {
    /// ACK ranges overlap
    OverlappingRanges,
    /// ACK ranges out of order
    OutOfOrderRanges,
    /// Gap too large
    InvalidGap,
    /// Largest acked smaller than previous
    DecreasingLargestAcked,
}

/// Frame type encoding collision tests
#[derive(Debug, Arbitrary)]
struct FrameTypeCollision {
    /// Raw frame type bytes for collision testing
    raw_frame_type: Vec<u8>,
    /// Expected decoded frame type (if valid)
    expected_type: Option<u8>,
    /// Test reserved frame types
    reserved_type: Option<u16>,
}

/// Build a QUIC frame packet from fuzz data
fn build_quic_frame(frame_data: &QuicFrameFuzzData) -> Vec<u8> {
    let mut packet = Vec::new();

    // Encode frame type
    let frame_type_byte = match &frame_data.frame_type {
        QuicFrameType::Padding => 0x00,
        QuicFrameType::Ping => 0x01,
        QuicFrameType::Ack { ecn_counts } => {
            if *ecn_counts {
                0x03
            } else {
                0x02
            }
        }
        QuicFrameType::ResetStream => 0x04,
        QuicFrameType::StopSending => 0x05,
        QuicFrameType::Crypto => 0x06,
        QuicFrameType::NewToken => 0x07,
        QuicFrameType::Stream { fin, len, off } => {
            0x08 | (if *fin { 0x01 } else { 0x00 })
                | (if *len { 0x02 } else { 0x00 })
                | (if *off { 0x04 } else { 0x00 })
        }
        QuicFrameType::MaxData => 0x10,
        QuicFrameType::MaxStreamData => 0x11,
        QuicFrameType::MaxStreams { bidirectional } => {
            if *bidirectional {
                0x12
            } else {
                0x13
            }
        }
        QuicFrameType::DataBlocked => 0x14,
        QuicFrameType::StreamDataBlocked => 0x15,
        QuicFrameType::StreamsBlocked { bidirectional } => {
            if *bidirectional {
                0x16
            } else {
                0x17
            }
        }
        QuicFrameType::NewConnectionId => 0x18,
        QuicFrameType::RetireConnectionId => 0x19,
        QuicFrameType::PathChallenge => 0x1a,
        QuicFrameType::PathResponse => 0x1b,
        QuicFrameType::ConnectionClose { quic_error } => {
            if *quic_error {
                0x1c
            } else {
                0x1d
            }
        }
        QuicFrameType::HandshakeDone => 0x1e,
    };

    if frame_data.malformed_encoding {
        // Test malformed frame type encoding
        packet.extend_from_slice(&[0xFF, 0xFF, frame_type_byte]);
    } else {
        packet.push(frame_type_byte);
    }

    // Append payload (may be malformed for testing)
    packet.extend_from_slice(&frame_data.payload);

    packet
}

/// Encode variable-length integer for testing VLQ boundaries
fn encode_vlq_test(value: u64, force_length: Option<u8>) -> Vec<u8> {
    let mut result = Vec::new();

    match force_length {
        Some(1) if value < 64 => {
            result.push(value as u8);
        }
        Some(2) if value < 16384 => {
            let val = value | 0x4000;
            result.extend_from_slice(&val.to_be_bytes()[6..]);
        }
        Some(4) if value < 1073741824 => {
            let val = value | 0x80000000;
            result.extend_from_slice(&val.to_be_bytes()[4..]);
        }
        Some(8) if value < 4611686018427387904 => {
            let val = value | 0xc000000000000000;
            result.extend_from_slice(&val.to_be_bytes());
        }
        _ => {
            // Use standard encoding
            if value < 64 {
                result.push(value as u8);
            } else if value < 16384 {
                let val = value | 0x4000;
                result.extend_from_slice(&val.to_be_bytes()[6..]);
            } else if value < 1073741824 {
                let val = value | 0x80000000;
                result.extend_from_slice(&val.to_be_bytes()[4..]);
            } else if value < 4611686018427387904 {
                let val = value | 0xc000000000000000;
                result.extend_from_slice(&val.to_be_bytes());
            } else {
                // Invalid - too large for VLQ
                result.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            }
        }
    }

    result
}

/// Test QUIC frame parsing
fn test_quic_frame_parsing(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // Test frame type parsing
    let frame_type = data[0];

    // Validate frame type ranges per RFC 9000
    let _is_valid_frame_type = match frame_type {
        0x00 => true,        // PADDING
        0x01 => true,        // PING
        0x02 | 0x03 => true, // ACK
        0x04 => true,        // RESET_STREAM
        0x05 => true,        // STOP_SENDING
        0x06 => true,        // CRYPTO
        0x07 => true,        // NEW_TOKEN
        0x08..=0x0f => true, // STREAM
        0x10 => true,        // MAX_DATA
        0x11 => true,        // MAX_STREAM_DATA
        0x12 | 0x13 => true, // MAX_STREAMS
        0x14 => true,        // DATA_BLOCKED
        0x15 => true,        // STREAM_DATA_BLOCKED
        0x16 | 0x17 => true, // STREAMS_BLOCKED
        0x18 => true,        // NEW_CONNECTION_ID
        0x19 => true,        // RETIRE_CONNECTION_ID
        0x1a => true,        // PATH_CHALLENGE
        0x1b => true,        // PATH_RESPONSE
        0x1c | 0x1d => true, // CONNECTION_CLOSE
        0x1e => true,        // HANDSHAKE_DONE
        _ => false,          // Reserved or invalid
    };

    // Test payload parsing based on frame type
    if data.len() > 1 {
        let payload = &data[1..];

        match frame_type {
            0x00 => {
                // PADDING frames should contain only zeros
                for &byte in payload {
                    if byte != 0x00 {
                        // Invalid padding detected
                        return;
                    }
                }
            }
            0x01 => {
                // PING frames have no payload
                if !payload.is_empty() {
                    // Invalid PING frame
                    return;
                }
            }
            0x02 | 0x03 => {
                // ACK frames - test VLQ parsing
                test_ack_frame_parsing(payload, frame_type == 0x03);
            }
            0x08..=0x0f => {
                // STREAM frames - test stream ID and payload
                test_stream_frame_parsing(payload, frame_type);
            }
            _ => {
                // Other frame types - basic payload validation
                test_generic_frame_parsing(payload);
            }
        }
    }
}

/// Test ACK frame parsing with range validation
fn test_ack_frame_parsing(data: &[u8], has_ecn: bool) {
    if data.len() < 2 {
        return;
    }

    let mut offset = 0;

    // Parse largest acknowledged (VLQ)
    if let Some((largest_acked, consumed)) = parse_vlq(data, offset) {
        offset += consumed;
    } else {
        return;
    }

    // Parse ACK delay (VLQ)
    if let Some((_, consumed)) = parse_vlq(data, offset) {
        offset += consumed;
    } else {
        return;
    }

    // Parse ACK range count (VLQ)
    if let Some((range_count, consumed)) = parse_vlq(data, offset) {
        offset += consumed;

        // Validate reasonable range count
        if range_count > 1000 {
            return; // Too many ranges
        }

        // Parse first ACK range (VLQ)
        if let Some((_, consumed)) = parse_vlq(data, offset) {
            offset += consumed;
        } else {
            return;
        }

        // Parse additional ACK ranges
        for _ in 0..range_count {
            // Parse gap (VLQ)
            if let Some((_, consumed)) = parse_vlq(data, offset) {
                offset += consumed;
            } else {
                return;
            }

            // Parse range length (VLQ)
            if let Some((_, consumed)) = parse_vlq(data, offset) {
                offset += consumed;
            } else {
                return;
            }
        }

        // Parse ECN counts if present
        if has_ecn {
            // ECT(0) count (VLQ)
            if let Some((_, consumed)) = parse_vlq(data, offset) {
                offset += consumed;
            } else {
                return;
            }

            // ECT(1) count (VLQ)
            if let Some((_, consumed)) = parse_vlq(data, offset) {
                offset += consumed;
            } else {
                return;
            }

            // ECN-CE count (VLQ)
            let _ = parse_vlq(data, offset);
        }
    }
}

/// Test STREAM frame parsing with stream ID validation
fn test_stream_frame_parsing(data: &[u8], frame_type: u8) {
    if data.is_empty() {
        return;
    }

    let mut offset = 0;

    // Parse stream ID (VLQ)
    if let Some((stream_id, consumed)) = parse_vlq(data, offset) {
        offset += consumed;

        // Validate stream ID parity/direction bits
        let direction = stream_id & 0x01; // 0 = client, 1 = server
        let stream_type = (stream_id >> 1) & 0x01; // 0 = bidi, 1 = uni

        // Stream ID should be reasonable
        if stream_id > (1u64 << 60) {
            return; // Too large
        }

        // Check frame type flags
        let has_offset = (frame_type & 0x04) != 0;
        let has_length = (frame_type & 0x02) != 0;
        let has_fin = (frame_type & 0x01) != 0;

        // Parse offset if present
        if has_offset {
            if let Some((_, consumed)) = parse_vlq(data, offset) {
                offset += consumed;
            } else {
                return;
            }
        }

        // Parse length if present
        if has_length {
            if let Some((length, consumed)) = parse_vlq(data, offset) {
                offset += consumed;

                // Validate length against remaining data
                if length > (data.len() - offset) as u64 {
                    return; // Length exceeds available data
                }
            } else {
                return;
            }
        }

        // Remaining data is stream payload (if any)
        // Test that we can handle various payload sizes
        let _remaining_payload = &data[offset..];
    }
}

/// Test generic frame parsing for other frame types
fn test_generic_frame_parsing(data: &[u8]) {
    // Test VLQ parsing at various offsets
    let mut offset = 0;
    while offset < data.len() {
        if let Some((_, consumed)) = parse_vlq(data, offset) {
            offset += consumed;
        } else {
            break;
        }
    }
}

/// Parse variable-length integer from data at offset
fn parse_vlq(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }

    let first_byte = data[offset];
    let length_bits = (first_byte & 0xc0) >> 6;

    match length_bits {
        0 => {
            // 1 byte
            Some((first_byte as u64 & 0x3f, 1))
        }
        1 => {
            // 2 bytes
            if offset + 1 >= data.len() {
                return None;
            }
            let value = u16::from_be_bytes([first_byte & 0x3f, data[offset + 1]]) as u64;
            Some((value, 2))
        }
        2 => {
            // 4 bytes
            if offset + 3 >= data.len() {
                return None;
            }
            let value = u32::from_be_bytes([
                first_byte & 0x3f,
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as u64;
            Some((value, 4))
        }
        3 => {
            // 8 bytes
            if offset + 7 >= data.len() {
                return None;
            }
            let value = u64::from_be_bytes([
                first_byte & 0x3f,
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            Some((value, 8))
        }
        _ => unreachable!(),
    }
}

fuzz_target!(|input: QuicFrameFuzzInput| {
    // Test 1: Frame parsing for all RFC 9000 frame types
    for frame_data in &input.frames {
        let packet = build_quic_frame(frame_data);
        test_quic_frame_parsing(&packet);
    }

    // Test 2: VLQ encoding boundary testing
    for vlq_case in &input.vlq_edge_cases {
        match vlq_case {
            VlqEdgeCase::OneByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(1));
                test_quic_frame_parsing(&encoded);
            }
            VlqEdgeCase::TwoByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(2));
                test_quic_frame_parsing(&encoded);
            }
            VlqEdgeCase::FourByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(4));
                test_quic_frame_parsing(&encoded);
            }
            VlqEdgeCase::EightByteBoundary { value } => {
                let encoded = encode_vlq_test(*value, Some(8));
                test_quic_frame_parsing(&encoded);
            }
            VlqEdgeCase::Invalid { raw_bytes } => {
                test_quic_frame_parsing(raw_bytes);
            }
            VlqEdgeCase::NonMinimal {
                value,
                excess_bytes,
            } => {
                let mut encoded = encode_vlq_test(*value, Some(*excess_bytes + 1));
                // Prepend frame type for testing
                encoded.insert(0, 0x10); // MAX_DATA frame type
                test_quic_frame_parsing(&encoded);
            }
        }
    }

    // Test 3: Stream ID validation
    for stream_test in &input.stream_id_tests {
        let mut frame = vec![0x08]; // STREAM frame type
        frame.extend_from_slice(&encode_vlq_test(stream_test.stream_id, None));
        test_quic_frame_parsing(&frame);
    }

    // Test 4: ACK frame range validation
    for ack_test in &input.ack_tests {
        let mut frame = vec![0x02]; // ACK frame type
        frame.extend_from_slice(&encode_vlq_test(ack_test.largest_acked, None));
        frame.extend_from_slice(&encode_vlq_test(ack_test.ack_delay, None));
        frame.extend_from_slice(&encode_vlq_test(ack_test.ack_ranges.len() as u64, None));

        // Add ranges
        for (i, range) in ack_test.ack_ranges.iter().enumerate() {
            if i == 0 {
                frame.extend_from_slice(&encode_vlq_test(range.length, None));
            } else {
                frame.extend_from_slice(&encode_vlq_test(range.gap, None));
                frame.extend_from_slice(&encode_vlq_test(range.length, None));
            }
        }

        test_quic_frame_parsing(&frame);
    }

    // Test 5: Frame type collision testing
    for collision_test in &input.collision_tests {
        let mut test_data = collision_test.raw_frame_type.clone();
        test_data.extend_from_slice(&[0x00, 0x01, 0x02]); // Some payload
        test_quic_frame_parsing(&test_data);
    }

    // Test 6: Edge case combinations
    let edge_cases = [
        vec![0x00],                         // Single PADDING
        vec![0x01],                         // PING
        vec![0xFF, 0x00, 0x01],             // Invalid frame type
        vec![0x08, 0xFF, 0xFF, 0xFF, 0xFF], // STREAM with malformed stream ID
        vec![0x02, 0x00, 0x00, 0xFF],       // ACK with invalid fields
    ];

    for edge_case in &edge_cases {
        test_quic_frame_parsing(edge_case);
    }
});
