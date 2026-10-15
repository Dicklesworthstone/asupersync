#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::quic_core::{
    PacketHeader, QUIC_VARINT_MAX, TransportParameters, decode_varint as real_decode_varint,
    encode_varint as real_encode_varint,
};
use libfuzzer_sys::fuzz_target;

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
    let largest_acked = if let Some((largest_acked, consumed)) = parse_vlq(data, offset) {
        offset += consumed;
        largest_acked
    } else {
        return;
    };

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
        if let Some((first_range, consumed)) = parse_vlq(data, offset) {
            if first_range > largest_acked {
                return;
            }
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
            observe_vlq_parse(parse_vlq(data, offset), data, offset, "ACK ECN-CE count");
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
        let _direction = stream_id & 0x01; // 0 = client, 1 = server
        let _stream_type = (stream_id >> 1) & 0x01; // 0 = bidi, 1 = uni

        // Stream ID should be reasonable
        if stream_id > (1u64 << 60) {
            return; // Too large
        }

        // Check frame type flags
        let has_offset = (frame_type & 0x04) != 0;
        let has_length = (frame_type & 0x02) != 0;
        let _has_fin = (frame_type & 0x01) != 0;

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
        _ => None,
    }
}

fn observe_vlq_parse(result: Option<(u64, usize)>, data: &[u8], offset: usize, context: &str) {
    if let Some((value, consumed)) = result {
        assert!(consumed > 0, "{context} accepted without consuming bytes");
        assert!(
            offset.saturating_add(consumed) <= data.len(),
            "{context} consumed past input boundary"
        );
        assert!(
            value <= QUIC_VARINT_MAX,
            "{context} exceeded QUIC varint max"
        );
    }
}

fn assert_nonempty_debug<T: core::fmt::Debug>(value: &T, context: &str) {
    let debug = format!("{value:?}");
    assert!(
        !debug.is_empty(),
        "{context} debug output should not be empty"
    );
}

fn observe_decode_result<T, E>(result: Result<T, E>, context: &str)
where
    T: core::fmt::Debug,
    E: core::fmt::Debug,
{
    match result {
        Ok(value) => assert_nonempty_debug(&value, context),
        Err(error) => assert_nonempty_debug(&error, context),
    }
}

fn observe_consuming_decode_result<T, E>(
    result: Result<(T, usize), E>,
    input_len: usize,
    context: &str,
) where
    T: core::fmt::Debug,
    E: core::fmt::Debug,
{
    match result {
        Ok((value, consumed)) => {
            assert!(consumed > 0, "{context} accepted without consuming bytes");
            assert!(
                consumed <= input_len,
                "{context} consumed {consumed} bytes from {input_len}-byte input"
            );
            assert_nonempty_debug(&value, context);
        }
        Err(error) => assert_nonempty_debug(&error, context),
    }
}

fn synthetic_cid(seed: u8, frame_bytes: &[u8]) -> [u8; 4] {
    let first = frame_bytes.first().copied().unwrap_or(seed);
    [seed, first, frame_bytes.len() as u8, seed ^ first]
}

fn build_short_header_packet(frame_bytes: &[u8]) -> Vec<u8> {
    let dcid = synthetic_cid(0x11, frame_bytes);
    let mut packet = Vec::with_capacity(1 + dcid.len() + 1 + frame_bytes.len());
    packet.push(0x40); // fixed bit set, 1-byte packet number
    packet.extend_from_slice(&dcid);
    packet.push(0x01); // packet number
    packet.extend_from_slice(frame_bytes);
    packet
}

fn build_initial_packet(frame_bytes: &[u8]) -> Vec<u8> {
    let dst_cid = synthetic_cid(0xa0, frame_bytes);
    let src_cid = synthetic_cid(0x10, frame_bytes);
    let mut packet = Vec::new();
    packet.push(0xc0); // Initial packet, 1-byte packet number
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(dst_cid.len() as u8);
    packet.extend_from_slice(&dst_cid);
    packet.push(src_cid.len() as u8);
    packet.extend_from_slice(&src_cid);
    packet.push(0x00); // zero-length token varint

    let mut payload_len = Vec::new();
    let total_payload_len = 1 + frame_bytes.len(); // packet number + payload
    if real_encode_varint(total_payload_len as u64, &mut payload_len).is_err() {
        return packet;
    }
    packet.extend_from_slice(&payload_len);
    packet.push(0x01); // packet number
    packet.extend_from_slice(frame_bytes);
    packet
}

fn exercise_real_quic_core_boundaries(frame_bytes: &[u8]) {
    observe_consuming_decode_result(
        real_decode_varint(frame_bytes),
        frame_bytes.len(),
        "QUIC varint decode",
    );
    observe_decode_result(
        TransportParameters::decode(frame_bytes),
        "QUIC transport parameter decode",
    );

    let short_packet = build_short_header_packet(frame_bytes);
    observe_consuming_decode_result(
        PacketHeader::decode(&short_packet, 4),
        short_packet.len(),
        "QUIC short packet header decode",
    );

    let initial_packet = build_initial_packet(frame_bytes);
    observe_consuming_decode_result(
        PacketHeader::decode(&initial_packet, 0),
        initial_packet.len(),
        "QUIC initial packet header decode",
    );
}

fn exercise_real_varint_roundtrip(value: u64) {
    if value > QUIC_VARINT_MAX {
        let mut out = Vec::new();
        let result = real_encode_varint(value, &mut out);
        assert!(
            result.is_err(),
            "out-of-range QUIC varint should fail to encode"
        );
        return;
    }

    let mut out = Vec::new();
    match real_encode_varint(value, &mut out) {
        Ok(()) => observe_consuming_decode_result(
            real_decode_varint(&out),
            out.len(),
            "QUIC varint roundtrip decode",
        ),
        Err(error) => panic!("in-range QUIC varint failed to encode: {error:?}"),
    }
}

fuzz_target!(|input: QuicFrameFuzzInput| {
    // Test 1: Frame parsing for all RFC 9000 frame types
    for frame_data in &input.frames {
        let packet = build_quic_frame(frame_data);
        test_quic_frame_parsing(&packet);
        exercise_real_quic_core_boundaries(&packet);
    }

    // Test 2: VLQ encoding boundary testing
    for vlq_case in &input.vlq_edge_cases {
        match vlq_case {
            VlqEdgeCase::OneByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(1));
                test_quic_frame_parsing(&encoded);
                exercise_real_varint_roundtrip(*value as u64);
            }
            VlqEdgeCase::TwoByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(2));
                test_quic_frame_parsing(&encoded);
                exercise_real_varint_roundtrip(*value as u64);
            }
            VlqEdgeCase::FourByteBoundary { value } => {
                let encoded = encode_vlq_test(*value as u64, Some(4));
                test_quic_frame_parsing(&encoded);
                exercise_real_varint_roundtrip(*value as u64);
            }
            VlqEdgeCase::EightByteBoundary { value } => {
                let encoded = encode_vlq_test(*value, Some(8));
                test_quic_frame_parsing(&encoded);
                exercise_real_varint_roundtrip(*value);
            }
            VlqEdgeCase::Invalid { raw_bytes } => {
                test_quic_frame_parsing(raw_bytes);
                exercise_real_quic_core_boundaries(raw_bytes);
            }
            VlqEdgeCase::NonMinimal {
                value,
                excess_bytes,
            } => {
                let mut encoded = encode_vlq_test(*value, Some(*excess_bytes + 1));
                // Prepend frame type for testing
                encoded.insert(0, 0x10); // MAX_DATA frame type
                test_quic_frame_parsing(&encoded);
                exercise_real_varint_roundtrip(*value);
                exercise_real_quic_core_boundaries(&encoded);
            }
        }
    }

    // Test 3: Stream ID validation
    for stream_test in &input.stream_id_tests {
        let mut frame = vec![0x08]; // STREAM frame type
        frame.extend_from_slice(&encode_vlq_test(stream_test.stream_id, None));
        test_quic_frame_parsing(&frame);
        exercise_real_quic_core_boundaries(&frame);

        let direction_bit = match &stream_test.expected_direction {
            StreamDirection::ClientInitiated => 0,
            StreamDirection::ServerInitiated => 1,
        };
        let type_bit = match &stream_test.expected_type {
            StreamType::Bidirectional => 0,
            StreamType::Unidirectional => 1,
        };
        let canonical_stream_id = (stream_test.stream_id & !0x03) | direction_bit | (type_bit << 1);
        let mut canonical_frame = vec![0x08];
        canonical_frame.extend_from_slice(&encode_vlq_test(canonical_stream_id, None));
        test_quic_frame_parsing(&canonical_frame);
        exercise_real_quic_core_boundaries(&canonical_frame);

        if let Some(invalid_scenario) = &stream_test.invalid_scenario {
            let invalid_stream_id = match invalid_scenario {
                InvalidStreamIdScenario::TooLarge => QUIC_VARINT_MAX,
                InvalidStreamIdScenario::OutOfOrder => stream_test.stream_id.saturating_sub(4),
                InvalidStreamIdScenario::ReservedBits => stream_test.stream_id | (1 << 60),
            };
            let mut invalid_frame = vec![0x08];
            invalid_frame.extend_from_slice(&encode_vlq_test(invalid_stream_id, None));
            test_quic_frame_parsing(&invalid_frame);
            exercise_real_quic_core_boundaries(&invalid_frame);
        }
    }

    // Test 4: ACK frame range validation
    for ack_test in &input.ack_tests {
        let mut frame = vec![if ack_test.ecn_counts.is_some() {
            0x03
        } else {
            0x02
        }]; // ACK frame type
        let largest_acked = match &ack_test.invalid_scenario {
            Some(InvalidAckScenario::DecreasingLargestAcked) => ack_test.largest_acked / 2,
            _ => ack_test.largest_acked,
        };
        frame.extend_from_slice(&encode_vlq_test(largest_acked, None));
        frame.extend_from_slice(&encode_vlq_test(ack_test.ack_delay, None));
        frame.extend_from_slice(&encode_vlq_test(ack_test.ack_ranges.len() as u64, None));

        // Add ranges
        for (i, range) in ack_test.ack_ranges.iter().enumerate() {
            if i == 0 {
                let first_range_len = match &ack_test.invalid_scenario {
                    Some(InvalidAckScenario::OverlappingRanges) => {
                        range.length.saturating_add(largest_acked)
                    }
                    _ => range.length,
                };
                frame.extend_from_slice(&encode_vlq_test(first_range_len, None));
            } else {
                let gap = match &ack_test.invalid_scenario {
                    Some(InvalidAckScenario::InvalidGap) => QUIC_VARINT_MAX,
                    Some(InvalidAckScenario::OutOfOrderRanges) => 0,
                    _ => range.gap,
                };
                frame.extend_from_slice(&encode_vlq_test(gap, None));
                frame.extend_from_slice(&encode_vlq_test(range.length, None));
            }
        }

        if let Some(ecn_counts) = &ack_test.ecn_counts {
            frame.extend_from_slice(&encode_vlq_test(ecn_counts.ect0_count, None));
            frame.extend_from_slice(&encode_vlq_test(ecn_counts.ect1_count, None));
            frame.extend_from_slice(&encode_vlq_test(ecn_counts.ecn_ce_count, None));
        }

        test_quic_frame_parsing(&frame);
        exercise_real_quic_core_boundaries(&frame);
    }

    // Test 5: Frame type collision testing
    for collision_test in &input.collision_tests {
        let mut test_data = collision_test.raw_frame_type.clone();
        test_data.extend_from_slice(&[0x00, 0x01, 0x02]); // Some payload
        test_quic_frame_parsing(&test_data);
        exercise_real_quic_core_boundaries(&test_data);

        if let Some(expected_type) = collision_test.expected_type {
            let expected_frame = [expected_type, 0x00, 0x01, 0x02];
            test_quic_frame_parsing(&expected_frame);
            exercise_real_quic_core_boundaries(&expected_frame);
        }

        if let Some(reserved_type) = collision_test.reserved_type {
            let mut reserved_frame = encode_vlq_test(reserved_type as u64, None);
            reserved_frame.extend_from_slice(&[0x00, 0x01, 0x02]);
            test_quic_frame_parsing(&reserved_frame);
            exercise_real_quic_core_boundaries(&reserved_frame);
        }
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
        exercise_real_quic_core_boundaries(edge_case);
    }
});
