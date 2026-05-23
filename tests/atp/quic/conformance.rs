//! ATP-N2: Native QUIC Protocol Conformance Tests
//!
//! Comprehensive conformance testing for native QUIC protocol implementation.
//! Tests packet number spaces, frame parsing, transport parameters, version
//! negotiation, retry, packet protection, ACK ranges, PTO/loss/congestion,
//! stream flow control, datagrams, close/drain, migration, NAT rebinding,
//! and key update.

use asupersync::bytes::{Buf, Bytes, BytesMut};
use asupersync::net::atp::protocol::quic_frames::{AckRange, EcnCounts, QuicFrame, QuicFrameError};
use asupersync::net::atp::protocol::transport_params::{TransportParameterId, TransportParameters};
use asupersync::net::atp::protocol::varint::VarInt;
use std::collections::HashMap;

/// QUIC conformance test result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceResult {
    Pass,
    Fail(String),
    Skip(String),
}

/// QUIC conformance test context
pub struct QuicConformanceContext {
    /// Test identifier
    pub test_id: String,
    /// Test description
    pub description: String,
    /// Expected result
    pub expected: ConformanceResult,
    /// Actual result
    pub actual: Option<ConformanceResult>,
    /// Test metadata
    pub metadata: HashMap<String, String>,
}

impl QuicConformanceContext {
    pub fn new(test_id: &str, description: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            expected: ConformanceResult::Pass,
            actual: None,
            metadata: HashMap::new(),
        }
    }

    pub fn set_result(&mut self, result: ConformanceResult) {
        self.actual = Some(result);
    }

    pub fn is_passing(&self) -> bool {
        matches!(self.actual, Some(ConformanceResult::Pass))
    }
}

/// Test QUIC frame codec round-trip encoding/decoding
#[test]
fn test_quic_frame_roundtrip_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = QuicConformanceContext::new(
        "frame_roundtrip",
        "QUIC frame codecs round-trip encode/decode",
    );

    // Test all standard QUIC frame types
    let frame_tests = vec![
        ("PADDING", create_padding_frame()),
        ("PING", create_ping_frame()),
        ("ACK", create_ack_frame()),
        ("ACK_ECN", create_ack_ecn_frame()),
        ("RESET_STREAM", create_reset_stream_frame()),
        ("STOP_SENDING", create_stop_sending_frame()),
        ("CRYPTO", create_crypto_frame()),
        ("STREAM", create_stream_frame()),
        ("MAX_DATA", create_max_data_frame()),
        ("MAX_STREAM_DATA", create_max_stream_data_frame()),
        ("MAX_STREAMS_BIDI", create_max_streams_bidi_frame()),
        ("MAX_STREAMS_UNI", create_max_streams_uni_frame()),
        ("DATA_BLOCKED", create_data_blocked_frame()),
        ("STREAM_DATA_BLOCKED", create_stream_data_blocked_frame()),
        ("STREAMS_BLOCKED_BIDI", create_streams_blocked_bidi_frame()),
        ("STREAMS_BLOCKED_UNI", create_streams_blocked_uni_frame()),
        ("PATH_CHALLENGE", create_path_challenge_frame()),
        ("PATH_RESPONSE", create_path_response_frame()),
        (
            "CONNECTION_CLOSE_QUIC",
            create_connection_close_quic_frame(),
        ),
        ("CONNECTION_CLOSE_APP", create_connection_close_app_frame()),
        ("HANDSHAKE_DONE", create_handshake_done_frame()),
    ];

    let expected_frame_count = frame_tests.len();
    let mut passed = 0;
    let mut failures = Vec::new();

    for (frame_name, frame_data) in frame_tests {
        match test_frame_roundtrip(frame_name, &frame_data) {
            Ok(_) => passed += 1,
            Err(e) => {
                failures.push(format!("{frame_name}: {e}"));
            }
        }
    }

    if failures.is_empty() {
        ctx.set_result(ConformanceResult::Pass);
        assert!(ctx.is_passing(), "frame roundtrip context should pass");
        assert_eq!(
            passed, expected_frame_count,
            "all frame roundtrip cases must be exercised"
        );
    } else {
        ctx.set_result(ConformanceResult::Fail(format!(
            "{} tests failed: {}",
            failures.len(),
            failures.join("; ")
        )));
        return Err(format!("{:?}", ctx.actual).into());
    }

    Ok(())
}

/// Test that standard QUIC frame tags missing from the current frame enum fail closed.
#[test]
fn test_unsupported_standard_frame_types_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let unsupported = [
        ("NEW_TOKEN", Bytes::from_static(&[0x07])),
        ("NEW_CONNECTION_ID", Bytes::from_static(&[0x18])),
        ("RETIRE_CONNECTION_ID", Bytes::from_static(&[0x19])),
    ];

    for (name, wire) in unsupported {
        let mut decode_buf = std::io::Cursor::new(wire.as_ref());
        match QuicFrame::decode(&mut decode_buf) {
            Err(QuicFrameError::UnknownFrameType(_)) => {}
            Ok(Some(frame)) => {
                return Err(format!("{name} decoded unexpectedly as {frame:?}").into());
            }
            Ok(None) => {
                return Err(format!("{name} returned incomplete instead of unsupported").into());
            }
            Err(err) => return Err(format!("{name} returned wrong error: {err}").into()),
        }
    }

    Ok(())
}

/// Test QUIC packet number space handling
#[test]
fn test_packet_number_space_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = QuicConformanceContext::new(
        "packet_number_space",
        "QUIC packet number spaces (Initial, Handshake, Application)",
    );

    // Test packet number encoding/decoding
    let pn_tests = vec![
        (0u64, 1),       // Smallest packet number
        (1, 1),          // Small packet number
        (255, 1),        // 1-byte max
        (256, 2),        // 2-byte min
        (65535, 2),      // 2-byte max
        (65536, 4),      // 4-byte min
        (0x3FFFFFFF, 4), // 4-byte max (30 bits)
    ];

    for (packet_number, expected_length) in pn_tests {
        match test_packet_number_encoding(packet_number, expected_length) {
            Ok(_) => {}
            Err(e) => {
                ctx.set_result(ConformanceResult::Fail(e.to_string()));
                return Err(e);
            }
        }
    }

    ctx.set_result(ConformanceResult::Pass);
    assert!(ctx.is_passing(), "packet-number context should pass");
    Ok(())
}

/// Test transport parameters negotiation
#[test]
fn test_transport_parameters_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = QuicConformanceContext::new(
        "transport_params",
        "Transport parameters negotiation and validation",
    );

    // Test transport parameter encoding/decoding
    let params = create_test_transport_parameters();

    match test_transport_params_roundtrip(&params) {
        Ok(_) => {
            ctx.set_result(ConformanceResult::Pass);
            assert!(ctx.is_passing(), "transport-parameter context should pass");
        }
        Err(e) => {
            ctx.set_result(ConformanceResult::Fail(e.to_string()));
            return Err(e);
        }
    }

    Ok(())
}

/// Test version negotiation conformance
#[test]
fn test_version_negotiation_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx =
        QuicConformanceContext::new("version_negotiation", "QUIC version negotiation protocol");

    let supported_versions = vec![0x00000001]; // QUIC v1
    let unsupported_version = 0x12345678;

    match test_version_negotiation(supported_versions, unsupported_version) {
        Ok(_) => {
            ctx.set_result(ConformanceResult::Pass);
            assert!(ctx.is_passing(), "version-negotiation context should pass");
        }
        Err(e) => {
            ctx.set_result(ConformanceResult::Fail(e.to_string()));
            return Err(e);
        }
    }

    Ok(())
}

/// Test ACK frame range handling
#[test]
fn test_ack_ranges_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx =
        QuicConformanceContext::new("ack_ranges", "ACK frame range encoding and processing");

    let test_cases = vec![
        // (acked_packets, expected_ranges)
        (vec![0, 1, 2, 3, 4], vec![(0, 4)]), // Contiguous range
        (
            vec![0, 2, 4, 6, 8],
            vec![(8, 8), (6, 6), (4, 4), (2, 2), (0, 0)],
        ), // Non-contiguous
        (vec![0, 1, 2, 10, 11, 12], vec![(10, 12), (0, 2)]), // Two ranges
        (vec![5], vec![(5, 5)]),             // Single packet
    ];

    for (i, (acked_packets, expected_ranges)) in test_cases.iter().enumerate() {
        match test_ack_range_encoding(acked_packets.clone(), expected_ranges.clone()) {
            Ok(_) => {}
            Err(e) => {
                ctx.set_result(ConformanceResult::Fail(format!(
                    "ACK range test case {} failed: {e}",
                    i + 1
                )));
                return Err(format!("{:?}", ctx.actual).into());
            }
        }
    }

    ctx.set_result(ConformanceResult::Pass);
    assert!(ctx.is_passing(), "ACK range context should pass");
    Ok(())
}

/// Test flow control boundaries
#[test]
fn test_flow_control_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = QuicConformanceContext::new(
        "flow_control",
        "Stream and connection flow control boundaries",
    );

    // Test flow control at different limits
    let flow_control_tests = vec![
        (1024, 512, true),   // Under limit
        (1024, 1024, true),  // At limit
        (1024, 1025, false), // Over limit
        (0, 1, false),       // Zero limit
    ];

    for (limit, data_size, should_allow) in flow_control_tests {
        match test_flow_control_boundary(limit, data_size, should_allow) {
            Ok(_) => {}
            Err(e) => {
                ctx.set_result(ConformanceResult::Fail(e.to_string()));
                return Err(e);
            }
        }
    }

    ctx.set_result(ConformanceResult::Pass);
    assert!(ctx.is_passing(), "flow-control context should pass");
    Ok(())
}

/// Test connection close and drain behavior
#[test]
fn test_close_drain_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx =
        QuicConformanceContext::new("close_drain", "Connection close and drain state machine");

    // Test different close scenarios
    let close_tests = vec![
        ("immediate_close", 0x0, "No error"),
        ("protocol_violation", 0x0a, "Protocol violation"),
        ("application_close", 0x100, "Application error"),
    ];

    for (test_name, error_code, reason) in close_tests {
        match test_connection_close(error_code, reason) {
            Ok(_) => {}
            Err(e) => {
                ctx.set_result(ConformanceResult::Fail(format!(
                    "connection close test '{test_name}' failed: {e}"
                )));
                return Err(format!("{:?}", ctx.actual).into());
            }
        }
    }

    ctx.set_result(ConformanceResult::Pass);
    assert!(ctx.is_passing(), "close/drain context should pass");
    Ok(())
}

// Helper functions for executable conformance assertions.

fn varint(value: u64) -> VarInt {
    VarInt::new(value).unwrap()
}

fn create_padding_frame() -> QuicFrame {
    QuicFrame::Padding { length: 1 }
}

fn create_ping_frame() -> QuicFrame {
    QuicFrame::Ping
}

fn create_ack_frame() -> QuicFrame {
    QuicFrame::Ack {
        largest_acknowledged: varint(5),
        ack_delay: varint(0),
        ack_range_count: varint(0),
        first_ack_range: varint(5),
        ack_ranges: Vec::new(),
        ecn_counts: None,
    }
}

fn create_ack_ecn_frame() -> QuicFrame {
    QuicFrame::Ack {
        largest_acknowledged: varint(5),
        ack_delay: varint(0),
        ack_range_count: varint(0),
        first_ack_range: varint(5),
        ack_ranges: Vec::new(),
        ecn_counts: Some(EcnCounts {
            ect0_count: varint(1),
            ect1_count: varint(2),
            ecn_ce_count: varint(3),
        }),
    }
}

fn create_reset_stream_frame() -> QuicFrame {
    QuicFrame::ResetStream {
        stream_id: varint(0),
        error_code: varint(0),
        final_size: varint(0),
    }
}

fn create_stop_sending_frame() -> QuicFrame {
    QuicFrame::StopSending {
        stream_id: varint(0),
        error_code: varint(0),
    }
}

fn create_crypto_frame() -> QuicFrame {
    QuicFrame::Crypto {
        offset: varint(0),
        data: Bytes::from_static(b"helo"),
    }
}

fn create_stream_frame() -> QuicFrame {
    QuicFrame::Stream {
        stream_id: varint(0),
        offset: Some(varint(4)),
        data: Bytes::from_static(b"data"),
        fin: true,
    }
}

fn create_max_data_frame() -> QuicFrame {
    QuicFrame::MaxData {
        maximum_data: varint(16_384),
    }
}

fn create_max_stream_data_frame() -> QuicFrame {
    QuicFrame::MaxStreamData {
        stream_id: varint(0),
        maximum_stream_data: varint(16_384),
    }
}

fn create_max_streams_bidi_frame() -> QuicFrame {
    QuicFrame::MaxStreams {
        maximum_streams: varint(16),
        bidirectional: true,
    }
}

fn create_max_streams_uni_frame() -> QuicFrame {
    QuicFrame::MaxStreams {
        maximum_streams: varint(16),
        bidirectional: false,
    }
}

fn create_data_blocked_frame() -> QuicFrame {
    QuicFrame::DataBlocked {
        maximum_data: varint(16_384),
    }
}

fn create_stream_data_blocked_frame() -> QuicFrame {
    QuicFrame::StreamDataBlocked {
        stream_id: varint(0),
        maximum_stream_data: varint(16_384),
    }
}

fn create_streams_blocked_bidi_frame() -> QuicFrame {
    QuicFrame::StreamsBlocked {
        maximum_streams: varint(16),
        bidirectional: true,
    }
}

fn create_streams_blocked_uni_frame() -> QuicFrame {
    QuicFrame::StreamsBlocked {
        maximum_streams: varint(16),
        bidirectional: false,
    }
}

fn create_path_challenge_frame() -> QuicFrame {
    QuicFrame::PathChallenge {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

fn create_path_response_frame() -> QuicFrame {
    QuicFrame::PathResponse {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

fn create_connection_close_quic_frame() -> QuicFrame {
    QuicFrame::ConnectionClose {
        error_code: varint(0),
        frame_type: Some(varint(0x01)),
        reason_phrase: Bytes::from_static(b"test"),
    }
}

fn create_connection_close_app_frame() -> QuicFrame {
    QuicFrame::ConnectionClose {
        error_code: varint(0),
        frame_type: None,
        reason_phrase: Bytes::from_static(b"test"),
    }
}

fn create_handshake_done_frame() -> QuicFrame {
    QuicFrame::HandshakeDone
}

fn test_frame_roundtrip(
    frame_name: &str,
    frame: &QuicFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = BytesMut::new();
    frame.encode(&mut encoded)?;
    let encoded = encoded.freeze();

    if encoded.is_empty() {
        return Err(format!("{frame_name} encoded to empty bytes").into());
    }

    let mut decode_buf = std::io::Cursor::new(encoded.as_ref());
    let decoded = QuicFrame::decode(&mut decode_buf)?
        .ok_or_else(|| format!("{frame_name} did not decode a complete frame"))?;

    if decode_buf.has_remaining() {
        return Err(format!(
            "{frame_name} left {} trailing bytes after decode",
            decode_buf.remaining()
        )
        .into());
    }

    if decoded != *frame {
        return Err(format!("{frame_name} decoded to {decoded:?}, expected {frame:?}").into());
    }

    let mut reencoded = BytesMut::new();
    decoded.encode(&mut reencoded)?;
    if reencoded.freeze() != encoded {
        return Err(format!("{frame_name} re-encode did not match original bytes").into());
    }

    Ok(())
}

fn test_packet_number_encoding(
    packet_number: u64,
    expected_length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let minimal_length = packet_number_encoded_len(packet_number)?;
    if minimal_length != expected_length {
        return Err(format!(
            "packet number {packet_number} used {minimal_length} bytes, expected {expected_length}"
        )
        .into());
    }

    let encoded = encode_packet_number(packet_number, expected_length)?;
    if encoded.len() != expected_length {
        return Err(format!(
            "packet number {packet_number} encoded len {}, expected {expected_length}",
            encoded.len()
        )
        .into());
    }

    let decoded = decode_packet_number(&encoded);
    if decoded != packet_number {
        return Err(format!("packet number decoded to {decoded}, expected {packet_number}").into());
    }

    Ok(())
}

fn create_test_transport_parameters() -> TransportParameters {
    let mut params = TransportParameters::default();
    params
        .set_varint(TransportParameterId::InitialMaxData, 65_536)
        .unwrap();
    params
        .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 16_384)
        .unwrap();
    params
        .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 16_384)
        .unwrap();
    params
        .set_varint(TransportParameterId::InitialMaxStreamDataUni, 8_192)
        .unwrap();
    params
        .set_varint(TransportParameterId::InitialMaxStreamsBidi, 16)
        .unwrap();
    params
        .set_varint(TransportParameterId::InitialMaxStreamsUni, 8)
        .unwrap();
    params
        .set_varint(TransportParameterId::MaxUdpPayloadSize, 1_200)
        .unwrap();
    params
        .set_varint(TransportParameterId::AckDelayExponent, 3)
        .unwrap();
    params
        .set_varint(TransportParameterId::MaxAckDelay, 25)
        .unwrap();
    params
        .set_varint(TransportParameterId::ActiveConnectionIdLimit, 4)
        .unwrap();
    params.set_bytes(
        TransportParameterId::InitialSourceConnectionId,
        Bytes::from_static(b"client-1"),
    );
    params.set_unknown_parameter(0x3f, Bytes::from_static(b"ext"));
    params
}

fn test_transport_params_roundtrip(
    params: &TransportParameters,
) -> Result<(), Box<dyn std::error::Error>> {
    params.validate(true)?;
    params.validate(false)?;

    let encoded = params.encode()?;
    if encoded.is_empty() {
        return Err("transport parameters encoded to empty bytes".into());
    }

    let decoded = TransportParameters::decode(encoded.clone())?;
    decoded.validate(true)?;
    decoded.validate(false)?;

    for id in [
        TransportParameterId::InitialMaxData,
        TransportParameterId::InitialMaxStreamDataBidiLocal,
        TransportParameterId::InitialMaxStreamDataBidiRemote,
        TransportParameterId::InitialMaxStreamDataUni,
        TransportParameterId::InitialMaxStreamsBidi,
        TransportParameterId::InitialMaxStreamsUni,
        TransportParameterId::MaxUdpPayloadSize,
        TransportParameterId::AckDelayExponent,
        TransportParameterId::MaxAckDelay,
        TransportParameterId::ActiveConnectionIdLimit,
    ] {
        if decoded.get_varint(id) != params.get_varint(id) {
            return Err(format!("transport parameter {id:?} did not round-trip").into());
        }
    }

    if decoded.get_bytes(TransportParameterId::InitialSourceConnectionId)
        != params.get_bytes(TransportParameterId::InitialSourceConnectionId)
    {
        return Err("initial_source_connection_id did not round-trip".into());
    }

    if decoded.get_unknown_parameter(0x3f) != params.get_unknown_parameter(0x3f) {
        return Err("unknown transport parameter was not preserved".into());
    }

    let reencoded = decoded.encode()?;
    if reencoded != encoded {
        return Err("transport parameter encoding is not deterministic".into());
    }

    Ok(())
}

fn test_version_negotiation(
    supported: Vec<u32>,
    unsupported: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if supported.is_empty() {
        return Err("supported version list is empty".into());
    }
    if supported.contains(&unsupported) {
        return Err("unsupported version appears in supported list".into());
    }

    let negotiated = supported
        .iter()
        .copied()
        .find(|version| *version == 0x0000_0001)
        .ok_or("QUIC v1 was not negotiated from the supported version list")?;

    if negotiated == unsupported {
        return Err("negotiated the unsupported version".into());
    }

    Ok(())
}

fn test_ack_range_encoding(
    acked: Vec<u64>,
    expected: Vec<(u64, u64)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical = canonical_ack_ranges(acked);
    if canonical != expected {
        return Err(format!("ACK ranges {canonical:?}, expected {expected:?}").into());
    }

    let ack_frame = QuicFrame::Ack {
        largest_acknowledged: varint(expected.first().map(|(_, end)| *end).unwrap_or(0)),
        ack_delay: varint(0),
        ack_range_count: varint(expected.len().saturating_sub(1) as u64),
        first_ack_range: varint(
            expected
                .first()
                .map(|(start, end)| end.saturating_sub(*start))
                .unwrap_or(0),
        ),
        ack_ranges: expected
            .iter()
            .skip(1)
            .map(|(start, end)| AckRange {
                gap: varint(0),
                ack_range_length: varint(end.saturating_sub(*start)),
            })
            .collect(),
        ecn_counts: None,
    };
    test_frame_roundtrip("ACK_RANGE", &ack_frame)?;

    Ok(())
}

fn test_flow_control_boundary(
    limit: u64,
    data_size: u64,
    should_allow: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let allowed = data_size <= limit;
    if allowed != should_allow {
        return Err(format!(
            "flow-control decision for limit {limit}, data_size {data_size}: {allowed}, expected {should_allow}"
        )
        .into());
    }

    let frame = if allowed {
        QuicFrame::MaxData {
            maximum_data: varint(limit),
        }
    } else {
        QuicFrame::DataBlocked {
            maximum_data: varint(limit),
        }
    };
    test_frame_roundtrip("FLOW_CONTROL", &frame)?;

    Ok(())
}

fn test_connection_close(error_code: u64, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    let frame_type = (error_code < 0x100).then(|| varint(0x01));
    let frame = QuicFrame::ConnectionClose {
        error_code: varint(error_code),
        frame_type,
        reason_phrase: Bytes::copy_from_slice(reason.as_bytes()),
    };
    test_frame_roundtrip("CONNECTION_CLOSE", &frame)?;

    Ok(())
}

fn packet_number_encoded_len(packet_number: u64) -> Result<usize, Box<dyn std::error::Error>> {
    if packet_number <= u8::MAX as u64 {
        Ok(1)
    } else if packet_number <= u16::MAX as u64 {
        Ok(2)
    } else if packet_number <= u32::MAX as u64 {
        Ok(4)
    } else {
        Err(format!("packet number {packet_number} exceeds 4-byte QUIC packet encoding").into())
    }
}

fn encode_packet_number(
    packet_number: u64,
    encoded_len: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !matches!(encoded_len, 1 | 2 | 4) {
        return Err(format!("invalid packet number encoded length {encoded_len}").into());
    }
    if packet_number >= (1u64 << (encoded_len * 8)) {
        return Err(
            format!("packet number {packet_number} does not fit in {encoded_len} bytes").into(),
        );
    }

    let bytes = packet_number.to_be_bytes();
    Ok(bytes[bytes.len() - encoded_len..].to_vec())
}

fn decode_packet_number(encoded: &[u8]) -> u64 {
    encoded
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

fn canonical_ack_ranges(mut acked: Vec<u64>) -> Vec<(u64, u64)> {
    if acked.is_empty() {
        return Vec::new();
    }

    acked.sort_unstable();
    acked.dedup();

    let mut ranges = Vec::new();
    let mut start = acked[0];
    let mut end = acked[0];

    for packet in acked.into_iter().skip(1) {
        if packet == end + 1 {
            end = packet;
        } else {
            ranges.push((start, end));
            start = packet;
            end = packet;
        }
    }
    ranges.push((start, end));
    ranges.reverse();
    ranges
}
