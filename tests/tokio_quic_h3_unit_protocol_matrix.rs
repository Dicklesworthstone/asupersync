#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for [T4.10] Exhaustive Unit/Protocol Test Matrix: QUIC and HTTP/3 State Machines.
//!
//! Bead: asupersync-2oh2u.4.10
//! Covers: T4.2 (QUIC core), T4.3 (transport/loss), T4.3/T4.4 (streams/flow), T4.4 (TLS/key),
//!         T4.2 (connection lifecycle), T4.5 (HTTP/3 frame codec + protocol)
//!
//! 68 deterministic, network-free unit tests across 7 categories:
//!   QC (5), QT (13), QS (15), TL (10), NC (6), HF (15), MV (4)

// ── Imports ─────────────────────────────────────────────────────────────

use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ControlState, H3Frame, H3NativeError, H3PseudoHeaders, H3QpackMode,
    H3RequestHead, H3ResponseHead, H3Settings,
};
use asupersync::net::quic_core::{ConnectionId, QUIC_VARINT_MAX, QuicCoreError};
use asupersync::net::quic_native::connection::NativeQuicConnectionConfig;
use asupersync::net::quic_native::streams::{
    FlowControlError, FlowCredit, StreamDirection, StreamId, StreamRole, StreamTable,
};
use asupersync::net::quic_native::tls::{
    CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine,
};
use asupersync::net::quic_native::transport::{
    AckRange, PacketNumberSpace, QuicConnectionState, QuicTransportMachine, RttEstimator,
    SentPacketMeta,
};

// ═══════════════════════════════════════════════════════════════════════
// 2.1 QUIC Core Codec (QC)
// ═══════════════════════════════════════════════════════════════════════

/// QC-01: ConnectionId::new with valid 0-byte CID.
#[test]
fn qc_01_connection_id_zero_bytes() {
    let cid = ConnectionId::new(&[]).expect("0-byte CID should be valid");
    assert_eq!(cid.len(), 0);
    assert!(cid.as_bytes().is_empty());
}

/// QC-02: ConnectionId::new with valid 20-byte CID.
#[test]
fn qc_02_connection_id_20_bytes() {
    let bytes: Vec<u8> = (0..20).collect();
    let cid = ConnectionId::new(&bytes).expect("20-byte CID should be valid");
    assert_eq!(cid.len(), 20);
    assert_eq!(cid.as_bytes(), &bytes[..]);
}

/// QC-03: ConnectionId::new with 21 bytes rejects.
#[test]
fn qc_03_connection_id_21_bytes_rejected() {
    let bytes: Vec<u8> = (0..21).collect();
    let err = ConnectionId::new(&bytes).expect_err("21-byte CID should fail");
    assert_eq!(err, QuicCoreError::InvalidConnectionIdLength(21));
}

/// QC-04: ConnectionId is_empty for 0-length.
#[test]
fn qc_04_connection_id_is_empty() {
    let cid = ConnectionId::new(&[]).expect("empty CID");
    assert!(cid.is_empty());
    let cid_nonempty = ConnectionId::new(&[0x42]).expect("1-byte CID");
    assert!(!cid_nonempty.is_empty());
}

/// QC-05: QUIC_VARINT_MAX constant equals (1<<62)-1.
#[test]
fn qc_05_varint_max_constant() {
    assert_eq!(QUIC_VARINT_MAX, (1u64 << 62) - 1);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.2 Transport State Machine (QT)
// ═══════════════════════════════════════════════════════════════════════

/// QT-01: New transport starts in Idle state.
#[test]
fn qt_01_initial_state_idle() {
    let tm = QuicTransportMachine::new();
    assert_eq!(tm.state(), QuicConnectionState::Idle);
}

/// QT-02: begin_handshake transitions Idle → Handshaking.
#[test]
fn qt_02_begin_handshake() {
    let mut tm = QuicTransportMachine::new();
    tm.begin_handshake().expect("Idle → Handshaking");
    assert_eq!(tm.state(), QuicConnectionState::Handshaking);
}

/// QT-03: on_established transitions Handshaking → Established.
#[test]
fn qt_03_on_established() {
    let mut tm = QuicTransportMachine::new();
    tm.begin_handshake().expect("handshake");
    tm.on_established().expect("Handshaking → Established");
    assert_eq!(tm.state(), QuicConnectionState::Established);
}

/// QT-04: begin_handshake from Established fails (not a valid transition).
#[test]
fn qt_04_begin_handshake_from_non_idle_fails() {
    let mut tm = QuicTransportMachine::new();
    tm.begin_handshake().expect("Idle → Handshaking");
    tm.on_established().expect("Handshaking → Established");
    let err = tm
        .begin_handshake()
        .expect_err("Established → Handshaking invalid");
    assert!(
        matches!(
            err,
            asupersync::net::quic_native::transport::TransportError::InvalidStateTransition { .. }
        ),
        "expected InvalidStateTransition, got {err:?}"
    );
}

/// QT-05: Initial congestion window is 12000 bytes.
#[test]
fn qt_05_initial_congestion_window() {
    let tm = QuicTransportMachine::new();
    assert_eq!(tm.congestion_window_bytes(), 12_000);
}

/// QT-06: Initial ssthresh is u64::MAX.
#[test]
fn qt_06_initial_ssthresh() {
    let tm = QuicTransportMachine::new();
    assert_eq!(tm.ssthresh_bytes(), u64::MAX);
}

/// QT-07: can_send with 0 in-flight returns true.
#[test]
fn qt_07_can_send_zero_in_flight() {
    let tm = QuicTransportMachine::new();
    assert!(tm.can_send(0), "0 in-flight should always be sendable");
    assert!(
        tm.can_send(1200),
        "single packet within initial cwnd should be sendable"
    );
}

/// QT-08: on_packet_sent increments bytes_in_flight.
#[test]
fn qt_08_packet_sent_increments_in_flight() {
    let mut tm = QuicTransportMachine::new();
    assert_eq!(tm.bytes_in_flight(), 0);

    let pkt = SentPacketMeta {
        space: PacketNumberSpace::ApplicationData,
        packet_number: 0,
        bytes: 1200,
        ack_eliciting: true,
        in_flight: true,
        time_sent_micros: 1000,
    };
    tm.on_packet_sent(pkt);
    assert_eq!(tm.bytes_in_flight(), 1200);
}

/// QT-09: RTT estimator starts with no samples.
#[test]
fn qt_09_rtt_no_initial_samples() {
    let rtt = RttEstimator::default();
    assert_eq!(rtt.smoothed_rtt_micros(), None);
}

/// QT-10: RTT update with first sample sets smoothed_rtt.
#[test]
fn qt_10_rtt_first_sample() {
    let mut rtt = RttEstimator::default();
    rtt.update(50_000, 0);
    assert_eq!(rtt.smoothed_rtt_micros(), Some(50_000));
}

/// QT-11: RTT update with ack_delay subtraction.
#[test]
fn qt_11_rtt_ack_delay_subtraction() {
    let mut rtt = RttEstimator::default();
    // First sample: 100ms, no delay
    rtt.update(100_000, 0);
    assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));
    // Second sample: 120ms with 10ms ack_delay
    // adjusted = 120000 - min(10000, 120000 - min_rtt(100000)) = 120000 - min(10000, 20000) = 110000
    // smoothed = (7/8)*100000 + (1/8)*110000 = 87500 + 13750 = 101250
    rtt.update(120_000, 10_000);
    let srtt = rtt.smoothed_rtt_micros().expect("should have smoothed RTT");
    assert_eq!(srtt, 101_250);
}

/// QT-12: AckRange new with valid range.
#[test]
fn qt_12_ack_range_valid() {
    let range = AckRange::new(10, 5).expect("valid range: largest >= smallest");
    assert_eq!(range.largest, 10);
    assert_eq!(range.smallest, 5);
}

/// QT-13: AckRange new with inverted range returns None.
#[test]
fn qt_13_ack_range_inverted() {
    let range = AckRange::new(5, 10);
    assert!(range.is_none(), "smallest > largest should return None");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.3 Stream and Flow Control (QS)
// ═══════════════════════════════════════════════════════════════════════

/// QS-01: FlowCredit new with limit.
#[test]
fn qs_01_flow_credit_new() {
    let fc = FlowCredit::new(1024);
    assert_eq!(fc.remaining(), 1024);
    assert_eq!(fc.used(), 0);
    assert_eq!(fc.limit(), 1024);
}

/// QS-02: FlowCredit consume decrements remaining.
#[test]
fn qs_02_flow_credit_consume() {
    let mut fc = FlowCredit::new(1024);
    fc.consume(100).expect("consume 100");
    assert_eq!(fc.remaining(), 924);
    assert_eq!(fc.used(), 100);
}

/// QS-03: FlowCredit consume beyond limit returns error.
#[test]
fn qs_03_flow_credit_exhausted() {
    let mut fc = FlowCredit::new(100);
    let err = fc.consume(101).expect_err("should exceed limit");
    assert!(
        matches!(
            err,
            FlowControlError::Exhausted {
                attempted: 101,
                remaining: 100
            }
        ),
        "expected Exhausted, got {err:?}"
    );
}

/// QS-04: FlowCredit increase_limit extends capacity.
#[test]
fn qs_04_flow_credit_increase_limit() {
    let mut fc = FlowCredit::new(100);
    fc.consume(50).expect("consume 50");
    fc.increase_limit(200).expect("increase to 200");
    assert_eq!(fc.remaining(), 150);
    assert_eq!(fc.limit(), 200);
}

/// QS-05: FlowCredit increase_limit regression fails.
#[test]
fn qs_05_flow_credit_limit_regression() {
    let fc_limit = 200;
    let mut fc = FlowCredit::new(fc_limit);
    let err = fc.increase_limit(100).expect_err("regression");
    assert!(
        matches!(
            err,
            FlowControlError::LimitRegression {
                current: 200,
                requested: 100
            }
        ),
        "expected LimitRegression, got {err:?}"
    );
}

/// QS-06: FlowCredit release increases remaining.
#[test]
fn qs_06_flow_credit_release() {
    let mut fc = FlowCredit::new(100);
    fc.consume(60).expect("consume 60");
    assert_eq!(fc.remaining(), 40);
    fc.release(30);
    assert_eq!(fc.remaining(), 70);
    assert_eq!(fc.used(), 30);
}

/// QS-07: StreamId client bidi stream encoding (0, 4, 8...).
#[test]
fn qs_07_stream_id_client_bidi() {
    for seq in 0..4u64 {
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, seq);
        // client=0, bidi=0 → lowest 2 bits = 0b00
        assert_eq!(id.0, seq << 2);
    }
}

/// QS-08: StreamId server bidi stream encoding (1, 5, 9...).
#[test]
fn qs_08_stream_id_server_bidi() {
    for seq in 0..4u64 {
        let id = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, seq);
        // server=1, bidi=0 → lowest 2 bits = 0b01
        assert_eq!(id.0, (seq << 2) | 1);
    }
}

/// QS-09: StreamId client uni stream encoding (2, 6, 10...).
#[test]
fn qs_09_stream_id_client_uni() {
    for seq in 0..4u64 {
        let id = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, seq);
        // client=0, uni=1 → lowest 2 bits = 0b10
        assert_eq!(id.0, (seq << 2) | 2);
    }
}

/// QS-10: StreamId direction detection.
#[test]
fn qs_10_stream_id_direction() {
    let bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
    assert_eq!(bidi.direction(), StreamDirection::Bidirectional);
    let uni = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 0);
    assert_eq!(uni.direction(), StreamDirection::Unidirectional);
}

/// QS-11: StreamId is_local_for checks from Client/Server perspective.
#[test]
fn qs_11_stream_id_is_local_for() {
    let client_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
    assert!(client_bidi.is_local_for(StreamRole::Client));
    assert!(!client_bidi.is_local_for(StreamRole::Server));

    let server_uni = StreamId::local(StreamRole::Server, StreamDirection::Unidirectional, 0);
    assert!(server_uni.is_local_for(StreamRole::Server));
    assert!(!server_uni.is_local_for(StreamRole::Client));
}

/// QS-12: Stream write consumes send credit (via StreamTable).
#[test]
fn qs_12_stream_write_consumes_send_credit() {
    let mut table = StreamTable::new(StreamRole::Client, 128, 128, 1024, 1024);
    let id = table.open_local_bidi().expect("open bidi");
    table.write_stream(id, 100).expect("write 100");
    let stream = table.stream(id).expect("get stream");
    assert_eq!(stream.send_credit.used(), 100);
    assert_eq!(stream.send_credit.remaining(), 924);
}

/// QS-13: Stream receive consumes recv credit (via StreamTable).
#[test]
fn qs_13_stream_receive_consumes_recv_credit() {
    let mut table = StreamTable::new(StreamRole::Client, 128, 128, 1024, 1024);
    let id = table.open_local_bidi().expect("open bidi");
    table.receive_stream(id, 200).expect("receive 200");
    let stream = table.stream(id).expect("get stream");
    assert_eq!(stream.recv_credit.used(), 200);
}

/// QS-14: Stream set_final_size consistency — second call with different size fails.
#[test]
fn qs_14_stream_final_size_inconsistency() {
    let mut table = StreamTable::new(StreamRole::Client, 128, 128, 1024, 1024);
    let id = table.open_local_bidi().expect("open bidi");
    let stream = table.stream_mut(id).expect("get stream");
    stream.set_final_size(500).expect("first final_size");
    let err = stream
        .set_final_size(600)
        .expect_err("inconsistent final_size");
    assert!(
        matches!(
            err,
            asupersync::net::quic_native::streams::QuicStreamError::InvalidFinalSize { .. }
        ),
        "expected InvalidFinalSize, got {err:?}"
    );
}

/// QS-15: Stream reset_send sets error code.
#[test]
fn qs_15_stream_reset_send() {
    let mut table = StreamTable::new(StreamRole::Client, 128, 128, 1024, 1024);
    let id = table.open_local_bidi().expect("open bidi");
    let stream = table.stream_mut(id).expect("get stream");
    stream.reset_send(0x42, 0).expect("reset_send");
    // Verify the send_reset state was set
    assert!(stream.send_reset.is_some());
    let (code, final_size) = stream.send_reset.unwrap();
    assert_eq!(code, 0x42);
    assert_eq!(final_size, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.4 TLS/Key Phase Machine (TL)
// ═══════════════════════════════════════════════════════════════════════

/// TL-01: New TLS machine at Initial level.
#[test]
fn tl_01_initial_level() {
    let m = QuicTlsMachine::new();
    assert_eq!(m.level(), CryptoLevel::Initial);
}

/// TL-02: on_handshake_keys transitions to Handshake.
#[test]
fn tl_02_handshake_transition() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake keys");
    assert_eq!(m.level(), CryptoLevel::Handshake);
}

/// TL-03: on_1rtt_keys transitions to OneRtt.
#[test]
fn tl_03_onertt_transition() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt keys");
    assert_eq!(m.level(), CryptoLevel::OneRtt);
}

/// TL-04: on_handshake_confirmed enables 1-RTT send.
#[test]
fn tl_04_handshake_confirmed_enables_1rtt() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt");
    assert!(!m.can_send_1rtt(), "should not send 1rtt before confirmed");
    m.on_handshake_confirmed().expect("confirmed");
    assert!(m.can_send_1rtt(), "should send 1rtt after confirmed");
}

/// TL-05: 0-RTT disabled by default.
#[test]
fn tl_05_zero_rtt_disabled_by_default() {
    let m = QuicTlsMachine::new();
    assert!(!m.can_send_0rtt());
    assert!(!m.resumption_enabled());
}

/// TL-06: enable_resumption then 0-RTT available (during handshake, before confirmed).
#[test]
fn tl_06_zero_rtt_after_resumption() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.enable_resumption();
    assert!(m.resumption_enabled());
    assert!(
        m.can_send_0rtt(),
        "0-RTT should be available during handshake with resumption"
    );
}

/// TL-07: request_local_key_update before confirmed fails.
#[test]
fn tl_07_key_update_before_confirmed_fails() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt");
    let err = m.request_local_key_update().expect_err("not confirmed");
    assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
}

/// TL-08: Key update after confirmed succeeds → LocalUpdateScheduled.
#[test]
fn tl_08_key_update_after_confirmed() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt");
    m.on_handshake_confirmed().expect("confirmed");
    let evt = m.request_local_key_update().expect("key update");
    assert_eq!(
        evt,
        KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: true,
            generation: 1
        }
    );
}

/// TL-09: Peer key phase change accepted → RemoteUpdateAccepted.
#[test]
fn tl_09_peer_key_phase_accepted() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt");
    m.on_handshake_confirmed().expect("confirmed");
    let evt = m.on_peer_key_phase(true).expect("peer phase change");
    assert_eq!(
        evt,
        KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: true,
            generation: 1
        }
    );
    assert!(m.remote_key_phase());
}

/// TL-10: Same peer key phase returns NoChange (stale case).
#[test]
fn tl_10_stale_peer_key_phase() {
    let mut m = QuicTlsMachine::new();
    m.on_handshake_keys_available().expect("handshake");
    m.on_1rtt_keys_available().expect("1rtt");
    m.on_handshake_confirmed().expect("confirmed");
    // Remote phase starts at false; sending false is same phase
    let evt = m.on_peer_key_phase(false).expect("same phase");
    assert_eq!(evt, KeyUpdateEvent::NoChange);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.5 Connection Lifecycle (NC)
// ═══════════════════════════════════════════════════════════════════════

/// NC-01: Default config has Client role.
#[test]
fn nc_01_default_client_role() {
    let config = NativeQuicConnectionConfig::default();
    assert_eq!(config.role, StreamRole::Client);
}

/// NC-02: Default max streams = 128 bidi + 128 uni.
#[test]
fn nc_02_default_max_streams() {
    let config = NativeQuicConnectionConfig::default();
    assert_eq!(config.max_local_bidi, 128);
    assert_eq!(config.max_local_uni, 128);
}

/// NC-03: Default send/recv window = 1MB.
#[test]
fn nc_03_default_stream_windows() {
    let config = NativeQuicConnectionConfig::default();
    assert_eq!(config.send_window, 1 << 20);
    assert_eq!(config.recv_window, 1 << 20);
}

/// NC-04: Default connection limits = 16MB.
#[test]
fn nc_04_default_connection_limits() {
    let config = NativeQuicConnectionConfig::default();
    assert_eq!(config.connection_send_limit, 16 << 20);
    assert_eq!(config.connection_recv_limit, 16 << 20);
}

/// NC-05: Default drain timeout = 3 seconds (3_000_000 micros).
#[test]
fn nc_05_default_drain_timeout() {
    let config = NativeQuicConnectionConfig::default();
    assert_eq!(config.drain_timeout_micros, 3_000_000);
}

/// NC-06: New connection starts in Idle state (via transport).
#[test]
fn nc_06_new_connection_idle() {
    let tm = QuicTransportMachine::new();
    assert_eq!(tm.state(), QuicConnectionState::Idle);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.6 HTTP/3 Frame Codec (HF)
// ═══════════════════════════════════════════════════════════════════════

/// HF-01: H3Frame::Data encode/decode round-trip.
#[test]
fn hf_01_data_round_trip() {
    let payload = b"hello, world".to_vec();
    let frame = H3Frame::Data(payload.clone());
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(consumed, buf.len());
    assert_eq!(decoded, H3Frame::Data(payload));
}

/// HF-02: H3Frame::Headers encode/decode round-trip.
#[test]
fn hf_02_headers_round_trip() {
    let field_block = vec![0x01, 0x02, 0x03];
    let frame = H3Frame::Headers(field_block.clone());
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(decoded, H3Frame::Headers(field_block));
}

/// HF-03: H3Frame::Settings encode/decode round-trip.
#[test]
fn hf_03_settings_round_trip() {
    let settings = H3Settings {
        qpack_max_table_capacity: Some(4096),
        max_field_section_size: Some(16384),
        qpack_blocked_streams: Some(100),
        enable_connect_protocol: Some(true),
        h3_datagram: Some(false),
        unknown: vec![],
    };
    let frame = H3Frame::Settings(settings.clone());
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(decoded, H3Frame::Settings(settings));
}

/// HF-04: H3Frame::Goaway encode/decode round-trip.
#[test]
fn hf_04_goaway_round_trip() {
    let frame = H3Frame::Goaway(42);
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(decoded, H3Frame::Goaway(42));
}

/// HF-05: H3Frame::CancelPush encode/decode round-trip.
#[test]
fn hf_05_cancel_push_round_trip() {
    let frame = H3Frame::CancelPush(7);
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(decoded, H3Frame::CancelPush(7));
}

/// HF-06: H3Frame::MaxPushId encode/decode round-trip.
#[test]
fn hf_06_max_push_id_round_trip() {
    let frame = H3Frame::MaxPushId(255);
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(decoded, H3Frame::MaxPushId(255));
}

/// HF-07: H3Frame::Unknown encode/decode round-trip.
#[test]
fn hf_07_unknown_frame_round_trip() {
    let frame = H3Frame::Unknown {
        frame_type: 0xFF,
        payload: vec![0xAA, 0xBB],
    };
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf).expect("decode");
    assert_eq!(
        decoded,
        H3Frame::Unknown {
            frame_type: 0xFF,
            payload: vec![0xAA, 0xBB],
        }
    );
}

/// HF-08: H3Settings duplicate setting rejected.
#[test]
fn hf_08_duplicate_setting_rejected() {
    // Encode a SETTINGS payload with QPACK_MAX_TABLE_CAPACITY (0x01) twice.
    // Use the real encode path to produce correct varints, then concatenate.
    let s1 = H3Settings {
        qpack_max_table_capacity: Some(100),
        ..H3Settings::default()
    };
    let mut first_payload = Vec::new();
    s1.encode_payload(&mut first_payload).expect("encode first");

    // Duplicate: append the same setting bytes again
    let mut double_payload = first_payload.clone();
    double_payload.extend_from_slice(&first_payload);

    let err = H3Settings::decode_payload(&double_payload).expect_err("duplicate");
    assert!(
        matches!(err, H3NativeError::DuplicateSetting(_)),
        "expected DuplicateSetting, got {err:?}"
    );
}

/// HF-09: H3ControlState: SETTINGS must be first frame.
#[test]
fn hf_09_settings_must_be_first() {
    let mut state = H3ControlState::new();
    // Send a non-SETTINGS frame first
    let data_frame = H3Frame::Data(vec![0x01]);
    let err = state
        .on_remote_control_frame(&data_frame)
        .expect_err("SETTINGS must be first");
    assert!(
        matches!(err, H3NativeError::ControlProtocol(_)),
        "expected ControlProtocol, got {err:?}"
    );
}

/// HF-10: H3ControlState: DATA on control stream rejected (after SETTINGS).
#[test]
fn hf_10_data_on_control_stream_rejected() {
    let mut state = H3ControlState::new();
    let settings_frame = H3Frame::Settings(H3Settings::default());
    state
        .on_remote_control_frame(&settings_frame)
        .expect("SETTINGS accepted");
    let data_frame = H3Frame::Data(vec![0x01]);
    let err = state
        .on_remote_control_frame(&data_frame)
        .expect_err("DATA not allowed on control");
    assert!(
        matches!(err, H3NativeError::ControlProtocol(_)),
        "expected ControlProtocol, got {err:?}"
    );
}

/// HF-11: H3RequestHead valid pseudo headers (:method + :scheme + :path).
#[test]
fn hf_11_request_head_valid() {
    let pseudo = H3PseudoHeaders {
        method: Some("GET".into()),
        scheme: Some("https".into()),
        path: Some("/".into()),
        ..H3PseudoHeaders::default()
    };
    let head = H3RequestHead::new(pseudo, vec![]).expect("valid request head");
    assert_eq!(head.pseudo.method.as_deref(), Some("GET"));
    assert_eq!(head.pseudo.scheme.as_deref(), Some("https"));
    assert_eq!(head.pseudo.path.as_deref(), Some("/"));
}

/// HF-12: H3RequestHead missing :method rejected.
#[test]
fn hf_12_request_head_missing_method() {
    let pseudo = H3PseudoHeaders {
        scheme: Some("https".into()),
        path: Some("/".into()),
        ..H3PseudoHeaders::default()
    };
    let err = H3RequestHead::new(pseudo, vec![]).expect_err("missing :method");
    assert!(
        matches!(err, H3NativeError::InvalidRequestPseudoHeader(_)),
        "expected InvalidRequestPseudoHeader, got {err:?}"
    );
}

/// HF-13: H3ResponseHead valid status 200.
#[test]
fn hf_13_response_head_valid() {
    let head = H3ResponseHead::new(200, vec![]).expect("valid response");
    assert_eq!(head.status, 200);
}

/// HF-14: H3ResponseHead invalid status (0) rejected.
#[test]
fn hf_14_response_head_invalid_status() {
    let err = H3ResponseHead::new(0, vec![]).expect_err("invalid status 0");
    assert!(
        matches!(err, H3NativeError::InvalidResponsePseudoHeader(_)),
        "expected InvalidResponsePseudoHeader, got {err:?}"
    );
}

/// HF-15: H3QpackMode default is StaticOnly.
#[test]
fn hf_15_qpack_mode_default() {
    let config = H3ConnectionConfig::default();
    assert_eq!(config.qpack_mode, H3QpackMode::StaticOnly);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.7 Matrix Validation (MV)
// ═══════════════════════════════════════════════════════════════════════

const JSON_ARTIFACT: &str = include_str!("../docs/tokio_quic_h3_unit_protocol_matrix.json");
const MD_DOC: &str = include_str!("../docs/tokio_quic_h3_unit_protocol_matrix.md");

/// MV-01: JSON artifact has bead_id = asupersync-2oh2u.4.10.
#[test]
fn mv_01_json_bead_id() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.4.10");
}

/// MV-02: Document has required sections (8 sections present).
#[test]
fn mv_02_document_sections() {
    let required_sections = [
        "## 1. Scope",
        "### 2.1 QUIC Core Codec (QC)",
        "### 2.2 Transport State Machine (QT)",
        "### 2.3 Stream and Flow Control (QS)",
        "### 2.4 TLS/Key Phase Machine (TL)",
        "### 2.5 Connection Lifecycle (NC)",
        "### 2.6 HTTP/3 Frame Codec (HF)",
        "### 2.7 Matrix Validation (MV)",
    ];
    for section in &required_sections {
        assert!(MD_DOC.contains(section), "missing section: {section}");
    }
}

/// MV-03: All test category prefixes present in JSON.
#[test]
fn mv_03_test_category_prefixes() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    let categories = v["test_categories"]
        .as_array()
        .expect("test_categories array");
    let prefixes: Vec<&str> = categories
        .iter()
        .filter_map(|c| c["prefix"].as_str())
        .collect();
    for expected in &["QC", "QT", "QS", "TL", "NC", "HF"] {
        assert!(prefixes.contains(expected), "missing prefix: {expected}");
    }
}

/// MV-04: Summary test count matches sum of categories.
#[test]
fn mv_04_summary_count_matches() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    let total = v["summary"]["total_tests"].as_u64().expect("total_tests");
    let categories = v["test_categories"].as_array().expect("test_categories");
    let sum: u64 = categories.iter().filter_map(|c| c["count"].as_u64()).sum();
    assert_eq!(
        total, sum,
        "total_tests ({total}) != sum of categories ({sum})"
    );
}
