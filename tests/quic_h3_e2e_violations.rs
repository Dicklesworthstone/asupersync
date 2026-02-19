//! QH3-E6 -- Protocol violation corpus (reject, don't panic).
//!
//! Negative/adversarial tests that verify the QUIC/H3 stack properly rejects
//! invalid inputs by returning `Err(...)` rather than panicking.  Each test
//! confirms that the stack remains in a valid state after the error.

use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionState, H3ControlState, H3Frame, H3Settings,
};
use asupersync::net::quic_core::{
    ConnectionId, PacketHeader, QuicCoreError, TransportParameters, encode_varint,
};
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicConnectionState, QuicStreamError, StreamId, StreamRole,
};
use asupersync::util::DetRng;

// ---------------------------------------------------------------------------
// Helpers (replicated from quic_h3_e2e.rs)
// ---------------------------------------------------------------------------

/// Build a test Cx with infinite budget and no cancellation.
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Deterministic microsecond clock starting at seed-derived offset.
struct DetClock {
    now_micros: u64,
}

impl DetClock {
    fn new(rng: &mut DetRng) -> Self {
        use asupersync::types::Time;
        let base_micros = Time::from_millis(1_000).as_nanos() / 1_000;
        let jitter = rng.next_u64() % 1_000;
        Self {
            now_micros: base_micros + jitter,
        }
    }

    fn advance(&mut self, delta_micros: u64) {
        self.now_micros += delta_micros;
    }

    fn now(&self) -> u64 {
        self.now_micros
    }
}

/// A paired client+server connection setup driven through the full handshake.
struct ConnectionPair {
    client: NativeQuicConnection,
    server: NativeQuicConnection,
    cx: Cx,
    clock: DetClock,
}

impl ConnectionPair {
    fn new(rng: &mut DetRng) -> Self {
        let cx = test_cx();
        let clock = DetClock::new(rng);

        let client_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Client,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let server_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Server,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let client = NativeQuicConnection::new(client_cfg);
        let server = NativeQuicConnection::new(server_cfg);

        Self {
            client,
            server,
            cx,
            clock,
        }
    }

    /// Drive both endpoints through the full handshake to Established state.
    fn establish(&mut self) {
        let cx = &self.cx;

        self.client.begin_handshake(cx).expect("client begin_handshake");
        self.server.begin_handshake(cx).expect("server begin_handshake");

        self.client
            .on_handshake_keys_available(cx)
            .expect("client hs keys");
        self.server
            .on_handshake_keys_available(cx)
            .expect("server hs keys");

        self.client
            .on_1rtt_keys_available(cx)
            .expect("client 1rtt keys");
        self.server
            .on_1rtt_keys_available(cx)
            .expect("server 1rtt keys");

        self.client
            .on_handshake_confirmed(cx)
            .expect("client confirmed");
        self.server
            .on_handshake_confirmed(cx)
            .expect("server confirmed");

        assert_eq!(self.client.state(), QuicConnectionState::Established);
        assert_eq!(self.server.state(), QuicConnectionState::Established);
    }
}

// ===========================================================================
// Test 1: Write after close -- verify explicit error, not panic
// ===========================================================================

#[test]
fn write_after_close_returns_error() {
    let mut rng = DetRng::new(0xE6_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and write some data.
    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.client
        .write_stream(cx, stream, 100)
        .expect("initial write");

    // Close the connection immediately.
    pair.client
        .close_immediately(cx, 0x00)
        .expect("close immediately");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    // Attempt to write after close -- must return Err, not panic.
    let err = pair
        .client
        .write_stream(cx, stream, 50)
        .expect_err("write after close must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );
}

// ===========================================================================
// Test 2: Open stream after close -- verify error
// ===========================================================================

#[test]
fn open_stream_after_close_returns_error() {
    let mut rng = DetRng::new(0xE6_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Close the connection.
    pair.client
        .close_immediately(cx, 0x01)
        .expect("close immediately");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    // Attempt to open a bidi stream after close -- must return Err.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open bidi after close must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Also try uni stream.
    let err = pair
        .client
        .open_local_uni(cx)
        .expect_err("open uni after close must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );
}

// ===========================================================================
// Test 3: Invalid connection state transitions -- begin_handshake on
//         already-established connection
// ===========================================================================

#[test]
fn begin_handshake_on_established_connection_returns_error() {
    let mut rng = DetRng::new(0xE6_0003);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Attempt begin_handshake on an already-established connection.
    let err = pair
        .client
        .begin_handshake(cx)
        .expect_err("begin_handshake on established must fail");

    // The transport layer should reject Established -> Handshaking.
    assert!(
        matches!(err, NativeQuicConnectionError::Transport(_)),
        "expected Transport error, got: {:?}",
        err
    );
}

// ===========================================================================
// Test 4: Invalid stream ID -- write to a non-existent stream
// ===========================================================================

#[test]
fn write_to_nonexistent_stream_returns_error() {
    let mut rng = DetRng::new(0xE6_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Construct a StreamId that was never opened.
    let nonexistent_stream = StreamId(0xDEAD);

    // Attempt to write to it -- must return Err.
    let err = pair
        .client
        .write_stream(cx, nonexistent_stream, 100)
        .expect_err("write to nonexistent stream must fail");

    // Should be a StreamTable error (UnknownStream).
    assert!(
        matches!(err, NativeQuicConnectionError::StreamTable(_)),
        "expected StreamTable error, got: {:?}",
        err
    );
}

// ===========================================================================
// Test 5: H3 invalid frame on control stream -- garbage before SETTINGS
// ===========================================================================

#[test]
fn h3_invalid_frame_on_control_stream() {
    let _rng = DetRng::new(0xE6_0005);

    let mut h3 = H3ConnectionState::new();

    // Feed a DATA frame before SETTINGS -- must be rejected.
    let data_frame = H3Frame::Data(vec![0xFF, 0xFE, 0xFD]);
    let err = h3
        .on_control_frame(&data_frame)
        .expect_err("DATA before SETTINGS must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: first remote control frame must be SETTINGS"
    );

    // Feed a HEADERS frame before SETTINGS -- also rejected.
    let mut h3_2 = H3ConnectionState::new();
    let headers_frame = H3Frame::Headers(vec![0x00, 0x80]);
    let err = h3_2
        .on_control_frame(&headers_frame)
        .expect_err("HEADERS before SETTINGS must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: first remote control frame must be SETTINGS"
    );

    // Feed a GOAWAY frame before SETTINGS -- also rejected.
    let mut h3_3 = H3ConnectionState::new();
    let err = h3_3
        .on_control_frame(&H3Frame::Goaway(0))
        .expect_err("GOAWAY before SETTINGS must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: first remote control frame must be SETTINGS"
    );
}

// ===========================================================================
// Test 6: H3 duplicate SETTINGS on control stream
// ===========================================================================

#[test]
fn h3_duplicate_settings_on_control_stream() {
    let _rng = DetRng::new(0xE6_0006);

    let mut h3 = H3ConnectionState::new();

    // Send first SETTINGS -- ok.
    h3.on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("first SETTINGS accepted");

    // Send second SETTINGS -- must be rejected as protocol violation.
    let err = h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect_err("duplicate SETTINGS must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: duplicate SETTINGS on remote control stream"
    );

    // Also verify that H3ControlState directly rejects duplicate local settings.
    let mut ctrl = H3ControlState::new();
    ctrl.build_local_settings(H3Settings::default())
        .expect("first local SETTINGS");
    let err = ctrl
        .build_local_settings(H3Settings::default())
        .expect_err("duplicate local SETTINGS must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: SETTINGS already sent on local control stream"
    );
}

// ===========================================================================
// Test 7: H3 frame decode with truncated data
// ===========================================================================

#[test]
fn h3_frame_decode_truncated_data() {
    let _rng = DetRng::new(0xE6_0007);

    // Empty buffer.
    let err = H3Frame::decode(&[]).expect_err("empty buffer must fail");
    assert_eq!(format!("{}", err), "invalid frame: frame type varint");

    // Single byte: frame type varint ok but no length varint.
    let err = H3Frame::decode(&[0x00]).expect_err("no length must fail");
    assert_eq!(format!("{}", err), "invalid frame: frame length varint");

    // DATA frame (type=0x00) with length=10 but only 3 payload bytes.
    let frame = H3Frame::Data(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let mut wire = Vec::new();
    frame.encode(&mut wire).expect("encode");
    // Truncate: keep only the header + 3 bytes of the 10-byte payload.
    let header_len = wire.len() - 10;
    let truncated = &wire[..header_len + 3];
    let err = H3Frame::decode(truncated).expect_err("truncated payload must fail");
    assert_eq!(format!("{}", err), "unexpected EOF");

    // GOAWAY frame with just the frame type and length but no stream ID payload.
    let goaway = H3Frame::Goaway(42);
    let mut goaway_wire = Vec::new();
    goaway.encode(&mut goaway_wire).expect("encode goaway");
    // Keep only the type and length bytes.
    let payload_start = goaway_wire.len() - 1; // GOAWAY payload is 1 varint byte for value 42
    let truncated_goaway = &goaway_wire[..payload_start];
    let err = H3Frame::decode(truncated_goaway).expect_err("truncated GOAWAY must fail");
    assert_eq!(format!("{}", err), "unexpected EOF");
}

// ===========================================================================
// Test 8: H3 GOAWAY with increasing stream ID -- verify protocol error
// ===========================================================================

#[test]
fn h3_goaway_increasing_stream_id_rejected() {
    let _rng = DetRng::new(0xE6_0008);

    let mut h3 = H3ConnectionState::new();

    // Accept SETTINGS first.
    h3.on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings accepted");

    // Send GOAWAY with stream ID 100.
    h3.on_control_frame(&H3Frame::Goaway(100))
        .expect("first goaway=100");
    assert_eq!(h3.goaway_id(), Some(100));

    // Send GOAWAY with lower stream ID 50 -- allowed (decreasing).
    h3.on_control_frame(&H3Frame::Goaway(50))
        .expect("goaway=50 (decreasing, allowed)");
    assert_eq!(h3.goaway_id(), Some(50));

    // Send GOAWAY with same stream ID 50 -- allowed (not increasing).
    h3.on_control_frame(&H3Frame::Goaway(50))
        .expect("goaway=50 again (same, allowed)");

    // Send GOAWAY with HIGHER stream ID 80 -- MUST be rejected.
    let err = h3
        .on_control_frame(&H3Frame::Goaway(80))
        .expect_err("increasing GOAWAY must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: GOAWAY id must not increase"
    );

    // State should still reflect the last valid goaway_id.
    assert_eq!(h3.goaway_id(), Some(50));
}

// ===========================================================================
// Test 9: Transport parameter decode with invalid encoding
// ===========================================================================

#[test]
fn transport_parameter_decode_invalid_encoding() {
    let _rng = DetRng::new(0xE6_0009);

    // 1) Completely empty buffer -- should decode to default (no error).
    let result = TransportParameters::decode(&[]);
    assert!(result.is_ok(), "empty buffer should decode to defaults");

    // 2) Truncated TLV: parameter ID present but length varint missing.
    let mut buf = Vec::new();
    encode_varint(0x01, &mut buf).expect("encode param id");
    // No length follows.
    let err = TransportParameters::decode(&buf).expect_err("truncated TLV must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 3) Length claims more bytes than available.
    let mut buf2 = Vec::new();
    encode_varint(0x01, &mut buf2).expect("encode param id");
    encode_varint(100, &mut buf2).expect("encode length=100");
    buf2.extend_from_slice(&[0x00; 5]); // Only 5 bytes, not 100.
    let err = TransportParameters::decode(&buf2).expect_err("short value must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 4) Duplicate transport parameter.
    let mut buf3 = Vec::new();
    // First max_idle_timeout = 1000.
    let mut body = Vec::new();
    encode_varint(1000, &mut body).expect("varint");
    encode_varint(0x01, &mut buf3).expect("id");
    encode_varint(body.len() as u64, &mut buf3).expect("len");
    buf3.extend_from_slice(&body);
    // Duplicate max_idle_timeout = 2000.
    let mut body2 = Vec::new();
    encode_varint(2000, &mut body2).expect("varint");
    encode_varint(0x01, &mut buf3).expect("id");
    encode_varint(body2.len() as u64, &mut buf3).expect("len");
    buf3.extend_from_slice(&body2);
    let err = TransportParameters::decode(&buf3).expect_err("duplicate param must fail");
    assert_eq!(err, QuicCoreError::DuplicateTransportParameter(0x01));

    // 5) Invalid ack_delay_exponent (> 20).
    let mut buf4 = Vec::new();
    let mut ade_body = Vec::new();
    encode_varint(21, &mut ade_body).expect("varint");
    encode_varint(0x0a, &mut buf4).expect("id"); // TP_ACK_DELAY_EXPONENT
    encode_varint(ade_body.len() as u64, &mut buf4).expect("len");
    buf4.extend_from_slice(&ade_body);
    let err = TransportParameters::decode(&buf4).expect_err("bad ack_delay_exponent must fail");
    assert_eq!(err, QuicCoreError::InvalidTransportParameter(0x0a));
}

// ===========================================================================
// Test 10: Packet header decode with truncated buffer
// ===========================================================================

#[test]
fn packet_header_decode_truncated_buffer() {
    let _rng = DetRng::new(0xE6_000A);

    // 1) Empty buffer.
    let err = PacketHeader::decode(&[], 0).expect_err("empty buffer must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 2) Single byte with long-header bit set -- not enough data.
    let err = PacketHeader::decode(&[0xC0], 0).expect_err("1-byte long header must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 3) Short header with insufficient data: just the first byte.
    let err = PacketHeader::decode(&[0x40], 4).expect_err("1-byte short header must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 4) Long header with valid first byte + version but truncated CIDs.
    let buf = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x04]; // version=1, dcid_len=4, then nothing
    let err = PacketHeader::decode(&buf, 0).expect_err("truncated CID must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);

    // 5) Short header: first byte ok, but not enough bytes for dst_cid + pn.
    // pn_len = (0x40 & 0x03) + 1 = 1, dst_cid_len = 8
    // Need: 1 (first) + 8 (cid) + 1 (pn) = 10 bytes, provide only 5.
    let short_buf = [0x40, 0xAA, 0xBB, 0xCC, 0xDD];
    let err = PacketHeader::decode(&short_buf, 8).expect_err("short header truncated must fail");
    assert_eq!(err, QuicCoreError::UnexpectedEof);
}

// ===========================================================================
// Test 11: Connection ID too long
// ===========================================================================

#[test]
fn connection_id_too_long_returns_error() {
    let _rng = DetRng::new(0xE6_000B);

    // Max allowed is 20 bytes -- 20 should succeed.
    let ok = ConnectionId::new(&[0xAB; 20]);
    assert!(ok.is_ok(), "20-byte CID should be valid");
    assert_eq!(ok.unwrap().len(), 20);

    // 21 bytes should fail.
    let err = ConnectionId::new(&[0xAB; 21]).expect_err("21-byte CID must fail");
    assert_eq!(err, QuicCoreError::InvalidConnectionIdLength(21));

    // 100 bytes should fail.
    let err = ConnectionId::new(&[0x00; 100]).expect_err("100-byte CID must fail");
    assert_eq!(err, QuicCoreError::InvalidConnectionIdLength(100));

    // 0 bytes is valid (empty CID).
    let empty = ConnectionId::new(&[]).expect("empty CID should be valid");
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

// ===========================================================================
// Test 12: Send on reset stream -- verify error
// ===========================================================================

#[test]
fn send_on_reset_stream_returns_error() {
    let mut rng = DetRng::new(0xE6_000C);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and write some data.
    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.client
        .write_stream(cx, stream, 50)
        .expect("initial write");

    // Reset the stream's send side.
    pair.client
        .reset_stream_send(cx, stream, 0x77, 50)
        .expect("reset send");

    // Verify the reset state was recorded.
    let s = pair.client.streams().stream(stream).expect("stream");
    assert_eq!(s.send_reset, Some((0x77, 50)));

    // Now simulate the peer acknowledging the reset by sending STOP_SENDING.
    pair.client
        .on_stop_sending(cx, stream, 0x77)
        .expect("stop_sending");

    // Attempt to write after reset + stop_sending -- must return Err.
    let err = pair
        .client
        .write_stream(cx, stream, 10)
        .expect_err("write on reset stream must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::Stream(QuicStreamError::SendStopped { code: 0x77 })
    );
}

// ===========================================================================
// Test 13: H3 disallowed frames on control stream after SETTINGS
// ===========================================================================

#[test]
fn h3_disallowed_frames_on_control_stream_after_settings() {
    let _rng = DetRng::new(0xE6_000D);

    let mut h3 = H3ConnectionState::new();

    // Accept SETTINGS first.
    h3.on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings accepted");

    // DATA frame on control stream after SETTINGS -- must be rejected.
    let err = h3
        .on_control_frame(&H3Frame::Data(vec![1, 2, 3]))
        .expect_err("DATA on control stream must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: frame type not allowed on control stream"
    );

    // HEADERS frame on control stream after SETTINGS -- must be rejected.
    let err = h3
        .on_control_frame(&H3Frame::Headers(vec![0x80]))
        .expect_err("HEADERS on control stream must fail");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: frame type not allowed on control stream"
    );

    // GOAWAY frame on control stream after SETTINGS -- allowed.
    h3.on_control_frame(&H3Frame::Goaway(10))
        .expect("GOAWAY on control stream is valid");

    // CANCEL_PUSH on control stream after SETTINGS -- allowed.
    h3.on_control_frame(&H3Frame::CancelPush(5))
        .expect("CANCEL_PUSH on control stream is valid");
}

// ===========================================================================
// Test 14: Write and open on draining connection -- verify errors
// ===========================================================================

#[test]
fn write_and_open_on_draining_connection() {
    let mut rng = DetRng::new(0xE6_000E);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream.
    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.client
        .write_stream(cx, stream, 100)
        .expect("initial write");

    // Begin graceful close (draining).
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x00)
        .expect("begin close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Write on existing stream while draining -- should fail because
    // can_send_1rtt() returns false when not Established.
    let err = pair
        .client
        .write_stream(cx, stream, 50)
        .expect_err("write while draining must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Open new stream while draining -- should fail.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("open bidi while draining must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Receive on existing stream while draining -- should succeed
    // (this is explicitly allowed).
    pair.client
        .receive_stream(cx, stream, 25)
        .expect("receive while draining is allowed");

    // Advance past drain timeout to reach Closed.
    pair.clock.advance(2_000_001);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll past deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    // After Closed, even receive should fail.
    let err = pair
        .client
        .receive_stream(cx, stream, 10)
        .expect_err("receive after closed must fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState(
            "stream operation requires established or draining state"
        )
    );
}
