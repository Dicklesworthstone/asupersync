//! Deterministic E2E integration tests for the native QUIC/H3 stack.
//!
//! This harness drives the full stack: connection setup, TLS handshake,
//! transport state transitions, stream operations, and H3 framing -- all
//! with deterministic seeds and scheduling. No async runtime is required.

use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionState, H3ControlState, H3Frame, H3PseudoHeaders, H3RequestHead,
    H3RequestStreamState, H3ResponseHead, H3Settings, qpack_static_plan_for_request,
    qpack_static_plan_for_response,
};
use asupersync::net::quic_core::{
    ConnectionId, LongHeader, LongPacketType, PacketHeader, ShortHeader, TransportParameters,
};
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
    PacketNumberSpace, QuicConnectionState, StreamDirection, StreamId, StreamRole,
};
use asupersync::types::Time;
use asupersync::util::DetRng;

// ---------------------------------------------------------------------------
// Helpers
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
        // Start at a deterministic time offset derived from seed.
        // Time::from_millis(1000) = 1_000_000_000 nanos = 1_000_000 micros.
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

        // Both sides begin handshake.
        self.client.begin_handshake(cx).expect("client begin_handshake");
        self.server.begin_handshake(cx).expect("server begin_handshake");

        assert_eq!(self.client.state(), QuicConnectionState::Handshaking);
        assert_eq!(self.server.state(), QuicConnectionState::Handshaking);

        // Handshake keys become available.
        self.client
            .on_handshake_keys_available(cx)
            .expect("client hs keys");
        self.server
            .on_handshake_keys_available(cx)
            .expect("server hs keys");

        // 1-RTT keys become available.
        self.client
            .on_1rtt_keys_available(cx)
            .expect("client 1rtt keys");
        self.server
            .on_1rtt_keys_available(cx)
            .expect("server 1rtt keys");

        // Handshake is confirmed on both sides.
        self.client
            .on_handshake_confirmed(cx)
            .expect("client confirmed");
        self.server
            .on_handshake_confirmed(cx)
            .expect("server confirmed");

        assert_eq!(self.client.state(), QuicConnectionState::Established);
        assert_eq!(self.server.state(), QuicConnectionState::Established);
        assert!(self.client.can_send_1rtt());
        assert!(self.server.can_send_1rtt());
    }
}

// ===========================================================================
// Test 1: Full handshake lifecycle with packet exchange simulation
// ===========================================================================

#[test]
fn handshake_lifecycle_with_packet_exchange() {
    let mut rng = DetRng::new(0xCAFE_BABE);
    let mut pair = ConnectionPair::new(&mut rng);
    let cx = &pair.cx;

    // Client sends Initial packet.
    pair.client.begin_handshake(cx).expect("client begin");
    pair.server.begin_handshake(cx).expect("server begin");

    // Simulate client sending Initial packet.
    let t_send = pair.clock.now();
    let client_pn0 = pair
        .client
        .on_packet_sent(
            cx,
            PacketNumberSpace::Initial,
            1200,
            true,
            true,
            t_send,
        )
        .expect("client send initial");
    assert_eq!(client_pn0, 0, "first packet number should be 0");

    // Advance time for the "flight" of the packet.
    pair.clock.advance(10_000); // 10ms RTT one-way

    // Server receives and sends Handshake response.
    let server_pn0 = pair
        .server
        .on_packet_sent(
            cx,
            PacketNumberSpace::Handshake,
            1200,
            true,
            true,
            pair.clock.now(),
        )
        .expect("server send handshake");
    assert_eq!(server_pn0, 0);

    pair.clock.advance(10_000); // 10ms return

    // Client receives server's ack of its Initial.
    let ack = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::Initial,
            &[0],
            0,
            pair.clock.now(),
        )
        .expect("client ack");
    assert_eq!(ack.acked_packets, 1);
    assert_eq!(ack.acked_bytes, 1200);

    // Verify RTT was estimated.
    let rtt = pair.client.transport().rtt().smoothed_rtt_micros();
    assert!(rtt.is_some(), "RTT should be estimated after first ack");
    let rtt_us = rtt.unwrap();
    assert_eq!(rtt_us, 20_000, "RTT should be ~20ms");

    // Complete handshake.
    pair.client
        .on_handshake_keys_available(cx)
        .expect("client hs keys");
    pair.server
        .on_handshake_keys_available(cx)
        .expect("server hs keys");
    pair.client
        .on_1rtt_keys_available(cx)
        .expect("client 1rtt");
    pair.server
        .on_1rtt_keys_available(cx)
        .expect("server 1rtt");
    pair.client
        .on_handshake_confirmed(cx)
        .expect("client confirmed");
    pair.server
        .on_handshake_confirmed(cx)
        .expect("server confirmed");

    assert!(pair.client.can_send_1rtt());
    assert!(pair.server.can_send_1rtt());
}

// ===========================================================================
// Test 2: Bidirectional stream data exchange between client and server
// ===========================================================================

#[test]
fn bidirectional_stream_data_exchange() {
    let mut rng = DetRng::new(0xDEAD_BEEF);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Client opens a bidirectional stream.
    let client_stream = pair.client.open_local_bidi(cx).expect("client open bidi");
    assert!(client_stream.is_local_for(StreamRole::Client));
    assert_eq!(client_stream.direction(), StreamDirection::Bidirectional);

    // Client writes 1024 bytes.
    pair.client
        .write_stream(cx, client_stream, 1024)
        .expect("client write");

    // Server accepts the remote stream.
    pair.server
        .accept_remote_stream(cx, client_stream)
        .expect("server accept");

    // Server receives the 1024 bytes.
    pair.server
        .receive_stream(cx, client_stream, 1024)
        .expect("server receive");

    // Server writes 512 bytes back on the same bidirectional stream.
    pair.server
        .write_stream(cx, client_stream, 512)
        .expect("server write back");

    // Client receives the 512 bytes from server.
    pair.client
        .receive_stream(cx, client_stream, 512)
        .expect("client receive");

    // Verify stream offsets.
    let client_view = pair.client.streams().stream(client_stream).expect("client stream");
    assert_eq!(client_view.send_offset, 1024);
    assert_eq!(client_view.recv_offset, 512);

    let server_view = pair.server.streams().stream(client_stream).expect("server stream");
    assert_eq!(server_view.recv_offset, 1024);
    assert_eq!(server_view.send_offset, 512);
}

// ===========================================================================
// Test 3: Multiple streams with round-robin scheduling
// ===========================================================================

#[test]
fn multiple_streams_round_robin_scheduling() {
    let mut rng = DetRng::new(0x1234_5678);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open 4 client-initiated bidirectional streams.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");
    let s2 = pair.client.open_local_bidi(cx).expect("open s2");
    let s3 = pair.client.open_local_bidi(cx).expect("open s3");

    // Verify round-robin scheduling returns them in order.
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s0)
    );
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s1)
    );
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s2)
    );
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s3)
    );
    // Wraps around.
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s0)
    );

    // Stop-send on s1 should skip it in the round-robin.
    pair.client
        .on_stop_sending(cx, s1, 0x77)
        .expect("stop s1");

    // Current cursor was at s0. Next should be s2 (skipping s1).
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s2)
    );
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s3)
    );
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s0)
    );
    // s1 is still skipped.
    assert_eq!(
        pair.client.next_writable_stream(cx).expect("writable"),
        Some(s2)
    );
}

// ===========================================================================
// Test 4: H3 frame encoding/decoding over a simulated QUIC stream
// ===========================================================================

#[test]
fn h3_frame_encode_decode_over_stream() {
    let mut rng = DetRng::new(0xABCD_EF01);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Client opens a bidirectional stream for a request.
    let stream = pair.client.open_local_bidi(cx).expect("open stream");

    // Build a SETTINGS frame.
    let settings = H3Settings {
        max_field_section_size: Some(16384),
        ..H3Settings::default()
    };
    let settings_frame = H3Frame::Settings(settings.clone());

    // Encode the SETTINGS frame.
    let mut wire = Vec::new();
    settings_frame.encode(&mut wire).expect("encode settings");

    // Build a HEADERS frame (simulated QPACK encoded header block).
    let headers_frame = H3Frame::Headers(vec![0x00, 0x00, 0x80, 0x81, 0x82]);
    headers_frame.encode(&mut wire).expect("encode headers");

    // Build a DATA frame with deterministic payload.
    let payload_len = 128;
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push((rng.next_u64() & 0xFF) as u8);
    }
    let data_frame = H3Frame::Data(payload.clone());
    data_frame.encode(&mut wire).expect("encode data");

    // Simulate writing the total wire bytes to the QUIC stream.
    let total_bytes = wire.len() as u64;
    pair.client
        .write_stream(cx, stream, total_bytes)
        .expect("write wire bytes");

    // Server side: accept the stream and receive.
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");
    pair.server
        .receive_stream(cx, stream, total_bytes)
        .expect("server receive");

    // Decode frames from the wire buffer on the "server" side.
    let mut pos = 0;
    let (decoded_settings, consumed) =
        H3Frame::decode(&wire[pos..]).expect("decode settings frame");
    pos += consumed;
    assert_eq!(decoded_settings, settings_frame);

    let (decoded_headers, consumed) =
        H3Frame::decode(&wire[pos..]).expect("decode headers frame");
    pos += consumed;
    assert_eq!(decoded_headers, headers_frame);

    let (decoded_data, consumed) = H3Frame::decode(&wire[pos..]).expect("decode data frame");
    pos += consumed;
    assert_eq!(pos, wire.len(), "all bytes consumed");

    match decoded_data {
        H3Frame::Data(ref data) => {
            assert_eq!(data.len(), payload_len);
            assert_eq!(data, &payload);
        }
        _ => panic!("expected Data frame"),
    }
}

// ===========================================================================
// Test 5: H3 request/response lifecycle with control + request streams
// ===========================================================================

#[test]
fn h3_request_response_lifecycle() {
    let mut rng = DetRng::new(0xFACE_F00D);

    // Create H3 connection state for both sides.
    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // -- Control stream exchange: SETTINGS --

    // Client builds local SETTINGS.
    let mut client_ctrl = H3ControlState::new();
    let client_settings_frame = client_ctrl
        .build_local_settings(H3Settings::default())
        .expect("client build settings");

    // Server receives client's SETTINGS on control stream.
    server_h3
        .on_control_frame(&client_settings_frame)
        .expect("server receive client settings");

    // Server builds local SETTINGS.
    let mut server_ctrl = H3ControlState::new();
    let server_settings_frame = server_ctrl
        .build_local_settings(H3Settings::default())
        .expect("server build settings");

    // Client receives server's SETTINGS on control stream.
    client_h3
        .on_control_frame(&server_settings_frame)
        .expect("client receive server settings");

    // -- Request stream: client sends GET / --

    let request_stream_id: u64 = 0; // Client-initiated bidi stream 0.

    // Build validated request head.
    let request_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
        },
        vec![("user-agent".to_string(), "asupersync/0.2".to_string())],
    )
    .expect("valid request head");

    // Generate QPACK plan (static-only).
    let req_plan = qpack_static_plan_for_request(&request_head);
    assert!(!req_plan.is_empty(), "plan should have entries");

    // Encode a HEADERS frame (simulated QPACK-encoded block).
    let headers_frame = H3Frame::Headers(vec![0x00, 0x00, 0x80, 0x17]); // minimal QPACK-encoded block
    let mut request_stream_state = H3RequestStreamState::new();
    request_stream_state
        .on_frame(&headers_frame)
        .expect("headers ok");

    // Server processes the request-stream frame.
    server_h3
        .on_request_stream_frame(request_stream_id, &headers_frame)
        .expect("server process request headers");

    // Client sends DATA.
    let data_bytes: Vec<u8> = (0..64).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
    let data_frame = H3Frame::Data(data_bytes.clone());
    request_stream_state
        .on_frame(&data_frame)
        .expect("data ok");

    server_h3
        .on_request_stream_frame(request_stream_id, &data_frame)
        .expect("server process request data");

    // Client marks end of stream.
    request_stream_state
        .mark_end_stream()
        .expect("end stream");

    // Server finishes the request stream.
    server_h3
        .finish_request_stream(request_stream_id)
        .expect("server finish request");

    // -- Server response --

    let response_head =
        H3ResponseHead::new(200, vec![("content-type".to_string(), "text/plain".to_string())])
            .expect("valid response");

    let resp_plan = qpack_static_plan_for_response(&response_head);
    assert!(!resp_plan.is_empty());

    // Encode response frames.
    let resp_headers = H3Frame::Headers(vec![0x00, 0x00, 0xD9]); // minimal QPACK-encoded block
    let resp_data = H3Frame::Data(b"Hello, world!".to_vec());

    let mut resp_wire = Vec::new();
    resp_headers
        .encode(&mut resp_wire)
        .expect("encode resp headers");
    resp_data.encode(&mut resp_wire).expect("encode resp data");

    // Decode on the "client" side.
    let mut pos = 0;
    let (dec_h, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp headers");
    pos += n;
    assert_eq!(dec_h, resp_headers);

    let (dec_d, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp data");
    pos += n;
    assert_eq!(dec_d, resp_data);
    assert_eq!(pos, resp_wire.len());
}

// ===========================================================================
// Test 6: Graceful close with drain transition
// ===========================================================================

#[test]
fn graceful_close_drain_transition() {
    let mut rng = DetRng::new(0x9876_5432);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and write some data.
    let stream = pair.client.open_local_bidi(cx).expect("open stream");
    pair.client
        .write_stream(cx, stream, 100)
        .expect("write");

    // Client initiates graceful close.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x0)
        .expect("begin close");

    assert_eq!(pair.client.state(), QuicConnectionState::Draining);
    assert_eq!(pair.client.transport().close_code(), Some(0x0));

    // While draining, the client can still receive data on existing streams.
    pair.client
        .receive_stream(cx, stream, 50)
        .expect("receive while draining");

    // But cannot open new streams.
    let err = pair.client.open_local_bidi(cx).expect_err("should fail");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Advance time but not past the drain timeout (2 seconds).
    pair.clock.advance(1_999_999);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll before deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Advance 1 more microsecond to reach the deadline.
    pair.clock.advance(1);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll at deadline");
    assert_eq!(pair.client.state(), QuicConnectionState::Closed);

    // After close, new operations fail.
    let err = pair
        .client
        .open_local_bidi(cx)
        .expect_err("should fail after close");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );
}

// ===========================================================================
// Test 7: Key update via NativeQuicConnection
// ===========================================================================

#[test]
fn key_update_lifecycle() {
    let mut rng = DetRng::new(0xAAAA_BBBB);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Client requests a local key update.
    let scheduled = pair
        .client
        .request_local_key_update(cx)
        .expect("request key update");
    match scheduled {
        asupersync::net::quic_native::KeyUpdateEvent::LocalUpdateScheduled {
            next_phase,
            generation,
        } => {
            assert!(next_phase, "phase should flip to true");
            assert_eq!(generation, 1);
        }
        other => panic!("expected LocalUpdateScheduled, got {:?}", other),
    }

    // Commit the key update.
    let committed = pair
        .client
        .commit_local_key_update(cx)
        .expect("commit key update");
    match committed {
        asupersync::net::quic_native::KeyUpdateEvent::LocalUpdateScheduled {
            next_phase,
            generation,
        } => {
            assert!(next_phase);
            assert_eq!(generation, 1);
        }
        other => panic!("expected LocalUpdateScheduled, got {:?}", other),
    }

    assert!(pair.client.tls().local_key_phase());

    // Server observes the peer key phase flip.
    let peer_evt = pair
        .server
        .on_peer_key_phase(cx, true)
        .expect("peer key phase");
    match peer_evt {
        asupersync::net::quic_native::KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase,
            generation,
        } => {
            assert!(new_phase);
            assert_eq!(generation, 1);
        }
        other => panic!("expected RemoteUpdateAccepted, got {:?}", other),
    }

    assert!(pair.server.tls().remote_key_phase());
}

// ===========================================================================
// Test 8: Out-of-order receive reassembly
// ===========================================================================

#[test]
fn out_of_order_receive_reassembly() {
    let mut rng = DetRng::new(0x5555_6666);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let stream = pair.client.open_local_bidi(cx).expect("open stream");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    // Simulate out-of-order receive on the server side.
    // Segment [10..20) arrives first.
    pair.server
        .receive_stream_segment(cx, stream, 10, 10, false)
        .expect("out-of-order segment");
    let s = pair.server.streams().stream(stream).expect("stream");
    assert_eq!(s.recv_offset, 0, "contiguous offset should not advance yet");

    // Segment [20..30) arrives second.
    pair.server
        .receive_stream_segment(cx, stream, 20, 10, false)
        .expect("second segment");
    let s = pair.server.streams().stream(stream).expect("stream");
    assert_eq!(s.recv_offset, 0, "still waiting for [0..10)");

    // Gap-filling segment [0..10) arrives.
    pair.server
        .receive_stream_segment(cx, stream, 0, 10, false)
        .expect("gap fill");
    let s = pair.server.streams().stream(stream).expect("stream");
    assert_eq!(
        s.recv_offset, 30,
        "contiguous offset should advance through all segments"
    );

    // Final segment with FIN.
    pair.server
        .receive_stream_segment(cx, stream, 30, 5, true)
        .expect("final segment with FIN");
    let s = pair.server.streams().stream(stream).expect("stream");
    assert_eq!(s.recv_offset, 35);
    assert_eq!(s.final_size, Some(35));
}

// ===========================================================================
// Test 9: Transport parameter and packet header codec roundtrips
// ===========================================================================

#[test]
fn transport_parameter_and_packet_header_roundtrips() {
    let mut rng = DetRng::new(0x7777_8888);

    // Transport parameters roundtrip.
    let tp = TransportParameters {
        max_idle_timeout: Some(30_000),
        initial_max_data: Some(1_000_000),
        initial_max_stream_data_bidi_local: Some(256_000),
        initial_max_stream_data_bidi_remote: Some(256_000),
        initial_max_streams_bidi: Some(100),
        initial_max_streams_uni: Some(50),
        disable_active_migration: true,
        ..TransportParameters::default()
    };

    let mut tp_buf = Vec::new();
    tp.encode(&mut tp_buf).expect("encode transport params");
    let tp_decoded = TransportParameters::decode(&tp_buf).expect("decode transport params");
    assert_eq!(tp, tp_decoded);

    // Long header (Initial) roundtrip with deterministic CID.
    let cid_bytes: Vec<u8> = (0..8).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
    let dst_cid = ConnectionId::new(&cid_bytes).expect("valid CID");
    let src_cid = ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).expect("valid CID");

    let long_hdr = PacketHeader::Long(LongHeader {
        packet_type: LongPacketType::Initial,
        version: 1,
        dst_cid,
        src_cid,
        token: vec![0xAA, 0xBB],
        payload_length: 1200,
        packet_number: 0,
        packet_number_len: 1,
    });

    let mut hdr_buf = Vec::new();
    long_hdr.encode(&mut hdr_buf).expect("encode long header");
    let (decoded_hdr, consumed) =
        PacketHeader::decode(&hdr_buf, 0).expect("decode long header");
    assert_eq!(decoded_hdr, long_hdr);
    assert_eq!(consumed, hdr_buf.len());

    // Short header roundtrip.
    let short_hdr = PacketHeader::Short(ShortHeader {
        spin: false,
        key_phase: true,
        dst_cid,
        packet_number: 42,
        packet_number_len: 2,
    });

    let mut short_buf = Vec::new();
    short_hdr
        .encode(&mut short_buf)
        .expect("encode short header");
    let (decoded_short, consumed) =
        PacketHeader::decode(&short_buf, dst_cid.len()).expect("decode short header");
    assert_eq!(decoded_short, short_hdr);
    assert_eq!(consumed, short_buf.len());
}

// ===========================================================================
// Test 10: Full H3 GOAWAY + drain + close lifecycle
// ===========================================================================

#[test]
fn h3_goaway_and_connection_drain() {
    let mut rng = DetRng::new(0xBEEF_CAFE);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Set up H3 connection state.
    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Exchange SETTINGS.
    client_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("client settings");
    server_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("server settings");

    // Client opens two request streams.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");

    // Send HEADERS on s0.
    server_h3
        .on_request_stream_frame(s0.0, &H3Frame::Headers(vec![0x80]))
        .expect("s0 headers");

    // Server sends GOAWAY with stream_id = s1.0 (reject s1 and later).
    let goaway = H3Frame::Goaway(s1.0);
    let mut goaway_wire = Vec::new();
    goaway.encode(&mut goaway_wire).expect("encode goaway");

    // Client decodes GOAWAY.
    let (decoded_goaway, _) = H3Frame::decode(&goaway_wire).expect("decode goaway");
    client_h3
        .on_control_frame(&decoded_goaway)
        .expect("client goaway");
    assert_eq!(client_h3.goaway_id(), Some(s1.0));

    // New request on s1 should be rejected by H3.
    let err = client_h3
        .on_request_stream_frame(s1.0, &H3Frame::Headers(vec![0x80]))
        .expect_err("should reject after goaway");
    assert_eq!(
        format!("{}", err),
        "control stream protocol violation: request stream id rejected after GOAWAY"
    );

    // QUIC-level graceful close.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x0100)
        .expect("client drain");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Server also starts draining.
    pair.server
        .begin_close(cx, now, 0x0100)
        .expect("server drain");
    assert_eq!(pair.server.state(), QuicConnectionState::Draining);

    // Fast-forward past drain timeout.
    pair.clock.advance(2_000_001);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("client poll");
    pair.server
        .poll(cx, pair.clock.now())
        .expect("server poll");

    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.server.state(), QuicConnectionState::Closed);
}

// ===========================================================================
// Test 11: Deterministic RNG produces identical sequences
// ===========================================================================

#[test]
fn deterministic_rng_reproducibility() {
    let seed = 0xDECAF_C0FFEE;
    let mut rng1 = DetRng::new(seed);
    let mut rng2 = DetRng::new(seed);

    for _ in 0..1000 {
        assert_eq!(
            rng1.next_u64(),
            rng2.next_u64(),
            "DetRng must produce identical sequences from the same seed"
        );
    }
}

// ===========================================================================
// Test 12: Deterministic time progression via Time::from_millis
// ===========================================================================

#[test]
fn deterministic_time_progression() {
    // Time::from_millis produces deterministic nanosecond values.
    let t0 = Time::from_millis(0);
    let t1 = Time::from_millis(1000);
    let t2 = Time::from_millis(2000);

    assert_eq!(t0.as_nanos(), 0);
    assert_eq!(t1.as_nanos(), 1_000_000_000);
    assert_eq!(t2.as_nanos(), 2_000_000_000);
    assert_eq!(t1.as_millis(), 1000);

    // QUIC transport uses raw u64 microsecond timestamps.
    // Derive deterministic microsecond times from Time:
    let t_send_us = Time::from_millis(100).as_nanos() / 1_000; // 100_000 us
    let t_ack_us = Time::from_millis(150).as_nanos() / 1_000; // 150_000 us
    assert_eq!(t_send_us, 100_000);
    assert_eq!(t_ack_us, 150_000);

    // Use in packet timing context.
    let mut rng = DetRng::new(42);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            t_send_us,
        )
        .expect("send");

    let ack = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[0],
            0,
            t_ack_us,
        )
        .expect("ack");
    assert_eq!(ack.acked_packets, 1);

    let rtt = pair.client.transport().rtt().smoothed_rtt_micros().unwrap();
    assert_eq!(rtt, 50_000, "50ms RTT expected from 100ms send to 150ms ack");
}

// ===========================================================================
// QH3-E2: Handshake + bidi/uni data + graceful close
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 13: Client opens uni stream, writes data, server receives
// ---------------------------------------------------------------------------

#[test]
fn uni_stream_client_to_server() {
    let mut rng = DetRng::new(0xE2_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Client opens a unidirectional stream.
    let uni = pair.client.open_local_uni(cx).expect("client open uni");
    assert!(uni.is_local_for(StreamRole::Client));
    assert_eq!(uni.direction(), StreamDirection::Unidirectional);

    // Client writes 256 bytes on the uni stream.
    pair.client
        .write_stream(cx, uni, 256)
        .expect("client write uni");

    // Server accepts the remote uni stream and receives data.
    pair.server
        .accept_remote_stream(cx, uni)
        .expect("server accept uni");
    pair.server
        .receive_stream(cx, uni, 256)
        .expect("server receive uni");

    // Verify offsets on both sides.
    let client_view = pair.client.streams().stream(uni).expect("client stream");
    assert_eq!(client_view.send_offset, 256);
    // Client recv_offset stays at 0 since it's uni (send-only from client POV).
    assert_eq!(client_view.recv_offset, 0);

    let server_view = pair.server.streams().stream(uni).expect("server stream");
    assert_eq!(server_view.recv_offset, 256);
    assert_eq!(server_view.send_offset, 0);
}

// ---------------------------------------------------------------------------
// Test 14: Server opens uni stream, writes data, client receives
// ---------------------------------------------------------------------------

#[test]
fn uni_stream_server_to_client() {
    let mut rng = DetRng::new(0xE2_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Server opens a unidirectional stream.
    let uni = pair.server.open_local_uni(cx).expect("server open uni");
    assert!(uni.is_local_for(StreamRole::Server));
    assert_eq!(uni.direction(), StreamDirection::Unidirectional);

    // Server writes 512 bytes.
    pair.server
        .write_stream(cx, uni, 512)
        .expect("server write uni");

    // Client accepts and receives.
    pair.client
        .accept_remote_stream(cx, uni)
        .expect("client accept uni");
    pair.client
        .receive_stream(cx, uni, 512)
        .expect("client receive uni");

    // Verify offsets.
    let server_view = pair.server.streams().stream(uni).expect("server stream");
    assert_eq!(server_view.send_offset, 512);

    let client_view = pair.client.streams().stream(uni).expect("client stream");
    assert_eq!(client_view.recv_offset, 512);
    assert_eq!(client_view.send_offset, 0);
}

// ---------------------------------------------------------------------------
// Test 15: Large data transfer (64KB) across bidi stream in multiple segments
// ---------------------------------------------------------------------------

#[test]
fn large_data_transfer_multi_segment() {
    let mut rng = DetRng::new(0xE2_0003);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let stream = pair.client.open_local_bidi(cx).expect("open bidi");

    // Send 64KB total in 16 segments of 4KB each.
    let segment_size: u64 = 4096;
    let segment_count: u64 = 16;
    let total: u64 = segment_size * segment_count;

    for _ in 0..segment_count {
        pair.client
            .write_stream(cx, stream, segment_size)
            .expect("client write segment");
    }

    // Verify client send offset accumulated correctly.
    let client_view = pair.client.streams().stream(stream).expect("client stream");
    assert_eq!(client_view.send_offset, total, "client should have sent 64KB");

    // Server accepts and receives all data in matching segments.
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    for _ in 0..segment_count {
        pair.server
            .receive_stream(cx, stream, segment_size)
            .expect("server receive segment");
    }

    // Verify server received the full 64KB.
    let server_view = pair.server.streams().stream(stream).expect("server stream");
    assert_eq!(
        server_view.recv_offset, total,
        "server should have received 64KB"
    );

    // Server responds with a 32KB payload in 8 segments.
    let resp_segment_count: u64 = 8;
    let resp_total: u64 = segment_size * resp_segment_count;
    for _ in 0..resp_segment_count {
        pair.server
            .write_stream(cx, stream, segment_size)
            .expect("server write segment");
    }

    for _ in 0..resp_segment_count {
        pair.client
            .receive_stream(cx, stream, segment_size)
            .expect("client receive segment");
    }

    let client_view = pair.client.streams().stream(stream).expect("client stream");
    assert_eq!(client_view.send_offset, total);
    assert_eq!(client_view.recv_offset, resp_total);
}

// ---------------------------------------------------------------------------
// Test 16: Multiple concurrent bidi streams (8 streams, independent data)
// ---------------------------------------------------------------------------

#[test]
fn multiple_concurrent_bidi_streams() {
    let mut rng = DetRng::new(0xE2_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open 8 bidirectional streams from the client.
    let mut streams = Vec::new();
    for _ in 0..8 {
        let s = pair.client.open_local_bidi(cx).expect("open bidi");
        streams.push(s);
    }
    assert_eq!(streams.len(), 8);

    // Write different amounts on each stream: stream[i] gets (i+1)*100 bytes.
    for (i, &s) in streams.iter().enumerate() {
        let bytes = ((i as u64) + 1) * 100;
        pair.client
            .write_stream(cx, s, bytes)
            .expect("client write");
    }

    // Server accepts all streams and receives data independently.
    for (i, &s) in streams.iter().enumerate() {
        pair.server
            .accept_remote_stream(cx, s)
            .expect("server accept");
        let bytes = ((i as u64) + 1) * 100;
        pair.server
            .receive_stream(cx, s, bytes)
            .expect("server receive");
    }

    // Verify independent offsets.
    for (i, &s) in streams.iter().enumerate() {
        let expected = ((i as u64) + 1) * 100;
        let client_view = pair.client.streams().stream(s).expect("client stream");
        assert_eq!(
            client_view.send_offset, expected,
            "stream {} send_offset mismatch",
            i
        );

        let server_view = pair.server.streams().stream(s).expect("server stream");
        assert_eq!(
            server_view.recv_offset, expected,
            "stream {} recv_offset mismatch",
            i
        );
    }

    // Server writes different responses back on each stream.
    for (i, &s) in streams.iter().enumerate() {
        let bytes = ((i as u64) + 1) * 50;
        pair.server
            .write_stream(cx, s, bytes)
            .expect("server write back");
    }

    for (i, &s) in streams.iter().enumerate() {
        let bytes = ((i as u64) + 1) * 50;
        pair.client
            .receive_stream(cx, s, bytes)
            .expect("client receive back");
    }

    // Final verification of bidirectional offsets.
    for (i, &s) in streams.iter().enumerate() {
        let sent = ((i as u64) + 1) * 100;
        let recv = ((i as u64) + 1) * 50;
        let client_view = pair.client.streams().stream(s).expect("client stream");
        assert_eq!(client_view.send_offset, sent);
        assert_eq!(client_view.recv_offset, recv);
    }
}

// ---------------------------------------------------------------------------
// Test 17: Stream FIN handling — final_size is set correctly
// ---------------------------------------------------------------------------

#[test]
fn stream_fin_sets_final_size() {
    let mut rng = DetRng::new(0xE2_0005);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    // Client writes 200 bytes, then we set the final size on the server side
    // (simulating reception of data with FIN).
    pair.client
        .write_stream(cx, stream, 200)
        .expect("client write");

    // Server receives data with FIN using receive_stream_segment.
    pair.server
        .receive_stream_segment(cx, stream, 0, 200, true)
        .expect("server receive with FIN");

    let server_view = pair.server.streams().stream(stream).expect("server stream");
    assert_eq!(server_view.recv_offset, 200);
    assert_eq!(
        server_view.final_size,
        Some(200),
        "final_size should match the FIN offset"
    );

    // Attempting to receive more data past the final_size must fail.
    let err = pair
        .server
        .receive_stream_segment(cx, stream, 200, 1, false)
        .expect_err("must fail past final_size");
    assert!(
        matches!(
            err,
            NativeQuicConnectionError::Stream(
                asupersync::net::quic_native::streams::QuicStreamError::InvalidFinalSize { .. }
            )
        ),
        "expected InvalidFinalSize, got {:?}",
        err
    );
}

// ---------------------------------------------------------------------------
// Test 18: FIN with zero-length final segment
// ---------------------------------------------------------------------------

#[test]
fn stream_fin_zero_length_segment() {
    let mut rng = DetRng::new(0xE2_0006);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    // Server receives 100 bytes of data first (no FIN).
    pair.server
        .receive_stream_segment(cx, stream, 0, 100, false)
        .expect("server receive data");

    // Then receives a zero-length segment with FIN at offset 100.
    pair.server
        .receive_stream_segment(cx, stream, 100, 0, true)
        .expect("server receive FIN");

    let server_view = pair.server.streams().stream(stream).expect("server stream");
    assert_eq!(server_view.recv_offset, 100);
    assert_eq!(
        server_view.final_size,
        Some(100),
        "final_size from zero-length FIN segment"
    );
}

// ---------------------------------------------------------------------------
// Test 19: Graceful close with in-flight data
// ---------------------------------------------------------------------------

#[test]
fn graceful_close_with_in_flight_data() {
    let mut rng = DetRng::new(0xE2_0007);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open two streams and write data on each.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");

    pair.client
        .write_stream(cx, s0, 500)
        .expect("write s0");
    pair.client
        .write_stream(cx, s1, 300)
        .expect("write s1");

    pair.server
        .accept_remote_stream(cx, s0)
        .expect("server accept s0");
    pair.server
        .accept_remote_stream(cx, s1)
        .expect("server accept s1");

    // Begin graceful close while data is in-flight.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x0)
        .expect("begin close");

    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    // Data is still accessible: the server can receive data on existing streams.
    pair.server
        .receive_stream(cx, s0, 500)
        .expect("server receive s0 while draining");
    pair.server
        .receive_stream(cx, s1, 300)
        .expect("server receive s1 while draining");

    // Client can still receive on existing streams while draining.
    pair.client
        .receive_stream(cx, s0, 100)
        .expect("client receive while draining");

    // But cannot open new streams.
    let err = pair.client.open_local_bidi(cx).expect_err("no new streams while draining");
    assert_eq!(
        err,
        NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
    );

    // Verify Draining -> Closed transition after timeout.
    pair.clock.advance(1_999_999);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll before deadline");
    assert_eq!(
        pair.client.state(),
        QuicConnectionState::Draining,
        "should still be draining before timeout"
    );

    pair.clock.advance(1);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("poll at deadline");
    assert_eq!(
        pair.client.state(),
        QuicConnectionState::Closed,
        "should be closed after drain timeout"
    );
}

// ---------------------------------------------------------------------------
// Test 20: Connection flow control — send credit tracking
// ---------------------------------------------------------------------------

#[test]
fn connection_flow_control_send_credit() {
    let mut rng = DetRng::new(0xE2_0008);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Connection send limit is 4 << 20 = 4_194_304 bytes.
    let initial_remaining = pair.client.streams().connection_send_remaining();
    assert_eq!(initial_remaining, 4 << 20);

    // Open a stream and write a large chunk.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let write_amount: u64 = 100_000;
    pair.client
        .write_stream(cx, s0, write_amount)
        .expect("write large");

    let after_write = pair.client.streams().connection_send_remaining();
    assert_eq!(
        after_write,
        initial_remaining - write_amount,
        "connection send credit should decrease by written amount"
    );

    // Write on a second stream and verify cumulative tracking.
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");
    let write_amount_2: u64 = 50_000;
    pair.client
        .write_stream(cx, s1, write_amount_2)
        .expect("write s1");

    let after_both = pair.client.streams().connection_send_remaining();
    assert_eq!(
        after_both,
        initial_remaining - write_amount - write_amount_2,
        "connection send credit tracks cumulative writes"
    );
}

// ---------------------------------------------------------------------------
// Test 21: Connection flow control — recv credit tracking
// ---------------------------------------------------------------------------

#[test]
fn connection_flow_control_recv_credit() {
    let mut rng = DetRng::new(0xE2_0009);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Connection recv limit is 4 << 20 = 4_194_304 bytes.
    let initial_remaining = pair.server.streams().connection_recv_remaining();
    assert_eq!(initial_remaining, 4 << 20);

    // Client opens a bidi stream, server accepts and receives data.
    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    let recv_amount: u64 = 200_000;
    pair.client
        .write_stream(cx, stream, recv_amount)
        .expect("client write");
    pair.server
        .receive_stream(cx, stream, recv_amount)
        .expect("server receive");

    let after_recv = pair.server.streams().connection_recv_remaining();
    assert_eq!(
        after_recv,
        initial_remaining - recv_amount,
        "connection recv credit should decrease by received amount"
    );
}

// ---------------------------------------------------------------------------
// Test 22: Multiple uni + bidi streams interleaved
// ---------------------------------------------------------------------------

#[test]
fn interleaved_uni_and_bidi_streams() {
    let mut rng = DetRng::new(0xE2_000A);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Client opens 3 bidi and 3 uni streams.
    let bidi0 = pair.client.open_local_bidi(cx).expect("bidi0");
    let uni0 = pair.client.open_local_uni(cx).expect("uni0");
    let bidi1 = pair.client.open_local_bidi(cx).expect("bidi1");
    let uni1 = pair.client.open_local_uni(cx).expect("uni1");
    let bidi2 = pair.client.open_local_bidi(cx).expect("bidi2");
    let uni2 = pair.client.open_local_uni(cx).expect("uni2");

    // Verify directions.
    assert_eq!(bidi0.direction(), StreamDirection::Bidirectional);
    assert_eq!(uni0.direction(), StreamDirection::Unidirectional);
    assert_eq!(bidi1.direction(), StreamDirection::Bidirectional);
    assert_eq!(uni1.direction(), StreamDirection::Unidirectional);
    assert_eq!(bidi2.direction(), StreamDirection::Bidirectional);
    assert_eq!(uni2.direction(), StreamDirection::Unidirectional);

    // Write on all streams in interleaved order.
    pair.client.write_stream(cx, bidi0, 100).expect("write bidi0");
    pair.client.write_stream(cx, uni0, 200).expect("write uni0");
    pair.client.write_stream(cx, bidi1, 300).expect("write bidi1");
    pair.client.write_stream(cx, uni1, 400).expect("write uni1");
    pair.client.write_stream(cx, bidi2, 500).expect("write bidi2");
    pair.client.write_stream(cx, uni2, 600).expect("write uni2");

    // Server accepts and receives everything.
    for &s in &[bidi0, uni0, bidi1, uni1, bidi2, uni2] {
        pair.server
            .accept_remote_stream(cx, s)
            .expect("server accept");
    }

    pair.server.receive_stream(cx, bidi0, 100).expect("recv bidi0");
    pair.server.receive_stream(cx, uni0, 200).expect("recv uni0");
    pair.server.receive_stream(cx, bidi1, 300).expect("recv bidi1");
    pair.server.receive_stream(cx, uni1, 400).expect("recv uni1");
    pair.server.receive_stream(cx, bidi2, 500).expect("recv bidi2");
    pair.server.receive_stream(cx, uni2, 600).expect("recv uni2");

    // Verify all offsets.
    let expected: [(StreamId, u64); 6] = [
        (bidi0, 100),
        (uni0, 200),
        (bidi1, 300),
        (uni1, 400),
        (bidi2, 500),
        (uni2, 600),
    ];
    for (s, expected_len) in expected {
        let sv = pair.server.streams().stream(s).expect("stream");
        assert_eq!(
            sv.recv_offset, expected_len,
            "stream {:?} recv_offset mismatch",
            s
        );
    }

    // Server writes back on bidi streams only.
    pair.server.write_stream(cx, bidi0, 10).expect("srv write bidi0");
    pair.server.write_stream(cx, bidi1, 30).expect("srv write bidi1");
    pair.server.write_stream(cx, bidi2, 50).expect("srv write bidi2");

    pair.client.receive_stream(cx, bidi0, 10).expect("cli recv bidi0");
    pair.client.receive_stream(cx, bidi1, 30).expect("cli recv bidi1");
    pair.client.receive_stream(cx, bidi2, 50).expect("cli recv bidi2");
}

// ---------------------------------------------------------------------------
// Test 23: Out-of-order multi-segment reception with FIN on last segment
// ---------------------------------------------------------------------------

#[test]
fn out_of_order_segments_with_fin() {
    let mut rng = DetRng::new(0xE2_000B);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");

    // Simulate out-of-order delivery: segments arrive as [20..30), [10..20), [30..40+FIN), [0..10).
    pair.server
        .receive_stream_segment(cx, stream, 20, 10, false)
        .expect("seg [20..30)");
    assert_eq!(
        pair.server.streams().stream(stream).expect("s").recv_offset,
        0,
        "contiguous offset should not advance yet"
    );

    pair.server
        .receive_stream_segment(cx, stream, 10, 10, false)
        .expect("seg [10..20)");
    assert_eq!(
        pair.server.streams().stream(stream).expect("s").recv_offset,
        0,
        "still waiting for [0..10)"
    );

    pair.server
        .receive_stream_segment(cx, stream, 30, 10, true)
        .expect("seg [30..40) with FIN");
    assert_eq!(
        pair.server.streams().stream(stream).expect("s").recv_offset,
        0,
        "still waiting for [0..10)"
    );
    assert_eq!(
        pair.server.streams().stream(stream).expect("s").final_size,
        Some(40),
        "final_size should be set from FIN"
    );

    // Fill the gap.
    pair.server
        .receive_stream_segment(cx, stream, 0, 10, false)
        .expect("seg [0..10)");

    let server_view = pair.server.streams().stream(stream).expect("server stream");
    assert_eq!(
        server_view.recv_offset, 40,
        "all segments reassembled, contiguous offset should be 40"
    );
    assert_eq!(server_view.final_size, Some(40));
}

// ---------------------------------------------------------------------------
// Test 24: Both sides drain simultaneously, both reach Closed
// ---------------------------------------------------------------------------

#[test]
fn both_sides_drain_to_closed() {
    let mut rng = DetRng::new(0xE2_000C);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open a stream and exchange some data.
    let stream = pair.client.open_local_bidi(cx).expect("open bidi");
    pair.client
        .write_stream(cx, stream, 1000)
        .expect("client write");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept");
    pair.server
        .receive_stream(cx, stream, 1000)
        .expect("server receive");

    // Both sides initiate graceful close simultaneously.
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x00)
        .expect("client drain");
    pair.server
        .begin_close(cx, now, 0x00)
        .expect("server drain");

    assert_eq!(pair.client.state(), QuicConnectionState::Draining);
    assert_eq!(pair.server.state(), QuicConnectionState::Draining);

    // Advance time past drain timeout.
    pair.clock.advance(2_000_000);
    pair.client
        .poll(cx, pair.clock.now())
        .expect("client poll");
    pair.server
        .poll(cx, pair.clock.now())
        .expect("server poll");

    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.server.state(), QuicConnectionState::Closed);
}
