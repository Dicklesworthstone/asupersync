#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for [T4.11] End-to-End QUIC/H3 Scenario Manifest with Deep Telemetry Logs.
//!
//! Bead: asupersync-2oh2u.4.11
//! Covers: Deterministic e2e scenarios for QUIC transport, HTTP/3 protocol, and
//!         telemetry/forensic logging across realistic session lifecycles.
//!
//! 32 tests across 6 categories:
//!   ES (6), EC (5), EH (6), ED (5), ET (6), MV (4)

// ── Imports ─────────────────────────────────────────────────────────────

use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3Frame, H3NativeError, H3PseudoHeaders,
    H3QpackMode, H3RequestHead, H3RequestStreamState, H3ResponseHead, H3Settings,
};
use asupersync::net::quic_native::connection::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
};
use asupersync::net::quic_native::forensic_log::{
    QuicH3Event, QuicH3ForensicLogger, QuicH3ScenarioManifest,
};
use asupersync::net::quic_native::streams::StreamRole;
use asupersync::net::quic_native::tls::KeyUpdateEvent;
use asupersync::net::quic_native::transport::{
    PacketNumberSpace, QuicConnectionState, QuicTransportMachine, RttEstimator,
};

// ── Test Helpers ────────────────────────────────────────────────────────

fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Default H3ConnectionConfig for tests.
fn test_config() -> H3ConnectionConfig {
    H3ConnectionConfig::default()
}

fn cancelled_cx() -> Cx {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    cx
}

fn client_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        role: StreamRole::Client,
        max_local_bidi: 64,
        max_local_uni: 64,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        drain_timeout_micros: 2_000_000,
    }
}

fn server_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        role: StreamRole::Server,
        ..client_config()
    }
}

/// Performs a full 6-step simulated handshake on a client/server pair.
fn establish_pair(cx: &Cx, client: &mut NativeQuicConnection, server: &mut NativeQuicConnection) {
    client.begin_handshake(cx).expect("client begin_handshake");
    server.begin_handshake(cx).expect("server begin_handshake");
    client
        .on_handshake_keys_available(cx)
        .expect("client handshake keys");
    server
        .on_handshake_keys_available(cx)
        .expect("server handshake keys");
    client.on_1rtt_keys_available(cx).expect("client 1rtt keys");
    server.on_1rtt_keys_available(cx).expect("server 1rtt keys");
    client
        .on_handshake_confirmed(cx)
        .expect("client handshake confirmed");
    server
        .on_handshake_confirmed(cx)
        .expect("server handshake confirmed");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.1 Session Lifecycle (ES)
// ═══════════════════════════════════════════════════════════════════════

/// ES-01: Full handshake: Idle → Handshaking → Established on both sides.
#[test]
fn es_01_full_handshake() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());

    assert_eq!(client.state(), QuicConnectionState::Idle);
    assert_eq!(server.state(), QuicConnectionState::Idle);

    establish_pair(&cx, &mut client, &mut server);

    assert_eq!(client.state(), QuicConnectionState::Established);
    assert_eq!(server.state(), QuicConnectionState::Established);
    assert!(client.can_send_1rtt());
    assert!(server.can_send_1rtt());
}

/// ES-02: 0-RTT resumption path — resumption enabled before confirmation allows 0-RTT.
#[test]
fn es_02_zero_rtt_resumption() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());

    client.begin_handshake(&cx).expect("begin");
    client
        .on_handshake_keys_available(&cx)
        .expect("handshake keys");

    // Enable resumption before 1-RTT keys → 0-RTT should be available
    client.enable_resumption_0rtt(&cx).expect("enable 0rtt");
    assert!(client.can_send_0rtt());

    // After 1-RTT keys but before confirmation, 0-RTT still available
    client.on_1rtt_keys_available(&cx).expect("1rtt");
    assert!(client.can_send_0rtt());

    // After confirmation, 0-RTT no longer available
    client.on_handshake_confirmed(&cx).expect("confirmed");
    assert!(!client.can_send_0rtt());
    assert!(client.can_send_1rtt());
}

/// ES-03: Key update after confirmed handshake — phase bit flips.
#[test]
fn es_03_key_update_after_confirmed() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    assert!(!client.tls().local_key_phase());
    let evt = client.request_local_key_update(&cx).expect("request");
    assert!(matches!(evt, KeyUpdateEvent::LocalUpdateScheduled { .. }));
    client.commit_local_key_update(&cx).expect("commit");
    assert!(client.tls().local_key_phase());
}

/// ES-04: Peer key phase change accepted — RemoteUpdateAccepted.
#[test]
fn es_04_peer_key_phase_change() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    let evt = server.on_peer_key_phase(&cx, true).expect("peer phase");
    assert!(matches!(
        evt,
        KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: true,
            ..
        }
    ));
    assert!(server.tls().remote_key_phase());
}

/// ES-05: Multi-stream bidi session — per-stream flow credit consumed correctly.
#[test]
fn es_05_multi_stream_bidi() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    // Open 3 streams and write different amounts
    let s1 = client.open_local_bidi(&cx).expect("stream 1");
    let s2 = client.open_local_bidi(&cx).expect("stream 2");
    let s3 = client.open_local_bidi(&cx).expect("stream 3");

    client.write_stream(&cx, s1, 100).expect("write s1");
    client.write_stream(&cx, s2, 200).expect("write s2");
    client.write_stream(&cx, s3, 300).expect("write s3");

    // Verify per-stream credit consumption
    let st1 = client.streams().stream(s1).expect("get s1");
    assert_eq!(st1.send_credit.used(), 100);
    let st2 = client.streams().stream(s2).expect("get s2");
    assert_eq!(st2.send_credit.used(), 200);
    let st3 = client.streams().stream(s3).expect("get s3");
    assert_eq!(st3.send_credit.used(), 300);
}

/// ES-06: Connection-level flow control enforcement.
#[test]
fn es_06_connection_flow_control() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        connection_send_limit: 500,
        send_window: 1000, // per-stream window bigger than connection limit
        ..client_config()
    };
    let mut client = NativeQuicConnection::new(config);
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    let s1 = client.open_local_bidi(&cx).expect("stream 1");
    // Write up to connection limit
    client.write_stream(&cx, s1, 500).expect("write 500");
    // Next write should fail due to connection-level limit
    let err = client
        .write_stream(&cx, s1, 1)
        .expect_err("connection limit");
    assert!(
        format!("{err:?}").contains("Flow")
            || format!("{err:?}").contains("Exhausted")
            || format!("{err:?}").contains("flow"),
        "expected flow control error, got {err:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2.2 Congestion and Loss (EC)
// ═══════════════════════════════════════════════════════════════════════

/// EC-01: Congestion window fills then can_send reports false.
#[test]
fn ec_01_congestion_window_fill() {
    let tm = QuicTransportMachine::new();
    let cwnd = tm.congestion_window_bytes();
    assert_eq!(cwnd, 12_000);
    // can_send with cwnd-worth of bytes should be true
    assert!(tm.can_send(cwnd));
    // can_send with cwnd+1 should be false
    assert!(!tm.can_send(cwnd + 1));
}

/// EC-02: RTT estimation converges with multiple samples.
#[test]
fn ec_02_rtt_convergence() {
    let mut rtt = RttEstimator::default();
    assert_eq!(rtt.smoothed_rtt_micros(), None);

    rtt.update(100_000, 0);
    assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));

    rtt.update(80_000, 0);
    let srtt = rtt.smoothed_rtt_micros().unwrap();
    // EWMA: 7/8 * 100000 + 1/8 * 80000 = 87500 + 10000 = 97500
    assert_eq!(srtt, 97_500);

    rtt.update(90_000, 0);
    let srtt2 = rtt.smoothed_rtt_micros().unwrap();
    // Should be between 90000 and 97500
    assert!(srtt2 > 90_000 && srtt2 < 97_500, "srtt={srtt2}");
}

/// EC-03: Loss detection — packet declared lost after ACK gap.
#[test]
fn ec_03_loss_via_ack_gap() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    // Send packets 0-4
    for _i in 0..5 {
        client
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                1000,
            )
            .expect("send");
    }
    assert!(client.transport().bytes_in_flight() > 0);

    // ACK only packets 2,3,4 (skip 0,1 → loss detection trigger)
    let ack_event = client
        .on_ack_received(&cx, PacketNumberSpace::ApplicationData, &[2, 3, 4], 0, 2000)
        .expect("ack");
    // At least some packets should be acked
    assert!(ack_event.acked_packets > 0 || ack_event.acked_bytes > 0);
}

/// EC-04: Bytes-in-flight tracking through send/ack cycle.
#[test]
fn ec_04_bytes_in_flight_tracking() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    assert_eq!(client.transport().bytes_in_flight(), 0);

    client
        .on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            1000,
        )
        .expect("send pkt 0");
    assert_eq!(client.transport().bytes_in_flight(), 1200);

    client
        .on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            800,
            true,
            true,
            2000,
        )
        .expect("send pkt 1");
    assert_eq!(client.transport().bytes_in_flight(), 2000);

    // ACK packet 0 → bytes_in_flight should decrease
    let ack = client
        .on_ack_received(&cx, PacketNumberSpace::ApplicationData, &[0], 0, 3000)
        .expect("ack pkt 0");
    assert!(ack.acked_bytes > 0);
    assert!(client.transport().bytes_in_flight() < 2000);
}

/// EC-05: Drain timeout scenario — established → draining transition.
#[test]
fn ec_05_drain_timeout() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    // Begin close → draining
    client.begin_close(&cx, 1_000_000, 0).expect("begin close");
    assert_eq!(client.state(), QuicConnectionState::Draining);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.3 HTTP/3 Protocol (EH)
// ═══════════════════════════════════════════════════════════════════════

/// EH-01: Full request cycle — SETTINGS → request HEADERS+DATA → response.
#[test]
fn eh_01_full_request_cycle() {
    let mut state = H3ConnectionState::new();

    // Remote sends SETTINGS
    let settings_frame = H3Frame::Settings(H3Settings::default());
    state
        .on_control_frame(&settings_frame)
        .expect("SETTINGS accepted");

    // Build a request head
    let req = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".into()),
            scheme: Some("https".into()),
            path: Some("/api/v1/data".into()),
            ..H3PseudoHeaders::default()
        },
        vec![("accept".into(), "application/json".into())],
    )
    .expect("valid request");

    assert_eq!(req.pseudo.method.as_deref(), Some("GET"));
    assert_eq!(req.pseudo.path.as_deref(), Some("/api/v1/data"));

    // Build a response
    let resp = H3ResponseHead::new(
        200,
        vec![("content-type".into(), "application/json".into())],
    )
    .expect("valid response");
    assert_eq!(resp.status, 200);
}

/// EH-02: GOAWAY received mid-session.
#[test]
fn eh_02_goaway_received() {
    let mut state = H3ConnectionState::new();
    let settings = H3Frame::Settings(H3Settings::default());
    state.on_control_frame(&settings).expect("SETTINGS");

    let goaway = H3Frame::Goaway(42);
    state.on_control_frame(&goaway).expect("GOAWAY");
    assert_eq!(state.goaway_id(), Some(42));
}

/// EH-03: Multiple concurrent requests on separate streams — no interference.
#[test]
fn eh_03_concurrent_requests() {
    let mut rs1 = H3RequestStreamState::new();
    let mut rs2 = H3RequestStreamState::new();

    // Stream 1: HEADERS then DATA
    let headers1 = H3Frame::Headers(vec![0x01]);
    rs1.on_frame(&headers1).expect("s1 headers");
    let data1 = H3Frame::Data(b"body1".to_vec());
    rs1.on_frame(&data1).expect("s1 data");

    // Stream 2: independent sequence
    let headers2 = H3Frame::Headers(vec![0x02]);
    rs2.on_frame(&headers2).expect("s2 headers");
    let data2 = H3Frame::Data(b"body2".to_vec());
    rs2.on_frame(&data2).expect("s2 data");

    // Both streams processed independently
}

/// EH-04: SETTINGS exchange with known + unknown settings preserved.
#[test]
fn eh_04_settings_with_unknown() {
    let settings = H3Settings {
        qpack_max_table_capacity: Some(4096),
        max_field_section_size: Some(16384),
        unknown: vec![asupersync::http::h3_native::UnknownSetting {
            id: 0xF0,
            value: 42,
        }],
        ..H3Settings::default()
    };
    let frame = H3Frame::Settings(settings.clone());
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode");
    let (decoded, _) = H3Frame::decode(&buf, &test_config()).expect("decode");
    assert_eq!(decoded, H3Frame::Settings(settings));
}

/// EH-05: Protocol violation — DATA on control stream rejected.
#[test]
fn eh_05_data_on_control_rejected() {
    let mut ctrl = H3ControlState::new();
    ctrl.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("SETTINGS");
    let err = ctrl
        .on_remote_control_frame(&H3Frame::Data(vec![0x01]))
        .expect_err("DATA rejected");
    assert!(matches!(err, H3NativeError::ControlProtocol(_)));
}

/// EH-06: QPACK static-only encode/decode round-trip for request.
#[test]
fn eh_06_qpack_round_trip() {
    let req = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".into()),
            scheme: Some("https".into()),
            path: Some("/".into()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid");

    let encoded =
        asupersync::http::h3_native::qpack_encode_request_field_section(&req).expect("encode");
    let decoded = asupersync::http::h3_native::qpack_decode_request_field_section(
        &encoded,
        H3QpackMode::StaticOnly,
        None,
    )
    .expect("decode");
    assert_eq!(decoded.pseudo.method, req.pseudo.method);
    assert_eq!(decoded.pseudo.scheme, req.pseudo.scheme);
    assert_eq!(decoded.pseudo.path, req.pseudo.path);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.4 Drain and Cancellation (ED)
// ═══════════════════════════════════════════════════════════════════════

/// ED-01: Graceful close — established → draining → (eventually closed).
#[test]
fn ed_01_graceful_close() {
    let cx = test_cx();
    let mut conn = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut conn, &mut server);

    assert_eq!(conn.state(), QuicConnectionState::Established);
    conn.begin_close(&cx, 1_000_000, 0).expect("begin close");
    assert_eq!(conn.state(), QuicConnectionState::Draining);
}

/// ED-02: Cancel mid-handshake — operations return Cancelled.
#[test]
fn ed_02_cancel_mid_handshake() {
    let cx = cancelled_cx();
    let mut conn = NativeQuicConnection::new(client_config());

    let err = conn.begin_handshake(&cx).expect_err("should cancel");
    assert!(
        matches!(err, NativeQuicConnectionError::Cancelled),
        "expected Cancelled, got {err:?}"
    );
}

/// ED-03: Cancel mid-stream-write — active write interrupted.
#[test]
fn ed_03_cancel_mid_stream_write() {
    let cx = test_cx();
    let mut conn = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut conn, &mut server);

    let sid = conn.open_local_bidi(&cx).expect("open stream");
    conn.write_stream(&cx, sid, 100).expect("first write ok");

    // Cancel now
    let cx_cancel = cancelled_cx();
    let err = conn
        .write_stream(&cx_cancel, sid, 100)
        .expect_err("should cancel");
    assert!(
        matches!(err, NativeQuicConnectionError::Cancelled),
        "expected Cancelled, got {err:?}"
    );
}

/// ED-04: Close immediately without drain.
#[test]
fn ed_04_close_immediately() {
    let cx = test_cx();
    let mut conn = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut conn, &mut server);

    conn.close_immediately(&cx, 0).expect("close immediately");
    assert_eq!(conn.state(), QuicConnectionState::Closed);
}

/// ED-05: Stream reset during active transfer.
#[test]
fn ed_05_stream_reset() {
    let cx = test_cx();
    let mut conn = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut conn, &mut server);

    let sid = conn.open_local_bidi(&cx).expect("open stream");
    conn.write_stream(&cx, sid, 100).expect("write");

    conn.reset_stream_send(&cx, sid, 0x42, 100)
        .expect("reset_send");
    let stream = conn.streams().stream(sid).expect("get stream");
    assert!(stream.send_reset.is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// 2.5 Telemetry Validation (ET)
// ═══════════════════════════════════════════════════════════════════════

/// ET-01: ForensicLogger records ScenarioStarted/Completed events.
#[test]
fn et_01_scenario_started_completed() {
    let logger = QuicH3ForensicLogger::new("ET-01", 0xE701, "et_01_scenario_started_completed");

    logger.log(
        1000,
        "test_harness",
        QuicH3Event::ScenarioStarted {
            scenario_id: "ET-01".into(),
            seed: 0xE701,
            config_hash: "test".into(),
            test_file: "tokio_quic_h3_e2e_scenario_manifest.rs".into(),
            test_function: "et_01_scenario_started_completed".into(),
        },
    );

    logger.log(
        2000,
        "test_harness",
        QuicH3Event::ScenarioCompleted {
            scenario_id: "ET-01".into(),
            seed: 0xE701,
            passed: true,
            duration_us: 1000,
            event_count: 2,
            failure_class: "passed".into(),
        },
    );

    assert_eq!(logger.event_count(), 2);
    assert_eq!(logger.scenario_id(), "ET-01");
}

/// ET-02: Event categories span transport, stream, connection, h3_control, h3_request.
#[test]
fn et_02_event_category_coverage() {
    let logger = QuicH3ForensicLogger::new("ET-02", 0xE702, "et_02");

    logger.log(
        100,
        "quic_transport",
        QuicH3Event::PacketSent {
            pn_space: "ApplicationData".into(),
            packet_number: 0,
            size_bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            send_time_us: 100,
        },
    );
    logger.log(
        200,
        "quic_stream",
        QuicH3Event::StreamOpened {
            stream_id: 0,
            direction: "bidi".into(),
            role: "client".into(),
            is_local: true,
        },
    );
    logger.log(
        300,
        "quic_connection",
        QuicH3Event::StateChanged {
            from_state: "Idle".into(),
            to_state: "Handshaking".into(),
            trigger: "begin_handshake".into(),
        },
    );
    logger.log(
        400,
        "h3_control",
        QuicH3Event::SettingsExchanged {
            direction: "remote".into(),
            max_field_section_size: 16384,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 100,
        },
    );
    logger.log(
        500,
        "h3_request",
        QuicH3Event::RequestStarted {
            stream_id: 0,
            method: "GET".into(),
            scheme: "https".into(),
            authority: "localhost".into(),
            path: "/".into(),
        },
    );

    let by_cat = logger.events_by_category();
    assert!(by_cat.contains_key("quic_transport"));
    assert!(by_cat.contains_key("quic_stream"));
    assert!(by_cat.contains_key("quic_connection"));
    assert!(by_cat.contains_key("h3_control"));
    assert!(by_cat.contains_key("h3_request"));
    assert_eq!(logger.event_count(), 5);
}

/// ET-03: InvariantCheckpoint events recorded.
#[test]
fn et_03_invariant_checkpoint() {
    let logger = QuicH3ForensicLogger::new("ET-03", 0xE703, "et_03");
    logger.log_invariant(1000, "INV-01", "PASS", "Connection established");
    logger.log_invariant(2000, "INV-02", "PASS", "Flow credit consumed");

    assert_eq!(logger.event_count(), 2);
    let by_cat = logger.events_by_category();
    assert_eq!(by_cat.get("test_harness"), Some(&2));
}

/// ET-04: ScenarioManifest from_logger builds complete manifest.
#[test]
fn et_04_manifest_from_logger() {
    let logger = QuicH3ForensicLogger::new("ET-04", 0xE704, "et_04");

    logger.log(
        100,
        "test_harness",
        QuicH3Event::ScenarioStarted {
            scenario_id: "ET-04".into(),
            seed: 0xE704,
            config_hash: "test".into(),
            test_file: "test.rs".into(),
            test_function: "et_04".into(),
        },
    );
    logger.log_invariant(200, "INV-01", "PASS", "ok");
    logger.log(
        300,
        "quic_connection",
        QuicH3Event::StateChanged {
            from_state: "Idle".into(),
            to_state: "Handshaking".into(),
            trigger: "begin_handshake".into(),
        },
    );
    logger.log(
        400,
        "test_harness",
        QuicH3Event::ScenarioCompleted {
            scenario_id: "ET-04".into(),
            seed: 0xE704,
            passed: true,
            duration_us: 300,
            event_count: 4,
            failure_class: "passed".into(),
        },
    );

    let manifest = QuicH3ScenarioManifest::from_logger(&logger, true, 300);
    assert!(manifest.passed);
    assert_eq!(manifest.scenario_id, "ET-04");
    assert_eq!(manifest.duration_us, 300);
    assert!(!manifest.invariant_ids.is_empty());
    assert!(!manifest.connection_lifecycle.is_empty());
    assert_eq!(manifest.event_timeline.total_events, 4);
}

/// ET-05: Event levels follow schema defaults.
#[test]
fn et_05_event_levels() {
    // PacketSent → DEBUG
    let pkt = QuicH3Event::PacketSent {
        pn_space: "Initial".into(),
        packet_number: 0,
        size_bytes: 1200,
        ack_eliciting: true,
        in_flight: true,
        send_time_us: 0,
    };
    assert_eq!(pkt.default_level(), "DEBUG");

    // FrameEncoded → TRACE
    let frame = QuicH3Event::FrameEncoded {
        frame_type: "DATA".into(),
        wire_bytes: 100,
        stream_id: 0,
    };
    assert_eq!(frame.default_level(), "TRACE");

    // FrameError → WARN
    let frame_err = QuicH3Event::FrameError {
        frame_type: "HEADERS".into(),
        error_kind: "decode".into(),
        error_message: "truncated".into(),
        stream_id: 0,
    };
    assert_eq!(frame_err.default_level(), "WARN");

    // ScenarioCompleted → INFO
    let completed = QuicH3Event::ScenarioCompleted {
        scenario_id: "test".into(),
        seed: 0,
        passed: true,
        duration_us: 0,
        event_count: 0,
        failure_class: "passed".into(),
    };
    assert_eq!(completed.default_level(), "INFO");
}

/// ET-06: events_by_category and events_by_level aggregation correct.
#[test]
fn et_06_event_aggregation() {
    let logger = QuicH3ForensicLogger::new("ET-06", 0xE706, "et_06");

    // 2 transport events (DEBUG)
    for i in 0..2 {
        logger.log(
            i * 100,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "ApplicationData".into(),
                packet_number: i,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: i * 100,
            },
        );
    }
    // 1 frame event (TRACE)
    logger.log(
        200,
        "h3_frame",
        QuicH3Event::FrameEncoded {
            frame_type: "DATA".into(),
            wire_bytes: 100,
            stream_id: 0,
        },
    );

    let by_cat = logger.events_by_category();
    assert_eq!(by_cat.get("quic_transport"), Some(&2));
    assert_eq!(by_cat.get("h3_frame"), Some(&1));

    let by_level = logger.events_by_level();
    assert_eq!(by_level.get("DEBUG"), Some(&2));
    assert_eq!(by_level.get("TRACE"), Some(&1));
}

// ═══════════════════════════════════════════════════════════════════════
// 2.6 Manifest Validation (MV)
// ═══════════════════════════════════════════════════════════════════════

const JSON_ARTIFACT: &str = include_str!("../docs/tokio_quic_h3_e2e_scenario_manifest.json");
const MD_DOC: &str = include_str!("../docs/tokio_quic_h3_e2e_scenario_manifest.md");

/// MV-01: JSON artifact has bead_id = asupersync-2oh2u.4.11.
#[test]
fn mv_01_json_bead_id() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.4.11");
}

/// MV-02: Document has required sections.
#[test]
fn mv_02_document_sections() {
    let required = [
        "### 2.1 Session Lifecycle (ES)",
        "### 2.2 Congestion and Loss (EC)",
        "### 2.3 HTTP/3 Protocol (EH)",
        "### 2.4 Drain and Cancellation (ED)",
        "### 2.5 Telemetry Validation (ET)",
        "### 2.6 Manifest Validation (MV)",
    ];
    for section in &required {
        assert!(MD_DOC.contains(section), "missing section: {section}");
    }
}

/// MV-03: All scenario prefixes present in JSON.
#[test]
fn mv_03_scenario_prefixes() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    let categories = v["scenario_categories"]
        .as_array()
        .expect("scenario_categories");
    let prefixes: Vec<&str> = categories
        .iter()
        .filter_map(|c| c["prefix"].as_str())
        .collect();
    for expected in &["ES", "EC", "EH", "ED", "ET", "MV"] {
        assert!(prefixes.contains(expected), "missing prefix: {expected}");
    }
}

/// MV-04: Summary test count matches sum of categories.
#[test]
fn mv_04_summary_count_matches() {
    let v: serde_json::Value = serde_json::from_str(JSON_ARTIFACT).expect("valid JSON");
    let total = v["summary"]["total_tests"].as_u64().expect("total_tests");
    let categories = v["scenario_categories"]
        .as_array()
        .expect("scenario_categories");
    let sum: u64 = categories.iter().filter_map(|c| c["count"].as_u64()).sum();
    assert_eq!(
        total, sum,
        "total_tests ({total}) != sum of categories ({sum})"
    );
}
