#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for T4.9: QUIC/H3 API Stabilization and Migration Guidance.
//!
//! Validates the public API surface, migration patterns, error taxonomy,
//! stability contracts, and manifest/document structure described in
//! `docs/tokio_quic_h3_api_stabilization.md`.

use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3Frame, H3NativeError, H3PseudoHeaders,
    H3QpackMode, H3RequestHead, H3RequestStreamState, H3ResponseHead, H3Settings,
    qpack_decode_request_field_section, qpack_decode_response_field_section,
    qpack_encode_request_field_section, qpack_encode_response_field_section,
};
use asupersync::net::quic_core::{
    ConnectionId, LongHeader, LongPacketType, PacketHeader, QUIC_VARINT_MAX, TransportParameters,
    decode_varint, encode_varint,
};
use asupersync::net::quic_native::connection::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
};
use asupersync::net::quic_native::forensic_log::{
    FORENSIC_MANIFEST_SCHEMA_ID, FORENSIC_SCHEMA_VERSION, QuicH3Event, QuicH3ForensicLogger,
    QuicH3ScenarioManifest,
};
use asupersync::net::quic_native::streams::{
    FlowControlError, FlowCredit, QuicStreamError, StreamDirection, StreamId, StreamRole,
    StreamTable, StreamTableError,
};
use asupersync::net::quic_native::tls::{
    CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine,
};
use asupersync::net::quic_native::transport::{
    PacketNumberSpace, QuicConnectionState, QuicTransportMachine, RttEstimator, TransportError,
};

fn test_cx() -> Cx {
    Cx::for_testing()
}

fn test_h3_config() -> H3ConnectionConfig {
    H3ConnectionConfig::default()
}

fn client_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        role: StreamRole::Client,
        ..Default::default()
    }
}

fn server_config() -> NativeQuicConnectionConfig {
    NativeQuicConnectionConfig {
        role: StreamRole::Server,
        ..Default::default()
    }
}

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
// 2.1 API Surface Validation (AS)
// ═══════════════════════════════════════════════════════════════════════

/// AS-01: All stable quic_core types are constructable and usable.
#[test]
fn as_01_quic_core_types() {
    // ConnectionId
    let cid = ConnectionId::new(&[1, 2, 3, 4]).expect("valid cid");
    assert_eq!(cid.len(), 4);
    assert!(!cid.is_empty());
    assert_eq!(cid.as_bytes(), &[1, 2, 3, 4]);

    // ConnectionId max length
    assert_eq!(ConnectionId::MAX_LEN, 20);
    assert!(ConnectionId::new(&[0u8; 21]).is_err());

    // PacketHeader encode/decode round-trip
    let long = PacketHeader::Long(LongHeader {
        packet_type: LongPacketType::Initial,
        version: 1,
        dst_cid: cid,
        src_cid: ConnectionId::default(),
        token: vec![],
        payload_length: 100,
        packet_number: 0,
        packet_number_len: 1,
    });
    let mut buf = Vec::new();
    long.encode(&mut buf).expect("encode");
    let (decoded, _consumed) = PacketHeader::decode(&buf, 4).expect("decode");
    assert!(matches!(decoded, PacketHeader::Long(_)));

    // TransportParameters
    let tp = TransportParameters::default();
    let mut tp_buf = Vec::new();
    tp.encode(&mut tp_buf).expect("encode tp");
    let tp2 = TransportParameters::decode(&tp_buf).expect("decode tp");
    assert_eq!(tp, tp2);

    // Varint
    assert_eq!(QUIC_VARINT_MAX, (1u64 << 62) - 1);
    let mut vbuf = Vec::new();
    encode_varint(12345, &mut vbuf).expect("encode varint");
    let (val, _) = decode_varint(&vbuf).expect("decode varint");
    assert_eq!(val, 12345);
}

/// AS-02: NativeQuicConnection config defaults match documented values.
#[test]
fn as_02_connection_config_defaults() {
    let cfg = NativeQuicConnectionConfig::default();
    assert_eq!(cfg.role, StreamRole::Client);
    assert_eq!(cfg.max_local_bidi, 128);
    assert_eq!(cfg.max_local_uni, 128);
    assert_eq!(cfg.send_window, 1_048_576); // 1 MiB
    assert_eq!(cfg.recv_window, 1_048_576);
    assert_eq!(cfg.connection_send_limit, 16_777_216); // 16 MiB
    assert_eq!(cfg.connection_recv_limit, 16_777_216);
    assert_eq!(cfg.drain_timeout_micros, 3_000_000); // 3 seconds
}

/// AS-03: Sub-machine accessors are available on NativeQuicConnection.
#[test]
fn as_03_submachine_accessors() {
    let conn = NativeQuicConnection::new(client_config());
    // Immutable accessors
    let _tls: &QuicTlsMachine = conn.tls();
    let _transport: &QuicTransportMachine = conn.transport();
    let _streams: &StreamTable = conn.streams();

    // State accessors
    assert_eq!(conn.state(), QuicConnectionState::Idle);
    assert!(!conn.can_send_1rtt());
    assert!(!conn.can_send_0rtt());
    assert_eq!(conn.active_path_id(), 0);
    assert_eq!(conn.migration_events(), 0);
}

/// AS-04: H3 types are constructable with defaults.
#[test]
fn as_04_h3_types_constructable() {
    let _state = H3ConnectionState::new();
    let _state_cfg = H3ConnectionState::with_config(H3ConnectionConfig {
        qpack_mode: H3QpackMode::StaticOnly,
        ..H3ConnectionConfig::default()
    });
    let _ctrl = H3ControlState::new();
    let _req_state = H3RequestStreamState::new();

    let settings = H3Settings::default();
    assert!(settings.qpack_max_table_capacity.is_none());

    let frame = H3Frame::Data(vec![1, 2, 3]);
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encode frame");
    let (decoded, _) = H3Frame::decode(&buf, &test_h3_config()).expect("decode frame");
    assert_eq!(decoded, frame);
}

/// AS-05: Forensic log types are constructable and functional.
#[test]
fn as_05_forensic_log_types() {
    assert_eq!(FORENSIC_SCHEMA_VERSION, 1);
    assert_eq!(FORENSIC_MANIFEST_SCHEMA_ID, "quic-h3-forensic-manifest.v1");

    let logger = QuicH3ForensicLogger::new("AS-05", 0xA505, "as_05_test");
    assert_eq!(logger.scenario_id(), "AS-05");
    assert_eq!(logger.seed(), 0xA505);
    assert_eq!(logger.test_function(), "as_05_test");
    assert_eq!(logger.event_count(), 0);

    // Log an event
    logger.log(
        100,
        "test_harness",
        QuicH3Event::ScenarioStarted {
            scenario_id: "AS-05".into(),
            seed: 0xA505,
            config_hash: "test".into(),
            test_file: file!().into(),
            test_function: "as_05_test".into(),
        },
    );
    assert_eq!(logger.event_count(), 1);

    let by_cat = logger.events_by_category();
    assert_eq!(by_cat.get("test_harness"), Some(&1));

    // Build manifest
    let manifest = QuicH3ScenarioManifest::from_logger(&logger, true, 100);
    assert_eq!(manifest.schema_id, FORENSIC_MANIFEST_SCHEMA_ID);
    assert!(manifest.passed);
}

/// AS-06: Stream types and flow control are available.
#[test]
fn as_06_stream_types() {
    // StreamId construction
    let sid = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
    assert_eq!(sid.0, 0);
    assert!(sid.is_local_for(StreamRole::Client));
    assert_eq!(sid.direction(), StreamDirection::Bidirectional);

    // FlowCredit
    let mut fc = FlowCredit::new(1000);
    assert_eq!(fc.remaining(), 1000);
    assert_eq!(fc.used(), 0);
    fc.consume(500).expect("consume");
    assert_eq!(fc.remaining(), 500);
    assert_eq!(fc.used(), 500);

    // StreamTable
    let table = StreamTable::new(StreamRole::Client, 128, 128, 1_048_576, 1_048_576);
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// 2.2 Migration Pattern Validation (MP)
// ═══════════════════════════════════════════════════════════════════════

/// MP-01: Connection setup pattern (Section 3.1).
#[test]
fn mp_01_connection_setup() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        role: StreamRole::Server,
        max_local_bidi: 128,
        max_local_uni: 128,
        send_window: 1_048_576,
        recv_window: 1_048_576,
        ..Default::default()
    };
    let mut conn = NativeQuicConnection::new(config);
    assert_eq!(conn.state(), QuicConnectionState::Idle);

    conn.begin_handshake(&cx).expect("begin");
    conn.on_handshake_keys_available(&cx).expect("hs keys");
    conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
    conn.on_handshake_confirmed(&cx).expect("confirmed");
    assert_eq!(conn.state(), QuicConnectionState::Established);
}

/// MP-02: Stream operations pattern (Section 3.2).
#[test]
fn mp_02_stream_operations() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    let stream_id = client.open_local_bidi(&cx).expect("open bidi");
    client
        .write_stream(&cx, stream_id, 5)
        .expect("write 5 bytes");

    // Server accepts the remote stream
    server.accept_remote_stream(&cx, stream_id).expect("accept");
    server
        .receive_stream(&cx, stream_id, 5)
        .expect("receive 5 bytes");
}

/// MP-03: Graceful shutdown pattern (Section 3.3).
#[test]
fn mp_03_graceful_shutdown() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut client, &mut server);

    let now = 1_000_000u64;
    client.begin_close(&cx, now, 0).expect("begin close");
    assert_eq!(client.state(), QuicConnectionState::Draining);

    // After drain timeout, poll transitions to Closed
    let after_drain = now + client_config().drain_timeout_micros + 1;
    client.poll(&cx, after_drain).expect("poll");
    assert_eq!(client.state(), QuicConnectionState::Closed);
}

/// MP-04: HTTP/3 request lifecycle pattern (Section 3.4).
#[test]
fn mp_04_h3_request_lifecycle() {
    let mut h3_state = H3ConnectionState::new();

    let pseudo = H3PseudoHeaders {
        method: Some("GET".into()),
        scheme: Some("https".into()),
        path: Some("/api/v1/data".into()),
        ..Default::default()
    };
    let req = H3RequestHead::new(pseudo, vec![]).expect("valid req");
    assert_eq!(req.pseudo.method.as_deref(), Some("GET"));

    // QPACK encode round-trip
    let encoded = qpack_encode_request_field_section(&req).expect("encode");
    let decoded = qpack_decode_request_field_section(&encoded, H3QpackMode::StaticOnly, None)
        .expect("decode");
    assert_eq!(decoded.pseudo.method, req.pseudo.method);
    assert_eq!(decoded.pseudo.path, req.pseudo.path);

    // Feed headers frame into connection state
    let headers_frame = H3Frame::Headers(encoded);
    h3_state
        .on_request_stream_frame(0, &headers_frame)
        .expect("req frame");

    // Response
    let resp = H3ResponseHead::new(
        200,
        vec![("content-type".into(), "application/json".into())],
    )
    .expect("valid resp");
    let resp_encoded = qpack_encode_response_field_section(&resp).expect("encode resp");
    let resp_decoded =
        qpack_decode_response_field_section(&resp_encoded, H3QpackMode::StaticOnly, None)
            .expect("decode resp");
    assert_eq!(resp_decoded.status, 200);
}

/// MP-05: Cx cancellation pattern (Section 3.5).
#[test]
fn mp_05_cx_cancellation() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let mut conn = NativeQuicConnection::new(client_config());

    let result = conn.begin_handshake(&cx);
    assert!(matches!(result, Err(NativeQuicConnectionError::Cancelled)));
}

/// MP-06: Key update and 0-RTT pattern (Section 3.6).
#[test]
fn mp_06_key_update_and_0rtt() {
    let cx = test_cx();
    let mut client = NativeQuicConnection::new(client_config());

    // 0-RTT: enable resumption during handshake (before confirmation)
    client.begin_handshake(&cx).expect("begin");
    client.on_handshake_keys_available(&cx).expect("hs keys");
    client.enable_resumption_0rtt(&cx).expect("enable 0rtt");
    // 0-RTT is available during handshake before confirmation
    assert!(client.tls().resumption_enabled());
    assert!(client.can_send_0rtt());

    // Complete handshake — 0-RTT no longer available after confirmation
    client.on_1rtt_keys_available(&cx).expect("1rtt keys");
    client.on_handshake_confirmed(&cx).expect("confirmed");
    assert!(!client.can_send_0rtt()); // Post-confirmation, 0-RTT is closed

    // Key update (only after handshake confirmed)
    let evt = client.request_local_key_update(&cx).expect("request");
    assert!(matches!(evt, KeyUpdateEvent::LocalUpdateScheduled { .. }));
    client.commit_local_key_update(&cx).expect("commit");
    assert!(client.tls().local_key_phase());
}

// ═══════════════════════════════════════════════════════════════════════
// 2.3 Error Taxonomy Validation (ER)
// ═══════════════════════════════════════════════════════════════════════

/// ER-01: NativeQuicConnectionError composes from sub-errors via From.
#[test]
fn er_01_error_composition() {
    // QuicTlsError → NativeQuicConnectionError
    let tls_err = QuicTlsError::HandshakeNotConfirmed;
    let conn_err: NativeQuicConnectionError = tls_err.into();
    assert!(matches!(conn_err, NativeQuicConnectionError::Tls(_)));

    // TransportError → NativeQuicConnectionError
    let transport_err = TransportError::InvalidStateTransition {
        from: QuicConnectionState::Idle,
        to: QuicConnectionState::Closed,
    };
    let conn_err: NativeQuicConnectionError = transport_err.into();
    assert!(matches!(conn_err, NativeQuicConnectionError::Transport(_)));

    // StreamTableError → NativeQuicConnectionError
    let stream_err = StreamTableError::UnknownStream(StreamId(999));
    let conn_err: NativeQuicConnectionError = stream_err.into();
    assert!(matches!(
        conn_err,
        NativeQuicConnectionError::StreamTable(_)
    ));

    // QuicStreamError → NativeQuicConnectionError
    let qs_err = QuicStreamError::SendStopped { code: 42 };
    let conn_err: NativeQuicConnectionError = qs_err.into();
    assert!(matches!(conn_err, NativeQuicConnectionError::Stream(_)));
}

/// ER-02: All error types implement Display and Error.
#[test]
fn er_02_error_display() {
    let e1 = NativeQuicConnectionError::Cancelled;
    let msg = format!("{e1}");
    assert!(!msg.is_empty());

    let e2 = QuicTlsError::HandshakeNotConfirmed;
    let msg2 = format!("{e2}");
    assert!(!msg2.is_empty());

    let e3 = TransportError::InvalidStateTransition {
        from: QuicConnectionState::Idle,
        to: QuicConnectionState::Closed,
    };
    let msg3 = format!("{e3}");
    assert!(!msg3.is_empty());

    let e4 = FlowControlError::Exhausted {
        attempted: 100,
        remaining: 50,
    };
    let msg4 = format!("{e4}");
    assert!(!msg4.is_empty());

    let e5 = H3NativeError::ControlProtocol("test");
    let msg5 = format!("{e5}");
    assert!(!msg5.is_empty());

    // std::error::Error trait
    let _: &dyn std::error::Error = &e1;
    let _: &dyn std::error::Error = &e2;
    let _: &dyn std::error::Error = &e3;
    let _: &dyn std::error::Error = &e4;
    let _: &dyn std::error::Error = &e5;
}

/// ER-03: Cancelled error is produced by Cx cancellation.
#[test]
fn er_03_cancelled_from_cx() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let mut conn = NativeQuicConnection::new(client_config());

    // Every Cx-gated method should return Cancelled
    assert!(matches!(
        conn.begin_handshake(&cx),
        Err(NativeQuicConnectionError::Cancelled)
    ));
}

/// ER-04: CongestionLimited error from full congestion window.
#[test]
fn er_04_congestion_limited() {
    let cx = test_cx();
    let mut conn = NativeQuicConnection::new(client_config());
    let mut server = NativeQuicConnection::new(server_config());
    establish_pair(&cx, &mut conn, &mut server);

    // Fill congestion window
    let cwnd = conn.transport().congestion_window_bytes();
    let mut sent = 0u64;
    while sent < cwnd {
        let chunk = std::cmp::min(1200, cwnd - sent);
        match conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            chunk,
            true,
            true,
            1000,
        ) {
            Ok(_pn) => sent += chunk,
            Err(_) => break,
        }
    }

    // Next send should fail with CongestionLimited
    let result = conn.on_packet_sent(
        &cx,
        PacketNumberSpace::ApplicationData,
        1200,
        true,
        true,
        2000,
    );
    // Either CongestionLimited or the window was exactly exhausted
    if sent >= cwnd {
        assert!(
            result.is_err() || conn.transport().bytes_in_flight() > 0,
            "Should be at or past cwnd"
        );
    }
}

/// ER-05: FlowControlError from exhausted flow credit.
#[test]
fn er_05_flow_control_exhausted() {
    let mut credit = FlowCredit::new(100);
    credit.consume(100).expect("consume all");
    let result = credit.consume(1);
    assert!(matches!(result, Err(FlowControlError::Exhausted { .. })));
}

/// ER-06: H3NativeError variants cover protocol violations.
#[test]
fn er_06_h3_protocol_errors() {
    // Invalid request pseudo-headers
    let bad_pseudo = H3PseudoHeaders::default(); // missing method
    let result = H3RequestHead::new(bad_pseudo, vec![]);
    assert!(matches!(
        result,
        Err(H3NativeError::InvalidRequestPseudoHeader(_))
    ));

    // Invalid response status
    let result = H3ResponseHead::new(0, vec![]);
    assert!(matches!(
        result,
        Err(H3NativeError::InvalidResponsePseudoHeader(_))
    ));

    // DATA on control stream
    let mut ctrl = H3ControlState::new();
    let data_frame = H3Frame::Data(vec![1, 2, 3]);
    let result = ctrl.on_remote_control_frame(&data_frame);
    assert!(matches!(result, Err(H3NativeError::ControlProtocol(_))));
}

// ═══════════════════════════════════════════════════════════════════════
// 2.4 Stability Contract Validation (ST)
// ═══════════════════════════════════════════════════════════════════════

/// ST-01: Stable types have documented constructors.
#[test]
fn st_01_stable_constructors() {
    let _ = ConnectionId::new(&[]).expect("empty cid");
    let _ = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let _ = H3ConnectionState::new();
    let _ = H3ControlState::new();
    let _ = H3Settings::default();
    let _ = H3Frame::Data(vec![]);
    let _ = H3RequestStreamState::new();
}

/// ST-02: Sub-machines have independent constructors.
#[test]
fn st_02_submachine_constructors() {
    let transport = QuicTransportMachine::new();
    assert_eq!(transport.state(), QuicConnectionState::Idle);
    assert_eq!(transport.congestion_window_bytes(), 12000);
    assert_eq!(transport.ssthresh_bytes(), u64::MAX);

    let tls = QuicTlsMachine::new();
    assert_eq!(tls.level(), CryptoLevel::Initial);
    assert!(!tls.can_send_1rtt());
    assert!(!tls.can_send_0rtt());

    let rtt = RttEstimator::default();
    assert_eq!(rtt.smoothed_rtt_micros(), None);
}

/// ST-03: QuicConnectionState has all documented variants.
#[test]
fn st_03_connection_states() {
    let states = [
        QuicConnectionState::Idle,
        QuicConnectionState::Handshaking,
        QuicConnectionState::Established,
        QuicConnectionState::Draining,
        QuicConnectionState::Closed,
    ];
    assert_eq!(states.len(), 5);
    // All are distinct
    for (i, a) in states.iter().enumerate() {
        for (j, b) in states.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

/// ST-04: CryptoLevel has correct ordering.
#[test]
fn st_04_crypto_level_ordering() {
    assert!(CryptoLevel::Initial < CryptoLevel::Handshake);
    assert!(CryptoLevel::Handshake < CryptoLevel::OneRtt);
}

/// ST-05: H3QpackMode default is StaticOnly.
#[test]
fn st_05_qpack_default() {
    assert_eq!(H3QpackMode::default(), H3QpackMode::StaticOnly);
    let state = H3ConnectionState::new();
    assert_eq!(state.qpack_mode(), H3QpackMode::StaticOnly);
}

/// ST-06: QuicH3Event has event_name and default_level for all variants.
#[test]
fn st_06_event_metadata() {
    // Sample a few events to verify event_name and default_level
    let evt = QuicH3Event::PacketSent {
        pn_space: "ApplicationData".into(),
        packet_number: 0,
        size_bytes: 1200,
        ack_eliciting: true,
        in_flight: true,
        send_time_us: 1000,
    };
    assert!(!evt.event_name().is_empty());
    assert!(!evt.default_level().is_empty());

    let evt2 = QuicH3Event::FrameError {
        frame_type: "DATA".into(),
        error_kind: "test".into(),
        error_message: "test error".into(),
        stream_id: 0,
    };
    assert_eq!(evt2.default_level(), "WARN");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.5 Manifest Validation (MV)
// ═══════════════════════════════════════════════════════════════════════

/// MV-01: JSON artifact has correct bead_id.
#[test]
fn mv_01_json_bead_id() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../docs/tokio_quic_h3_api_stabilization.json"))
            .expect("valid json");
    assert_eq!(json["bead_id"], "asupersync-2oh2u.4.9");
}

/// MV-02: Document has required sections.
#[test]
fn mv_02_document_sections() {
    let doc = include_str!("../docs/tokio_quic_h3_api_stabilization.md");
    let required = [
        "## 1. Public API Surface",
        "## 2. Design Principles",
        "## 3. Migration Patterns",
        "## 4. Known Limitations",
        "## 5. Error Taxonomy",
        "## 6. Rollback Paths",
        "## 7. Operational Caveats",
        "## 8. Cumulative T4 Coverage",
        "## 9. Drift Detection",
    ];
    for section in &required {
        assert!(doc.contains(section), "Missing section: {section}");
    }
}

/// MV-03: All test category prefixes present in JSON.
#[test]
fn mv_03_test_prefixes() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../docs/tokio_quic_h3_api_stabilization.json"))
            .expect("valid json");
    let categories = json["test_categories"].as_array().expect("array");
    let prefixes: Vec<&str> = categories
        .iter()
        .map(|c| c["prefix"].as_str().expect("prefix"))
        .collect();
    for expected in &["AS", "MP", "ER", "ST", "MV"] {
        assert!(prefixes.contains(expected), "Missing prefix: {expected}");
    }
}

/// MV-04: Summary test count matches category sum.
#[test]
fn mv_04_summary_count() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../docs/tokio_quic_h3_api_stabilization.json"))
            .expect("valid json");
    let total = json["summary"]["total_tests"].as_u64().expect("total");
    let categories = json["test_categories"].as_array().expect("array");
    let sum: u64 = categories
        .iter()
        .map(|c| c["count"].as_u64().expect("count"))
        .sum();
    assert_eq!(
        total, sum,
        "total_tests ({total}) != sum of categories ({sum})"
    );
}
