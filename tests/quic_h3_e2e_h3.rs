//! QH3-E4: HTTP/3 control/request lifecycle and GOAWAY E2E tests.
//!
//! This test file covers the full H3 protocol lifecycle including request-response
//! cycles, concurrent requests, SETTINGS exchange, GOAWAY stream acceptance
//! boundaries, CANCEL_PUSH/MAX_PUSH_ID handling, error paths, request stream
//! state transitions, and QPACK static table planning.
//!
//! All tests are synchronous (no tokio, no async) and use DetRng for
//! reproducible deterministic seeds.

#[cfg(feature = "http3")]
use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3Frame, H3NativeError, H3PseudoHeaders,
    H3QpackMode, H3RequestHead, H3RequestStreamState, H3ResponseHead, H3Settings, QpackFieldPlan,
    qpack_decode_field_section, qpack_encode_field_section, qpack_plan_to_header_fields,
    qpack_static_plan_for_request, qpack_static_plan_for_response,
};
#[cfg(feature = "http3")]
use asupersync::http::h3_native::{
    qpack_encode_request_field_section, qpack_encode_response_field_section,
};
#[cfg(feature = "http3")]
use asupersync::http::h3_quic::{
    H3_REQUEST_CANCELLED, NativeH3Event, NativeH3Session, NativeH3SessionError,
};
#[cfg(all(feature = "http3", feature = "test-internals"))]
use asupersync::net::quic_native::drop_app_data_packet;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, QuicConnectionState, StreamDirection,
    StreamRole,
};
#[cfg(feature = "http3")]
use asupersync::net::quic_native::{QuicConnection, establish_loopback, pump_app_data};
use asupersync::types::Time;
use asupersync::util::DetRng;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers (replicated from quic_h3_e2e.rs)
// ---------------------------------------------------------------------------

/// Build a test Cx with infinite budget and no cancellation.
fn test_cx() -> Cx {
    Cx::for_testing()
}

fn test_config() -> H3ConnectionConfig {
    H3ConnectionConfig::default()
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string length must be even");
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex nibble at {i}"));
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex nibble at {}", i + 1));
        out.push(((hi << 4) | lo) as u8);
    }
    out
}

fn fixture_plan_from_json(value: &Value) -> Vec<QpackFieldPlan> {
    let entries = value
        .as_array()
        .expect("expected fixture expected_plan to be array");
    entries
        .iter()
        .map(|entry| {
            let kind = entry
                .get("kind")
                .and_then(Value::as_str)
                .expect("expected plan entry kind");
            match kind {
                "static" => QpackFieldPlan::StaticIndex(
                    entry
                        .get("index")
                        .and_then(Value::as_u64)
                        .expect("expected static index"),
                ),
                "literal" => QpackFieldPlan::Literal {
                    name: entry
                        .get("name")
                        .and_then(Value::as_str)
                        .expect("expected literal name")
                        .to_string(),
                    value: entry
                        .get("value")
                        .and_then(Value::as_str)
                        .expect("expected literal value")
                        .to_string(),
                },
                other => panic!("unknown expected_plan kind: {other}"),
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
enum H3HarnessEvent {
    Control(H3Frame),
    RequestFrame { stream_id: u64, frame: H3Frame },
    FinishRequest { stream_id: u64 },
}

#[derive(Clone, Debug)]
struct ScheduledH3Event {
    origin: usize,
    event: H3HarnessEvent,
}

fn build_fault_schedule(
    base: &[H3HarnessEvent],
    drops: &[usize],
    duplicates: &[usize],
    swaps: &[(usize, usize)],
) -> Vec<ScheduledH3Event> {
    // Deterministic operation order:
    // 1) drop by origin from base sequence
    // 2) apply swaps against the unique-origin post-drop sequence
    // 3) duplicate by origin on the swapped sequence
    let mut schedule: Vec<ScheduledH3Event> = base
        .iter()
        .enumerate()
        .filter_map(|(origin, event)| {
            if drops.contains(&origin) {
                None
            } else {
                Some(ScheduledH3Event {
                    origin,
                    event: event.clone(),
                })
            }
        })
        .collect();

    for (a, b) in swaps {
        let a_pos = schedule
            .iter()
            .position(|event| event.origin == *a)
            .unwrap_or_else(|| panic!("swap origin {a} missing in schedule"));
        let b_pos = schedule
            .iter()
            .position(|event| event.origin == *b)
            .unwrap_or_else(|| panic!("swap origin {b} missing in schedule"));
        if a_pos != b_pos {
            schedule.swap(a_pos, b_pos);
        }
    }

    for origin in duplicates {
        let pos = schedule
            .iter()
            .rposition(|event| event.origin == *origin)
            .unwrap_or_else(|| panic!("duplicate origin {origin} missing after drop/swap"));
        let duplicate_event = schedule[pos].clone();
        schedule.insert(pos + 1, duplicate_event);
    }

    schedule
}

fn run_fault_schedule(
    state: &mut H3ConnectionState,
    schedule: &[ScheduledH3Event],
) -> Vec<(usize, Result<(), H3NativeError>)> {
    schedule
        .iter()
        .map(|scheduled| {
            let result = match &scheduled.event {
                H3HarnessEvent::Control(frame) => state.on_control_frame(frame),
                H3HarnessEvent::RequestFrame { stream_id, frame } => {
                    state.on_request_stream_frame(*stream_id, frame)
                }
                H3HarnessEvent::FinishRequest { stream_id } => {
                    state.finish_request_stream(*stream_id)
                }
            };
            (scheduled.origin, result)
        })
        .collect()
}

/// Deterministic microsecond clock starting at seed-derived offset.
struct DetClock {
    now_micros: u64,
}

impl DetClock {
    fn new(rng: &mut DetRng) -> Self {
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
            max_datagram_frame_size: 1_200,
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
            max_datagram_frame_size: 1_200,
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

        self.client
            .begin_handshake(cx)
            .expect("client begin_handshake");
        self.server
            .begin_handshake(cx)
            .expect("server begin_handshake");

        assert_eq!(self.client.state(), QuicConnectionState::Handshaking);
        assert_eq!(self.server.state(), QuicConnectionState::Handshaking);

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

        self.client.record_verified_server_identity();
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
// Test 1: Full request-response cycle with QPACK encoding
// ===========================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn full_request_response_cycle() {
    let mut rng = DetRng::new(0xE4_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // -- Set up H3 state on both sides --
    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Exchange SETTINGS (control stream).
    let mut client_ctrl = H3ControlState::new();
    let client_settings_frame = client_ctrl
        .build_local_settings(H3Settings::default())
        .expect("client build settings");
    server_h3
        .on_control_frame(&client_settings_frame)
        .expect("server receives client settings");

    let mut server_ctrl = H3ControlState::new();
    let server_settings_frame = server_ctrl
        .build_local_settings(H3Settings::default())
        .expect("server build settings");
    client_h3
        .on_control_frame(&server_settings_frame)
        .expect("client receives server settings");

    // -- Client opens a request stream --
    let stream = pair
        .client
        .open_local_bidi(cx)
        .expect("open request stream");
    assert!(stream.is_local_for(StreamRole::Client));
    assert_eq!(stream.direction(), StreamDirection::Bidirectional);

    let request_stream_id: u64 = stream.0;

    // Build a valid request head.
    let request_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("api.example.com".to_string()),
            path: Some("/upload".to_string()),
            status: None,
            protocol: None,
        },
        vec![
            (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("user-agent".to_string(), "asupersync/0.2".to_string()),
        ],
    )
    .expect("valid request head");

    // Generate QPACK plan and verify it has entries.
    let req_plan = qpack_static_plan_for_request(&request_head);
    assert!(!req_plan.is_empty(), "request plan should not be empty");
    // POST -> static index 20
    assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(20)));
    // https -> static index 23
    assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(23)));

    // Client sends HEADERS frame on request stream.
    let headers_frame = H3Frame::Headers(vec![0x00, 0x00, 0x80, 0x17]);
    let mut req_stream_state = H3RequestStreamState::new();
    req_stream_state
        .on_frame(&headers_frame)
        .expect("client headers ok");
    server_h3
        .on_request_stream_frame(request_stream_id, &headers_frame)
        .expect("server process request headers");

    // Client sends DATA frame.
    let body_data: Vec<u8> = (0..256).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
    let data_frame = H3Frame::Data(body_data);
    req_stream_state
        .on_frame(&data_frame)
        .expect("client data ok");
    server_h3
        .on_request_stream_frame(request_stream_id, &data_frame)
        .expect("server process request data");

    // Client marks end-of-stream.
    req_stream_state
        .mark_end_stream()
        .expect("client end stream");
    server_h3
        .finish_request_stream(request_stream_id)
        .expect("server finish request");

    // Simulate wire: encode request frames and transport them.
    let mut request_wire = Vec::new();
    headers_frame
        .encode(&mut request_wire)
        .expect("encode headers");
    data_frame.encode(&mut request_wire).expect("encode data");

    let wire_len = request_wire.len() as u64;
    pair.client
        .write_stream(cx, stream, wire_len)
        .expect("client write wire bytes");
    pair.server
        .accept_remote_stream(cx, stream)
        .expect("server accept stream");
    pair.server
        .receive_stream(cx, stream, wire_len)
        .expect("server receive wire bytes");

    // -- Server sends response --
    let response_head = H3ResponseHead::new(
        200,
        vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ],
    )
    .expect("valid response head");

    let resp_plan = qpack_static_plan_for_response(&response_head);
    assert!(!resp_plan.is_empty());
    // 200 -> static index 25
    assert_eq!(resp_plan[0], QpackFieldPlan::StaticIndex(25));

    let resp_headers = H3Frame::Headers(vec![0x00, 0x00, 0xD9]);
    let resp_body = H3Frame::Data(b"OK: uploaded successfully".to_vec());

    let mut resp_wire = Vec::new();
    resp_headers
        .encode(&mut resp_wire)
        .expect("encode resp headers");
    resp_body.encode(&mut resp_wire).expect("encode resp body");

    // Transport response bytes.
    let resp_len = resp_wire.len() as u64;
    pair.server
        .write_stream(cx, stream, resp_len)
        .expect("server write response");
    pair.client
        .receive_stream(cx, stream, resp_len)
        .expect("client receive response");

    // Client decodes response frames.
    let mut pos = 0;
    let (dec_h, n) =
        H3Frame::decode(&resp_wire[pos..], &test_config()).expect("decode resp headers");
    pos += n;
    assert_eq!(dec_h, resp_headers);

    let (dec_d, n) = H3Frame::decode(&resp_wire[pos..], &test_config()).expect("decode resp body");
    pos += n;
    assert_eq!(dec_d, resp_body);
    assert_eq!(pos, resp_wire.len(), "all response bytes consumed");

    // Verify stream offsets.
    let client_view = pair.client.streams().stream(stream).expect("client stream");
    assert_eq!(client_view.send_offset, wire_len);
    assert_eq!(client_view.recv_offset, resp_len);
}

// ===========================================================================
// Test 2: Multiple concurrent requests with independent processing
// ===========================================================================

#[test]
fn multiple_concurrent_requests() {
    let mut rng = DetRng::new(0xE4_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Set up H3 state.
    let mut server_h3 = H3ConnectionState::new();
    server_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("server settings");

    // Define 4 distinct requests.
    let methods = ["GET", "POST", "PUT", "DELETE"];
    let paths = ["/users", "/upload", "/items/42", "/items/99"];
    let bodies: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            (0..(32 * (i + 1)))
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect()
        })
        .collect();

    // Open 4 client-initiated bidirectional streams simultaneously.
    let streams: Vec<_> = (0..4)
        .map(|_| pair.client.open_local_bidi(cx).expect("open bidi"))
        .collect();

    // All streams should have distinct IDs.
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(streams[i], streams[j], "stream IDs must be unique");
        }
    }

    // Send HEADERS + DATA on each stream, track states independently.
    let mut stream_states: Vec<H3RequestStreamState> =
        (0..4).map(|_| H3RequestStreamState::new()).collect();

    for i in 0..4 {
        let stream_id = streams[i].0;

        // HEADERS frame.
        let headers_frame = H3Frame::Headers(vec![0x00, 0x00, 0x80 | (i as u8)]);
        stream_states[i]
            .on_frame(&headers_frame)
            .expect("headers ok");
        server_h3
            .on_request_stream_frame(stream_id, &headers_frame)
            .unwrap_or_else(|e| panic!("server headers stream {i}: {e}"));

        // DATA frame with body.
        let data_frame = H3Frame::Data(bodies[i].clone());
        stream_states[i].on_frame(&data_frame).expect("data ok");
        server_h3
            .on_request_stream_frame(stream_id, &data_frame)
            .unwrap_or_else(|e| panic!("server data stream {i}: {e}"));

        // End stream.
        stream_states[i].mark_end_stream().expect("end stream ok");
        server_h3
            .finish_request_stream(stream_id)
            .unwrap_or_else(|e| panic!("server finish stream {i}: {e}"));
    }

    // Verify all streams ended independently.
    for (i, state) in stream_states.iter().enumerate().take(4) {
        // After mark_end_stream, further frames should be rejected.
        let err = state
            .clone()
            .on_frame(&H3Frame::Data(vec![0xFF]))
            .expect_err("should reject after end");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished"),
            "stream {i} should be finished"
        );
    }

    // Validate request heads.
    for i in 0..4 {
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some(methods[i].to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some(paths[i].to_string()),
                status: None,
                protocol: None,
            },
            vec![],
        )
        .expect("valid request head");

        let plan = qpack_static_plan_for_request(&head);
        assert!(
            !plan.is_empty(),
            "plan for {} should have entries",
            methods[i]
        );
    }
}

// ===========================================================================
// Test 3: Control stream SETTINGS exchange and parameter negotiation
// ===========================================================================

#[test]
fn control_stream_settings_exchange() {
    let _rng = DetRng::new(0xE4_0003);

    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Client sends SETTINGS with specific parameters.
    let client_settings = H3Settings {
        max_field_section_size: Some(16384),
        qpack_max_table_capacity: Some(0),
        qpack_blocked_streams: Some(0),
        enable_connect_protocol: Some(true),
        h3_datagram: Some(false),
        unknown: vec![],
    };

    let mut client_ctrl = H3ControlState::new();
    let client_settings_frame = client_ctrl
        .build_local_settings(client_settings)
        .expect("client build settings");

    // Verify the frame is indeed a Settings frame.
    match &client_settings_frame {
        H3Frame::Settings(s) => {
            assert_eq!(s.max_field_section_size, Some(16384));
            assert_eq!(s.enable_connect_protocol, Some(true));
        }
        other => panic!("expected Settings frame, got {other:?}"),
    }

    // Server processes client SETTINGS.
    server_h3
        .on_control_frame(&client_settings_frame)
        .expect("server receives client settings");

    // Server sends its own SETTINGS.
    let server_settings = H3Settings {
        max_field_section_size: Some(8192),
        qpack_max_table_capacity: Some(0),
        qpack_blocked_streams: Some(0),
        enable_connect_protocol: None,
        h3_datagram: Some(true),
        unknown: vec![],
    };

    let mut server_ctrl = H3ControlState::new();
    let server_settings_frame = server_ctrl
        .build_local_settings(server_settings)
        .expect("server build settings");

    // Client processes server SETTINGS.
    client_h3
        .on_control_frame(&server_settings_frame)
        .expect("client receives server settings");

    // Verify SETTINGS roundtrip: encode and decode.
    let mut settings_wire = Vec::new();
    client_settings_frame
        .encode(&mut settings_wire)
        .expect("encode client settings");
    let (decoded_frame, consumed) =
        H3Frame::decode(&settings_wire, &test_config()).expect("decode client settings");
    assert_eq!(decoded_frame, client_settings_frame);
    assert_eq!(consumed, settings_wire.len());

    // Verify duplicate SETTINGS is rejected.
    let err = client_ctrl
        .build_local_settings(H3Settings::default())
        .expect_err("duplicate settings");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("SETTINGS already sent on local control stream")
    );

    // Peer QPACK capacity is permission; a static-only encoder accepts it and
    // simply declines to emit dynamic references.
    let mut strict_h3 = H3ConnectionState::new();
    let dynamic_settings = H3Settings {
        qpack_max_table_capacity: Some(4096),
        ..H3Settings::default()
    };
    strict_h3
        .on_control_frame(&H3Frame::Settings(dynamic_settings))
        .expect("static encoder accepts peer dynamic-table capacity");

    // Verify DynamicTableAllowed mode accepts nonzero capacity.
    let config = H3ConnectionConfig {
        qpack_mode: H3QpackMode::DynamicTableAllowed,
        ..H3ConnectionConfig::default()
    };
    let mut permissive_h3 = H3ConnectionState::with_config(config);
    let dynamic_settings_ok = H3Settings {
        qpack_max_table_capacity: Some(4096),
        qpack_blocked_streams: Some(100),
        ..H3Settings::default()
    };
    permissive_h3
        .on_control_frame(&H3Frame::Settings(dynamic_settings_ok))
        .expect("dynamic settings accepted");
}

// ===========================================================================
// Test 4: GOAWAY with stream acceptance boundary
// ===========================================================================

#[test]
fn goaway_stream_acceptance_boundary() {
    let mut rng = DetRng::new(0xE4_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Exchange SETTINGS.
    client_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("client settings");
    server_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("server settings");

    // Open 4 streams. Client-initiated bidi stream IDs: 0, 4, 8, 12.
    let s0 = pair.client.open_local_bidi(cx).expect("open s0");
    let s1 = pair.client.open_local_bidi(cx).expect("open s1");
    let s2 = pair.client.open_local_bidi(cx).expect("open s2");
    let s3 = pair.client.open_local_bidi(cx).expect("open s3");

    assert_eq!(s0.0, 0);
    assert_eq!(s1.0, 4);
    assert_eq!(s2.0, 8);
    assert_eq!(s3.0, 12);

    // Send HEADERS on s0 and s1 before GOAWAY.
    server_h3
        .on_request_stream_frame(s0.0, &H3Frame::Headers(vec![0x80]))
        .expect("s0 headers");
    server_h3
        .on_request_stream_frame(s1.0, &H3Frame::Headers(vec![0x81]))
        .expect("s1 headers");

    // Server sends GOAWAY with stream_id = 8 (accept s0=0, s1=4; reject s2=8, s3=12).
    let goaway = H3Frame::Goaway(8);
    let mut goaway_wire = Vec::new();
    goaway.encode(&mut goaway_wire).expect("encode goaway");

    // Client decodes and processes GOAWAY.
    let (decoded_goaway, _) = H3Frame::decode(&goaway_wire, &test_config()).expect("decode goaway");
    client_h3
        .on_control_frame(&decoded_goaway)
        .expect("client goaway");
    assert_eq!(client_h3.goaway_id(), Some(8));

    // Streams below GOAWAY ID: s0 (0) and s1 (4) are accepted.
    client_h3
        .on_request_stream_frame(s0.0, &H3Frame::Headers(vec![0x80]))
        .expect("s0 allowed after goaway");
    client_h3
        .on_request_stream_frame(s1.0, &H3Frame::Headers(vec![0x81]))
        .expect("s1 allowed after goaway");

    // Stream at GOAWAY ID: s2 (8) is rejected.
    let err = client_h3
        .on_request_stream_frame(s2.0, &H3Frame::Headers(vec![0x82]))
        .expect_err("s2 should be rejected");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
    );

    // Stream above GOAWAY ID: s3 (12) is rejected.
    let err = client_h3
        .on_request_stream_frame(s3.0, &H3Frame::Headers(vec![0x83]))
        .expect_err("s3 should be rejected");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
    );

    // Decreasing GOAWAY is allowed (narrows acceptance).
    client_h3
        .on_control_frame(&H3Frame::Goaway(4))
        .expect("narrowing goaway");
    assert_eq!(client_h3.goaway_id(), Some(4));

    // Now s1 (4) is also rejected.
    let err = client_h3
        .on_request_stream_frame(s1.0, &H3Frame::Headers(vec![0x84]))
        .expect_err("s1 should now be rejected");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
    );

    // s0 (0) still accepted.
    // (Already registered, so additional frames on same stream are fine.)
    client_h3
        .on_request_stream_frame(s0.0, &H3Frame::Data(vec![0x01, 0x02]))
        .expect("s0 still accepted after narrowing");

    // Increasing GOAWAY is rejected.
    let err = client_h3
        .on_control_frame(&H3Frame::Goaway(100))
        .expect_err("increasing goaway must fail");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("GOAWAY id must not increase")
    );
}

// ===========================================================================
// Test 5: CANCEL_PUSH frame encode/decode and rejection semantics
// ===========================================================================

#[test]
fn cancel_push_frame_handling() {
    let _rng = DetRng::new(0xE4_0005);

    // Encode and decode various CANCEL_PUSH frames.
    let push_ids: Vec<u64> = vec![0, 1, 42, 255, 65535, 0x3FFF_FFFF_FFFF_FFFF];

    for push_id in &push_ids {
        let frame = H3Frame::CancelPush(*push_id);
        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("encode cancel_push");

        let (decoded, consumed) =
            H3Frame::decode(&wire, &test_config()).expect("decode cancel_push");
        assert_eq!(decoded, frame, "roundtrip mismatch for push_id={push_id}");
        assert_eq!(consumed, wire.len());
    }

    // CANCEL_PUSH is valid on control stream (after SETTINGS).
    let mut ctrl = H3ControlState::new();
    ctrl.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings first");
    ctrl.on_remote_control_frame(&H3Frame::CancelPush(7))
        .expect("cancel_push on control stream is valid");

    // CANCEL_PUSH is NOT valid on request streams.
    let mut req_state = H3RequestStreamState::new();
    let err = req_state
        .on_frame(&H3Frame::CancelPush(7))
        .expect_err("cancel_push not allowed on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("control frames are not valid on request streams")
    );

    // CANCEL_PUSH before SETTINGS on control stream is rejected.
    let mut ctrl2 = H3ControlState::new();
    let err = ctrl2
        .on_remote_control_frame(&H3Frame::CancelPush(1))
        .expect_err("cancel_push before settings");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
    );
}

// ===========================================================================
// Test 6: MAX_PUSH_ID frame encode/decode
// ===========================================================================

#[test]
fn max_push_id_frame_handling() {
    let _rng = DetRng::new(0xE4_0006);

    // Encode and decode various MAX_PUSH_ID frames.
    let max_ids: Vec<u64> = vec![0, 1, 100, 1000, 0x3FFF_FFFF_FFFF_FFFF];

    for max_id in &max_ids {
        let frame = H3Frame::MaxPushId(*max_id);
        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("encode max_push_id");

        let (decoded, consumed) =
            H3Frame::decode(&wire, &test_config()).expect("decode max_push_id");
        assert_eq!(decoded, frame, "roundtrip mismatch for max_id={max_id}");
        assert_eq!(consumed, wire.len());
    }

    // MAX_PUSH_ID is valid on control stream (after SETTINGS).
    let mut ctrl = H3ControlState::new();
    ctrl.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings first");
    ctrl.on_remote_control_frame(&H3Frame::MaxPushId(50))
        .expect("max_push_id on control stream is valid");

    // MAX_PUSH_ID is NOT valid on request streams.
    let mut req_state = H3RequestStreamState::new();
    let err = req_state
        .on_frame(&H3Frame::MaxPushId(50))
        .expect_err("max_push_id not allowed on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("control frames are not valid on request streams")
    );

    // MAX_PUSH_ID before SETTINGS on control stream is rejected.
    let mut ctrl2 = H3ControlState::new();
    let err = ctrl2
        .on_remote_control_frame(&H3Frame::MaxPushId(10))
        .expect_err("max_push_id before settings");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
    );
}

// ===========================================================================
// Test 7: H3 error handling -- invalid frames on various stream types
// ===========================================================================

#[test]
fn h3_error_handling_invalid_frames() {
    let _rng = DetRng::new(0xE4_0007);

    // -- Invalid frame on control stream --

    // DATA on control stream after SETTINGS is rejected.
    let mut ctrl = H3ControlState::new();
    ctrl.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings");
    let err = ctrl
        .on_remote_control_frame(&H3Frame::Data(vec![0x01]))
        .expect_err("data on control stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("frame type not allowed on control stream")
    );

    // HEADERS on control stream after SETTINGS is rejected.
    let mut ctrl2 = H3ControlState::new();
    ctrl2
        .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings");
    let err = ctrl2
        .on_remote_control_frame(&H3Frame::Headers(vec![0x80]))
        .expect_err("headers on control stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("frame type not allowed on control stream")
    );

    // PUSH_PROMISE on control stream is rejected.
    let mut ctrl3 = H3ControlState::new();
    ctrl3
        .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings");
    let err = ctrl3
        .on_remote_control_frame(&H3Frame::PushPromise {
            push_id: 0,
            field_block: vec![0x80],
        })
        .expect_err("push_promise on control stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("frame type not allowed on control stream")
    );

    // -- Invalid frame on request stream --

    // SETTINGS on request stream is rejected.
    let mut req = H3RequestStreamState::new();
    let err = req
        .on_frame(&H3Frame::Settings(H3Settings::default()))
        .expect_err("settings on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("control frames are not valid on request streams")
    );

    // GOAWAY on request stream is rejected.
    let mut req2 = H3RequestStreamState::new();
    let err = req2
        .on_frame(&H3Frame::Goaway(0))
        .expect_err("goaway on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("control frames are not valid on request streams")
    );

    // Unknown frames on request streams are ignored for GREASE / forward compatibility.
    let mut req3 = H3RequestStreamState::new();
    req3.on_frame(&H3Frame::Unknown {
        frame_type: 0xFF,
        payload: vec![],
    })
    .expect("unknown frame on request stream is ignored");

    // -- Unexpected frame type: unidirectional stream ID for request stream --
    let mut conn = H3ConnectionState::new();
    conn.on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("settings");
    // Stream ID 2 is unidirectional (bit 1 set).
    let err = conn
        .on_request_stream_frame(2, &H3Frame::Headers(vec![0x80]))
        .expect_err("uni stream id for request");
    assert_eq!(
        err,
        H3NativeError::StreamProtocol("request stream id must be client-initiated bidirectional")
    );
}

// ===========================================================================
// Test 8: Request stream state transitions
// ===========================================================================

#[test]
fn request_stream_state_transitions() {
    let _rng = DetRng::new(0xE4_0008);

    // -- Idle -> Headers -> Data -> Complete (with trailers) --
    let mut st = H3RequestStreamState::new();

    // State: Idle -- DATA should be rejected.
    let err = st
        .on_frame(&H3Frame::Data(vec![0x01]))
        .expect_err("data before headers");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
    );

    // Transition: Idle -> Headers
    st.on_frame(&H3Frame::Headers(vec![0x80]))
        .expect("initial HEADERS");

    // State: Headers -- DATA is allowed.
    st.on_frame(&H3Frame::Data(vec![0x01, 0x02, 0x03]))
        .expect("first DATA chunk");

    // Multiple DATA frames are fine.
    st.on_frame(&H3Frame::Data(vec![0x04, 0x05]))
        .expect("second DATA chunk");

    // Transition: Data -> Trailers (second HEADERS after DATA).
    st.on_frame(&H3Frame::Headers(vec![0x81]))
        .expect("trailing HEADERS");

    // After trailers, DATA is rejected.
    let err = st
        .on_frame(&H3Frame::Data(vec![0xFF]))
        .expect_err("data after trailers");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("DATA not allowed after trailing HEADERS")
    );

    // Transition: Trailers -> Complete (end stream).
    st.mark_end_stream().expect("end stream");

    // After end stream, any frame is rejected.
    let err = st
        .on_frame(&H3Frame::Headers(vec![0x82]))
        .expect_err("frame after end stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream already finished")
    );

    // -- Headers-only request (no DATA, no trailers) --
    let mut st2 = H3RequestStreamState::new();
    st2.on_frame(&H3Frame::Headers(vec![0x80]))
        .expect("initial HEADERS");
    st2.mark_end_stream().expect("headers-only end stream");

    // -- Third HEADERS is rejected (only initial + trailers allowed) --
    let mut st3 = H3RequestStreamState::new();
    st3.on_frame(&H3Frame::Headers(vec![0x80]))
        .expect("initial HEADERS");
    st3.on_frame(&H3Frame::Headers(vec![0x81]))
        .expect("trailing HEADERS");
    let err = st3
        .on_frame(&H3Frame::Headers(vec![0x82]))
        .expect_err("third headers");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("invalid HEADERS ordering on request stream")
    );

    // -- End stream before any HEADERS is rejected --
    let mut st4 = H3RequestStreamState::new();
    let err = st4.mark_end_stream().expect_err("end before headers");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream ended before initial HEADERS")
    );
}

// ===========================================================================
// Test 9: QPACK static table plan coverage
// ===========================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn qpack_static_table_plan_coverage() {
    let _rng = DetRng::new(0xE4_0009);

    // -- Request plans: methods with known static indices --
    let static_methods = [
        ("CONNECT", 15),
        ("DELETE", 16),
        ("GET", 17),
        ("HEAD", 18),
        ("OPTIONS", 19),
        ("POST", 20),
        ("PUT", 21),
    ];

    for (method, expected_idx) in &static_methods {
        // CONNECT has special pseudo-header requirements.
        let pseudo = if *method == "CONNECT" {
            H3PseudoHeaders {
                method: Some(method.to_string()),
                authority: Some("upstream.example:443".to_string()),
                scheme: None,
                path: None,
                status: None,
                protocol: None,
            }
        } else {
            H3PseudoHeaders {
                method: Some(method.to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
                protocol: None,
            }
        };
        let head = H3RequestHead::new(pseudo, vec![]).expect("valid request");
        let plan = qpack_static_plan_for_request(&head);
        assert!(
            plan.contains(&QpackFieldPlan::StaticIndex(*expected_idx)),
            "method {method} should map to static index {expected_idx}"
        );
    }

    // Non-static method should produce a Literal.
    let patch_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("PATCH".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/resource".to_string()),
            status: None,
            protocol: None,
        },
        vec![],
    )
    .expect("valid PATCH request");
    let patch_plan = qpack_static_plan_for_request(&patch_head);
    assert_eq!(
        patch_plan[0],
        QpackFieldPlan::Literal {
            name: ":method".to_string(),
            value: "PATCH".to_string(),
        }
    );

    // -- Request plans: schemes --
    // "http" -> index 22, "https" -> index 23.
    let http_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("http".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        },
        vec![],
    )
    .expect("valid http request");
    let http_plan = qpack_static_plan_for_request(&http_head);
    assert!(http_plan.contains(&QpackFieldPlan::StaticIndex(22)));

    // Non-static scheme produces Literal.
    let ftp_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("ftp".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        },
        vec![],
    )
    .expect("valid ftp request");
    let ftp_plan = qpack_static_plan_for_request(&ftp_head);
    assert!(ftp_plan.contains(&QpackFieldPlan::Literal {
        name: ":scheme".to_string(),
        value: "ftp".to_string(),
    }));

    // -- Request plans: path "/" -> index 1, other paths -> Literal --
    let root_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        },
        vec![],
    )
    .expect("valid root path request");
    let root_plan = qpack_static_plan_for_request(&root_head);
    assert!(root_plan.contains(&QpackFieldPlan::StaticIndex(1)));

    let nonroot_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/api/v2/data".to_string()),
            status: None,
            protocol: None,
        },
        vec![],
    )
    .expect("valid non-root request");
    let nonroot_plan = qpack_static_plan_for_request(&nonroot_head);
    assert!(nonroot_plan.contains(&QpackFieldPlan::Literal {
        name: ":path".to_string(),
        value: "/api/v2/data".to_string(),
    }));

    // -- Request plans: authority is always Literal --
    assert!(root_plan.contains(&QpackFieldPlan::Literal {
        name: ":authority".to_string(),
        value: "example.com".to_string(),
    }));

    // -- Request plans: custom headers are Literal --
    let with_headers_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
            protocol: None,
        },
        vec![
            ("accept".to_string(), "text/html".to_string()),
            ("x-custom".to_string(), "value".to_string()),
        ],
    )
    .expect("valid request with headers");
    let headers_plan = qpack_static_plan_for_request(&with_headers_head);
    assert!(headers_plan.contains(&QpackFieldPlan::Literal {
        name: "accept".to_string(),
        value: "text/html".to_string(),
    }));
    assert!(headers_plan.contains(&QpackFieldPlan::Literal {
        name: "x-custom".to_string(),
        value: "value".to_string(),
    }));

    // -- Response plans: status codes with known static indices --
    let static_statuses: Vec<(u16, u64)> = vec![
        (103, 24),
        (200, 25),
        (304, 26),
        (404, 27),
        (503, 28),
        (100, 63),
        (204, 64),
        (206, 65),
        (302, 66),
        (400, 67),
        (403, 68),
        (421, 69),
        (425, 70),
        (500, 71),
    ];

    for (status, expected_idx) in &static_statuses {
        let resp = H3ResponseHead::new(*status, vec![]).expect("valid response");
        let resp_plan = qpack_static_plan_for_response(&resp);
        assert_eq!(
            resp_plan[0],
            QpackFieldPlan::StaticIndex(*expected_idx),
            "status {status} should map to static index {expected_idx}"
        );
    }

    // Non-indexed valid status produces Literal. HTTP/3 explicitly rejects
    // 101 Switching Protocols, so it is covered separately below.
    let non_indexed_statuses: Vec<u16> = vec![201, 202, 301, 307, 401, 405, 502];
    for status in &non_indexed_statuses {
        let resp = H3ResponseHead::new(*status, vec![]).expect("valid response");
        let resp_plan = qpack_static_plan_for_response(&resp);
        assert_eq!(
            resp_plan[0],
            QpackFieldPlan::Literal {
                name: ":status".to_string(),
                value: status.to_string(),
            },
            "status {status} should produce Literal"
        );
    }
    assert_eq!(
        H3ResponseHead::new(101, vec![]).expect_err("HTTP/3 rejects 101"),
        H3NativeError::InvalidResponsePseudoHeader(
            "HTTP/3 does not support 101 Switching Protocols"
        )
    );

    // Response with custom headers.
    let resp_with_headers = H3ResponseHead::new(
        200,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
        ],
    )
    .expect("valid response with headers");
    let resp_plan = qpack_static_plan_for_response(&resp_with_headers);
    assert_eq!(resp_plan[0], QpackFieldPlan::StaticIndex(25)); // 200
    assert!(resp_plan.contains(&QpackFieldPlan::Literal {
        name: "content-type".to_string(),
        value: "application/json".to_string(),
    }));
    assert!(resp_plan.contains(&QpackFieldPlan::Literal {
        name: "cache-control".to_string(),
        value: "no-cache".to_string(),
    }));
}

// ===========================================================================
// Test 10: GOAWAY zero blocks all streams and full QUIC drain
// ===========================================================================

#[test]
fn goaway_zero_and_quic_drain() {
    let mut rng = DetRng::new(0xE4_000A);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Exchange SETTINGS.
    client_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("client settings");
    server_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("server settings");

    // GOAWAY with id=0 should block all streams.
    client_h3
        .on_control_frame(&H3Frame::Goaway(0))
        .expect("goaway=0");
    assert_eq!(client_h3.goaway_id(), Some(0));

    // Even stream ID 0 is rejected.
    let err = client_h3
        .on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
        .expect_err("stream 0 blocked");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
    );

    // Initiate QUIC-level close with H3_NO_ERROR (0x100).
    let now = pair.clock.now();
    pair.client
        .begin_close(cx, now, 0x0100)
        .expect("client begin close");
    assert_eq!(pair.client.state(), QuicConnectionState::Draining);

    pair.server
        .begin_close(cx, now, 0x0100)
        .expect("server begin close");
    assert_eq!(pair.server.state(), QuicConnectionState::Draining);

    // Fast-forward past drain timeout.
    pair.clock.advance(2_000_001);
    pair.client.poll(cx, pair.clock.now()).expect("client poll");
    pair.server.poll(cx, pair.clock.now()).expect("server poll");

    assert_eq!(pair.client.state(), QuicConnectionState::Closed);
    assert_eq!(pair.server.state(), QuicConnectionState::Closed);
}

// ===========================================================================
// Test 11: Multiple frames in a single wire buffer decode sequentially
// ===========================================================================

#[test]
fn multi_frame_wire_sequential_decode() {
    let mut rng = DetRng::new(0xE4_000B);

    // Build a wire buffer with multiple different frames.
    let frames = vec![
        H3Frame::Settings(H3Settings {
            max_field_section_size: Some(8192),
            ..H3Settings::default()
        }),
        H3Frame::Headers(vec![0x00, 0x00, 0x80, 0x17]),
        H3Frame::Data((0..64).map(|_| (rng.next_u64() & 0xFF) as u8).collect()),
        H3Frame::Headers(vec![0x00, 0x00, 0x81]), // trailing headers
        H3Frame::Goaway(12),
        H3Frame::CancelPush(99),
        H3Frame::MaxPushId(500),
    ];

    let mut wire = Vec::new();
    for frame in &frames {
        frame.encode(&mut wire).expect("encode");
    }

    // Decode all frames sequentially.
    let mut pos = 0;
    let mut decoded_frames = Vec::new();
    while pos < wire.len() {
        let (frame, consumed) = H3Frame::decode(&wire[pos..], &test_config()).expect("decode");
        pos += consumed;
        decoded_frames.push(frame);
    }

    assert_eq!(pos, wire.len(), "all bytes consumed");
    assert_eq!(decoded_frames.len(), frames.len(), "same number of frames");

    for (i, (original, decoded)) in frames.iter().zip(decoded_frames.iter()).enumerate() {
        assert_eq!(original, decoded, "frame {i} mismatch");
    }
}

// ===========================================================================
// Test 12: Full H3 lifecycle over QUIC streams with response validation
// ===========================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn full_h3_lifecycle_over_quic_streams() {
    let mut rng = DetRng::new(0xE4_000C);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Set up H3 states.
    let mut client_h3 = H3ConnectionState::new();
    let mut server_h3 = H3ConnectionState::new();

    // Exchange SETTINGS.
    client_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("client settings");
    server_h3
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .expect("server settings");

    // Client opens 3 request streams.
    let streams: Vec<_> = (0..3)
        .map(|_| pair.client.open_local_bidi(cx).expect("open bidi"))
        .collect();

    // For each stream: send request, process on server, send response, validate on client.
    let requests = [
        ("GET", "/index.html", b"" as &[u8]),
        ("POST", "/api/data", b"request-body-content" as &[u8]),
        ("DELETE", "/items/42", b"" as &[u8]),
    ];
    let responses = [
        (200u16, b"<html>Hello</html>" as &[u8]),
        (201u16, b"created" as &[u8]),
        (204u16, b"" as &[u8]),
    ];

    for (i, ((method, path, req_body), (status, resp_body))) in
        requests.iter().zip(responses.iter()).enumerate()
    {
        let stream = streams[i];
        let stream_id = stream.0;

        // -- Client sends request --
        let req_headers = H3Frame::Headers(vec![0x00, 0x00, 0x80 | (i as u8)]);
        server_h3
            .on_request_stream_frame(stream_id, &req_headers)
            .unwrap_or_else(|e| panic!("server headers stream {i}: {e}"));

        if !req_body.is_empty() {
            let req_data = H3Frame::Data(req_body.to_vec());
            server_h3
                .on_request_stream_frame(stream_id, &req_data)
                .unwrap_or_else(|e| panic!("server data stream {i}: {e}"));
        }

        server_h3
            .finish_request_stream(stream_id)
            .unwrap_or_else(|e| panic!("server finish stream {i}: {e}"));

        // -- Server builds and sends response --
        let resp_head = H3ResponseHead::new(*status, vec![]).expect("valid response");
        let resp_plan = qpack_static_plan_for_response(&resp_head);
        assert!(!resp_plan.is_empty());

        let resp_headers_frame = H3Frame::Headers(vec![0x00, 0x00, 0xD0 | (i as u8)]);
        let resp_data_frame = H3Frame::Data(resp_body.to_vec());

        let mut resp_wire = Vec::new();
        resp_headers_frame
            .encode(&mut resp_wire)
            .expect("encode resp headers");
        if !resp_body.is_empty() {
            resp_data_frame
                .encode(&mut resp_wire)
                .expect("encode resp data");
        }

        // Transport response bytes over QUIC.
        let resp_len = resp_wire.len() as u64;
        pair.server
            .accept_remote_stream(cx, stream)
            .expect("server accept");
        pair.server
            .write_stream(cx, stream, resp_len)
            .expect("server write response");
        pair.client
            .receive_stream(cx, stream, resp_len)
            .expect("client receive response");

        // Client decodes response frames.
        let mut pos = 0;
        let (dec_h, n) =
            H3Frame::decode(&resp_wire[pos..], &test_config()).expect("decode resp headers");
        pos += n;
        assert_eq!(dec_h, resp_headers_frame);

        if !resp_body.is_empty() {
            let (dec_d, n) =
                H3Frame::decode(&resp_wire[pos..], &test_config()).expect("decode resp data");
            pos += n;
            assert_eq!(dec_d, resp_data_frame);
        }
        assert_eq!(
            pos,
            resp_wire.len(),
            "all response bytes consumed for stream {i}"
        );

        // Validate QPACK plan for this request.
        let pseudo = if *method == "CONNECT" {
            H3PseudoHeaders {
                method: Some(method.to_string()),
                authority: Some("example.com".to_string()),
                ..H3PseudoHeaders::default()
            }
        } else {
            H3PseudoHeaders {
                method: Some(method.to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some(path.to_string()),
                status: None,
                protocol: None,
            }
        };
        let req_head = H3RequestHead::new(pseudo, vec![]).expect("valid request head");
        let req_plan = qpack_static_plan_for_request(&req_head);
        assert!(
            !req_plan.is_empty(),
            "plan should not be empty for {method}"
        );
    }

    // Verify QUIC-level stream offsets for stream 1 (POST with body).
    let post_stream = streams[1];
    let client_view = pair
        .client
        .streams()
        .stream(post_stream)
        .expect("client stream view");
    assert!(
        client_view.recv_offset > 0,
        "client should have received response data"
    );
}

#[cfg(feature = "http3")]
fn pump_h3_events(
    cx: &Cx,
    from: &mut QuicConnection,
    to: &mut QuicConnection,
    receiver: &mut NativeH3Session,
) -> (Vec<NativeH3Event>, usize) {
    let mut events = Vec::new();
    let mut rounds = 0usize;
    loop {
        let moved = pump_app_data(cx, from, to, 40, rounds as u64)
            .expect("native QUIC application-data pump");
        if moved > 0 {
            rounds += 1;
        }
        while let Some(event) = receiver
            .next_event(cx, to)
            .expect("decode HTTP/3 event from native QUIC stream")
        {
            events.push(event);
        }
        if moved == 0 {
            return (events, rounds);
        }
    }
}

// ===========================================================================
// Test 13: Native H3 frames traverse native QUIC stream bytes
// ===========================================================================

#[test]
#[cfg(feature = "http3")]
fn native_h3_session_routes_real_stream_bytes_and_survives_reset() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 16,
        max_local_uni: 8,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");

    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3 control stream");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3 control stream");

    let (server_control, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert_eq!(
        server_control,
        vec![NativeH3Event::Settings(H3Settings::default())],
        "server must decode SETTINGS from bytes delivered on the peer control stream"
    );
    let (client_control, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert_eq!(
        client_control,
        vec![NativeH3Event::Settings(H3Settings::default())],
        "client must decode SETTINGS from bytes delivered on the peer control stream"
    );

    let first_request = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("api.example.test".to_string()),
            path: Some("/upload?q=wire".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        )],
    )
    .expect("valid first request");
    let first_body = Bytes::from_static(b"body split across multiple native QUIC STREAM frames");
    let first_stream = client_h3
        .send_request(&cx, &mut client, &first_request, first_body.clone())
        .expect("send first H3 request");
    let (first_server_events, request_pump_rounds) =
        pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(
        request_pump_rounds > 1,
        "40-byte packet budget must exercise incremental frame reassembly"
    );
    assert!(
        first_server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::RequestHeaders { stream_id, head }
                if *stream_id == first_stream && head == &first_request
        )),
        "server must decode the exact request HEADERS: {first_server_events:?}"
    );
    assert!(
        first_server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::Data { stream_id, bytes }
                if *stream_id == first_stream && bytes == &first_body
        )),
        "server must decode the exact request DATA: {first_server_events:?}"
    );
    assert!(
        first_server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::Finished { stream_id } if *stream_id == first_stream
        )),
        "server must observe request FIN: {first_server_events:?}"
    );

    let first_response = H3ResponseHead::new(
        201,
        vec![("x-transport".to_string(), "native-quic".to_string())],
    )
    .expect("valid first response");
    let first_response_body = Bytes::from_static(b"created over h3");
    server_h3
        .send_response(
            &cx,
            &mut server,
            first_stream,
            &first_response,
            first_response_body.clone(),
        )
        .expect("send first H3 response");
    let (first_client_events, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert!(
        first_client_events.iter().any(|event| matches!(
            event,
            NativeH3Event::ResponseHeaders { stream_id, head }
                if *stream_id == first_stream && head == &first_response
        )),
        "client must decode the exact response HEADERS: {first_client_events:?}"
    );
    assert!(
        first_client_events.iter().any(|event| matches!(
            event,
            NativeH3Event::Data { stream_id, bytes }
                if *stream_id == first_stream && bytes == &first_response_body
        )),
        "client must decode the exact response DATA: {first_client_events:?}"
    );

    let cancelled_request = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("api.example.test".to_string()),
            path: Some("/cancel-me".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid cancelled request");
    let cancelled_stream = client_h3
        .send_request(&cx, &mut client, &cancelled_request, Bytes::new())
        .expect("queue request before cancellation");
    client_h3
        .cancel_request(&cx, &mut client, cancelled_stream)
        .expect("queue H3 request cancellation");
    let (cancel_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert_eq!(
        cancel_events,
        vec![NativeH3Event::StreamReset {
            stream_id: cancelled_stream,
            error_code: H3_REQUEST_CANCELLED,
            final_size: client
                .inner()
                .streams()
                .stream(cancelled_stream)
                .expect("cancelled client stream")
                .send_offset,
        }],
        "reset must cross the native QUIC frame path without dispatching HEADERS"
    );

    let survivor_request = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("api.example.test".to_string()),
            path: Some("/after-cancel".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid survivor request");
    let survivor_stream = client_h3
        .send_request(&cx, &mut client, &survivor_request, Bytes::new())
        .expect("connection accepts a request after stream reset");
    let (survivor_server_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(
        survivor_server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::RequestHeaders { stream_id, head }
                if *stream_id == survivor_stream && head == &survivor_request
        )),
        "next request must survive the prior stream reset: {survivor_server_events:?}"
    );
    assert!(
        survivor_server_events.iter().any(|event| matches!(
            event,
            NativeH3Event::Finished { stream_id } if *stream_id == survivor_stream
        )),
        "survivor request must reach FIN: {survivor_server_events:?}"
    );

    let survivor_response = H3ResponseHead::new(200, vec![]).expect("valid survivor response");
    server_h3
        .send_response(
            &cx,
            &mut server,
            survivor_stream,
            &survivor_response,
            Bytes::from_static(b"still alive"),
        )
        .expect("respond after prior stream reset");
    let (survivor_client_events, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert!(
        survivor_client_events.iter().any(|event| matches!(
            event,
            NativeH3Event::ResponseHeaders { stream_id, head }
                if *stream_id == survivor_stream && head == &survivor_response
        )),
        "client must receive response after prior reset: {survivor_client_events:?}"
    );

    let invalid_goaway = server_h3
        .graceful_close(&cx, &mut server, survivor_stream.0 + 1)
        .expect_err("server must reject a non-client-bidirectional GOAWAY id");
    assert!(matches!(
        invalid_goaway,
        NativeH3SessionError::InvalidState(_)
    ));
    server_h3
        .graceful_close(&cx, &mut server, survivor_stream.0 + 4)
        .expect("queue H3 GOAWAY");
    let (goaway_events, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert!(
        goaway_events
            .iter()
            .any(|event| *event == NativeH3Event::Goaway(survivor_stream.0 + 4)),
        "GOAWAY must cross the peer control stream: {goaway_events:?}"
    );
    let after_goaway = client_h3
        .send_request(&cx, &mut client, &survivor_request, Bytes::new())
        .expect_err("peer GOAWAY must reject the next request before opening a stream");
    assert!(matches!(
        after_goaway,
        NativeH3SessionError::InvalidState(_)
    ));
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_router_dispatches_completed_streams_and_refuses_invalid_messages() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use asupersync::web::extract::Request;
    use asupersync::web::handler::{FnHandler, Handler};
    use asupersync::web::{
        NativeH3Router, NativeH3RouterConfig, NativeH3RouterEvent, NativeH3RouterIngress,
        NativeH3RouterRefusal, Response, Router, StatusCode, get, post,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedRequest {
        method: String,
        path: String,
        query: Option<String>,
        host: Option<String>,
        sequence: Option<String>,
        body: Vec<u8>,
    }

    struct RecordingHandler {
        calls: Arc<AtomicUsize>,
        recorded: Arc<Mutex<Option<RecordedRequest>>>,
    }

    impl Handler for RecordingHandler {
        fn call(
            &self,
            _cx: &Cx,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let calls = Arc::clone(&self.calls);
            let recorded = Arc::clone(&self.recorded);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                *recorded.lock().expect("recorded request lock") = Some(RecordedRequest {
                    method: request.method,
                    path: request.path,
                    query: request.query,
                    host: request.headers.get("host").cloned(),
                    sequence: request.headers.get("x-sequence").cloned(),
                    body: request.body.to_vec(),
                });
                let mut response = Response::new(StatusCode::CREATED, "created-via-router");
                response.set_header("x-zeta", "z");
                response.set_header("x-alpha", "a");
                response.append_set_cookie("a=1");
                response.append_set_cookie("b=2");
                response
            })
        }
    }

    struct PendingOnceHandler {
        started: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
        observed_request_id: Arc<Mutex<Option<String>>>,
    }

    impl Handler for PendingOnceHandler {
        fn call(
            &self,
            cx: &Cx,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let started = Arc::clone(&self.started);
            let completed = Arc::clone(&self.completed);
            let observed_request_id = Arc::clone(&self.observed_request_id);
            let request_id = cx.request_id();
            let mut yielded = false;
            Box::pin(std::future::poll_fn(move |_| {
                if !yielded {
                    yielded = true;
                    started.fetch_add(1, Ordering::SeqCst);
                    *observed_request_id
                        .lock()
                        .expect("observed request id lock") = request_id.clone();
                    Poll::Pending
                } else {
                    completed.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(Response::new(StatusCode::OK, "unexpected completion"))
                }
            }))
        }
    }

    fn switching_protocols() -> Response {
        Response::new(StatusCode::SWITCHING_PROTOCOLS, "must-not-ship")
    }

    fn forbidden_response_header() -> Response {
        let mut response = Response::new(StatusCode::OK, "must-not-ship");
        response.set_header("connection", "keep-alive");
        response
    }

    fn drive_router_event(
        bridge: &mut NativeH3Router,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        event: NativeH3Event,
    ) -> NativeH3RouterEvent {
        match bridge
            .ingest_event_with_cx(cx, session, connection, event)
            .expect("ingest H3 Router event")
        {
            NativeH3RouterIngress::Event(event) => event,
            NativeH3RouterIngress::Dispatch(dispatch) => {
                let prepared = futures_lite::future::block_on(dispatch.run(cx));
                bridge
                    .complete_dispatch_with_cx(cx, session, connection, &prepared)
                    .expect("complete H3 Router dispatch")
            }
            _ => panic!("unexpected future H3 Router ingress variant"),
        }
    }

    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 32,
        max_local_uni: 8,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");

    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3 control stream");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3 control stream");
    assert_eq!(
        pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0,
        vec![NativeH3Event::Settings(H3Settings::default())]
    );
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Settings(H3Settings::default())]
    );

    let matched_calls = Arc::new(AtomicUsize::new(0));
    let cancelled_started = Arc::new(AtomicUsize::new(0));
    let cancelled_calls = Arc::new(AtomicUsize::new(0));
    let cancelled_scope_request_id = Arc::new(Mutex::new(None));
    let fast_calls = Arc::new(AtomicUsize::new(0));
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::new(Mutex::new(None));
    let fast_calls_for_handler = Arc::clone(&fast_calls);
    let fallback_calls_for_handler = Arc::clone(&fallback_calls);
    let router = Arc::new(
        Router::new()
            .route(
                "/ingest",
                post(RecordingHandler {
                    calls: Arc::clone(&matched_calls),
                    recorded: Arc::clone(&recorded),
                }),
            )
            .route(
                "/cancel-me",
                post(PendingOnceHandler {
                    started: Arc::clone(&cancelled_started),
                    completed: Arc::clone(&cancelled_calls),
                    observed_request_id: Arc::clone(&cancelled_scope_request_id),
                }),
            )
            .route(
                "/fast",
                get(FnHandler::new(move || {
                    fast_calls_for_handler.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::OK, "fast")
                })),
            )
            .route("/bad-status", get(FnHandler::new(switching_protocols)))
            .route(
                "/bad-header",
                get(FnHandler::new(forbidden_response_header)),
            )
            .fallback(FnHandler::new(move || {
                fallback_calls_for_handler.fetch_add(1, Ordering::SeqCst);
                StatusCode::NOT_FOUND
            }))
            .without_default_trace(),
    );
    let bridge_config = NativeH3RouterConfig::default()
        .max_buffered_body_bytes(4096)
        .max_total_buffered_body_bytes(4096);
    let mut bridge = NativeH3Router::with_shared_config(Arc::clone(&router), bridge_config);
    let mut wrong_bridge = NativeH3Router::from_shared(router);

    let matched_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/ingest?mode=h3&n=7".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![
            (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("x-sequence".to_string(), "old".to_string()),
            ("x-sequence".to_string(), "final".to_string()),
        ],
    )
    .expect("valid matched request");
    let matched_body = Bytes::from(vec![b'm'; 4096]);
    let matched_stream = client_h3
        .send_request(&cx, &mut client, &matched_head, matched_body.clone())
        .expect("send matched request");
    let mut saw_matched_headers = false;
    for round in 0..64 {
        assert!(
            pump_app_data(&cx, &mut client, &mut server, 40, 100 + round)
                .expect("deliver staged matched request packet")
                > 0
        );
        while let Some(event) = server_h3
            .next_event(&cx, &mut server)
            .expect("decode staged matched request event")
        {
            match event {
                NativeH3Event::RequestHeaders { stream_id, .. } if stream_id == matched_stream => {
                    assert_eq!(
                        drive_router_event(&mut bridge, &cx, &mut server_h3, &mut server, event),
                        NativeH3RouterEvent::RequestBuffered {
                            stream_id: matched_stream,
                            body_bytes: 0,
                        }
                    );
                    saw_matched_headers = true;
                    break;
                }
                other => panic!("matched request must remain before DATA/FIN: {other:?}"),
            }
        }
        if saw_matched_headers {
            break;
        }
    }
    assert!(saw_matched_headers, "request HEADERS must reach the bridge");
    assert_eq!(matched_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.pending_request_count(), 1);
    assert!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3)
            .0
            .is_empty(),
        "the bridge must not emit a response while request DATA/FIN remain undelivered"
    );

    let matched_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(
        matched_events.len(),
        2,
        "DATA and FIN expected after staging"
    );
    assert_eq!(
        drive_router_event(
            &mut bridge,
            &cx,
            &mut server_h3,
            &mut server,
            matched_events[0].clone(),
        ),
        NativeH3RouterEvent::RequestBuffered {
            stream_id: matched_stream,
            body_bytes: matched_body.len(),
        }
    );
    assert_eq!(matched_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.pending_request_count(), 1);
    assert_eq!(
        drive_router_event(
            &mut bridge,
            &cx,
            &mut server_h3,
            &mut server,
            matched_events[1].clone(),
        ),
        NativeH3RouterEvent::ResponseSent {
            stream_id: matched_stream,
            status: 201,
        }
    );
    assert_eq!(matched_calls.load(Ordering::SeqCst), 1);
    assert_eq!(bridge.pending_request_count(), 0);
    assert_eq!(
        recorded.lock().expect("recorded request lock").clone(),
        Some(RecordedRequest {
            method: "POST".to_string(),
            path: "/ingest".to_string(),
            query: Some("mode=h3&n=7".to_string()),
            host: Some("router.example.test".to_string()),
            sequence: Some("final".to_string()),
            body: matched_body.to_vec(),
        })
    );
    let matched_response = H3ResponseHead::new(
        201,
        vec![
            ("x-alpha".to_string(), "a".to_string()),
            ("x-zeta".to_string(), "z".to_string()),
            ("set-cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ],
    )
    .expect("valid expected response");
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: matched_stream,
                head: matched_response,
            },
            NativeH3Event::Data {
                stream_id: matched_stream,
                bytes: Bytes::from_static(b"created-via-router"),
            },
            NativeH3Event::Finished {
                stream_id: matched_stream,
            },
        ]
    );

    let delayed_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/cancel-me".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid delayed-dispatch request");
    let delayed_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &delayed_head,
            Bytes::from(vec![b'd'; 3072]),
        )
        .expect("send delayed-dispatch request");
    let delayed_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(delayed_events.len(), 3, "HEADERS, DATA, and FIN expected");
    let mut delayed_dispatch = None;
    for event in delayed_events {
        match bridge
            .ingest_event_with_cx(&cx, &mut server_h3, &mut server, event)
            .expect("ingest delayed-dispatch event")
        {
            NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestBuffered {
                stream_id,
                body_bytes,
            }) => {
                assert_eq!(stream_id, delayed_stream);
                assert!(body_bytes == 0 || body_bytes == 3072);
            }
            NativeH3RouterIngress::Dispatch(dispatch) => {
                assert_eq!(dispatch.stream_id(), delayed_stream);
                delayed_dispatch = Some(dispatch);
            }
            other => panic!("unexpected delayed-dispatch ingress: {other:?}"),
        }
    }
    let delayed_dispatch = delayed_dispatch.expect("FIN must detach a Router dispatch");
    let delayed_token = delayed_dispatch.cancellation_token();
    assert_eq!(bridge.in_flight_dispatch_count(), 1);
    let request_cx = test_cx();
    request_cx.set_request_id("native-h3-request-scope");
    let mut delayed_future = Box::pin(delayed_dispatch.run(&request_cx));
    let mut task_context = Context::from_waker(Waker::noop());
    assert!(
        delayed_future.as_mut().poll(&mut task_context).is_pending(),
        "the delayed handler must start and remain pending"
    );
    assert_eq!(cancelled_started.load(Ordering::SeqCst), 1);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        cancelled_scope_request_id
            .lock()
            .expect("cancelled request id lock")
            .as_deref(),
        Some("native-h3-request-scope"),
        "the handler must receive the caller-owned request-scope Cx"
    );

    let over_budget_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/ingest".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid over-budget request");
    let over_budget_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &over_budget_head,
            Bytes::from(vec![b'b'; 2048]),
        )
        .expect("send request while prior body remains in-flight");
    let over_budget_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(over_budget_events.len(), 3);
    for (index, event) in over_budget_events.into_iter().enumerate() {
        let outcome = drive_router_event(&mut bridge, &cx, &mut server_h3, &mut server, event);
        match index {
            0 => assert_eq!(
                outcome,
                NativeH3RouterEvent::RequestBuffered {
                    stream_id: over_budget_stream,
                    body_bytes: 0,
                }
            ),
            1 => assert_eq!(
                outcome,
                NativeH3RouterEvent::RequestRefused {
                    stream_id: over_budget_stream,
                    reason: NativeH3RouterRefusal::ConnectionBodyBudgetExhausted { limit: 4096 },
                }
            ),
            2 => assert_eq!(
                outcome,
                NativeH3RouterEvent::RequestDiscarded {
                    stream_id: over_budget_stream,
                }
            ),
            _ => unreachable!(),
        }
    }
    assert_eq!(matched_calls.load(Ordering::SeqCst), 1);
    assert_eq!(bridge.in_flight_dispatch_count(), 1);
    assert!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3)
            .0
            .iter()
            .any(|event| matches!(
                event,
                NativeH3Event::StreamReset {
                    stream_id,
                    error_code: H3_REQUEST_CANCELLED,
                    final_size: 0,
                } if *stream_id == over_budget_stream
            )),
        "in-flight body retention must fail closed before dispatching the next handler"
    );
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);

    let fast_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/fast".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid fast request");
    let fast_stream = client_h3
        .send_request(&cx, &mut client, &fast_head, Bytes::new())
        .expect("send fast request while another dispatch is held");
    let mut fast_prepared = None;
    for event in pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0 {
        match bridge
            .ingest_event_with_cx(&cx, &mut server_h3, &mut server, event)
            .expect("ingest fast request while delayed handler is pending")
        {
            NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestBuffered {
                stream_id,
                body_bytes: 0,
            }) => assert_eq!(stream_id, fast_stream),
            NativeH3RouterIngress::Dispatch(dispatch) => {
                fast_prepared = Some(futures_lite::future::block_on(dispatch.run(&cx)));
            }
            other => panic!("unexpected fast-request ingress: {other:?}"),
        }
    }
    let fast_prepared = fast_prepared.expect("fast request FIN must produce a dispatch");
    assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.in_flight_dispatch_count(), 2);
    assert!(matches!(
        wrong_bridge.complete_dispatch_with_cx(&cx, &mut server_h3, &mut server, &fast_prepared,),
        Err(NativeH3SessionError::InvalidState(
            "HTTP/3 Router completion belongs to a different bridge"
        ))
    ));
    assert_eq!(wrong_bridge.in_flight_dispatch_count(), 0);
    assert_eq!(bridge.in_flight_dispatch_count(), 2);
    let cancelled_connection_cx = test_cx();
    cancelled_connection_cx.set_cancel_requested(true);
    assert!(matches!(
        bridge.complete_dispatch_with_cx(
            &cancelled_connection_cx,
            &mut server_h3,
            &mut server,
            &fast_prepared,
        ),
        Err(NativeH3SessionError::Transport(
            asupersync::net::quic_native::NativeQuicConnectionError::Cancelled
        ))
    ));
    assert_eq!(
        bridge.in_flight_dispatch_count(),
        2,
        "a failed atomic transport write must retain the prepared dispatch for retry"
    );
    assert_eq!(
        bridge
            .complete_dispatch_with_cx(&cx, &mut server_h3, &mut server, &fast_prepared)
            .expect("complete fast response through its originating bridge"),
        NativeH3RouterEvent::ResponseSent {
            stream_id: fast_stream,
            status: 200,
        }
    );
    assert_eq!(bridge.in_flight_dispatch_count(), 1);
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: fast_stream,
                head: H3ResponseHead::new(200, vec![]).expect("valid fast response"),
            },
            NativeH3Event::Data {
                stream_id: fast_stream,
                bytes: Bytes::from_static(b"fast"),
            },
            NativeH3Event::Finished {
                stream_id: fast_stream,
            },
        ]
    );
    assert_eq!(
        bridge
            .cancel_dispatch_with_cx(&cx, &mut server_h3, &mut server, &delayed_token)
            .expect("cancel caller-scoped delayed dispatch"),
        NativeH3RouterEvent::RequestRefused {
            stream_id: delayed_stream,
            reason: NativeH3RouterRefusal::DispatchCancelled,
        }
    );
    drop(delayed_future);
    assert_eq!(bridge.in_flight_dispatch_count(), 0);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    assert!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3)
            .0
            .iter()
            .any(|event| matches!(
                event,
                NativeH3Event::StreamReset {
                    stream_id,
                    error_code: H3_REQUEST_CANCELLED,
                    final_size: 0,
                } if *stream_id == delayed_stream
            )),
        "cancelling the request scope must reset the exact request stream"
    );
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);

    let cancelled_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/cancel-me".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid cancelled request");
    let cancelled_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &cancelled_head,
            Bytes::from(vec![b'x'; 4096]),
        )
        .expect("queue cancelled request");
    let mut saw_cancelled_headers = false;
    for round in 0..64 {
        assert!(
            pump_app_data(&cx, &mut client, &mut server, 40, round)
                .expect("deliver staged cancelled request packet")
                > 0
        );
        while let Some(event) = server_h3
            .next_event(&cx, &mut server)
            .expect("decode staged cancelled request event")
        {
            match event {
                NativeH3Event::RequestHeaders { stream_id, .. }
                    if stream_id == cancelled_stream =>
                {
                    assert_eq!(
                        drive_router_event(&mut bridge, &cx, &mut server_h3, &mut server, event,),
                        NativeH3RouterEvent::RequestBuffered {
                            stream_id: cancelled_stream,
                            body_bytes: 0,
                        }
                    );
                    saw_cancelled_headers = true;
                }
                other => panic!("request must remain incomplete before cancellation: {other:?}"),
            }
        }
        if saw_cancelled_headers {
            break;
        }
    }
    assert!(
        saw_cancelled_headers,
        "request HEADERS must reach the bridge"
    );
    assert_eq!(bridge.pending_request_count(), 1);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    client_h3
        .cancel_request(&cx, &mut client, cancelled_stream)
        .expect("cancel after HEADERS but before request FIN");
    let cancelled_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(cancelled_events.len(), 1);
    let cancelled_event = cancelled_events.into_iter().next().expect("reset event");
    assert!(matches!(
        cancelled_event,
        NativeH3Event::StreamReset {
            stream_id,
            error_code: H3_REQUEST_CANCELLED,
            ..
        } if stream_id == cancelled_stream
    ));
    assert!(matches!(
        drive_router_event(
            &mut bridge,
            &cx,
            &mut server_h3,
            &mut server,
            cancelled_event,
        ),
        NativeH3RouterEvent::StreamReset {
            stream_id,
            error_code: H3_REQUEST_CANCELLED,
            ..
        } if stream_id == cancelled_stream
    ));
    assert_eq!(bridge.pending_request_count(), 0);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    assert_eq!(matched_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);

    let connect_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("router.example.test".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid basic CONNECT request");
    let connect_stream = client_h3
        .send_request(&cx, &mut client, &connect_head, Bytes::new())
        .expect("send CONNECT request");
    let connect_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(connect_events.len(), 2, "CONNECT HEADERS and FIN expected");
    for (index, event) in connect_events.into_iter().enumerate() {
        let outcome = drive_router_event(&mut bridge, &cx, &mut server_h3, &mut server, event);
        if index == 0 {
            assert_eq!(
                outcome,
                NativeH3RouterEvent::RequestRefused {
                    stream_id: connect_stream,
                    reason: NativeH3RouterRefusal::ConnectUnsupported,
                }
            );
        } else {
            assert_eq!(
                outcome,
                NativeH3RouterEvent::RequestDiscarded {
                    stream_id: connect_stream,
                }
            );
        }
    }
    assert_eq!(matched_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.pending_request_count(), 0);
    let connect_refusal_events = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0;
    assert!(connect_refusal_events.iter().any(|event| matches!(
        event,
        NativeH3Event::StreamReset {
            stream_id,
            error_code: H3_REQUEST_CANCELLED,
            final_size: 0,
        } if *stream_id == connect_stream
    )));
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);

    for (path, expected_error) in [
        (
            "/bad-status",
            H3NativeError::InvalidResponsePseudoHeader(
                "informational status is not a final Router response",
            ),
        ),
        (
            "/bad-header",
            H3NativeError::InvalidFrame("header field name forbidden in HTTP/3 (RFC 9114 §4.2)"),
        ),
    ] {
        let invalid_head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("router.example.test".to_string()),
                path: Some(path.to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid invalid-response request");
        let invalid_stream = client_h3
            .send_request(&cx, &mut client, &invalid_head, Bytes::new())
            .expect("send invalid-response request");
        let invalid_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
        assert_eq!(invalid_events.len(), 2);
        let mut last_outcome = None;
        for event in invalid_events {
            last_outcome = Some(drive_router_event(
                &mut bridge,
                &cx,
                &mut server_h3,
                &mut server,
                event,
            ));
        }
        let Some(NativeH3RouterEvent::RequestRefused {
            stream_id,
            reason: NativeH3RouterRefusal::InvalidResponse(error),
        }) = last_outcome
        else {
            panic!("expected invalid-response refusal, got {last_outcome:?}");
        };
        assert_eq!(stream_id, invalid_stream);
        assert_eq!(error, expected_error);
        let refusal_events = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0;
        assert!(refusal_events.iter().any(|event| matches!(
            event,
            NativeH3Event::StreamReset {
                stream_id,
                error_code: H3_REQUEST_CANCELLED,
                final_size: 0,
            } if *stream_id == invalid_stream
        )));
        assert!(!refusal_events.iter().any(|event| matches!(
            event,
            NativeH3Event::ResponseHeaders { stream_id, .. }
                | NativeH3Event::Data { stream_id, .. }
                | NativeH3Event::Finished { stream_id }
                if *stream_id == invalid_stream
        )));
        let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    }

    let survivor_head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("router.example.test".to_string()),
            path: Some("/does-not-exist?after=reset".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid survivor request");
    let survivor_stream = client_h3
        .send_request(&cx, &mut client, &survivor_head, Bytes::new())
        .expect("send survivor request");
    let survivor_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    assert_eq!(survivor_events.len(), 2);
    for event in survivor_events {
        drive_router_event(&mut bridge, &cx, &mut server_h3, &mut server, event);
    }
    assert_eq!(matched_calls.load(Ordering::SeqCst), 1);
    assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: survivor_stream,
                head: H3ResponseHead::new(404, vec![]).expect("valid 404 response"),
            },
            NativeH3Event::Finished {
                stream_id: survivor_stream,
            },
        ]
    );

    let goaway_id = survivor_stream.0 + 4;
    server_h3
        .graceful_close(&cx, &mut server, goaway_id)
        .expect("queue H3 GOAWAY");
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Goaway(goaway_id)]
    );
    assert_eq!(
        client_h3
            .send_request(&cx, &mut client, &survivor_head, Bytes::new())
            .expect_err("GOAWAY must reject the next request"),
        NativeH3SessionError::InvalidState("peer GOAWAY rejects the next request stream")
    );
}

#[test]
#[cfg(all(feature = "http3", feature = "test-internals"))]
fn native_h3_reliable_frames_recover_after_deliberate_loss_and_cancel_both_directions() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 16,
        max_local_uni: 8,
        send_window: 1 << 18,
        recv_window: 1 << 18,
        connection_send_limit: 4 << 20,
        connection_recv_limit: 4 << 20,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);

    let head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("loss.example.test".to_string()),
            path: Some("/retransmit".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid request");
    let body = Bytes::from_static(b"reliable HTTP/3 bytes survive a dropped first packet");
    let stream = client_h3
        .send_request(&cx, &mut client, &head, body.clone())
        .expect("queue request");
    assert!(drop_app_data_packet(&cx, &mut client, 40).expect("drop first request packet") > 0);
    let (events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(events.iter().any(|event| matches!(
        event,
        NativeH3Event::RequestHeaders { stream_id, head: received }
            if *stream_id == stream && received == &head
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        NativeH3Event::Data { stream_id, bytes }
            if *stream_id == stream && bytes == &body
    )));
    assert!(events.iter().any(
        |event| matches!(event, NativeH3Event::Finished { stream_id } if *stream_id == stream)
    ));

    let client_cancelled = client_h3
        .send_request(&cx, &mut client, &head, Bytes::new())
        .expect("queue client-cancelled request");
    client_h3
        .cancel_request(&cx, &mut client, client_cancelled)
        .expect("cancel request from client role");
    assert!(
        drop_app_data_packet(&cx, &mut client, 1200).expect("drop first cancellation packet") > 0
    );
    let (server_cancel_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(server_cancel_events.iter().any(|event| matches!(
        event,
        NativeH3Event::StreamReset { stream_id, error_code, .. }
            if *stream_id == client_cancelled && *error_code == H3_REQUEST_CANCELLED
    )));
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert_eq!(
        client
            .inner()
            .streams()
            .stream(client_cancelled)
            .expect("client-cancelled stream")
            .recv_reset
            .map(|(code, _)| code),
        Some(H3_REQUEST_CANCELLED),
        "peer must answer STOP_SENDING with RESET_STREAM"
    );

    let server_cancelled = client_h3
        .send_request(&cx, &mut client, &head, Bytes::new())
        .expect("queue server-cancelled request");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    server_h3
        .cancel_request(&cx, &mut server, server_cancelled)
        .expect("cancel request from server role");
    let (client_cancel_events, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert!(client_cancel_events.iter().any(|event| matches!(
        event,
        NativeH3Event::StreamReset { stream_id, error_code, .. }
            if *stream_id == server_cancelled && *error_code == H3_REQUEST_CANCELLED
    )));
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert_eq!(
        server
            .inner()
            .streams()
            .stream(server_cancelled)
            .expect("server-cancelled stream")
            .recv_reset
            .map(|(code, _)| code),
        Some(H3_REQUEST_CANCELLED),
        "client must answer server STOP_SENDING with RESET_STREAM"
    );
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_critical_reset_is_fatal_even_before_poll() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig::default();
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    let client_control = client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3 control stream");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3");

    assert!(
        pump_app_data(&cx, &mut client, &mut server, 1200, 0)
            .expect("deliver control bytes without polling H3")
            > 0
    );
    client
        .reset_stream(&cx, client_control, H3_REQUEST_CANCELLED)
        .expect("reset already-delivered control stream");
    assert!(
        pump_app_data(&cx, &mut client, &mut server, 1200, 1).expect("deliver control reset") > 0
    );
    let error = server_h3
        .next_event(&cx, &mut server)
        .expect_err("control-stream reset must fail the H3 connection");
    assert_eq!(
        error,
        NativeH3SessionError::CriticalStreamClosed {
            stream_id: client_control,
            stream_type: asupersync::http::h3_native::H3UniStreamType::Control,
        }
    );
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_reset_retires_request_state_and_trailers_decode_on_successor() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 8,
        max_local_uni: 8,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::with_config(H3ConnectionConfig {
        endpoint_role: asupersync::http::h3_native::H3EndpointRole::Server,
        max_concurrent_request_streams: Some(1),
        ..H3ConnectionConfig::default()
    });
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);

    let head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("state.example.test".to_string()),
            path: Some("/first".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid request");
    let first = client
        .open_bidi_stream(&cx)
        .expect("open first raw request");
    let mut first_wire = Vec::new();
    H3Frame::Headers(qpack_encode_request_field_section(&head).expect("encode request"))
        .encode(&mut first_wire)
        .expect("encode HEADERS frame");
    client
        .write_stream(&cx, first, Bytes::from(first_wire), false)
        .expect("write unterminated request HEADERS");
    let (first_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(first_events.iter().any(|event| matches!(
        event,
        NativeH3Event::RequestHeaders { stream_id, .. } if *stream_id == first
    )));

    client
        .reset_stream(&cx, first, H3_REQUEST_CANCELLED)
        .expect("reset first request mid-message");
    let (reset_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(reset_events.iter().any(|event| matches!(
        event,
        NativeH3Event::StreamReset { stream_id, .. } if *stream_id == first
    )));

    let successor = client
        .open_bidi_stream(&cx)
        .expect("open successor request after reset");
    let successor_head = H3RequestHead::new(
        H3PseudoHeaders {
            path: Some("/successor".to_string()),
            ..head.pseudo.clone()
        },
        vec![],
    )
    .expect("valid successor request");
    let trailer_fields = vec![("x-checksum".to_string(), "abc123".to_string())];
    let trailer_plan = trailer_fields
        .iter()
        .map(|(name, value)| QpackFieldPlan::Literal {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let mut successor_wire = Vec::new();
    H3Frame::Headers(
        qpack_encode_request_field_section(&successor_head).expect("encode successor request"),
    )
    .encode(&mut successor_wire)
    .expect("encode successor HEADERS");
    H3Frame::Data(b"payload".to_vec())
        .encode(&mut successor_wire)
        .expect("encode successor DATA");
    H3Frame::Headers(qpack_encode_field_section(&trailer_plan).expect("encode trailers"))
        .encode(&mut successor_wire)
        .expect("encode trailer HEADERS");
    client
        .write_stream(&cx, successor, Bytes::from(successor_wire), true)
        .expect("write successor with trailers");
    let (successor_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(successor_events.iter().any(|event| matches!(
        event,
        NativeH3Event::RequestHeaders { stream_id, head }
            if *stream_id == successor && head == &successor_head
    )));
    assert!(successor_events.iter().any(|event| matches!(
        event,
        NativeH3Event::Trailers { stream_id, fields }
            if *stream_id == successor && fields == &trailer_fields
    )));
    assert!(successor_events.iter().any(|event| matches!(
        event,
        NativeH3Event::Finished { stream_id } if *stream_id == successor
    )));
}

// ===========================================================================
// Test 14: Wire-level QPACK field section roundtrip + header projection
// ===========================================================================

#[test]
fn qpack_wire_field_section_roundtrip_and_header_projection() {
    let plan = vec![
        QpackFieldPlan::StaticIndex(17), // :method GET
        QpackFieldPlan::StaticIndex(23), // :scheme https
        QpackFieldPlan::StaticIndex(1),  // :path /
        QpackFieldPlan::Literal {
            name: ":authority".to_string(),
            value: "example.com".to_string(),
        },
        QpackFieldPlan::Literal {
            name: "accept".to_string(),
            value: "application/json".to_string(),
        },
    ];

    let wire = qpack_encode_field_section(&plan).expect("encode field section");
    let decoded =
        qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect("decode field section");
    assert_eq!(decoded, plan);

    let projected = qpack_plan_to_header_fields(&decoded, None).expect("project to header fields");
    assert_eq!(projected[0], (":method".to_string(), "GET".to_string()));
    assert_eq!(projected[1], (":scheme".to_string(), "https".to_string()));
    assert_eq!(projected[2], (":path".to_string(), "/".to_string()));
    assert_eq!(
        projected[3],
        (":authority".to_string(), "example.com".to_string())
    );
}

// ===========================================================================
// Test 15: Interop capture corpus fixtures (black-box) validate decode policy
// ===========================================================================

#[test]
fn qpack_interop_capture_corpus_v1_fixtures() {
    let corpus_json = include_str!("../artifacts/quic_h3_interop_capture_corpus_v1.json");
    let corpus: Value = serde_json::from_str(corpus_json).expect("parse interop corpus");

    assert_eq!(
        corpus
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version"),
        "quic-h3-interop-capture-corpus-v1"
    );

    let fixtures = corpus
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures array");
    assert!(
        !fixtures.is_empty(),
        "interop corpus must contain at least one fixture"
    );

    for fixture in fixtures {
        let id = fixture
            .get("id")
            .and_then(Value::as_str)
            .expect("fixture id");
        let wire_hex = fixture
            .get("wire_hex")
            .and_then(Value::as_str)
            .expect("fixture wire_hex");
        let expect_decode = fixture
            .get("expect_decode")
            .and_then(Value::as_str)
            .expect("fixture expect_decode");
        let wire = decode_hex(wire_hex);

        match expect_decode {
            "ok" => {
                let decoded = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly)
                    .unwrap_or_else(|e| panic!("{id}: decode failed: {e}"));
                let expected = fixture_plan_from_json(
                    fixture
                        .get("expected_plan")
                        .expect("expected expected_plan for ok fixture"),
                );
                assert_eq!(decoded, expected, "{id}: decoded plan mismatch");

                let reencoded = qpack_encode_field_section(&decoded)
                    .unwrap_or_else(|e| panic!("{id}: re-encode failed: {e}"));
                let decoded_again = qpack_decode_field_section(&reencoded, H3QpackMode::StaticOnly)
                    .unwrap_or_else(|e| panic!("{id}: decode(re-encode) failed: {e}"));
                assert_eq!(
                    decoded_again, decoded,
                    "{id}: decode(re-encode) must preserve plan semantics"
                );

                let projected = qpack_plan_to_header_fields(&decoded, None)
                    .unwrap_or_else(|e| panic!("{id}: projection failed: {e}"));
                assert!(
                    !projected.is_empty(),
                    "{id}: projected headers must be non-empty"
                );
            }
            "error" => {
                let expected_error = fixture.get("expected_error").expect("expected_error block");
                let expected_variant = expected_error
                    .get("variant")
                    .and_then(Value::as_str)
                    .expect("expected_error.variant");
                let expected_message = expected_error
                    .get("message")
                    .and_then(Value::as_str)
                    .expect("expected_error.message");

                let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly)
                    .expect_err("fixture should fail decode");
                match err {
                    H3NativeError::QpackPolicy(msg) => {
                        assert_eq!(expected_variant, "QpackPolicy", "{id}: wrong error variant");
                        assert_eq!(msg, expected_message, "{id}: error message mismatch");
                    }
                    H3NativeError::InvalidFrame(msg) => {
                        assert_eq!(
                            expected_variant, "InvalidFrame",
                            "{id}: wrong error variant"
                        );
                        assert_eq!(msg, expected_message, "{id}: error message mismatch");
                    }
                    other => panic!("{id}: unexpected error variant: {other:?}"),
                }
            }
            other => panic!("{id}: unknown expect_decode value: {other}"),
        }
    }
}

// ===========================================================================
// Test 15: Deterministic fault schedule -- GOAWAY reorder boundary behavior
// ===========================================================================

#[test]
fn h3_fault_schedule_reorder_goaway_before_request_rejects_boundary_stream() {
    let base = vec![
        H3HarnessEvent::Control(H3Frame::Settings(H3Settings::default())),
        H3HarnessEvent::RequestFrame {
            stream_id: 8,
            frame: H3Frame::Headers(vec![0x80, 0x00]),
        },
        H3HarnessEvent::Control(H3Frame::Goaway(8)),
    ];

    let baseline_schedule = build_fault_schedule(&base, &[], &[], &[]);
    let mut baseline_state = H3ConnectionState::new();
    let baseline = run_fault_schedule(&mut baseline_state, &baseline_schedule);
    assert_eq!(baseline.len(), 3);
    assert!(baseline.iter().all(|(_, result)| result.is_ok()));

    let reordered_schedule = build_fault_schedule(&base, &[], &[], &[(1, 2)]);
    let mut reordered_state = H3ConnectionState::new();
    let reordered = run_fault_schedule(&mut reordered_state, &reordered_schedule);

    assert_eq!(reordered.len(), 3);
    assert_eq!(reordered[0].0, 0, "first event should remain SETTINGS");
    assert!(reordered[0].1.is_ok());
    assert_eq!(reordered[1].0, 2, "second event should be reordered GOAWAY");
    assert!(reordered[1].1.is_ok());
    assert_eq!(reordered[2].0, 1, "third event should be reordered request");
    match &reordered[2].1 {
        Err(H3NativeError::ControlProtocol(msg)) => {
            assert_eq!(*msg, "request stream id rejected after GOAWAY");
        }
        other => panic!("expected GOAWAY boundary rejection, got {other:?}"),
    }
}

// ===========================================================================
// Test 16: Deterministic fault schedule -- duplicate/drop injected controls
// ===========================================================================

#[test]
fn h3_fault_schedule_duplicate_and_drop_injection_are_deterministic() {
    let base = vec![
        H3HarnessEvent::Control(H3Frame::Settings(H3Settings::default())),
        H3HarnessEvent::RequestFrame {
            stream_id: 0,
            frame: H3Frame::Headers(vec![0x80, 0x00]),
        },
        H3HarnessEvent::RequestFrame {
            stream_id: 0,
            frame: H3Frame::Data(vec![1, 2, 3]),
        },
        H3HarnessEvent::FinishRequest { stream_id: 0 },
    ];

    let duplicate_schedule = build_fault_schedule(&base, &[], &[0], &[]);
    let mut duplicate_state = H3ConnectionState::new();
    let duplicate_results = run_fault_schedule(&mut duplicate_state, &duplicate_schedule);

    assert_eq!(duplicate_results.len(), 5);
    assert!(duplicate_results[0].1.is_ok());
    match &duplicate_results[1].1 {
        Err(H3NativeError::ControlProtocol(msg)) => {
            assert_eq!(*msg, "duplicate SETTINGS on remote control stream");
        }
        other => panic!("expected duplicate SETTINGS error, got {other:?}"),
    }
    assert!(duplicate_results[2].1.is_ok());
    assert!(duplicate_results[3].1.is_ok());
    assert!(duplicate_results[4].1.is_ok());

    let dropped_headers_schedule = build_fault_schedule(&base, &[1], &[], &[]);
    let mut dropped_headers_state = H3ConnectionState::new();
    let dropped_headers_results =
        run_fault_schedule(&mut dropped_headers_state, &dropped_headers_schedule);

    assert_eq!(dropped_headers_results.len(), 3);
    assert!(dropped_headers_results[0].1.is_ok());
    match &dropped_headers_results[1].1 {
        Err(H3NativeError::ControlProtocol(msg)) => {
            assert_eq!(*msg, "DATA before initial HEADERS on request stream");
        }
        other => panic!("expected DATA-before-HEADERS error, got {other:?}"),
    }
    match &dropped_headers_results[2].1 {
        Err(H3NativeError::ControlProtocol(msg)) => {
            assert_eq!(*msg, "unknown request stream on finish");
        }
        other => panic!("expected unknown-stream finish error, got {other:?}"),
    }
}

// ===========================================================================
// Test 17: Deterministic transform ordering for swap+duplicate composition
// ===========================================================================

#[test]
fn h3_fault_schedule_operation_order_is_deterministic() {
    let base = vec![
        H3HarnessEvent::Control(H3Frame::Settings(H3Settings::default())), // origin 0
        H3HarnessEvent::RequestFrame {
            stream_id: 0,
            frame: H3Frame::Headers(vec![0x80, 0x00]), // origin 1
        },
        H3HarnessEvent::FinishRequest { stream_id: 0 }, // origin 2
    ];

    // Swaps are applied before duplication:
    // [0,1,2] --swap(0,2)--> [2,1,0] --dup(0)--> [2,1,0,0]
    let schedule = build_fault_schedule(&base, &[], &[0], &[(0, 2)]);
    let origins: Vec<usize> = schedule.iter().map(|event| event.origin).collect();
    assert_eq!(origins, vec![2, 1, 0, 0]);
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_static_encoder_accepts_peer_capacity_but_advertises_zero_decoder_limits() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig::default();
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(
            &cx,
            &mut client,
            H3Settings {
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(16),
                max_field_section_size: Some(8192),
                ..H3Settings::default()
            },
        )
        .expect("initialize static client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize static server H3");

    let (events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert_eq!(
        events,
        vec![NativeH3Event::Settings(H3Settings {
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            max_field_section_size: Some(8192),
            ..H3Settings::default()
        })]
    );

    // The converse is interoperable too: non-zero peer limits are permission
    // that this static encoder declines, not a connection error.
    let peer_settings = H3Frame::Settings(H3Settings {
        qpack_max_table_capacity: Some(2048),
        qpack_blocked_streams: Some(8),
        ..H3Settings::default()
    });
    let mut client_mapping = H3ConnectionState::new_client();
    client_mapping
        .on_control_frame(&peer_settings)
        .expect("static encoder accepts peer dynamic-table permission");

    let qpack_encoder = client
        .open_uni_stream(&cx)
        .expect("open peer QPACK encoder stream");
    client
        .write_stream(&cx, qpack_encoder, Bytes::from_static(&[0x02, 0x20]), false)
        .expect("queue QPACK encoder type and capacity-zero instruction");
    let (qpack_events, _) = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    assert!(
        qpack_events.is_empty(),
        "SetDynamicTableCapacity(0) is a legal no-op, not an H3 event"
    );

    client
        .write_stream(&cx, qpack_encoder, Bytes::from_static(&[0x00]), false)
        .expect("queue forbidden duplicate instruction");
    assert!(
        pump_app_data(&cx, &mut client, &mut server, 1200, 1)
            .expect("deliver forbidden QPACK instruction")
            > 0
    );
    let error = server_h3
        .next_event(&cx, &mut server)
        .expect_err("static adapter must reject dynamic-table mutation");
    assert_eq!(
        error,
        NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
            "static QPACK forbids dynamic encoder instructions"
        ))
    );
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_client_accepts_informational_then_final_response_and_trailers() {
    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 8,
        max_local_uni: 8,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);

    let request = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("info.example.test".to_string()),
            path: Some("/early-hints".to_string()),
            ..H3PseudoHeaders::default()
        },
        vec![],
    )
    .expect("valid request");
    let stream = client_h3
        .send_request(&cx, &mut client, &request, Bytes::new())
        .expect("send request");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);

    let informational = H3ResponseHead::new(
        103,
        vec![("link".to_string(), "</style.css>; rel=preload".to_string())],
    )
    .expect("valid informational response");
    let final_response = H3ResponseHead::new(
        200,
        vec![("content-type".to_string(), "text/plain".to_string())],
    )
    .expect("valid final response");
    let trailer_plan = vec![QpackFieldPlan::Literal {
        name: "x-checksum".to_string(),
        value: "abc123".to_string(),
    }];
    let wrong_api = server_h3
        .send_response(&cx, &mut server, stream, &informational, Bytes::new())
        .expect_err("complete-response API must not FIN an informational response");
    assert!(matches!(
        wrong_api,
        NativeH3SessionError::InvalidState(
            "informational responses require send_informational_response"
        )
    ));
    server_h3
        .send_informational_response(&cx, &mut server, stream, &informational)
        .expect("queue informational response without FIN");
    let mut wire = Vec::new();
    for frame in [
        H3Frame::Headers(
            qpack_encode_response_field_section(&final_response).expect("encode final"),
        ),
        H3Frame::Data(b"ready".to_vec()),
        H3Frame::Headers(qpack_encode_field_section(&trailer_plan).expect("encode trailers")),
    ] {
        frame.encode(&mut wire).expect("encode H3 frame");
    }
    server
        .write_stream(&cx, stream, Bytes::from(wire), true)
        .expect("queue final response and trailers");

    let (events, _) = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);
    assert_eq!(
        events,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: stream,
                head: informational,
            },
            NativeH3Event::ResponseHeaders {
                stream_id: stream,
                head: final_response,
            },
            NativeH3Event::Data {
                stream_id: stream,
                bytes: Bytes::from_static(b"ready"),
            },
            NativeH3Event::Trailers {
                stream_id: stream,
                fields: vec![("x-checksum".to_string(), "abc123".to_string())],
            },
            NativeH3Event::Finished { stream_id: stream },
        ]
    );
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_router_produced_response_is_demand_driven_and_head_suppresses_factory() {
    use std::future::Future;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use asupersync::http::{HeaderMap, HeaderName, HeaderValue};
    use asupersync::web::{
        AsyncCxFnHandler1, FnHandler, Http3StreamResponder, NativeH3ProducedEvent, NativeH3Router,
        NativeH3RouterEvent, NativeH3RouterIngress, NativeH3RouterProducedDispatch, Response,
        Router, StatusCode, get,
    };

    fn request_head(method: &str, path: &str) -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some(method.to_string()),
                scheme: Some("https".to_string()),
                authority: Some("produced.example.test".to_string()),
                path: Some(path.to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid produced-response request")
    }

    fn take_dispatch(
        bridge: &mut NativeH3Router,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        events: Vec<NativeH3Event>,
    ) -> asupersync::web::NativeH3RouterDispatch {
        let mut dispatch = None;
        for event in events {
            match bridge
                .ingest_event_with_cx(cx, session, connection, event)
                .expect("ingest produced-response request")
            {
                NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestBuffered { .. }) => {}
                NativeH3RouterIngress::Dispatch(next) => dispatch = Some(next),
                other => panic!("unexpected produced-response ingress: {other:?}"),
            }
        }
        dispatch.expect("request FIN must detach a Router dispatch")
    }

    let cx = test_cx();
    let config = NativeQuicConnectionConfig {
        max_local_bidi: 8,
        max_local_uni: 4,
        send_window: 512,
        recv_window: 512,
        connection_send_limit: 4096,
        connection_recv_limit: 4096,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(config);
    let mut server = QuicConnection::server(config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish native QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize server H3");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);

    let body_factory_calls = Arc::new(AtomicUsize::new(0));
    let body_factory_calls_for_route = Arc::clone(&body_factory_calls);
    let head_factory_calls = Arc::new(AtomicUsize::new(0));
    let head_factory_calls_for_route = Arc::clone(&head_factory_calls);
    let cancelled_factory_calls = Arc::new(AtomicUsize::new(0));
    let cancelled_factory_calls_for_route = Arc::clone(&cancelled_factory_calls);
    let router = Router::new()
        .route(
            "/stream",
            get(AsyncCxFnHandler1::<_, Http3StreamResponder>::new(
                move |_handler_cx: Cx, responder: Http3StreamResponder| {
                    let body_factory_calls = Arc::clone(&body_factory_calls_for_route);
                    async move {
                        responder.streaming(
                            StatusCode::OK,
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(3).expect("non-zero H3 frame limit"),
                            move |producer_cx, mut sender| async move {
                                body_factory_calls.fetch_add(1, Ordering::SeqCst);
                                sender
                                    .send_bytes(&producer_cx, Bytes::from_static(b"abc"))
                                    .await?;
                                sender
                                    .send_bytes(&producer_cx, Bytes::from_static(b"def"))
                                    .await?;
                                let mut trailers = HeaderMap::new();
                                trailers.insert(
                                    HeaderName::from_static("x-checksum"),
                                    HeaderValue::from_static("abcdef"),
                                );
                                sender.send_trailers(&producer_cx, trailers).await?;
                                sender.finish(&producer_cx)?;
                                Ok(sender)
                            },
                        )
                    }
                },
            )),
        )
        .route(
            "/head-stream",
            get(FnHandler::new(|| StatusCode::METHOD_NOT_ALLOWED)).head(AsyncCxFnHandler1::<
                _,
                Http3StreamResponder,
            >::new(
                move |_handler_cx: Cx, responder: Http3StreamResponder| {
                    let head_factory_calls = Arc::clone(&head_factory_calls_for_route);
                    async move {
                        responder
                            .streaming(
                                StatusCode::OK,
                                NonZeroUsize::MIN,
                                NonZeroUsize::new(3).expect("non-zero H3 frame limit"),
                                move |_producer_cx, sender| async move {
                                    head_factory_calls.fetch_add(1, Ordering::SeqCst);
                                    Ok(sender)
                                },
                            )
                            .header("content-length", "6")
                    }
                },
            )),
        )
        .route(
            "/cancel-stream",
            get(AsyncCxFnHandler1::<_, Http3StreamResponder>::new(
                move |_handler_cx: Cx, responder: Http3StreamResponder| {
                    let cancelled_factory_calls = Arc::clone(&cancelled_factory_calls_for_route);
                    async move {
                        responder.streaming(
                            StatusCode::OK,
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(3).expect("non-zero H3 frame limit"),
                            move |producer_cx, mut sender| async move {
                                cancelled_factory_calls.fetch_add(1, Ordering::SeqCst);
                                sender
                                    .send_bytes(&producer_cx, Bytes::from_static(b"abc"))
                                    .await?;
                                std::future::pending::<()>().await;
                                Ok(sender)
                            },
                        )
                    }
                },
            )),
        )
        .route(
            "/buffered",
            get(FnHandler::new(|| {
                Response::new(StatusCode::OK, "buffered-after-reset")
            })),
        )
        .without_default_trace();
    let mut bridge = NativeH3Router::new(router);

    let stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &request_head("GET", "/stream"),
            Bytes::new(),
        )
        .expect("send produced request");
    let request_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    let dispatch = take_dispatch(
        &mut bridge,
        &cx,
        &mut server_h3,
        &mut server,
        request_events,
    );
    let prepared = match futures_lite::future::block_on(dispatch.run_produced(&cx)) {
        NativeH3RouterProducedDispatch::Produced(prepared) => prepared,
        NativeH3RouterProducedDispatch::Buffered(_) => {
            panic!("Http3StreamResponder must register a produced response")
        }
    };
    assert_eq!(body_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        bridge
            .start_produced_dispatch_with_cx(&cx, &mut server_h3, &mut server, prepared)
            .expect("install produced response"),
        NativeH3RouterEvent::ResponseStarted {
            stream_id: stream,
            status: 200,
        }
    );
    assert_eq!(body_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.in_flight_dispatch_count(), 1);

    let mut task_cx = Context::from_waker(Waker::noop());
    let mut producer =
        match bridge.poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx)
        {
            Poll::Ready(Ok(NativeH3ProducedEvent::ProducerReady {
                stream_id,
                producer,
            })) => {
                assert_eq!(stream_id, stream);
                Box::pin(producer)
            }
            _ => panic!("HEADERS admission must yield the caller-owned producer"),
        };
    assert_eq!(body_factory_calls.load(Ordering::SeqCst), 0);
    assert!(producer.as_mut().poll(&mut task_cx).is_pending());
    assert_eq!(body_factory_calls.load(Ordering::SeqCst), 1);
    assert!(
        bridge
            .poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx,)
            .is_pending(),
        "queued HEADERS must block the first body pull"
    );
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::ResponseHeaders {
            stream_id: stream,
            head: H3ResponseHead::new(200, vec![]).expect("valid response head"),
        }]
    );

    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::DataQueued {
            stream_id,
            payload_bytes: 3,
        })) if stream_id == stream
    ));
    assert!(producer.as_mut().poll(&mut task_cx).is_pending());
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Data {
            stream_id: stream,
            bytes: Bytes::from_static(b"abc"),
        }]
    );

    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::DataQueued {
            stream_id,
            payload_bytes: 3,
        })) if stream_id == stream
    ));
    assert!(producer.as_mut().poll(&mut task_cx).is_ready());
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Data {
            stream_id: stream,
            bytes: Bytes::from_static(b"def"),
        }]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::TerminalQueued { stream_id }))
            if stream_id == stream
    ));
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::Trailers {
                stream_id: stream,
                fields: vec![("x-checksum".to_string(), "abcdef".to_string())],
            },
            NativeH3Event::Finished { stream_id: stream },
        ]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::ResponseSent {
            stream_id,
            status: 200,
        })) if stream_id == stream
    ));
    assert_eq!(bridge.in_flight_dispatch_count(), 0);

    let head_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &request_head("HEAD", "/head-stream"),
            Bytes::new(),
        )
        .expect("send HEAD produced request");
    let head_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    let head_dispatch = take_dispatch(&mut bridge, &cx, &mut server_h3, &mut server, head_events);
    let head_prepared = match futures_lite::future::block_on(head_dispatch.run_produced(&cx)) {
        NativeH3RouterProducedDispatch::Produced(prepared) => prepared,
        NativeH3RouterProducedDispatch::Buffered(_) => panic!("HEAD must retain authored plan"),
    };
    bridge
        .start_produced_dispatch_with_cx(&cx, &mut server_h3, &mut server, head_prepared)
        .expect("install HEAD response");
    assert_eq!(head_factory_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::HeadQueued {
            stream_id,
            status: 200,
        })) if stream_id == head_stream
    ));
    assert_eq!(head_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: head_stream,
                head: H3ResponseHead::new(
                    200,
                    vec![("content-length".to_string(), "6".to_string())],
                )
                .expect("valid HEAD response"),
            },
            NativeH3Event::Finished {
                stream_id: head_stream,
            },
        ]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::ResponseSent {
            stream_id,
            status: 200,
        })) if stream_id == head_stream
    ));
    assert_eq!(head_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.in_flight_dispatch_count(), 0);

    let cancelled_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &request_head("GET", "/cancel-stream"),
            Bytes::new(),
        )
        .expect("send cancellable produced request");
    let cancelled_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    let cancelled_dispatch = take_dispatch(
        &mut bridge,
        &cx,
        &mut server_h3,
        &mut server,
        cancelled_events,
    );
    let cancelled_prepared =
        match futures_lite::future::block_on(cancelled_dispatch.run_produced(&cx)) {
            NativeH3RouterProducedDispatch::Produced(prepared) => prepared,
            NativeH3RouterProducedDispatch::Buffered(_) => {
                panic!("cancellable route must retain authored plan")
            }
        };
    bridge
        .start_produced_dispatch_with_cx(&cx, &mut server_h3, &mut server, cancelled_prepared)
        .expect("install cancellable response");
    let mut cancelled_producer =
        match bridge.poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx)
        {
            Poll::Ready(Ok(NativeH3ProducedEvent::ProducerReady {
                stream_id,
                producer,
            })) => {
                assert_eq!(stream_id, cancelled_stream);
                Box::pin(producer)
            }
            _ => panic!("cancellable response must yield its producer after HEADERS"),
        };
    assert!(cancelled_producer.as_mut().poll(&mut task_cx).is_pending());
    assert_eq!(cancelled_factory_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::ResponseHeaders {
            stream_id: cancelled_stream,
            head: H3ResponseHead::new(200, vec![]).expect("valid cancellable response head"),
        }]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::DataQueued {
            stream_id,
            payload_bytes: 3,
        })) if stream_id == cancelled_stream
    ));
    let ingress = bridge
        .ingest_event_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            NativeH3Event::StreamReset {
                stream_id: cancelled_stream,
                error_code: H3_REQUEST_CANCELLED,
                final_size: 0,
            },
        )
        .expect("ingest peer RESET_STREAM during produced response");
    assert!(matches!(
        ingress,
        NativeH3RouterIngress::Event(NativeH3RouterEvent::StreamReset {
            stream_id,
            error_code: H3_REQUEST_CANCELLED,
            ..
        }) if stream_id == cancelled_stream
    ));
    assert!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3)
            .0
            .iter()
            .any(|event| matches!(
                event,
                NativeH3Event::StreamReset {
                    stream_id,
                    error_code: H3_REQUEST_CANCELLED,
                    ..
                } if *stream_id == cancelled_stream
            )),
        "a peer RESET_STREAM must make the bridge reset its response send side"
    );
    assert_eq!(
        bridge.in_flight_dispatch_count(),
        1,
        "peer reset must retain admission until producer exit is acknowledged"
    );
    drop(cancelled_producer);
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::RequestReset { stream_id }))
            if stream_id == cancelled_stream
    ));
    assert_eq!(bridge.in_flight_dispatch_count(), 0);

    let buffered_stream = client_h3
        .send_request(
            &cx,
            &mut client,
            &request_head("GET", "/buffered"),
            Bytes::new(),
        )
        .expect("send buffered survivor request");
    let buffered_events = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0;
    let buffered_dispatch = take_dispatch(
        &mut bridge,
        &cx,
        &mut server_h3,
        &mut server,
        buffered_events,
    );
    let buffered_prepared =
        match futures_lite::future::block_on(buffered_dispatch.run_produced(&cx)) {
            NativeH3RouterProducedDispatch::Buffered(prepared) => prepared,
            NativeH3RouterProducedDispatch::Produced(_) => {
                panic!("ordinary route must stay on the buffered completion path")
            }
        };
    assert_eq!(
        bridge
            .complete_dispatch_with_cx(&cx, &mut server_h3, &mut server, &buffered_prepared)
            .expect("complete buffered survivor response"),
        NativeH3RouterEvent::ResponseSent {
            stream_id: buffered_stream,
            status: 200,
        }
    );
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![
            NativeH3Event::ResponseHeaders {
                stream_id: buffered_stream,
                head: H3ResponseHead::new(200, vec![]).expect("valid buffered response head"),
            },
            NativeH3Event::Data {
                stream_id: buffered_stream,
                bytes: Bytes::from_static(b"buffered-after-reset"),
            },
            NativeH3Event::Finished {
                stream_id: buffered_stream,
            },
        ]
    );
}

#[test]
#[cfg(feature = "http3")]
fn native_h3_router_produced_response_resumes_after_independent_live_credit_updates() {
    use std::future::Future;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use asupersync::web::{
        AsyncCxFnHandler1, Http3StreamResponder, NativeH3ProducedEvent, NativeH3Router,
        NativeH3RouterEvent, NativeH3RouterIngress, NativeH3RouterProducedDispatch, Router,
        StatusCode, get,
    };

    fn request_head() -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("credit.example.test".to_string()),
                path: Some("/credit".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![],
        )
        .expect("valid credit-gated request")
    }

    let cx = test_cx();
    let client_config = NativeQuicConnectionConfig {
        max_local_bidi: 8,
        max_local_uni: 4,
        send_window: 512,
        recv_window: 512,
        connection_send_limit: 4096,
        connection_recv_limit: 64,
        ..NativeQuicConnectionConfig::default()
    };
    let server_config = NativeQuicConnectionConfig {
        max_local_bidi: 8,
        max_local_uni: 4,
        send_window: 512,
        recv_window: 512,
        connection_send_limit: 4096,
        connection_recv_limit: 4096,
        ..NativeQuicConnectionConfig::default()
    };
    let mut client = QuicConnection::client(client_config);
    let mut server = QuicConnection::server(server_config);
    client.record_verified_server_identity();
    establish_loopback(&cx, &mut client, &mut server).expect("establish constrained QUIC pair");
    let mut client_h3 = NativeH3Session::client();
    let mut server_h3 = NativeH3Session::server();
    client_h3
        .initialize(&cx, &mut client, H3Settings::default())
        .expect("initialize constrained client H3");
    server_h3
        .initialize(&cx, &mut server, H3Settings::default())
        .expect("initialize constrained server H3");
    let _ = pump_h3_events(&cx, &mut client, &mut server, &mut server_h3);
    let _ = pump_h3_events(&cx, &mut server, &mut client, &mut client_h3);

    let factory_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls_for_route = Arc::clone(&factory_calls);
    let router = Router::new()
        .route(
            "/credit",
            get(AsyncCxFnHandler1::<_, Http3StreamResponder>::new(
                move |_handler_cx: Cx, responder: Http3StreamResponder| {
                    let factory_calls = Arc::clone(&factory_calls_for_route);
                    async move {
                        responder.streaming(
                            StatusCode::OK,
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(3).expect("non-zero H3 frame limit"),
                            move |producer_cx, mut sender| async move {
                                factory_calls.fetch_add(1, Ordering::SeqCst);
                                sender
                                    .send_bytes(&producer_cx, Bytes::from_static(b"abc"))
                                    .await?;
                                sender.finish(&producer_cx)?;
                                Ok(sender)
                            },
                        )
                    }
                },
            )),
        )
        .without_default_trace();
    let mut bridge = NativeH3Router::new(router);

    let stream = client_h3
        .send_request(&cx, &mut client, &request_head(), Bytes::new())
        .expect("send credit-gated request");
    let mut dispatch = None;
    for event in pump_h3_events(&cx, &mut client, &mut server, &mut server_h3).0 {
        match bridge
            .ingest_event_with_cx(&cx, &mut server_h3, &mut server, event)
            .expect("ingest credit-gated request")
        {
            NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestBuffered { .. }) => {}
            NativeH3RouterIngress::Dispatch(next) => dispatch = Some(next),
            other => panic!("unexpected credit-gated ingress: {other:?}"),
        }
    }
    let dispatch = dispatch.expect("request FIN must detach a Router dispatch");
    let prepared = match futures_lite::future::block_on(dispatch.run_produced(&cx)) {
        NativeH3RouterProducedDispatch::Produced(prepared) => prepared,
        NativeH3RouterProducedDispatch::Buffered(_) => {
            panic!("credit-gated route must retain authored plan")
        }
    };
    bridge
        .start_produced_dispatch_with_cx(&cx, &mut server_h3, &mut server, prepared)
        .expect("install credit-gated response");

    let mut task_cx = Context::from_waker(Waker::noop());
    let mut producer =
        match bridge.poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx)
        {
            Poll::Ready(Ok(NativeH3ProducedEvent::ProducerReady {
                stream_id,
                producer,
            })) => {
                assert_eq!(stream_id, stream);
                Box::pin(producer)
            }
            _ => panic!("constrained HEADERS must fit exactly before DATA blocks"),
        };
    assert!(producer.as_mut().poll(&mut task_cx).is_ready());
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::ResponseHeaders {
            stream_id: stream,
            head: H3ResponseHead::new(200, vec![]).expect("valid constrained response head"),
        }]
    );

    let stream_send_offset = server
        .inner()
        .streams()
        .stream(stream)
        .expect("response stream remains open")
        .send_offset;
    let connection_bytes_sent = 4096_u64
        .checked_sub(server.inner().streams().connection_send_remaining())
        .expect("remaining connection credit cannot exceed configured limit");
    assert_eq!(
        server
            .constrain_stream_send_limit_for_testing(&cx, stream, stream_send_offset)
            .expect("plant exact stream-credit stall"),
        stream_send_offset
    );
    assert_eq!(
        server
            .constrain_connection_send_limit_for_testing(&cx, connection_bytes_sent)
            .expect("plant exact connection-credit stall"),
        connection_bytes_sent
    );

    assert!(
        server.inner().stream_send_credit_remaining(stream) < 5,
        "test hook must exhaust the stream DATA-frame budget after HEADERS"
    );
    assert!(
        server.inner().streams().connection_send_remaining() < 5,
        "test hook must exhaust connection DATA-frame budget after HEADERS"
    );
    assert!(
        bridge
            .poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx,)
            .is_pending(),
        "the body must not dequeue while both credit scopes are short"
    );

    let advertised_stream_limit = client
        .configure_stream_receive_window(&cx, stream, 5)
        .expect("queue live MAX_STREAM_DATA");
    assert!(advertised_stream_limit >= 5);
    assert!(
        pump_h3_events(&cx, &mut client, &mut server, &mut server_h3)
            .0
            .is_empty(),
        "transport credit updates must not fabricate H3 events"
    );
    assert!(server.inner().stream_send_credit_remaining(stream) >= 5);
    assert!(server.inner().streams().connection_send_remaining() < 5);
    assert!(
        bridge
            .poll_produced_response_with_cx(&cx, &mut server_h3, &mut server, &mut task_cx,)
            .is_pending(),
        "MAX_STREAM_DATA alone must not bypass exhausted MAX_DATA"
    );

    client
        .advertise_connection_receive_limit(&cx, 69)
        .expect("queue live MAX_DATA");
    assert!(
        pump_h3_events(&cx, &mut client, &mut server, &mut server_h3)
            .0
            .is_empty(),
        "connection credit update must stay below H3"
    );
    assert!(server.inner().streams().connection_send_remaining() >= 5);
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::DataQueued {
            stream_id,
            payload_bytes: 3,
        })) if stream_id == stream
    ));
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Data {
            stream_id: stream,
            bytes: Bytes::from_static(b"abc"),
        }]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::TerminalQueued { stream_id }))
            if stream_id == stream
    ));
    assert_eq!(
        pump_h3_events(&cx, &mut server, &mut client, &mut client_h3).0,
        vec![NativeH3Event::Finished { stream_id: stream }]
    );
    assert!(matches!(
        bridge.poll_produced_response_with_cx(
            &cx,
            &mut server_h3,
            &mut server,
            &mut task_cx,
        ),
        Poll::Ready(Ok(NativeH3ProducedEvent::ResponseSent {
            stream_id,
            status: 200,
        })) if stream_id == stream
    ));
    assert_eq!(bridge.in_flight_dispatch_count(), 0);
}
