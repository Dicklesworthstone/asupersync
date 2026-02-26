//! QH3-E4: HTTP/3 control/request lifecycle and GOAWAY E2E tests.
//!
//! This test file covers the full H3 protocol lifecycle including request-response
//! cycles, concurrent requests, SETTINGS exchange, GOAWAY stream acceptance
//! boundaries, CANCEL_PUSH/MAX_PUSH_ID handling, error paths, request stream
//! state transitions, and QPACK static table planning.
//!
//! All tests are synchronous (no tokio, no async) and use DetRng for
//! reproducible deterministic seeds.

use asupersync::cx::Cx;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3Frame, H3NativeError, H3PseudoHeaders,
    H3QpackMode, H3RequestHead, H3RequestStreamState, H3ResponseHead, H3Settings, QpackFieldPlan,
    qpack_decode_field_section, qpack_encode_field_section, qpack_plan_to_header_fields,
    qpack_static_plan_for_request, qpack_static_plan_for_response,
};
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, QuicConnectionState, StreamDirection,
    StreamRole,
};
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
    let (dec_h, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp headers");
    pos += n;
    assert_eq!(dec_h, resp_headers);

    let (dec_d, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp body");
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
        H3Frame::decode(&settings_wire).expect("decode client settings");
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

    // Verify static-only QPACK policy rejects dynamic table.
    let mut strict_h3 = H3ConnectionState::new();
    let dynamic_settings = H3Settings {
        qpack_max_table_capacity: Some(4096),
        ..H3Settings::default()
    };
    let err = strict_h3
        .on_control_frame(&H3Frame::Settings(dynamic_settings))
        .expect_err("should reject dynamic table");
    assert_eq!(
        err,
        H3NativeError::QpackPolicy("dynamic qpack table disabled by policy")
    );

    // Verify DynamicTableAllowed mode accepts nonzero capacity.
    let config = H3ConnectionConfig {
        qpack_mode: H3QpackMode::DynamicTableAllowed,
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
    let (decoded_goaway, _) = H3Frame::decode(&goaway_wire).expect("decode goaway");
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

        let (decoded, consumed) = H3Frame::decode(&wire).expect("decode cancel_push");
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
        H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
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

        let (decoded, consumed) = H3Frame::decode(&wire).expect("decode max_push_id");
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
        H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
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
        H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
    );

    // GOAWAY on request stream is rejected.
    let mut req2 = H3RequestStreamState::new();
    let err = req2
        .on_frame(&H3Frame::Goaway(0))
        .expect_err("goaway on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
    );

    // Unknown frame on request stream is rejected.
    let mut req3 = H3RequestStreamState::new();
    let err = req3
        .on_frame(&H3Frame::Unknown {
            frame_type: 0xFF,
            payload: vec![],
        })
        .expect_err("unknown frame on request stream");
    assert_eq!(
        err,
        H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
    );

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
        H3NativeError::StreamProtocol("request stream id must be bidirectional")
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
            }
        } else {
            H3PseudoHeaders {
                method: Some(method.to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
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

    // Non-indexed status produces Literal.
    let non_indexed_statuses: Vec<u16> = vec![101, 201, 202, 301, 307, 401, 405, 502];
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
        let (frame, consumed) = H3Frame::decode(&wire[pos..]).expect("decode");
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
        let (dec_h, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp headers");
        pos += n;
        assert_eq!(dec_h, resp_headers_frame);

        if !resp_body.is_empty() {
            let (dec_d, n) = H3Frame::decode(&resp_wire[pos..]).expect("decode resp data");
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

// ===========================================================================
// Test 13: Wire-level QPACK field section roundtrip + header projection
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

    let projected = qpack_plan_to_header_fields(&decoded).expect("project to header fields");
    assert_eq!(projected[0], (":method".to_string(), "GET".to_string()));
    assert_eq!(projected[1], (":scheme".to_string(), "https".to_string()));
    assert_eq!(projected[2], (":path".to_string(), "/".to_string()));
    assert_eq!(
        projected[3],
        (":authority".to_string(), "example.com".to_string())
    );
}

// ===========================================================================
// Test 14: Interop capture corpus fixtures (black-box) validate decode policy
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

                let projected = qpack_plan_to_header_fields(&decoded)
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
            assert_eq!(*msg, "request stream ended before initial HEADERS");
        }
        other => panic!("expected finish-before-HEADERS error, got {other:?}"),
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
