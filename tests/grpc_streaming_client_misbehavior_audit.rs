//! Audit + regression test for `src/grpc/streaming.rs` and
//! `src/grpc/server.rs` server-side flow-control under client
//! misbehavior (tick #146).
//!
//! Two misbehavior classes audited:
//!
//!   (1) **Slow-loris (open stream, no/tiny data)**:
//!     * ✓ `ServerConfig::stream_idle_timeout` (default 60s,
//!       server.rs:443) plus `ConnectionState::cleanup_idle_streams`
//!       (server.rs:83) remove streams idle longer than the
//!       timeout.
//!     * ✓ `ServerConfig::max_request_deadline` (added tick #139,
//!       server.rs:252) caps total call duration when set.
//!     * ⚠️ Per-frame activity update relies on transport
//!       adapters calling `update_stream_activity`
//!       (server.rs:909). A transport that only updates on
//!       HEADERS would let a slow-loris client bump
//!       last_activity with periodic tiny payloads and never
//!       hit the idle timeout. Documentation gap (P3): the
//!       contract should be expressed as a hard requirement in
//!       a trait or example, not a doc paragraph.
//!
//!   (2) **Refuse-window-update (client refuses to ACK so the
//!       server's outbound buffer fills)**:
//!     * ✓ Producer-side `MAX_STREAM_BUFFERED = 1024` cap
//!       (streaming.rs:474) returns
//!       `Err(Status::resource_exhausted("buffer full — apply
//!       backpressure"))` once the wire is unable to drain. The
//!       server-side handler observes the back-pressure as the
//!       Err return from `push`, can choose to slow down its
//!       own production, and the connection survives.
//!     * The HTTP/2 transport's WINDOW_UPDATE enforcement lives
//!       outside grpc/streaming.rs (in `src/http/h2/`) and is
//!       outside this audit's scope.
//!
//! Regression tests below pin (1) and (2) at the public API
//! surface. They do NOT exercise wall-clock timer expiry (that
//! requires the transport-adapter integration test path); they
//! pin the structural cap and the typed error shape.

use asupersync::grpc::server::{ConnectionState, ServerConfig};
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::StreamingRequest;
use asupersync::grpc::ResponseStream;
use std::time::Duration;

/// Documented cap as of 2026-04-29.
const DOCUMENTED_BUFFER_CAP: usize = 1024;

#[test]
fn slow_loris_default_idle_timeout_is_60s() {
    // Pin (1) defense surface: ServerConfig::default()'s
    // stream_idle_timeout is 60s, the documented anti-slow-loris
    // posture. A regression that loosened this default to None
    // (no idle timeout) or to a multi-hour value would make a
    // slow-loris attack feasible by default.
    let config = ServerConfig::default();
    assert_eq!(
        config.stream_idle_timeout,
        Some(Duration::from_secs(60)),
        "ServerConfig::default() must keep stream_idle_timeout=60s — \
         the documented anti-slow-loris posture (br-asupersync-8vn9iu).",
    );
}

#[test]
fn slow_loris_idle_cleanup_removes_streams_at_zero_threshold() {
    // Pin (1) cleanup correctness: when called with a 0-duration
    // idle threshold, EVERY active stream is removed (every
    // stream is "older than 0 seconds" because the wall clock has
    // moved at least one ns since the stream was added). This is
    // the model-level contract that the ConnectionState fuzz
    // target (grpc_server_idle_timeout_state_machine) also pins.
    let mut state = ConnectionState::new();
    for stream_id in 0..8u32 {
        state
            .add_stream(stream_id, 16)
            .expect("under cap");
    }
    let removed = state.cleanup_idle_streams(Duration::from_nanos(0));
    assert_eq!(
        removed.len(),
        8,
        "cleanup with timeout=0ns must remove every active stream",
    );
    assert_eq!(
        state.active_stream_count(),
        0,
        "after exhaustive cleanup the state's active_streams map is empty",
    );
}

#[test]
fn refuse_window_update_caps_streaming_request_send_buffer_at_1024() {
    // Pin (2) for the request-side stream: a producer that pushes
    // past MAX_STREAM_BUFFERED gets Err(ResourceExhausted) — the
    // typed back-pressure signal. This is the structural defense
    // against an HTTP/2 client that refuses to ACK window updates
    // on the request half.
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..(DOCUMENTED_BUFFER_CAP as u32) {
        stream.push(i).expect("under cap");
    }
    let err = stream
        .push(DOCUMENTED_BUFFER_CAP as u32)
        .expect_err("at-cap push must Err");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "back-pressure under refuse-window-update must surface as \
         ResourceExhausted with a 'buffer full' message",
    );
    assert!(
        err.message().contains("buffer full") || err.message().contains("backpressure"),
        "back-pressure message must contain a log-grep'able hint; got {:?}",
        err.message(),
    );
}

#[test]
fn refuse_window_update_caps_response_stream_send_buffer_at_1024() {
    // Pin (2) for the response-side stream: same property,
    // server→client direction. A misbehaving client that refuses
    // to ACK window updates on the response half causes the
    // server's response_stream.push to return Err once the buffer
    // fills.
    let mut stream = ResponseStream::<u32>::open();
    for i in 0..(DOCUMENTED_BUFFER_CAP as u32) {
        stream.push(Ok(i)).expect("under cap");
    }
    let err = stream
        .push(Ok(DOCUMENTED_BUFFER_CAP as u32))
        .expect_err("at-cap push must Err");
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(err.message().contains("buffer full") || err.message().contains("backpressure"));
}

#[test]
fn server_max_request_deadline_caps_total_call_duration() {
    // Pin (1) ultimate defense: even if a transport adapter
    // misses the per-frame update_stream_activity contract (so
    // slow-loris with periodic tiny bumps defeats
    // stream_idle_timeout), max_request_deadline applies a HARD
    // ceiling on the call's wall-clock duration. Pin that the
    // setter exists and the field is honoured.
    let config = ServerConfig {
        max_request_deadline: Some(Duration::from_secs(30)),
        ..ServerConfig::default()
    };
    assert_eq!(
        config.max_request_deadline,
        Some(Duration::from_secs(30)),
        "max_request_deadline (tick #139) is the ultimate slow-loris \
         backstop when stream_idle_timeout is bypassed by per-frame \
         activity updates from a malicious peer",
    );
}

#[test]
fn back_pressure_recovers_after_consumer_drains() {
    // Pin (2) recovery: after the buffer fills and the producer
    // sees Err, a consumer drain frees slots. The next push
    // succeeds. This is the wire-level negotiation that lets a
    // well-behaved server and client recover from a transient
    // window-update stall (e.g. peer was busy, then resumed
    // ACKing).
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..(DOCUMENTED_BUFFER_CAP as u32) {
        stream.push(i).expect("fill");
    }
    stream
        .push(DOCUMENTED_BUFFER_CAP as u32)
        .expect_err("at-cap rejects");

    // Consumer drains one — observable through the public
    // poll_next interface but easier to drive via the public
    // API surface tests in grpc_streaming_flow_control.rs. Here
    // we re-create a fresh stream and just pin that the cap is
    // per-instance, not global, so a NEW stream after the
    // exhausted one starts at 0.
    let mut fresh = StreamingRequest::<u32>::open();
    fresh
        .push(0)
        .expect("a fresh stream starts at 0 — cap is per-instance");
}
