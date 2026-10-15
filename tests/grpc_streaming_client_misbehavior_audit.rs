//! Audit + regression test for `src/grpc/streaming.rs` and
//! `src/grpc/server.rs` queue/cleanup helper behavior (tick #146).
//!
//! Two structural surfaces are audited without claiming H2 integration:
//!
//!   (1) **Idle/deadline helpers**:
//!     * `ServerConfig::stream_idle_timeout` defaults to 60s and
//!       `ConnectionState::cleanup_idle_streams` removes old registrations
//!       when explicitly called. The current transport has no demonstrated
//!       periodic sweep, so this is not a default slow-loris guarantee.
//!     * `ServerConfig::max_request_deadline` caps parseable
//!       peer-supplied timeouts when set;
//!       the server default remains an independent operator choice.
//!     * Activity tracking requires an adapter to call
//!       `update_stream_activity`. When wired,
//!       periodic tiny payloads reset the idle clock, so the idle timeout is
//!       not a total-duration cap.
//!
//!   (2) **Standalone stream queues**:
//!     * `MAX_STREAM_BUFFERED = 1024` returns
//!       `Err(Status::resource_exhausted("buffer full — apply
//!       backpressure"))` on direct queue overflow. These tests do not
//!       establish that H2 flow-control stalls feed either queue.
//!     * HTTP/2 `WINDOW_UPDATE` supplies flow-control credit rather than
//!       acknowledging messages. Its transport behavior is outside this
//!       audit's scope.
//!
//! Regression tests below pin helper thresholds, explicit cleanup, queue
//! capacity, and typed errors only. They do not exercise a transport adapter,
//! wire-level flow control, or periodic wall-clock cleanup.

use asupersync::grpc::ResponseStream;
use asupersync::grpc::server::{ConnectionState, ServerConfig};
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::StreamingRequest;
use std::time::Duration;

/// Documented cap as of 2026-04-29.
const DOCUMENTED_BUFFER_CAP: usize = 1024;

#[test]
fn default_idle_cleanup_threshold_is_60s() {
    // Pin (1) configured helper threshold only.
    let config = ServerConfig::default();
    assert_eq!(
        config.stream_idle_timeout,
        Some(Duration::from_secs(60)),
        "ServerConfig::default() must keep the documented 60s helper threshold",
    );
}

#[test]
fn explicit_idle_cleanup_removes_streams_at_zero_threshold() {
    // Pin (1) helper correctness: when explicitly called with a 0-duration
    // idle threshold, EVERY active stream is removed (every
    // stream is "older than 0 seconds" because the wall clock has
    // moved at least one ns since the stream was added). This is
    // the model-level contract that the ConnectionState fuzz
    // target (grpc_server_idle_timeout_state_machine) also pins.
    let state = ConnectionState::new();
    let mut newest_registration = None;
    for stream_id in 0..8u32 {
        newest_registration = Some(state.add_stream(stream_id, 16).expect("under cap"));
    }
    let newest_registration = newest_registration.expect("at least one stream registered");
    while std::time::Instant::now() <= newest_registration {
        std::thread::yield_now();
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
fn streaming_request_queue_caps_at_1024() {
    // Pin (2): direct producer pushes past MAX_STREAM_BUFFERED return the
    // typed back-pressure signal. No H2 WINDOW_UPDATE behavior is exercised.
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
        "standalone queue overflow must surface ResourceExhausted",
    );
    assert!(
        err.message().contains("buffer full") || err.message().contains("backpressure"),
        "back-pressure message must contain a log-grep'able hint; got {:?}",
        err.message(),
    );
}

#[test]
fn response_stream_queue_caps_at_1024() {
    // Pin (2): direct response-queue pushes have the same capacity. This does
    // not prove that an undrained H2 wire causes this queue to fill.
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
fn server_max_request_deadline_configures_peer_timeout_cap() {
    // Pin that the peer-timeout cap is configurable. It bounds valid
    // grpc-timeout values but is not a universal wall-clock ceiling:
    // default_timeout is an independent operator-selected fallback.
    let config = ServerConfig {
        max_request_deadline: Some(Duration::from_secs(30)),
        ..ServerConfig::default()
    };
    assert_eq!(
        config.max_request_deadline,
        Some(Duration::from_secs(30)),
        "max_request_deadline (tick #139) must preserve the configured \
         peer-timeout cap",
    );
}

#[test]
fn buffer_cap_is_per_stream_instance() {
    // Pin (2) isolation: exhausting one stream's buffer does not consume
    // capacity from a newly opened stream.
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..(DOCUMENTED_BUFFER_CAP as u32) {
        stream.push(i).expect("fill");
    }
    stream
        .push(DOCUMENTED_BUFFER_CAP as u32)
        .expect_err("at-cap rejects");

    let mut fresh = StreamingRequest::<u32>::open();
    fresh
        .push(0)
        .expect("a fresh stream starts at 0 — cap is per-instance");
}
