//! Audit + regression test for `src/grpc/server.rs` request body
//! upload limit (tick #203).
//!
//! Operator's question: "verify request body upload limit."
//!
//! Audit result: the public server surface contains several configuration
//! values and helper types associated with upload control, but they do not
//! currently compose into a proven production transport bound:
//!
//!     Configuration/helper seams:
//!       1. HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE
//!          (`initial_stream_window_size`, default 1 MiB) is stored on
//!          `ServerConfig`; no current server-to-H2 bridge consumes it.
//!       2. HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS
//!          (`max_concurrent_streams`, default 100) is enforced by the
//!          `ConnectionState` helper path, but that wrapped dispatch has no
//!          production callsite today.
//!       3. Per-message LPM body cap
//!          (`max_recv_message_size`, default 4 MiB) configures
//!          `Server::framed_codec`; the helper has no current production
//!          transport callsite.
//!       4. Stream buffer cap (MAX_STREAM_BUFFERED = 1024
//!          items) is live on standalone `StreamingRequest` instances, but
//!          this audit does not prove an H2 transport feeds that queue.
//!       5. `stream_idle_timeout` configures a cleanup helper. Cleanup runs
//!          when explicitly invoked (and during later stream admission), not
//!          from a demonstrated periodic production sweep.
//!       6. `max_request_body_bytes` (opt-in) configures a
//!          RequestBodyMeter, but the built-in dispatch/streaming paths
//!          do not currently instantiate it automatically.
//!
//! Audit findings:
//!
//!   (a) **`max_recv_message_size` defaults to 4 MiB.** This is a
//!       configuration/codec-helper contract, not transport proof.
//!
//!   (b) **Standalone queue cap = MAX_STREAM_BUFFERED = 1024.**
//!       Directly pushing past 1024 items on `StreamingRequest` returns
//!       `ResourceExhausted`; no wire-path claim follows from that test.
//!
//!   (c) **`initial_stream_window_size` defaults to 1 MiB.** The test
//!       pins the stored value only; it does not prove emitted H2 settings.
//!
//!   (d) **`max_concurrent_streams` defaults to 100.** Multiplying
//!       stored values yields 400 GiB, but that arithmetic is not a live
//!       per-connection bound unless all three controls share a wired path.
//!
//!   (e) **Per-call aggregate helper is opt-in and not yet wired.**
//!       The `max_request_body_bytes` setting and `RequestBodyMeter`
//!       provide the ingredients for a decoded-byte ceiling. An adapter
//!       must explicitly construct and call the meter; configuring the
//!       field alone is not a built-in upload defense today.
//!
//! Regression tests below pin configuration/helper behavior only. They
//! deliberately make no H2 transport, aggregate-memory, or production
//! enforcement claim.

use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::StreamingRequest;
use asupersync::grpc::{ServerBuilder, ServerConfig};

const MAX_STREAM_BUFFERED: usize = 1024;

#[test]
fn default_max_recv_message_size_is_4_mib() {
    // Pin (a): stored codec-helper configuration only.
    let config = ServerConfig::default();
    assert_eq!(
        config.max_recv_message_size,
        4 * 1024 * 1024,
        "default max_recv_message_size configuration is 4 MiB",
    );
}

#[test]
fn streaming_request_buffer_caps_at_1024_items() {
    // Pin (b): the standalone in-memory queue rejects its 1025th item.
    // This test does not assert that a production H2 transport owns or
    // drains this exact instance.
    let mut stream = StreamingRequest::<u32>::open();
    for i in 0..MAX_STREAM_BUFFERED as u32 {
        stream.push(i).expect("under cap");
    }
    let err = stream
        .push(MAX_STREAM_BUFFERED as u32)
        .expect_err("at-cap push must reject");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "in-flight item cap rejection is ResourceExhausted — \
         the canonical back-pressure signal",
    );
    assert!(
        err.message().contains("buffer full") || err.message().contains("backpressure"),
        "rejection message is operator-grep'able; got {:?}",
        err.message(),
    );
}

#[test]
fn default_initial_stream_window_size_is_1_mib() {
    // Pin (c): stored configuration value only. No transport setting frame
    // or flow-control behavior is exercised here.
    let config = ServerConfig::default();
    assert_eq!(
        config.initial_stream_window_size,
        1024 * 1024,
        "default initial_stream_window_size configuration is 1 MiB",
    );
}

#[test]
fn default_max_concurrent_streams_is_100() {
    // Pin (d): stored configuration value only. This test does not drive a
    // production H2 peer or assert REFUSED_STREAM behavior.
    let config = ServerConfig::default();
    assert_eq!(
        config.max_concurrent_streams, 100,
        "default max_concurrent_streams = 100 — gRPC ecosystem \
         convention",
    );
}

#[test]
fn configured_limit_product_is_400_gib_but_not_transport_proof() {
    // Pin arithmetic over three independently stored/helper values. The
    // result is NOT asserted as a live in-flight bound because this audit
    // has not established a common production transport path.
    let config = ServerConfig::default();
    let theoretical_max_bytes_per_connection: u128 = (config.max_concurrent_streams as u128)
        .saturating_mul(MAX_STREAM_BUFFERED as u128)
        .saturating_mul(config.max_recv_message_size as u128);
    assert_eq!(
        theoretical_max_bytes_per_connection,
        100u128 * 1024 * 4 * 1024 * 1024, // 100 × 1024 × 4 MiB
        "stored defaults multiply to the documented 400 GiB value",
    );
}

#[test]
fn server_builder_changes_configured_limit_product() {
    // Pin that the builder updates the configuration arithmetic. This is not
    // evidence that a production transport consumes the value.
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024)
        .build();
    let config = server.config();
    let theoretical: u128 = (config.max_concurrent_streams as u128)
        * (MAX_STREAM_BUFFERED as u128)
        * (config.max_recv_message_size as u128);
    assert_eq!(
        theoretical,
        25u128 * 1024 * 1024 * 1024,
        "100 × 1024 × 256 KiB must equal the exact 25 GiB stored-value product",
    );
}

#[test]
fn default_stream_idle_timeout_is_60s() {
    // Pin the configured helper threshold. No periodic transport sweep is
    // exercised, and activity resets the clock when the helper is wired.
    let config = ServerConfig::default();
    assert_eq!(
        config.stream_idle_timeout,
        Some(std::time::Duration::from_secs(60)),
        "default stream_idle_timeout helper threshold is 60 s",
    );
}

#[test]
fn aggregate_request_body_meter_configuration_is_available_and_opt_in() {
    // Pin (e): the aggregate meter configuration exists and remains opt-in.
    // This structural test does not claim that built-in transport uses it.
    let default_config = ServerConfig::default();
    assert_eq!(default_config.max_request_body_bytes, None);

    let server = ServerBuilder::new().max_request_body_bytes(4096).build();
    assert_eq!(
        server.config().max_request_body_bytes,
        Some(4096),
        "builder must expose the per-call RequestBodyMeter configuration",
    );
}

#[test]
fn upload_limit_is_per_stream_instance() {
    // Pin (b) extension: the stream-buffer cap is PER-INSTANCE
    // — a fresh stream after one is exhausted starts at 0.
    // Users of this standalone queue type get this isolation.
    let mut full = StreamingRequest::<u32>::open();
    for i in 0..MAX_STREAM_BUFFERED as u32 {
        full.push(i).expect("fill");
    }
    full.push(MAX_STREAM_BUFFERED as u32)
        .expect_err("at-cap rejects");

    let mut fresh = StreamingRequest::<u32>::open();
    fresh
        .push(0)
        .expect("a fresh stream starts at 0 — cap is per-instance");
}

#[test]
fn upload_control_configuration_seams_remain_independent() {
    // Pin presence/defaults only. These fields and helpers are independent;
    // this test intentionally does not call them a live defense chain.
    let config = ServerConfig::default();

    // Core layering knobs are present (assert structural).
    assert!(config.max_recv_message_size > 0);
    assert!(config.initial_stream_window_size > 0);
    assert!(config.max_concurrent_streams > 0);
    assert!(config.stream_idle_timeout.is_some());
    assert!(config.max_request_body_bytes.is_none());
    assert!(config.default_timeout.is_none());
    // max_request_deadline is also opt-in, so assert the knob exists.
    let _ = config.max_request_deadline;
}
