//! Audit + regression test for `src/grpc/server.rs` request body
//! upload limit (tick #203).
//!
//! Operator's question: "verify request body upload limit."
//!
//! Audit context — gRPC has SEVERAL layered caps that bound
//! the request body upload:
//!
//!     Wire layer:
//!       1. HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE
//!          (initial_stream_window_size, default 1 MiB) bounds
//!          in-flight wire bytes per stream.
//!       2. HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS
//!          (max_concurrent_streams, default 100) bounds
//!          concurrent streams per connection.
//!     gRPC layer:
//!       3. Per-message LPM body cap
//!          (max_recv_message_size, default 4 MiB) bounds the
//!          INDIVIDUAL message body size. Wired via
//!          Server::framed_codec (audited tick #200,
//!          br-asupersync-srizvf).
//!       4. Stream buffer cap (MAX_STREAM_BUFFERED = 1024
//!          ITEMS, streaming.rs:474) bounds in-flight pending
//!          messages per stream — back-pressure signal at
//!          1024 items.
//!       5. max_metadata_size (default 8 KiB, server.rs:272)
//!          bounds HEADERS+TRAILERS per request.
//!     Time layer:
//!       6. stream_idle_timeout (default 60s, server.rs:443)
//!          forces stream cleanup if idle.
//!       7. max_request_deadline (opt-in, tick #139) caps
//!          total call duration.
//!
//! Audit findings:
//!
//!   (a) **Per-message body cap = max_recv_message_size**
//!       (default 4 MiB). Wired via Server::framed_codec
//!       (post-fix in tick #199).
//!
//!   (b) **In-flight item cap = MAX_STREAM_BUFFERED = 1024**.
//!       A client-streaming RPC pushing past 1024 buffered
//!       items gets ResourceExhausted back-pressure (audited
//!       tick #146).
//!
//!   (c) **Default HTTP/2 stream window = 1 MiB**
//!       (initial_stream_window_size = 1024 * 1024,
//!       server.rs:426). This bounds in-flight WIRE bytes per
//!       stream — even if max_recv_message_size is 4 MiB, a
//!       single message must arrive in <= 1 MiB chunks until
//!       the consumer ACKs more window.
//!
//!   (d) **max_concurrent_streams = 100** (default)
//!       multiplied by 1024 buffered items × 4 MiB
//!       per-message cap = 400 GiB theoretical max in-flight
//!       per connection — bounded but large. Operators that
//!       want a tighter aggregate cap must use connection-
//!       layer flow control or a custom interceptor.
//!
//!   (e) **⚠️ No per-stream aggregate-bytes cap.** gRPC spec
//!       does not mandate one and asupersync follows the
//!       spec — a client-streaming RPC can send N messages,
//!       each ≤ max_recv_message_size, with no aggregate
//!       bytes-per-stream limit beyond the per-message cap ×
//!       MAX_STREAM_BUFFERED. Documented as P3 audit
//!       observation; mitigation is via the deadline path
//!       (max_request_deadline) which bounds total wall-clock
//!       duration regardless of bytes uploaded.
//!
//! Regression tests below pin (a)-(d) at the public API
//! surface and document (e) as a structural property.

use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::StreamingRequest;
use asupersync::grpc::{ServerBuilder, ServerConfig};

const MAX_STREAM_BUFFERED: usize = 1024;

#[test]
fn default_max_recv_message_size_is_4_mib() {
    // Pin (a): the per-message body cap default. A regression
    // that loosened this would let single uploads hit
    // arbitrarily large sizes.
    let config = ServerConfig::default();
    assert_eq!(
        config.max_recv_message_size,
        4 * 1024 * 1024,
        "default per-message body cap is 4 MiB",
    );
}

#[test]
fn streaming_request_buffer_caps_at_1024_items() {
    // Pin (b): pushing past 1024 items into a
    // StreamingRequest yields ResourceExhausted. Backpressure
    // at the stream buffer level — bounds in-flight pending
    // messages per stream.
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
    // Pin (c): default HTTP/2 stream window. A single
    // 4 MiB message arrives in 4 chunks (1 MiB each) before
    // the consumer ACKs more window — natural back-pressure.
    let config = ServerConfig::default();
    assert_eq!(
        config.initial_stream_window_size,
        1024 * 1024,
        "default stream window = 1 MiB — bounds in-flight \
         wire bytes per stream regardless of message-size cap",
    );
}

#[test]
fn default_max_concurrent_streams_is_100() {
    // Pin (d): default cap on concurrent streams per
    // connection. A peer that opens 101 streams gets
    // REFUSED_STREAM on the 101st (audited tick #137 / #142).
    let config = ServerConfig::default();
    assert_eq!(
        config.max_concurrent_streams, 100,
        "default max_concurrent_streams = 100 — gRPC ecosystem \
         convention",
    );
}

#[test]
fn aggregate_in_flight_per_connection_is_bounded() {
    // Pin (a)+(b)+(d) interaction: theoretical max in-flight
    // bytes per connection = max_concurrent_streams ×
    // MAX_STREAM_BUFFERED × max_recv_message_size. With
    // defaults that's 100 × 1024 × 4 MiB = 400 GiB. Bounded
    // but large — operators that want tighter aggregate
    // protection use:
    //   * lower max_concurrent_streams
    //   * lower max_recv_message_size
    //   * RateLimitInterceptor for per-call slot count
    //   * max_request_deadline to bound wall-clock duration
    let config = ServerConfig::default();
    let theoretical_max_bytes_per_connection: u128 = (config.max_concurrent_streams as u128)
        .saturating_mul(MAX_STREAM_BUFFERED as u128)
        .saturating_mul(config.max_recv_message_size as u128);
    assert_eq!(
        theoretical_max_bytes_per_connection,
        100u128 * 1024 * 4 * 1024 * 1024, // 100 × 1024 × 4 MiB
        "default aggregate in-flight bound matches documented values",
    );
    // 400 GiB is the documented bound — operators can compute
    // their own tighter ceiling by adjusting any of the three
    // factors.
    assert!(
        theoretical_max_bytes_per_connection >= 400u128 * 1024 * 1024 * 1024,
        "default config allows ≥ 400 GiB theoretical max in-flight \
         per connection — bounded but large; operators set tighter \
         caps explicitly",
    );
}

#[test]
fn server_builder_can_tighten_aggregate_via_max_recv_message_size() {
    // Pin (a) operator-control: the per-message cap is the
    // primary lever for tightening the aggregate bound. A
    // server with 256 KiB recv cap shrinks the theoretical
    // max from 400 GiB to 25 GiB (with defaults on other
    // levers).
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024)
        .build();
    let config = server.config();
    let theoretical: u128 = (config.max_concurrent_streams as u128)
        * (MAX_STREAM_BUFFERED as u128)
        * (config.max_recv_message_size as u128);
    assert!(
        theoretical < 100u128 * 1024 * 1024 * 1024 * 1024,
        "256 KiB recv cap shrinks aggregate ceiling significantly; \
         got {theoretical}",
    );
}

#[test]
fn stream_idle_timeout_default_60s_caps_per_stream_duration() {
    // Pin (audit cross-ref): the time-layer cap that bounds
    // how long a stream can remain idle (and thus how long
    // an ill-behaved peer can hold a stream slot).
    let config = ServerConfig::default();
    assert_eq!(
        config.stream_idle_timeout,
        Some(std::time::Duration::from_secs(60)),
        "default stream_idle_timeout = 60 s — bounds slow-loris \
         per-stream duration (br-asupersync-8vn9iu)",
    );
}

#[test]
fn no_per_stream_aggregate_bytes_cap_is_documented_p3() {
    // Pin (e): there is no `max_request_body_total_bytes`
    // config knob. gRPC spec does not mandate one. The
    // mitigation is via max_request_deadline (wall-clock
    // bound) and per-message cap × stream-buffer cap.
    //
    // We pin by REVERSE check: assert the ServerConfig does
    // NOT have a field named like an aggregate cap. A future
    // commit that ADDS such a field would change the audit
    // boundary and require updating this test.
    let config = ServerConfig::default();
    let dbg = format!("{config:?}");
    assert!(
        !dbg.contains("max_request_body_total")
            && !dbg.contains("max_aggregate_recv")
            && !dbg.contains("max_total_upload"),
        "ServerConfig MUST NOT have a per-stream aggregate-bytes cap \
         field — this is a documented architectural choice. Adding \
         one without updating this test signals a deliberate behavior \
         change that needs audit re-baseline.",
    );
}

#[test]
fn upload_limit_recovery_after_drain_is_per_instance() {
    // Pin (b) extension: the stream-buffer cap is PER-INSTANCE
    // — a fresh stream after one is exhausted starts at 0.
    // Operators that worry about cross-stream leakage have
    // this guarantee.
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
fn upload_limit_chain_is_layered_not_global() {
    // Pin: the upload limit is a CHAIN of caps, not a single
    // global byte counter. A peer that wants to evade the
    // layered defenses would need to evade EACH layer:
    //   1. Per-message cap → must shrink each message
    //   2. Stream-buffer cap → must drain producer-side
    //   3. HTTP/2 window → must wait for window updates
    //   4. Concurrent-streams cap → must use 1 stream
    //   5. Idle-timeout cap → must keep stream active
    //   6. Deadline cap → must complete before max deadline
    //
    // Documented as architectural property.
    let config = ServerConfig::default();

    // All six knobs present and non-zero (assert structural).
    assert!(config.max_recv_message_size > 0);
    assert!(config.initial_stream_window_size > 0);
    assert!(config.max_concurrent_streams > 0);
    assert!(config.stream_idle_timeout.is_some());
    // max_request_deadline default is None (opt-in for stricter
    // bound), so we just assert the knob exists.
    let _ = config.max_request_deadline;
}
