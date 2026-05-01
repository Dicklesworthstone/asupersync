//! Audit + regression test for `src/grpc/server.rs` aggregate
//! request-body cap (tick #204, P3 fix from tick #203).
//!
//! Operator's question: "verify aggregate request-body cap (P3
//! fix)." Closes the no-aggregate-cap finding from tick #203.
//!
//! Audit context — pre-fix the only upload bounds were:
//!   * Per-message LPM body cap (max_recv_message_size).
//!   * In-flight item count cap (MAX_STREAM_BUFFERED = 1024).
//!   * HTTP/2 stream window (1 MiB default).
//!   * Wall-clock cap (max_request_deadline, opt-in).
//!
//! Theoretical max in-flight per stream was thus
//! 1024 × max_recv_message_size = 4 GiB (default 4 MiB cap),
//! and the spec doesn't bound aggregate bytes per stream.
//!
//! Fix: add `ServerConfig::max_request_body_bytes: Option<usize>`
//! and a `RequestBodyMeter` helper that transport adapters
//! instantiate per-call and increment after each message decode.
//!
//! Audit findings, post-fix:
//!
//!   (a) **`max_request_body_bytes` defaults to None** — pre-fix
//!       behavior preserved; opt-in for stricter ceiling.
//!   (b) **`ServerBuilder::max_request_body_bytes(size)`** sets
//!       the cap.
//!   (c) **`RequestBodyMeter::from_config(&config)`** wires the
//!       per-call meter from the server config.
//!   (d) **`record_message_bytes(n)`** accumulates and rejects
//!       at `total > cap` with `Status::resource_exhausted`.
//!   (e) **None-cap meter records but never rejects** — preserves
//!       pre-fix behavior under default config.
//!   (f) **Saturating accumulator** — `usize::MAX` argument
//!       cannot wrap past the cap check.
//!   (g) **Error message includes both actual and cap** for SRE
//!       diagnostics.
//!   (h) **Per-call instance** — operators that maintain a
//!       meter per stream don't accidentally share state.
//!
//! Regression tests below pin (a)-(h).

use asupersync::grpc::server::RequestBodyMeter;
use asupersync::grpc::status::Code;
use asupersync::grpc::{ServerBuilder, ServerConfig};

#[test]
fn default_server_config_has_no_aggregate_cap() {
    // Pin (a): default is None — pre-fix behavior preserved.
    let config = ServerConfig::default();
    assert!(
        config.max_request_body_bytes.is_none(),
        "default max_request_body_bytes is None — opt-in only",
    );
}

#[test]
fn server_builder_max_request_body_bytes_sets_cap() {
    // Pin (b): the builder method stores the value.
    let server = ServerBuilder::new()
        .max_request_body_bytes(2 * 1024 * 1024)
        .build();
    assert_eq!(
        server.config().max_request_body_bytes,
        Some(2 * 1024 * 1024),
        "max_request_body_bytes builder stores the cap",
    );
}

#[test]
fn request_body_meter_from_config_inherits_cap() {
    // Pin (c): from_config wires the per-call meter from the
    // configured server cap.
    let server = ServerBuilder::new()
        .max_request_body_bytes(1024 * 1024)
        .build();
    let meter = RequestBodyMeter::from_config(server.config());
    assert_eq!(meter.cap(), Some(1024 * 1024));
    assert_eq!(meter.bytes_accumulated(), 0);
}

#[test]
fn request_body_meter_records_and_accumulates_under_cap() {
    // Pin (d) success path: under-cap pushes accumulate and
    // succeed.
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter.record_message_bytes(256).expect("256 bytes OK");
    meter.record_message_bytes(512).expect("768 total OK");
    meter.record_message_bytes(255).expect("1023 total OK");
    assert_eq!(meter.bytes_accumulated(), 1023);
}

#[test]
fn request_body_meter_rejects_at_cap_plus_one_with_resource_exhausted() {
    // Pin (d) rejection path: total > cap surfaces
    // ResourceExhausted with both values in message.
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter.record_message_bytes(512).expect("under cap");
    let err = meter
        .record_message_bytes(513)
        .expect_err("512+513 = 1025 > 1024, rejects");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "aggregate-cap rejection MUST be ResourceExhausted",
    );
    let msg = err.message();
    assert!(
        msg.contains("max_request_body_bytes"),
        "error message references the config knob; got {msg}",
    );
    assert!(
        msg.contains("1025") && msg.contains("1024"),
        "error message includes both actual and cap; got {msg}",
    );
}

#[test]
fn request_body_meter_at_exact_cap_succeeds() {
    // Pin (d) boundary: total == cap is OK (strict `>`
    // rejection).
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter
        .record_message_bytes(1024)
        .expect("at-cap exactly is OK (strict > boundary)");
    assert_eq!(meter.bytes_accumulated(), 1024);
}

#[test]
fn request_body_meter_with_none_cap_never_rejects() {
    // Pin (e): None cap records but never rejects — pre-fix
    // behavior preserved.
    let mut meter = RequestBodyMeter::new(None);
    meter
        .record_message_bytes(usize::MAX / 2)
        .expect("None cap accepts huge");
    meter
        .record_message_bytes(usize::MAX / 2)
        .expect("None cap accepts second huge");
    // Saturating accumulator still doesn't reject under None.
    assert!(meter.bytes_accumulated() > 0);
}

#[test]
fn request_body_meter_saturates_on_usize_max_argument() {
    // Pin (f): a peer that somehow triggers a usize::MAX byte
    // count cannot wrap the accumulator past the cap-check.
    // Saturating add caps at usize::MAX.
    let mut meter = RequestBodyMeter::new(Some(1024));
    let err = meter
        .record_message_bytes(usize::MAX)
        .expect_err("usize::MAX rejects");
    assert_eq!(err.code(), Code::ResourceExhausted);
    // Accumulator saturated at usize::MAX (NOT wrapped to 0
    // or some smaller value).
    assert_eq!(meter.bytes_accumulated(), usize::MAX);
}

#[test]
fn request_body_meter_per_call_instance_independence() {
    // Pin (h): two meters from the same config are
    // independent — adapters that maintain one per stream
    // don't share state.
    let server = ServerBuilder::new().max_request_body_bytes(1024).build();
    let mut meter_a = RequestBodyMeter::from_config(server.config());
    let mut meter_b = RequestBodyMeter::from_config(server.config());

    meter_a.record_message_bytes(800).expect("a OK");
    meter_b.record_message_bytes(800).expect("b OK");

    // a is at 800; b is at 800. Both independently can take
    // 224 more before rejecting.
    assert_eq!(meter_a.bytes_accumulated(), 800);
    assert_eq!(meter_b.bytes_accumulated(), 800);

    meter_a
        .record_message_bytes(225)
        .expect_err("a at 1025 rejects");
    meter_b
        .record_message_bytes(225)
        .expect_err("b at 1025 rejects");
}

#[test]
fn request_body_meter_first_message_can_alone_exceed_cap() {
    // Pin (d): a single message larger than the configured
    // aggregate cap rejects on the first record_message_bytes
    // call.
    let mut meter = RequestBodyMeter::new(Some(1024));
    let err = meter
        .record_message_bytes(2048)
        .expect_err("first message > cap rejects");
    assert_eq!(err.code(), Code::ResourceExhausted);
}

#[test]
fn request_body_meter_zero_bytes_record_is_idempotent() {
    // Pin (d) edge: recording 0 bytes is a no-op — useful
    // for adapters that call record on every chunk including
    // empty CONTINUATION frames.
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter.record_message_bytes(0).expect("0 bytes OK");
    meter.record_message_bytes(0).expect("repeat 0 bytes OK");
    assert_eq!(meter.bytes_accumulated(), 0);
}

#[test]
fn server_config_max_request_body_bytes_is_documented_field() {
    // Pin: the new field is documented at the source level.
    // Pinned via grep for the bead reference.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs =
        std::fs::read_to_string(std::path::Path::new(manifest_dir).join("src/grpc/server.rs"))
            .expect("read src/grpc/server.rs");
    assert!(
        server_rs.contains("br-asupersync-woj18e"),
        "max_request_body_bytes field MUST reference the fix bead so \
         operators can correlate the cap with the audit history",
    );
    assert!(
        server_rs.contains("RequestBodyMeter"),
        "RequestBodyMeter helper documented at the field's doc comment \
         as the wiring path",
    );
}
