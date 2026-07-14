//! Audit + regression test for `src/grpc/server.rs` aggregate
//! request-body meter seam (tick #204, follow-up to tick #203).
//!
//! Operator's question: "verify aggregate request-body cap (P3
//! fix)." The configuration and helper exist, but source inspection
//! shows that the built-in dispatch/streaming paths do not instantiate
//! the meter. This audit therefore does not claim live enforcement.
//!
//! Audit context: the older audit multiplied the configured per-message
//! value by the standalone queue capacity and described the 4 GiB product
//! as a live per-stream bound. Current source inspection finds no common
//! production transport path connecting those helpers, the stored H2 window
//! value, and the stream queue. They are independent configuration/helper
//! values; their arithmetic product is not transport proof.
//!
//! Helper seam: `ServerConfig::max_request_body_bytes: Option<usize>`
//! plus `RequestBodyMeter`, which an integrating transport adapter can
//! instantiate per call and increment after each message decode.
//!
//! Audit findings:
//!
//!   (a) **`max_request_body_bytes` defaults to None** — pre-helper
//!       behavior preserved; opt-in configuration.
//!   (b) **`ServerBuilder::max_request_body_bytes(size)`** stores
//!       the caller-created meter limit.
//!   (c) **`RequestBodyMeter::from_config(&config)`** configures a
//!       caller-created meter from the server config.
//!   (d) **`record_message_bytes(n)`** accumulates and rejects
//!       at `total > cap` with `Status::resource_exhausted`.
//!   (e) **None-cap meter records but never rejects** — preserves
//!       pre-fix behavior under default config.
//!   (f) **Overflow fails closed under a cap** — checked addition
//!       rejects mathematical totals above `usize::MAX`, including
//!       when the configured cap itself is `usize::MAX`. With no
//!       cap, diagnostic accounting saturates instead of wrapping.
//!   (g) **Error message includes both actual and cap** for SRE
//!       diagnostics.
//!   (h) **Per-call instance** — adapters that maintain a
//!       meter per stream don't accidentally share state.
//!   (i) **Built-in enforcement remains unwired.** `dispatch_unary`
//!       and the current streaming transport do not construct or call
//!       `RequestBodyMeter`; setting the builder field alone therefore
//!       does not impose a live aggregate body limit.
//!
//! Regression tests below pin the configuration/helper behavior only.

use asupersync::grpc::server::RequestBodyMeter;
use asupersync::grpc::status::Code;
use asupersync::grpc::{ServerBuilder, ServerConfig};

#[test]
fn default_server_config_has_no_aggregate_meter_limit() {
    // Pin (a): default is None — pre-fix behavior preserved.
    let config = ServerConfig::default();
    assert!(
        config.max_request_body_bytes.is_none(),
        "default max_request_body_bytes is None — opt-in only",
    );
}

#[test]
fn server_builder_max_request_body_bytes_sets_meter_limit() {
    // Pin (b): the builder method stores the value.
    let server = ServerBuilder::new()
        .max_request_body_bytes(2 * 1024 * 1024)
        .build();
    assert_eq!(
        server.config().max_request_body_bytes,
        Some(2 * 1024 * 1024),
        "max_request_body_bytes builder stores the meter limit",
    );
}

#[test]
fn request_body_meter_from_config_inherits_cap() {
    // Pin (c): from_config initializes a caller-created meter from the
    // configured limit. It does not prove transport integration.
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
    meter
        .record_message_bytes(2)
        .expect("None cap accepts the saturating addition");
    assert_eq!(
        meter.bytes_accumulated(),
        usize::MAX,
        "None-limit accumulation must saturate rather than wrap",
    );
}

#[test]
fn request_body_meter_saturates_on_usize_max_argument() {
    // Pin (f): a peer that somehow triggers a usize::MAX byte
    // count cannot wrap the accumulator past the cap-check.
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter.record_message_bytes(1).expect("seed under cap");
    let err = meter
        .record_message_bytes(usize::MAX)
        .expect_err("1 + usize::MAX must saturate above the cap");
    assert_eq!(err.code(), Code::ResourceExhausted);
    // Accumulator saturated at usize::MAX (NOT wrapped to 0
    // or some smaller value).
    assert_eq!(meter.bytes_accumulated(), usize::MAX);
}

#[test]
fn request_body_meter_rejects_overflow_when_cap_is_usize_max() {
    // Exact-cap is allowed, but one more byte has a mathematical total
    // larger than usize::MAX and must fail closed rather than appear equal.
    let mut meter = RequestBodyMeter::new(Some(usize::MAX));
    meter
        .record_message_bytes(usize::MAX)
        .expect("exact usize::MAX cap is allowed");
    let err = meter
        .record_message_bytes(1)
        .expect_err("usize::MAX + 1 must reject even when cap is usize::MAX");
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(
        err.message().contains("overflow") && err.message().contains(&usize::MAX.to_string()),
        "overflow diagnostic must name the fail-closed condition and cap; got {}",
        err.message(),
    );
    assert_eq!(meter.bytes_accumulated(), usize::MAX);
    let sticky = meter
        .record_message_bytes(0)
        .expect_err("an unrepresentable cumulative total must remain over cap");
    assert_eq!(sticky.code(), Code::ResourceExhausted);
    assert!(sticky.message().contains("prior byte-total overflow"));
}

#[test]
fn request_body_meter_per_call_instance_independence() {
    // Pin (h): two meters from the same config are independent — adapters
    // that explicitly maintain one per stream
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
    // Pin (d) edge: recording a zero-length decoded message is a no-op.
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
        "max_request_body_bytes field must reference the helper-seam bead so \
         operators can correlate the limit with the audit history",
    );
    assert!(
        server_rs.contains("RequestBodyMeter"),
        "RequestBodyMeter helper must be documented at the field's doc comment",
    );
}
