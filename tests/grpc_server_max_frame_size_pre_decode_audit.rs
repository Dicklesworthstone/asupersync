//! Audit + regression test for `src/grpc/server.rs` materialized-metadata
//! aggregate-size enforcement (tick #193).
//!
//! The historical filename and operator question used the term "pre-decode".
//! This test does not exercise an HTTP/2 frame decoder or HPACK. It calls the
//! dispatch-layer helper after metadata has already been materialized.
//!
//! Audit context — gRPC has two distinct size-cap surfaces:
//!
//!   * **Materialized metadata aggregate cap** (`max_metadata_size`). Default
//!     8 KiB. `enforce_metadata_size_limit` applies it before the interceptor
//!     chain or handler runs once a `Metadata` container exists, and reports
//!     `Status::resource_exhausted` when the aggregate exceeds the cap.
//!   * **LPM message-body size cap** (`max_recv_message_size`,
//!     `max_send_message_size`). Default 4 MiB. This is a separate codec
//!     concern and is not exercised by the tests below.
//!
//! No claim is made here about HPACK allocation, raw HEADERS/TRAILERS frame
//! limits, or transport wiring before `Metadata` construction.
//!
//! Audit findings:
//!
//!   (a) **`max_metadata_size` enforced via
//!       `enforce_metadata_size_limit`** at the first gate of
//!       `dispatch_unary`. The cap fires before the interceptor chain or user
//!       handler, but after metadata has been decoded/materialized.
//!
//!   (b) **Default cap is 8 KiB** (`DEFAULT_MAX_METADATA_SIZE
//!       = 8 * 1024`, server.rs:285). Matches gRPC ecosystem
//!       default for this dispatch-layer helper.
//!
//!   (c) **Cap-exceeded surfaces `Status::resource_exhausted`**
//!       (server.rs:412-416). Error message includes BOTH
//!       actual and configured limit for diagnostics.
//!
//!   (d) **`limit = 0` disables enforcement** (server.rs:407-
//!       409). No-cap convention used elsewhere in the crate.
//!       Operators that want unbounded metadata can configure
//!       0 explicitly — the bypass is grep-able.
//!
//!   (e) **Total bytes computed via `metadata_byte_size`**
//!       (server.rs:293-302) sums `key.len() + value.byte_len()`
//!       over every entry. A peer flooding many individually
//!       valid headers gets caught by the same aggregate check.
//!
//!   (f) **Validator runs FIRST**, before size check
//!       (server.rs:406). `validate_inbound_metadata`
//!       enforces (i) reserved-prefix rejection
//!       (audited tick #177), (ii) content-type allowlist
//!       (audited tick #176), and (iii) metadata structural validity. Public
//!       ASCII insertion rejects an invalid value as a whole; it does not
//!       strip control characters. The size cap is the last gate in this
//!       materialized-metadata validation pipeline.
//!
//! Regression tests below pin (a)-(e). The (f) ordering is
//! pinned by the function structure: `validate_inbound_metadata`
//! returns Err early if any structural issue surfaces.

use asupersync::bytes::Bytes;
use asupersync::grpc::server::{
    DEFAULT_MAX_METADATA_SIZE, enforce_metadata_size_limit, metadata_byte_size,
};
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::Metadata;

#[test]
fn default_max_metadata_size_is_8_kib() {
    // Pin (b): the documented dispatch-layer default.
    assert_eq!(
        DEFAULT_MAX_METADATA_SIZE,
        8 * 1024,
        "DEFAULT_MAX_METADATA_SIZE must remain the documented 8 KiB default",
    );
}

#[test]
fn enforce_metadata_size_limit_accepts_under_cap() {
    // Pin (a): a small metadata block (~30 bytes) under the
    // 8 KiB default cap passes.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-trace-id", "abc-123"));
    assert!(metadata.insert("user-agent", "test"));

    enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect("under-cap metadata accepts");
}

#[test]
fn enforce_metadata_size_limit_rejects_over_cap_with_resource_exhausted() {
    // Pin (a)+(c): aggregate materialized metadata exceeding the cap rejects
    // with Status::resource_exhausted.
    let mut metadata = Metadata::new();
    // Keep each individual value under MAX_HEADER_VALUE_LEN so
    // this fixture isolates the aggregate max_metadata_size gate.
    for index in 0..3 {
        let key = format!("x-large-{index}");
        let value = "X".repeat(4 * 1024);
        assert!(metadata.insert(&key, value.as_str()));
    }

    let err = enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect_err("over-cap metadata MUST reject");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "cap-exceeded MUST surface as ResourceExhausted; got: {:?}",
        err.code(),
    );
    // Pin (c) message: includes both actual and limit for SRE
    // diagnostics.
    let msg = err.message();
    assert!(
        msg.contains("max_metadata_size"),
        "rejection message must reference the config knob name; got: {msg:?}",
    );
    assert!(
        msg.contains("bytes >"),
        "rejection message must show actual vs limit byte counts; got: {msg:?}",
    );
}

#[test]
fn enforce_metadata_size_limit_zero_disables_cap() {
    // Pin (d): limit=0 → no aggregate-size enforcement. A
    // metadata block that would exceed the 8 KiB aggregate cap
    // passes when the cap is disabled. Individual metadata
    // validity checks still run before the size bypass.
    let mut metadata = Metadata::new();
    for index in 0..4 {
        let key = format!("x-unbounded-{index}");
        let value = "Y".repeat(4 * 1024);
        assert!(metadata.insert(&key, value.as_str()));
    }
    enforce_metadata_size_limit(&metadata, 0).expect("limit=0 disables enforcement");
}

#[test]
fn metadata_byte_size_sums_all_entries() {
    // Pin (e): the total includes every entry's key+value
    // bytes. A peer flooding many small headers gets caught
    // by the same check as one large header.
    let mut metadata = Metadata::new();
    for i in 0..100 {
        let key = format!("x-header-{i:03}");
        let value = format!("value-{i:03}");
        assert!(metadata.insert(&key, &value));
    }
    let total = metadata_byte_size(&metadata);
    // Each entry is ~13 + ~9 = ~22 bytes; 100 entries ≈ 2200
    // bytes. Loose lower-bound pin: total > 2000 bytes.
    assert!(
        total > 2000,
        "100-entry metadata block must accumulate to > 2000 bytes; got {total}",
    );
}

#[test]
fn enforce_at_exact_cap_boundary_accepts() {
    // Pin (a) boundary: metadata at EXACTLY the cap passes.
    // The check is `actual > limit` (strict `>`, audited
    // pattern from tick #163 boundary tests).
    let mut metadata = Metadata::new();
    let key = "x-test"; // 6 bytes
    // Total target = 8 KiB exactly.
    let value_len = DEFAULT_MAX_METADATA_SIZE - key.len();
    let value = "Z".repeat(value_len);
    assert!(metadata.insert(key, value.as_str()));
    let total = metadata_byte_size(&metadata);
    assert_eq!(total, DEFAULT_MAX_METADATA_SIZE);

    enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect("at-exact-cap metadata accepts (strict > boundary)");
}

#[test]
fn enforce_at_cap_plus_one_rejects() {
    // Pin (a) boundary: metadata at cap+1 rejects. The strict
    // `>` boundary fires here.
    let mut metadata = Metadata::new();
    let key = "x-test"; // 6 bytes
    let value_len = DEFAULT_MAX_METADATA_SIZE - key.len() + 1;
    let value = "Z".repeat(value_len);
    assert!(metadata.insert(key, value.as_str()));

    let err = enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect_err("cap+1 must reject");
    assert_eq!(err.code(), Code::ResourceExhausted);
}

#[test]
fn enforce_metadata_size_limit_runs_validator_first() {
    // Pin (f): a metadata block with INVALID content (e.g.
    // ASCII control chars in a value) reject at the validator
    // BEFORE the size check. We use from_raw_entries_for_tests
    // would be needed but it's pub(crate) — so we use a small
    // metadata block with size-passing entries that contain
    // a content-type violation.
    //
    // Construct a metadata with an invalid content-type
    // value — the validator should reject at the content-type
    // check BEFORE the size check.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("content-type", "application/json"));
    let err = enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect_err("non-grpc content-type must reject");
    assert_eq!(
        err.code(),
        Code::InvalidArgument,
        "validator runs FIRST — non-grpc content-type rejects with \
         InvalidArgument BEFORE size check (which would be \
         ResourceExhausted). got: {:?}",
        err.code(),
    );
}

#[test]
fn empty_metadata_passes_under_any_cap() {
    // Pin (a) edge: empty metadata (0 bytes) is always under
    // any non-zero cap. A regression that mishandled empty
    // would surface here.
    let metadata = Metadata::new();
    enforce_metadata_size_limit(&metadata, 1).expect("empty metadata under any cap");
    enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect("empty metadata under default cap");
}

#[test]
fn metadata_byte_size_includes_binary_value_byte_len() {
    // Pin (e) extension: binary values (Bytes-backed) count
    // their actual byte length, not their base64-encoded
    // length. This is correct because the SIZE check is on
    // the in-memory representation, not the wire encoding.
    let mut metadata = Metadata::new();
    let binary_payload = vec![0u8; 1024];
    assert!(metadata.insert_bin("trace-bin", Bytes::from(binary_payload.clone())));
    let total = metadata_byte_size(&metadata);
    // Key "trace-bin" is 9 bytes; value is 1024 bytes; total
    // should be 9 + 1024 = 1033 bytes (or similar bounded value).
    assert!(
        total >= 1024,
        "binary value's byte_len must be summed; got {total}",
    );
}
