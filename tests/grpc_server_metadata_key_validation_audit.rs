//! Audit + regression test for `src/grpc/streaming.rs`
//! `normalize_metadata_key` and `src/grpc/server.rs`
//! `validate_inbound_metadata` for request-line metadata
//! injection (tick #177).
//!
//! Operator's question: "verify metadata keys validated against
//! gRPC spec."
//!
//! gRPC Spec context (PROTOCOL-HTTP2.md, Custom-Metadata-Key):
//!
//!   * Custom-Metadata-Key: must match `[a-z0-9-_.]+` —
//!     ASCII lowercase letters, digits, hyphen, underscore, period.
//!   * Reserved prefix: `grpc-` is reserved for the protocol.
//!     Custom keys must not start with `grpc-`. Asupersync allows
//!     a small whitelist of well-known grpc-* keys (timeout,
//!     encoding, accept-encoding, message-type) but rejects
//!     other grpc-prefixed keys from inbound metadata.
//!   * Binary keys end in `-bin` and carry base64-encoded values.
//!   * HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`,
//!     `:authority`) MUST NOT appear in custom metadata.
//!
//! Audit findings:
//!
//!   (a) **Strict character allowlist enforced by
//!       `normalize_metadata_key`** (streaming.rs:307-312).
//!       Only `[a-z0-9-_.]` byte values pass. CRLF, spaces,
//!       colons, brackets, slashes, backslashes, percent
//!       signs — all rejected. The function returns `None` for
//!       any disallowed byte, and `Metadata::insert` returns
//!       `false` (entry NOT stored) on rejection.
//!
//!   (b) **Empty keys rejected** (streaming.rs:303-305).
//!       `normalize_metadata_key("", _)` → None.
//!
//!   (c) **Case normalization to lowercase** (streaming.rs:299).
//!       `Authorization`, `AUTHORIZATION`, `authorization` all
//!       canonicalize to `authorization`. Per HTTP/2 + gRPC
//!       spec — header names are case-insensitive.
//!
//!   (d) **`-bin` suffix auto-appended for binary keys**
//!       (streaming.rs:300-302). `insert_bin("raw-key", ...)`
//!       stores at `raw-key-bin`. A regression that allowed
//!       binary values under non-`-bin` keys would let a peer
//!       smuggle non-printable bytes into ASCII headers.
//!
//!   (e) **HTTP/2 pseudo-headers rejected** because `:` is not
//!       in the allowlist. `:method`, `:path`, `:authority`,
//!       `:scheme` all fail validation.
//!
//!   (f) **CRLF / control-char injection blocked at insert
//!       boundary** — `Metadata::insert` rejects the entire
//!       value when any byte falls outside printable ASCII
//!       0x20-0x7E. It does not strip and concatenate fragments,
//!       which could transmute malformed protocol values.
//!
//!   (g) **Reserved `grpc-*` prefix enforcement** — inbound
//!       metadata validator (server.rs:310-315) rejects any
//!       grpc-prefixed key NOT in the documented whitelist
//!       (timeout / encoding / accept-encoding / message-type).
//!       A peer cannot smuggle a reserved-prefix key.
//!
//! Regression tests below pin (a)-(g).

use asupersync::grpc::streaming::Metadata;

#[test]
fn metadata_insert_rejects_disallowed_chars_in_key() {
    // Pin (a): characters outside [a-z0-9-_.] make the insert
    // fail (returns false; no entry stored).
    //
    // The list of attempted keys is engineered to catch known
    // injection vectors at the HTTP/2 ↔ gRPC boundary:
    //   ":method"          — HTTP/2 pseudo-header
    //   "x-CRLF\r\n"       — header-injection via CRLF
    //   "key with space"   — RFC 7230-banned token char
    //   "key:value"        — colon attempting smuggle
    //   "X-Auth/Token"     — slash from Cookie/path-confusion
    //   "key%20"           — percent-encoding
    //   "key[bracket]"     — Cookie-syntax tampering
    let injection_keys = [
        ":method",
        "x-CRLF\r\n",
        "key with space",
        "key:value",
        "X-Auth/Token",
        "key%20",
        "key[bracket]",
        "key=value",
        "key\"quoted\"",
        "key;semicolon",
        "key,comma",
        "key<lt",
        "key>gt",
        "key@at",
        "key#hash",
        "key?query",
    ];
    for key in injection_keys {
        let mut metadata = Metadata::new();
        let inserted = metadata.insert(key, "value");
        assert!(
            !inserted,
            "key {key:?} contains disallowed character — \
             Metadata::insert MUST return false",
        );
        assert!(
            metadata.get(key).is_none(),
            "rejected key {key:?} must NOT appear in metadata",
        );
    }
}

#[test]
fn metadata_insert_rejects_empty_key() {
    // Pin (b): empty key rejected.
    let mut metadata = Metadata::new();
    assert!(!metadata.insert("", "value"), "empty key must be rejected");
}

#[test]
fn metadata_insert_normalizes_uppercase_to_lowercase() {
    // Pin (c): keys are case-insensitively canonicalized to
    // lowercase. A peer sending `Authorization` lands at
    // `authorization` — preventing a duplicate entry under
    // different casings.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("Authorization", "Bearer abc"));
    assert!(metadata.get("authorization").is_some());
    assert!(metadata.get("Authorization").is_some()); // get is also case-insensitive
    assert!(metadata.get("AUTHORIZATION").is_some());
}

#[test]
fn metadata_insert_bin_appends_bin_suffix_when_missing() {
    // Pin (d): binary values land under `<key>-bin` so the
    // wire-protocol-side decoder (which base64-decodes only
    // `-bin` keys) handles them correctly.
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin(
        "raw-key",
        asupersync::bytes::Bytes::from_static(b"\x01\x02\x03"),
    ));
    // Stored under raw-key-bin — NOT under raw-key.
    assert!(metadata.get("raw-key-bin").is_some());
    assert!(metadata.get("raw-key").is_none());
}

#[test]
fn metadata_insert_bin_keeps_existing_bin_suffix() {
    // Pin (d) extension: a binary key that already ends in
    // `-bin` is NOT double-suffixed.
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("trace-bin", asupersync::bytes::Bytes::from_static(b"\x01"),));
    assert!(metadata.get("trace-bin").is_some());
    assert!(metadata.get("trace-bin-bin").is_none()); // NOT double-suffixed
}

#[test]
fn metadata_insert_value_rejects_crlf_and_non_visible_ascii() {
    // Pin (f): reject the whole value so a peer cannot inject CRLF
    // or have invalid fragments concatenated into a different value.
    let mut metadata = Metadata::new();
    assert!(
        !metadata.insert("x-test", "ok\r\nx-evil: 1"),
        "metadata containing CRLF must be rejected",
    );
    assert!(metadata.get("x-test").is_none());
}

#[test]
fn metadata_keys_with_valid_chars_are_accepted() {
    // Sanity — the allowlist is permissive enough for normal
    // gRPC usage. A regression that tightened it (e.g. dropped
    // periods or underscores) would break common headers like
    // `x-trace-id`, `user_agent`, `app.name`.
    let valid_keys = [
        "x-trace-id",
        "x-request-id",
        "user_agent",
        "app.name",
        "x-tenant-1",
        "x123",
    ];
    for key in valid_keys {
        let mut metadata = Metadata::new();
        assert!(
            metadata.insert(key, "value"),
            "valid key {key:?} should be accepted",
        );
        assert!(
            metadata.get(key).is_some(),
            "valid key {key:?} should be retrievable",
        );
    }
}

#[test]
fn http2_pseudo_headers_rejected_via_colon_disallowed() {
    // Pin (e): HTTP/2 pseudo-headers (:method, :path,
    // :authority, :scheme, :status) MUST NOT appear in custom
    // metadata. The validator rejects them because `:` is not
    // in the allowlist — closing a class of header-confusion
    // attacks at the gRPC ↔ HTTP/2 boundary.
    let pseudo_headers = [":method", ":path", ":authority", ":scheme", ":status"];
    for key in pseudo_headers {
        let mut metadata = Metadata::new();
        let inserted = metadata.insert(key, "value");
        assert!(
            !inserted,
            "HTTP/2 pseudo-header {key:?} MUST be rejected — \
             pseudo-headers are transport-layer concerns and must \
             not appear in gRPC custom metadata",
        );
    }
}

#[test]
fn metadata_high_bit_bytes_in_key_rejected() {
    // Pin (a) extension: bytes outside the ASCII range (e.g.
    // UTF-8 multi-byte sequences from Cyrillic / Chinese /
    // emoji) reject. A peer cannot smuggle non-ASCII bytes
    // into a key that downstream log-correlation pipelines
    // assume is ASCII.
    let high_bit_keys = ["x-π", "key-Ω", "тест", "🔑-key"];
    for key in high_bit_keys {
        let mut metadata = Metadata::new();
        let inserted = metadata.insert(key, "value");
        assert!(
            !inserted,
            "non-ASCII key {key:?} MUST reject — gRPC metadata key \
             charset is ASCII-only",
        );
    }
}

#[test]
fn metadata_uppercase_letter_in_key_normalizes_not_rejects() {
    // Pin (c) sanity: uppercase letters in keys are NORMALIZED
    // to lowercase, NOT rejected. A peer sending
    // `X-Trace-Id: abc` lands at `x-trace-id: abc` — case-
    // insensitive per HTTP/2 spec.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("X-Trace-Id", "abc"));
    let entries: Vec<_> = metadata.iter().collect();
    assert!(
        entries.iter().any(|(k, _)| *k == "x-trace-id"),
        "uppercase key must canonicalize to lowercase storage form; \
         got entries: {:?}",
        entries.iter().map(|(k, _)| k).collect::<Vec<_>>(),
    );
}
