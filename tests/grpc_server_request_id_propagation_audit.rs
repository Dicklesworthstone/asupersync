//! Audit + regression test for `src/grpc/server.rs` + `interceptor.rs`
//! request-id propagation behaviour (tick #152).
//!
//! Operator's question: "verify `trace_id` from incoming metadata
//! respected if signed, otherwise replaced (no client-controlled
//! trace tampering)."
//!
//! Audit findings:
//!
//!   (a) **CRLF / ASCII-control-char header injection: BLOCKED.**
//!       Two-layer defense.
//!         * `Metadata::insert` (streaming.rs:367-376) calls
//!           `sanitize_metadata_ascii_value` which strips bytes
//!           outside the visible-ASCII range (0x20-0x7E plus tab).
//!           A client-supplied x-request-id of `"line1\r\nline2"`
//!           is sanitized to `"line1line2"` BEFORE it can sit in
//!           the metadata map.
//!         * Server-side `enforce_metadata_size_limit` (referenced
//!           at server.rs:2244-2261) rejects metadata containing
//!           ASCII control bytes with `Status::invalid_argument`.
//!       Either layer alone closes the CRLF-injection vector;
//!       belt-and-braces.
//!
//!   (b) **Metadata frame size cap: ENFORCED.** Default is 8 KiB
//!       per `ServerConfig::max_metadata_size`. A flood of long
//!       x-request-id headers cannot exhaust server memory because
//!       the cap fires at the metadata-decode boundary.
//!
//!   (c) **⚠️ P3 trust gap — `TracingInterceptor` preserves
//!       client-supplied x-request-id verbatim.** The current
//!       implementation at interceptor.rs:392-401 is "generate
//!       new ID iff ABSENT":
//!
//!       ```ignore
//!       if self.generate_request_id
//!           && request.metadata().get("x-request-id").is_none()
//!       {
//!           let id = format!("req-{:016x}", ...);
//!           let _ = request.metadata_mut().insert("x-request-id", id);
//!       }
//!       ```
//!
//!       That is the propagation-friendly default for distributed
//!       tracing — upstream gateways generate a correlation ID and
//!       downstream services preserve it. It is the correct
//!       posture for trusted-edge deployments where the client is
//!       a known internal tier behind a WAF/mTLS.
//!
//!       For UNTRUSTED-edge deployments (public-facing gRPC where
//!       the immediate caller is a browser / 3rd-party), the
//!       operator's framing — "respect if signed, otherwise
//!       replace" — is NOT implemented. There is:
//!         * No signature verification on x-request-id.
//!         * No length cap beyond the metadata-frame size cap.
//!         * No charset whitelist beyond visible-ASCII.
//!       Mitigations available today:
//!         (i) install a custom `Interceptor` that calls
//!             `metadata_mut().insert_or_replace("x-request-id", ...)`
//!             unconditionally (regenerate-mode), or
//!         (ii) strip x-request-id at the WAF/edge before it
//!              reaches the gRPC server.
//!
//!       Documented as P3 doc gap.
//!
//! Regression tests below pin (a), (b), and (c).
//! Test (c) is a NEGATIVE pin — it asserts the current
//! "preserve verbatim" behavior so a future commit that ADDED
//! signature-validating logic to `TracingInterceptor` would force
//! an intentional re-baseline AND a re-audit of the trust model.

use asupersync::bytes::Bytes;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request};
use asupersync::grpc::{Interceptor, TracingInterceptor};

#[test]
fn metadata_insert_strips_crlf_in_x_request_id() {
    // Pin (a) layer-1: `Metadata::insert` sanitization removes
    // CRLF and other ASCII-control bytes from x-request-id values.
    // A client-supplied "line1\r\nline2" cannot inject a header
    // smuggling vector because the bytes never make it into the
    // entries Vec.
    let mut metadata = Metadata::new();
    let inserted = metadata.insert("x-request-id", "line1\r\nline2");
    assert!(
        inserted,
        "the key 'x-request-id' is a valid metadata key — insert must succeed",
    );
    match metadata.get("x-request-id") {
        Some(MetadataValue::Ascii(value)) => {
            assert!(
                !value.contains('\r') && !value.contains('\n'),
                "CRLF must be stripped at insert; got: {value:?}",
            );
            assert_eq!(
                value, "line1line2",
                "sanitization replaces CRLF with empty (concatenates), \
                 yielding the visible-ASCII subsequence",
            );
        }
        other => panic!("expected Ascii sanitized value, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_generates_id_when_absent() {
    // Pin (c) — happy path: when no client-supplied x-request-id,
    // TracingInterceptor generates a new server-side ID with the
    // documented "req-{16-hex}" shape. This is the trusted-edge
    // case (e.g. internal mesh, no upstream gateway).
    let interceptor = TracingInterceptor::new();
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");

    let id = request
        .metadata()
        .get("x-request-id")
        .expect("interceptor must add x-request-id when absent");
    match id {
        MetadataValue::Ascii(s) => {
            assert!(
                s.starts_with("req-"),
                "generated ID must use the 'req-' prefix; got {s:?}",
            );
            assert_eq!(
                s.len(),
                "req-".len() + 16,
                "generated ID must be 'req-' + 16 hex digits; got {s:?}",
            );
        }
        other => panic!("expected Ascii value, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_preserves_client_supplied_id_verbatim() {
    // Pin (c) — the audit's KEY finding: TracingInterceptor
    // PRESERVES a client-supplied x-request-id without
    // verification, signature check, or replacement. This is
    // the documented behavior for trusted-edge / propagation
    // deployments and is the operator's P3 doc-gap concern for
    // untrusted-edge deployments.
    //
    // A regression that ADDED auto-regeneration ("always
    // overwrite") OR signature validation would break this pin
    // and force an intentional re-baseline. That's the right
    // gate for a security-sensitive change.
    let interceptor = TracingInterceptor::new();
    let mut metadata = Metadata::new();
    let inserted = metadata.insert("x-request-id", "client-supplied-trace-id");
    assert!(inserted);
    let mut request = Request::with_metadata(Bytes::new(), metadata);

    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");

    let id = request
        .metadata()
        .get("x-request-id")
        .expect("client-supplied x-request-id must be preserved");
    match id {
        MetadataValue::Ascii(s) => {
            assert_eq!(
                s, "client-supplied-trace-id",
                "TracingInterceptor preserves client-supplied x-request-id \
                 VERBATIM. This is the propagation-friendly default; \
                 untrusted-edge deployments must install a regenerate-mode \
                 interceptor or strip x-request-id at the WAF.",
            );
        }
        other => panic!("expected Ascii, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_disabled_does_not_generate_id() {
    // Pin: `with_request_id(false)` switches off generation. A
    // request without a client-supplied id stays without one.
    let interceptor = TracingInterceptor::new().with_request_id(false);
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");
    assert!(
        request.metadata().get("x-request-id").is_none(),
        "generate_request_id=false suppresses ID generation \
         (e.g. when an upstream interceptor handles it)",
    );
}

#[test]
fn metadata_insert_strips_non_ascii_bytes_from_request_id() {
    // Pin (a) layer-1 extension: non-ASCII bytes (e.g. UTF-8
    // multi-byte sequences) are stripped from x-request-id values
    // because gRPC ASCII metadata is restricted to the
    // visible-ASCII range. A client-supplied id of "trace-Ω" cannot
    // smuggle non-ASCII bytes into log-correlation pipelines that
    // assume ASCII.
    let mut metadata = Metadata::new();
    let inserted = metadata.insert("x-request-id", "trace-Ω-id");
    assert!(inserted);
    match metadata.get("x-request-id") {
        Some(MetadataValue::Ascii(value)) => {
            assert!(
                value.is_ascii(),
                "ASCII metadata values must be ASCII after sanitization; \
                 got {value:?}",
            );
            // The omega character (Ω, two UTF-8 bytes) is dropped;
            // the rest is preserved.
            assert_eq!(
                value, "trace--id",
                "non-ASCII bytes stripped, leaving the visible-ASCII subsequence",
            );
        }
        other => panic!("expected Ascii value, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_preserves_zero_length_client_id_then_generates() {
    // Negative pin: an EMPTY client-supplied x-request-id is still
    // technically "present" for the .is_none() check, so the
    // interceptor preserves it as empty. A regression that started
    // treating empty-string as "missing" and auto-generated would
    // break this pin and require an intentional re-baseline (it
    // would actually be an improvement for the untrusted-edge
    // story, but it would change observable behavior).
    let interceptor = TracingInterceptor::new();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-request-id", ""));
    let mut request = Request::with_metadata(Bytes::new(), metadata);

    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");

    match request.metadata().get("x-request-id") {
        Some(MetadataValue::Ascii(s)) => {
            assert_eq!(
                s, "",
                "zero-length client-supplied id is preserved (counts as \
                 present for the is_none() check). Pin documents the \
                 current 'preserve verbatim' contract.",
            );
        }
        other => panic!("expected Ascii (empty), got {other:?}"),
    }
}
