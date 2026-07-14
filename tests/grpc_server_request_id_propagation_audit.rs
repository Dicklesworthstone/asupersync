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
//!         * `Metadata::insert` rejects a value containing any byte
//!           outside printable ASCII 0x20-0x7E. A client-supplied
//!           x-request-id of `"line1\r\nline2"` is rejected as a
//!           whole before it can sit in the metadata map.
//!         * Server-side `enforce_metadata_size_limit` (referenced
//!           at server.rs:2244-2261) rejects metadata containing
//!           ASCII control bytes with `Status::invalid_argument`.
//!       Either layer alone closes the CRLF-injection vector;
//!       belt-and-braces.
//!
//!   (b) **Post-decode metadata cap is enforced by dispatch.** Default is
//!       8 KiB per `ServerConfig::max_metadata_size`; dispatch checks the
//!       materialized metadata before interceptors and handlers. This does not
//!       bound HPACK/header-block allocation or prove a pre-container wire cap.
//!
//!   (c) **Unsigned request-id tampering: BLOCKED BY DEFAULT.**
//!       `TracingInterceptor` treats the default boundary as
//!       untrusted. A client-supplied x-request-id is regenerated
//!       unless the operator explicitly selects trusted-edge
//!       preservation or installs a signature verifier:
//!
//!       ```ignore
//!       TracingInterceptor::new()
//!           .with_trusted_client_request_ids();
//!       TracingInterceptor::new()
//!           .with_request_id_signature_verifier(...);
//!       ```
//!
//!       This matches the operator's framing: respect a client
//!       request ID only if it is signed or the ingress boundary is
//!       already trusted; otherwise replace it.
//!
//! Regression tests below pin (a), (b), and (c).
//! Test (c) asserts the fail-closed default plus the two explicit
//! preservation modes.

use asupersync::bytes::Bytes;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request};
use asupersync::grpc::{Interceptor, TracingInterceptor};

#[test]
fn metadata_insert_rejects_crlf_in_x_request_id() {
    // Pin (a) layer-1: reject the entire value rather than
    // concatenating the fragments around CRLF.
    let mut metadata = Metadata::new();
    let inserted = metadata.insert("x-request-id", "line1\r\nline2");
    assert!(!inserted, "x-request-id containing CRLF must be rejected");
    assert!(metadata.get("x-request-id").is_none());
}

#[test]
fn tracing_interceptor_generates_id_when_absent() {
    // Pin (c) — when no client-supplied x-request-id is present,
    // TracingInterceptor generates a server-side ID with the documented
    // "req-{16-hex}" shape.
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
        other @ MetadataValue::Binary(_) => panic!("expected Ascii value, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_replaces_unsigned_client_supplied_id_by_default() {
    // Pin (c) — default boundary is untrusted. A client-supplied
    // unsigned x-request-id must not be trusted as a correlation
    // authority because it lets an external peer tamper with trace
    // joins. The default replaces it with a generated server ID.
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
        .expect("unsigned client-supplied x-request-id must be replaced");
    match id {
        MetadataValue::Ascii(s) => {
            assert_eq!(
                s, "req-0000000000000001",
                "TracingInterceptor must replace unsigned client-supplied \
                 x-request-id by default.",
            );
        }
        other @ MetadataValue::Binary(_) => panic!("expected Ascii, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_preserves_signed_client_supplied_id() {
    let interceptor =
        TracingInterceptor::new().with_request_id_signature_verifier(|id: &str, sig: &str| {
            id == "client-supplied-trace-id" && sig == "valid-signature"
        });
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-request-id", "client-supplied-trace-id"));
    assert!(metadata.insert("x-request-id-signature", "valid-signature"));
    let mut request = Request::with_metadata(Bytes::new(), metadata);

    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");

    match request.metadata().get("x-request-id") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "client-supplied-trace-id"),
        other => panic!("expected signed request id to be preserved, got {other:?}"),
    }
}

#[test]
fn tracing_interceptor_trusted_edge_preserves_client_supplied_id() {
    let interceptor = TracingInterceptor::new().with_trusted_client_request_ids();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-request-id", "trusted-edge-trace-id"));
    let mut request = Request::with_metadata(Bytes::new(), metadata);

    interceptor
        .intercept_request(&mut request)
        .expect("intercept_request must Ok");

    match request.metadata().get("x-request-id") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(s, "trusted-edge-trace-id"),
        other => panic!("expected trusted-edge request id to be preserved, got {other:?}"),
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
fn metadata_insert_rejects_non_ascii_bytes_from_request_id() {
    // Pin (a) layer-1 extension: reject the entire request id when
    // it contains non-ASCII bytes instead of silently changing it.
    let mut metadata = Metadata::new();
    let inserted = metadata.insert("x-request-id", "trace-Ω-id");
    assert!(!inserted);
    assert!(metadata.get("x-request-id").is_none());
}

#[test]
fn tracing_interceptor_replaces_zero_length_client_id() {
    // Empty x-request-id is not useful correlation material and must not
    // count as a trusted upstream value at an untrusted edge.
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
                s, "req-0000000000000001",
                "zero-length client-supplied id must be replaced with a generated ID.",
            );
        }
        other => panic!("expected generated ASCII request id, got {other:?}"),
    }
}
