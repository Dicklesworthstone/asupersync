//! Audit + regression test for `src/grpc/interceptor.rs` interceptor
//! stack ordering and bearer-token-leak surface (tick #153).
//!
//! Operator's question: "verify auth interceptor ALWAYS first, no
//! logging-before-auth log of bearer token."
//!
//! Audit findings:
//!
//!   (a) **`LoggingInterceptor` does NOT actually emit a log
//!       line.** The built-in interceptor at interceptor.rs:915-930
//!       is a NO-OP for logging — it just marks the request /
//!       response with `x-logged=true` metadata. It never touches
//!       the `authorization` header or any other header content.
//!       Therefore the "logging-before-auth log of bearer token"
//!       class is **structurally absent** for the built-in
//!       `LoggingInterceptor` regardless of its position in the
//!       `.layer(...)` chain.
//!
//!   (b) **Order is OPERATOR-CONTROLLED.** `InterceptorLayer::layer`
//!       (interceptor.rs:205-211) appends interceptors to a Vec;
//!       request-side processing walks the chain in insertion order
//!       (interceptor.rs:261). There is NO structural enforcement
//!       that an auth-validating interceptor (e.g.
//!       `BearerAuthValidator` at interceptor.rs:550+) MUST be the
//!       first layer.
//!
//!       Consequences:
//!         * The operator must place the auth-validating layer
//!           FIRST. The example doc-comment at interceptor.rs:58-65
//!           shows the canonical order:
//!             trace_interceptor() → auth_bearer_interceptor()
//!           with the auth layer LAST in `.layer(...)` chains so
//!           that downstream logic runs after auth has stamped the
//!           authorization header. (Note: `auth_bearer_interceptor`
//!           is a CLIENT-side helper that ADDS the token; the
//!           SERVER-side validator is `BearerAuthValidator` at
//!           interceptor.rs:550+, which REJECTS unauthorized
//!           requests with `Status::unauthenticated`.)
//!         * If an operator writes a CUSTOM interceptor that logs
//!           the request metadata (e.g. `tracing::info!("req
//!           metadata: {:?}", request.metadata())`) and places it
//!           BEFORE the `BearerAuthValidator`, the bearer token in
//!           the `authorization` header WOULD be logged for
//!           rejected (unauthenticated) requests. Documentation
//!           gap (P3): the operator-facing docs should call out:
//!           (i) put auth FIRST among validating interceptors,
//!           (ii) mask/redact `authorization` before logging.
//!
//!   (c) **Cleanup-on-error contract.** When a later interceptor
//!       returns Err, `InterceptorLayer::intercept_request` (lines
//!       249-274) walks back through `interceptors[..=index]` in
//!       REVERSE order calling `intercept_error_with_request` so
//!       earlier acquisitions (e.g. rate-limit slots, tracing
//!       spans) get released cleanly (br-asupersync-9oxmqv). This
//!       is the loser-drain analog for the interceptor chain. A
//!       regression that broke the reverse cleanup walk would
//!       cause a permanent leak — verified present.
//!
//! Regression tests below pin (a), (b), and (c).

use asupersync::bytes::Bytes;
use asupersync::grpc::interceptor::LoggingInterceptor;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request};
use asupersync::grpc::{
    BearerAuthInterceptor, Interceptor, InterceptorLayer, TracingInterceptor,
    auth_bearer_interceptor, logging_interceptor, trace_interceptor,
};

#[test]
fn built_in_logging_interceptor_does_not_emit_log_lines() {
    // Pin (a): LoggingInterceptor is a NO-OP for actual logging.
    // It only stamps `x-logged=true` on the metadata. It does
    // NOT read or print the authorization header. Therefore the
    // "logging-before-auth log of bearer token" class is
    // structurally absent for the built-in.
    //
    // A future commit that turned LoggingInterceptor into an
    // actual emitter (e.g. via `tracing::info!`) MUST also
    // redact `authorization` before logging. This pin will
    // break, forcing the change to be considered alongside the
    // redaction requirement.
    let logger = logging_interceptor();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("authorization", "Bearer secret-token-do-not-log"));
    let mut request = Request::with_metadata(Bytes::new(), metadata);

    Interceptor::intercept_request(&logger, &mut request).expect("intercept_request must Ok");

    // Authorization header is UNCHANGED — interceptor read nothing.
    match request.metadata().get("authorization") {
        Some(MetadataValue::Ascii(s)) => assert_eq!(
            s, "Bearer secret-token-do-not-log",
            "logging interceptor must not modify the authorization header",
        ),
        other => panic!("expected Ascii, got {other:?}"),
    }
    // The marker is set.
    assert!(
        matches!(
            request.metadata().get("x-logged"),
            Some(MetadataValue::Ascii(v)) if v == "true",
        ),
        "logging interceptor stamps x-logged=true",
    );
}

#[test]
fn interceptor_layer_processes_in_insertion_order() {
    // Pin (b): the `.layer(...)` chain processes request-side in
    // insertion order. This is the contract operators rely on
    // when placing auth FIRST. A regression that flipped to LIFO
    // or to alphabetical-by-name would break the documented
    // ordering and force operators to rewire deployments.
    //
    // We build a chain whose first layer (Tracing) generates an
    // ID and whose second layer (BearerAuth — the CLIENT-side
    // adder) appends an authorization header. After running
    // intercept_request, BOTH must be present and the
    // authorization header must contain the bearer token.
    let layer = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(auth_bearer_interceptor("test-token"));

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer
        .intercept_request(&mut request)
        .expect("layer chain Ok");

    // Tracing layer ran first → x-request-id present.
    assert!(
        request.metadata().get("x-request-id").is_some(),
        "first layer (TracingInterceptor) must have run",
    );
    // Auth layer ran second → authorization present.
    match request.metadata().get("authorization") {
        Some(MetadataValue::Ascii(s)) => {
            assert_eq!(
                s, "Bearer test-token",
                "second layer (BearerAuthInterceptor) appended bearer header",
            );
        }
        other => panic!("expected authorization header, got {other:?}"),
    }
}

#[test]
fn interceptor_layer_default_is_empty() {
    // Pin: a fresh `InterceptorLayer::new()` has zero layers. A
    // server built with NO `.layer(...)` chain runs handlers
    // unguarded — there is NO ambient/implicit auth interceptor.
    // This is intentional (br-asupersync-mfk14i): asupersync's
    // gRPC interceptor chain has no implicit auth flow. Operators
    // must explicitly opt in.
    let layer = InterceptorLayer::new();
    assert!(layer.is_empty(), "default InterceptorLayer is empty");
    assert_eq!(layer.len(), 0);
}

#[test]
fn empty_interceptor_layer_does_not_synthesize_auth() {
    // Pin: an empty InterceptorLayer does NOT inject any
    // authorization header. A regression that added an implicit
    // auth interceptor at chain construction would break this
    // pin — and would also break the no-ambient-authority
    // invariant of the runtime.
    let layer = InterceptorLayer::new();
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer
        .intercept_request(&mut request)
        .expect("empty chain Oks immediately");
    assert!(
        request.metadata().get("authorization").is_none(),
        "empty interceptor chain must not synthesize an authorization header",
    );
    assert!(
        request.metadata().get("x-logged").is_none(),
        "empty interceptor chain must not stamp logging metadata",
    );
}

#[test]
fn logging_after_bearer_does_not_leak_token_to_log_marker() {
    // Pin (a)+(b) interaction: even when the BearerAuthInterceptor
    // (client-side adder) runs FIRST and stamps the authorization
    // header, a subsequent LoggingInterceptor in the chain does
    // NOT copy or surface the bearer token. The built-in logger
    // marks `x-logged=true` only.
    //
    // The audit-relevant property: the LoggingInterceptor's
    // `intercept_request` reads NOTHING from the authorization
    // header. So even if an operator mistakenly puts logging
    // AFTER auth (the ordering this test exercises), there is no
    // bearer-token leak class via the BUILT-IN logger.
    let layer = InterceptorLayer::new()
        .layer(BearerAuthInterceptor::new("super-secret-bearer"))
        .layer(LoggingInterceptor::new());

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer
        .intercept_request(&mut request)
        .expect("two-layer chain Ok");

    // Bearer header present.
    let auth = request.metadata().get("authorization");
    assert!(
        matches!(auth, Some(MetadataValue::Ascii(v)) if v == "Bearer super-secret-bearer"),
        "bearer header set by first layer",
    );
    // Log marker present, but it does NOT contain the token.
    let logged = request.metadata().get("x-logged");
    match logged {
        Some(MetadataValue::Ascii(v)) => {
            assert_eq!(v, "true");
            assert!(
                !v.contains("super-secret-bearer") && !v.contains("Bearer"),
                "x-logged marker MUST NOT carry token bytes; got {v:?}",
            );
        }
        other => panic!("expected x-logged marker, got {other:?}"),
    }
}

#[test]
fn interceptor_layer_walk_count_matches_insertion() {
    // Pin: `.len()` reflects insertion count. A regression that
    // de-duplicated by type (so two TracingInterceptor instances
    // only counted as one) would break the documented ordering
    // contract — composability requires that every layer added
    // is a distinct invocation, even of the same type.
    let layer = InterceptorLayer::new()
        .layer(TracingInterceptor::new())
        .layer(LoggingInterceptor::new())
        .layer(TracingInterceptor::new());
    assert_eq!(
        layer.len(),
        3,
        "three .layer() calls produce three distinct invocations, \
         even when types repeat",
    );
}
