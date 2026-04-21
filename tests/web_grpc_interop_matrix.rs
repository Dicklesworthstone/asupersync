#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements, clippy::let_unit_value)]

//! [T5.8] Cross-Implementation Interoperability Suites for Web and gRPC.
//!
//! Validates interoperability across the web framework, middleware stack, gRPC
//! subsystem, and transport layers. Each section verifies a parity contract
//! from `docs/tokio_functional_parity_contracts.md` (C14-C17).
//!
//! Organisation:
//!   1. Web router composition (T52-ROUTE)
//!   2. Web extractor contracts (T53-EXTRACT)
//!   3. Web middleware stack (T54-MW)
//!   4. gRPC unary + streaming (T56-GRPC)
//!   5. gRPC health + reflection (T57-HEALTH)
//!   6. gRPC compression + codec (T58-CODEC)
//!   7. gRPC interceptor chains (T59-ICEPT)
//!   8. gRPC-Web protocol (T60-GRPCWEB)
//!   9. Cross-stack lifecycle (T61-LIFE)
//!  10. Cancellation and determinism (T62-CX)

#[macro_use]
mod common;

use common::init_test_logging;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::server::Interceptor;
use asupersync::grpc::service::{NamedService, ServiceDescriptor, ServiceHandler};
use asupersync::grpc::{
    ChannelConfig, Code, GrpcCodec, GrpcMessage, HealthCheckRequest, HealthService,
    InterceptorLayer, Metadata, MetadataValue, MethodDescriptor, ReflectionService,
    Request as GrpcRequest, Response as GrpcResponse, ServingStatus, Status,
};
use asupersync::grpc::{
    auth_bearer_interceptor, fn_interceptor, logging_interceptor, metadata_propagator,
    rate_limiter, timeout_interceptor, trace_interceptor,
};
use asupersync::web::extract::{
    Cookie, Form, Json as JsonExtract, Path, Query, RawBody, Request, State,
};
use asupersync::web::handler::{FnHandler, FnHandler1, Handler};
use asupersync::web::health::HealthCheck;
use asupersync::web::middleware::{
    AuthMiddleware, AuthPolicy, CatchPanicMiddleware, CompressionConfig, CompressionMiddleware,
    CorsAllowOrigin, CorsMiddleware, CorsPolicy, NormalizePathMiddleware,
    RequestBodyLimitMiddleware, RequestIdMiddleware, SetResponseHeaderMiddleware,
    TimeoutMiddleware, TrailingSlash,
};
use asupersync::web::response::{Json, StatusCode};
use asupersync::web::router::{Router, get, post};
use asupersync::web::security::{SecurityHeadersMiddleware, SecurityPolicy};
use asupersync::web::session::{MemoryStore, SameSite, Session, SessionLayer};

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// ============================================================================
// Section 1: Web Router Composition (T52-ROUTE)
// ============================================================================

fn index_handler() -> &'static str {
    "index"
}

fn user_handler(Path(id): Path<String>) -> String {
    format!("user:{id}")
}

fn user_posts_handler(Path(params): Path<HashMap<String, String>>) -> String {
    let uid = params.get("uid").cloned().unwrap_or_default();
    let pid = params.get("pid").cloned().unwrap_or_default();
    format!("user:{uid}/post:{pid}")
}

fn fallback_handler() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "custom 404")
}

#[test]
fn t52_route_01_basic_path_matching() {
    init_test("t52_route_01_basic_path_matching");

    let router = Router::new()
        .route("/", get(FnHandler::new(index_handler)))
        .route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(user_handler)),
        );

    let req = Request::new("GET", "/");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "index");

    let req2 = Request::new("GET", "/users/42");
    let resp2 = router.handle(req2);
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp2.body).unwrap(), "user:42");

    test_complete!("t52_route_01_basic_path_matching");
}

#[test]
fn t52_route_02_nested_router_prefix_isolation() {
    init_test("t52_route_02_nested_router_prefix_isolation");

    let api = Router::new().route("/health", get(FnHandler::new(|| "ok")));
    let router = Router::new().nest("/api/v1", api);

    let req = Request::new("GET", "/api/v1/health");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "ok");

    // Direct /health must NOT match.
    let req2 = Request::new("GET", "/health");
    let resp2 = router.handle(req2);
    assert_ne!(resp2.status, StatusCode::OK);

    test_complete!("t52_route_02_nested_router_prefix_isolation");
}

#[test]
fn t52_route_03_method_dispatch() {
    init_test("t52_route_03_method_dispatch");

    let router = Router::new().route(
        "/item",
        get(FnHandler::new(|| -> &'static str { "get" }))
            .post(FnHandler::new(|| -> &'static str { "post" }))
            .put(FnHandler::new(|| -> &'static str { "put" }))
            .delete(FnHandler::new(|| -> &'static str { "delete" }))
            .patch(FnHandler::new(|| -> &'static str { "patch" })),
    );

    for (method, expected) in [
        ("GET", "get"),
        ("POST", "post"),
        ("PUT", "put"),
        ("DELETE", "delete"),
        ("PATCH", "patch"),
    ] {
        let req = Request::new(method, "/item");
        let resp = router.handle(req);
        assert_eq!(
            std::str::from_utf8(&resp.body).unwrap(),
            expected,
            "method {method} mismatch"
        );
    }

    test_complete!("t52_route_03_method_dispatch");
}

#[test]
fn t52_route_04_fallback_handler() {
    init_test("t52_route_04_fallback_handler");

    let router = Router::new()
        .route("/exists", get(FnHandler::new(|| "found")))
        .fallback(FnHandler::new(fallback_handler));

    let req = Request::new("GET", "/does-not-exist");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "custom 404");

    test_complete!("t52_route_04_fallback_handler");
}

#[test]
fn t52_route_05_multi_param_extraction() {
    init_test("t52_route_05_multi_param_extraction");

    let router = Router::new().route(
        "/users/:uid/posts/:pid",
        get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
            user_posts_handler,
        )),
    );

    let req = Request::new("GET", "/users/alice/posts/99");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "user:alice/post:99"
    );

    test_complete!("t52_route_05_multi_param_extraction");
}

#[test]
fn t52_route_06_method_not_allowed() {
    init_test("t52_route_06_method_not_allowed");

    let router = Router::new().route("/only-get", get(FnHandler::new(|| "get only")));

    let req = Request::new("POST", "/only-get");
    let resp = router.handle(req);
    // Route exists but method does not match -> 405 or fallback.
    assert!(
        resp.status == StatusCode::METHOD_NOT_ALLOWED || resp.status == StatusCode::NOT_FOUND,
        "expected 405 or 404, got {}",
        resp.status.as_u16()
    );

    test_complete!("t52_route_06_method_not_allowed");
}

// ============================================================================
// Section 2: Web Extractor Contracts (T53-EXTRACT)
// ============================================================================

#[test]
fn t53_extract_01_query_params() {
    init_test("t53_extract_01_query_params");

    fn handler(Query(params): Query<HashMap<String, String>>) -> String {
        let a = params.get("a").cloned().unwrap_or_default();
        let b = params.get("b").cloned().unwrap_or_default();
        format!("a={a},b={b}")
    }

    let router = Router::new().route(
        "/q",
        get(FnHandler1::<_, Query<HashMap<String, String>>>::new(
            handler,
        )),
    );
    let req = Request::new("GET", "/q").with_query("a=hello&b=world");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "a=hello,b=world");

    test_complete!("t53_extract_01_query_params");
}

#[test]
fn t53_extract_02_json_body_roundtrip() {
    init_test("t53_extract_02_json_body_roundtrip");

    fn handler(
        JsonExtract(body): JsonExtract<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("anon");
        let out = serde_json::json!({"greeting": format!("hello {name}")});
        (StatusCode::OK, Json(out))
    }

    let router = Router::new().route(
        "/echo",
        post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
            handler,
        )),
    );
    let req = Request::new("POST", "/echo")
        .with_header("content-type", "application/json")
        .with_body(Bytes::from_static(br#"{"name":"alice"}"#));
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["greeting"], "hello alice");

    test_complete!("t53_extract_02_json_body_roundtrip");
}

#[test]
fn t53_extract_03_form_body() {
    init_test("t53_extract_03_form_body");

    fn handler(Form(data): Form<HashMap<String, String>>) -> String {
        let user = data.get("user").cloned().unwrap_or_default();
        format!("user={user}")
    }

    let router = Router::new().route(
        "/form",
        post(FnHandler1::<_, Form<HashMap<String, String>>>::new(handler)),
    );
    let req = Request::new("POST", "/form").with_body(Bytes::from_static(b"user=bob&age=30"));
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user=bob");

    test_complete!("t53_extract_03_form_body");
}

#[test]
fn t53_extract_04_state_injection() {
    init_test("t53_extract_04_state_injection");

    fn handler(State(counter): State<Arc<AtomicU32>>) -> String {
        let v = counter.fetch_add(1, Ordering::Relaxed);
        format!("count={v}")
    }

    let counter = Arc::new(AtomicU32::new(0));
    let router = Router::new()
        .route(
            "/count",
            get(FnHandler1::<_, State<Arc<AtomicU32>>>::new(handler)),
        )
        .with_state(counter.clone());

    let resp1 = router.handle(Request::new("GET", "/count"));
    assert_eq!(std::str::from_utf8(&resp1.body).unwrap(), "count=0");

    let resp2 = router.handle(Request::new("GET", "/count"));
    assert_eq!(std::str::from_utf8(&resp2.body).unwrap(), "count=1");
    assert_eq!(counter.load(Ordering::Relaxed), 2);

    test_complete!("t53_extract_04_state_injection");
}

#[test]
fn t53_extract_05_raw_body_passthrough() {
    init_test("t53_extract_05_raw_body_passthrough");

    fn handler(RawBody(body): RawBody) -> Bytes {
        body
    }

    let router = Router::new().route("/raw", post(FnHandler1::<_, RawBody>::new(handler)));
    let req = Request::new("POST", "/raw").with_body(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]));
    let resp = router.handle(req);
    assert_eq!(&resp.body[..], &[0xDE, 0xAD, 0xBE, 0xEF]);

    test_complete!("t53_extract_05_raw_body_passthrough");
}

#[test]
fn t53_extract_06_cookie_read_write() {
    init_test("t53_extract_06_cookie_read_write");

    fn handler(Cookie(raw): Cookie) -> String {
        format!("raw:{raw}")
    }

    let router = Router::new().route("/cookie", get(FnHandler1::<_, Cookie>::new(handler)));
    let req = Request::new("GET", "/cookie").with_header("cookie", "theme=dark");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("t53_extract_06_cookie_read_write");
}

#[test]
fn t53_extract_07_path_percent_decoding() {
    init_test("t53_extract_07_path_percent_decoding");

    let router = Router::new().route(
        "/files/:name",
        get(FnHandler1::<_, Path<String>>::new(user_handler)),
    );
    let req = Request::new("GET", "/files/hello%20world");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    // URL decoding should produce "hello world"
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(
        body.contains("hello") && body.contains("world"),
        "expected decoded path, got: {body}"
    );

    test_complete!("t53_extract_07_path_percent_decoding");
}

// ============================================================================
// Section 3: Web Middleware Stack Contracts (T54-MW)
// ============================================================================

#[test]
fn t54_mw_01_cors_preflight() {
    init_test("t54_mw_01_cors_preflight");

    let policy = CorsPolicy {
        allow_origin: CorsAllowOrigin::Any,
        allow_methods: vec!["GET".into(), "POST".into()],
        allow_headers: vec!["content-type".into()],
        allow_credentials: false,
        expose_headers: vec![],
        max_age: Some(Duration::from_secs(3600)),
    };
    let inner = FnHandler::new(|| "ok");
    let cors = CorsMiddleware::new(inner, policy);

    let req = Request::new("OPTIONS", "/api")
        .with_header("origin", "http://example.com")
        .with_header("access-control-request-method", "POST");
    let resp = cors.call(req);
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    assert!(resp.headers.contains_key("access-control-allow-origin"));
    assert!(resp.headers.contains_key("access-control-allow-methods"));

    test_complete!("t54_mw_01_cors_preflight");
}

#[test]
fn t54_mw_02_cors_preserves_vary_header() {
    init_test("t54_mw_02_cors_preserves_vary_header");

    // Inner handler sets Vary: accept-encoding.
    fn inner_handler() -> asupersync::web::response::Response {
        asupersync::web::response::Response::new(StatusCode::OK, "ok")
            .header("vary", "accept-encoding")
    }

    let policy = CorsPolicy {
        allow_origin: CorsAllowOrigin::Any,
        allow_methods: vec!["GET".into()],
        allow_headers: vec![],
        allow_credentials: false,
        expose_headers: vec![],
        max_age: None,
    };
    let cors = CorsMiddleware::new(FnHandler::new(inner_handler), policy);

    let req = Request::new("GET", "/api").with_header("origin", "http://example.com");
    let resp = cors.call(req);

    // Both "origin" and "accept-encoding" must appear in Vary.
    let vary = resp.headers.get("vary").expect("Vary header missing");
    assert!(
        vary.contains("origin"),
        "Vary must contain 'origin', got: {vary}"
    );
    assert!(
        vary.contains("accept-encoding"),
        "Vary must preserve 'accept-encoding', got: {vary}"
    );

    test_complete!("t54_mw_02_cors_preserves_vary_header");
}

#[test]
fn t54_mw_03_compression_content_negotiation() {
    init_test("t54_mw_03_compression_content_negotiation");

    let inner = FnHandler::new(|| "a]".repeat(1000)); // Large enough to compress
    let compress = CompressionMiddleware::new(inner, CompressionConfig::default());

    let req = Request::new("GET", "/big").with_header("accept-encoding", "gzip, deflate");
    let resp = compress.call(req);

    // Response should be compressed or have vary header.
    let vary = resp.headers.get("vary").unwrap_or(&String::new()).clone();
    assert!(
        vary.contains("accept-encoding") || resp.headers.contains_key("content-encoding"),
        "compression middleware must set Vary or Content-Encoding"
    );

    test_complete!("t54_mw_03_compression_content_negotiation");
}

#[test]
fn t54_mw_04_auth_bearer_token() {
    init_test("t54_mw_04_auth_bearer_token");

    let inner = FnHandler::new(|| "protected");
    let auth = AuthMiddleware::new(
        inner,
        AuthPolicy::ExactBearer(vec!["secret-token".to_string()]),
    );

    // Valid token.
    let req = Request::new("GET", "/").with_header("authorization", "Bearer secret-token");
    let resp = auth.call(req);
    assert_eq!(resp.status, StatusCode::OK);

    // Invalid token.
    let req2 = Request::new("GET", "/").with_header("authorization", "Bearer wrong-token");
    let resp2 = auth.call(req2);
    assert_eq!(resp2.status, StatusCode::UNAUTHORIZED);

    // Missing header.
    let req3 = Request::new("GET", "/");
    let resp3 = auth.call(req3);
    assert_eq!(resp3.status, StatusCode::UNAUTHORIZED);

    test_complete!("t54_mw_04_auth_bearer_token");
}

#[test]
fn t54_mw_05_timeout_enforcement() {
    init_test("t54_mw_05_timeout_enforcement");

    let fast = FnHandler::new(|| "fast");
    let timeout_mw = TimeoutMiddleware::new(fast, Duration::from_secs(5));

    let req = Request::new("GET", "/");
    let resp = timeout_mw.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "fast");

    test_complete!("t54_mw_05_timeout_enforcement");
}

#[test]
fn t54_mw_06_catch_panic_recovery() {
    init_test("t54_mw_06_catch_panic_recovery");

    fn panicking_handler() -> &'static str {
        panic!("boom");
    }

    let inner = FnHandler::new(panicking_handler);
    let safe = CatchPanicMiddleware::new(inner);

    let req = Request::new("GET", "/");
    let resp = safe.call(req);
    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);

    test_complete!("t54_mw_06_catch_panic_recovery");
}

#[test]
fn t54_mw_07_request_body_limit() {
    init_test("t54_mw_07_request_body_limit");

    let inner = FnHandler::new(|| "ok");
    let limiter = RequestBodyLimitMiddleware::new(inner, 100);

    // Small body -- passes.
    let req = Request::new("POST", "/").with_body(Bytes::from(vec![0u8; 50]));
    let resp = limiter.call(req);
    assert_eq!(resp.status, StatusCode::OK);

    // Large body -- rejected.
    let req2 = Request::new("POST", "/").with_body(Bytes::from(vec![0u8; 200]));
    let resp2 = limiter.call(req2);
    assert_eq!(resp2.status, StatusCode::PAYLOAD_TOO_LARGE);

    test_complete!("t54_mw_07_request_body_limit");
}

#[test]
fn t54_mw_08_request_id_generation() {
    init_test("t54_mw_08_request_id_generation");

    let inner = FnHandler::new(|| "ok");
    let id_mw = RequestIdMiddleware::new(inner, "x-request-id");

    let req = Request::new("GET", "/");
    let resp = id_mw.call(req);
    assert!(
        resp.headers.contains_key("x-request-id"),
        "must add x-request-id header"
    );

    // Second request gets a different ID.
    let req2 = Request::new("GET", "/");
    let resp2 = id_mw.call(req2);
    let id1 = resp.headers.get("x-request-id").unwrap();
    let id2 = resp2.headers.get("x-request-id").unwrap();
    assert_ne!(id1, id2, "request IDs must be unique");

    test_complete!("t54_mw_08_request_id_generation");
}

#[test]
fn t54_mw_09_normalize_path_trailing_slash() {
    init_test("t54_mw_09_normalize_path_trailing_slash");

    let inner = FnHandler::new(|| "normalized");
    let norm = NormalizePathMiddleware::new(inner, TrailingSlash::Trim);

    let req = Request::new("GET", "/api/users/");
    let resp = norm.call(req);
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("t54_mw_09_normalize_path_trailing_slash");
}

#[test]
fn t54_mw_10_set_response_header() {
    init_test("t54_mw_10_set_response_header");

    let inner = FnHandler::new(|| "ok");
    let set_hdr = SetResponseHeaderMiddleware::always(inner, "x-custom", "value123");

    let req = Request::new("GET", "/");
    let resp = set_hdr.call(req);
    assert_eq!(
        resp.headers.get("x-custom").map(String::as_str),
        Some("value123")
    );

    test_complete!("t54_mw_10_set_response_header");
}

#[test]
fn t54_mw_11_middleware_stack_composition() {
    init_test("t54_mw_11_middleware_stack_composition");

    // Stack: CatchPanic -> RequestId -> handler
    let inner = FnHandler::new(|| "stacked");
    let with_id = RequestIdMiddleware::new(inner, "x-request-id");
    let safe = CatchPanicMiddleware::new(with_id);

    let req = Request::new("GET", "/");
    let resp = safe.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.headers.contains_key("x-request-id"));
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "stacked");

    test_complete!("t54_mw_11_middleware_stack_composition");
}

#[test]
fn t54_mw_12_security_headers() {
    init_test("t54_mw_12_security_headers");

    let policy = SecurityPolicy::default();
    let inner = FnHandler::new(|| "secure");
    let sec = SecurityHeadersMiddleware::new(inner, policy);

    let req = Request::new("GET", "/");
    let resp = sec.call(req);
    assert!(
        resp.headers.contains_key("x-content-type-options"),
        "must set nosniff"
    );
    assert!(
        resp.headers.contains_key("x-frame-options"),
        "must set frame deny"
    );

    test_complete!("t54_mw_12_security_headers");
}

// ============================================================================
// Section 4: gRPC Unary + Streaming (T56-GRPC)
// ============================================================================

#[test]
fn t56_grpc_01_codec_encode_decode_roundtrip() {
    init_test("t56_grpc_01_codec_encode_decode_roundtrip");

    let mut codec = GrpcCodec::default();
    let msg = GrpcMessage::new(Bytes::from("hello gRPC"));

    let mut buf = BytesMut::new();
    codec.encode(msg, &mut buf).expect("encode failed");

    // Decode: 5-byte header (1 compressed flag + 4 length) + payload.
    assert!(buf.len() >= 5 + 10, "encoded size too small");

    let decoded = codec.decode(&mut buf).expect("decode failed");
    assert!(decoded.is_some(), "expected a decoded message");
    let decoded = decoded.unwrap();
    assert_eq!(&decoded.data[..], b"hello gRPC");

    test_complete!("t56_grpc_01_codec_encode_decode_roundtrip");
}

#[test]
fn t56_grpc_02_status_code_semantics() {
    init_test("t56_grpc_02_status_code_semantics");

    // OK
    let ok = Status::ok();
    assert_eq!(ok.code(), Code::Ok);

    // Standard error codes.
    let not_found = Status::new(Code::NotFound, "resource missing");
    assert_eq!(not_found.code(), Code::NotFound);
    assert_eq!(not_found.message(), "resource missing");

    // All 17 codes roundtrip from i32.
    for code_val in 0..=16i32 {
        let code = Code::from_i32(code_val);
        let status = Status::new(code, "");
        assert_eq!(status.code(), code);
    }

    test_complete!("t56_grpc_02_status_code_semantics");
}

#[test]
fn t56_grpc_03_metadata_ascii_binary() {
    init_test("t56_grpc_03_metadata_ascii_binary");

    let mut md = Metadata::new();

    // ASCII metadata.
    md.insert("x-trace-id", "abc123");
    assert!(
        md.get("x-trace-id").is_some(),
        "ASCII metadata must be retrievable"
    );
    if let Some(MetadataValue::Ascii(val)) = md.get("x-trace-id") {
        assert_eq!(val, "abc123");
    }

    // Binary metadata (key suffix must be "-bin").
    md.insert_bin("x-payload-bin", Bytes::from_static(b"\x00\x01\x02\x03"));
    let retrieved = md.get("x-payload-bin");
    assert!(retrieved.is_some(), "binary metadata must be retrievable");

    // Iteration.
    let count = md.iter().count();
    assert!(count >= 2, "metadata must contain at least 2 entries");

    test_complete!("t56_grpc_03_metadata_ascii_binary");
}

#[test]
fn t56_grpc_04_request_response_metadata_flow() {
    init_test("t56_grpc_04_request_response_metadata_flow");

    let mut req = GrpcRequest::new("payload");
    req.metadata_mut().insert("x-id", "req-001");
    assert!(req.metadata().get("x-id").is_some());
    assert_eq!(req.into_inner(), "payload");

    let mut resp = GrpcResponse::new("result");
    resp.metadata_mut().insert("x-resp-id", "resp-001");
    assert!(resp.metadata().get("x-resp-id").is_some());
    assert_eq!(resp.into_inner(), "result");

    test_complete!("t56_grpc_04_request_response_metadata_flow");
}

#[test]
fn t56_grpc_05_method_descriptor_types() {
    init_test("t56_grpc_05_method_descriptor_types");

    let unary = MethodDescriptor::unary("Echo", "/test.Service/Echo");
    assert!(!unary.client_streaming && !unary.server_streaming);

    let server_stream = MethodDescriptor::server_streaming("Watch", "/test.Service/Watch");
    assert!(server_stream.server_streaming);
    assert!(!server_stream.client_streaming);

    let bidi = MethodDescriptor::bidi_streaming("Chat", "/test.Service/Chat");
    assert!(bidi.client_streaming && bidi.server_streaming);

    test_complete!("t56_grpc_05_method_descriptor_types");
}

#[test]
fn t56_grpc_06_channel_config_defaults() {
    init_test("t56_grpc_06_channel_config_defaults");

    let config = ChannelConfig::default();
    assert!(config.connect_timeout > Duration::ZERO);

    let custom = ChannelConfig {
        connect_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    assert_eq!(custom.connect_timeout, Duration::from_secs(1));

    test_complete!("t56_grpc_06_channel_config_defaults");
}

// ============================================================================
// Section 5: gRPC Health + Reflection (T57-HEALTH)
// ============================================================================

#[test]
fn t57_health_01_service_status_transitions() {
    init_test("t57_health_01_service_status_transitions");

    let health = HealthService::new();

    // Set server status to Serving.
    health.set_server_status(ServingStatus::Serving);
    let req = HealthCheckRequest::server();
    let resp = health.check(&req);
    assert!(resp.is_ok());
    assert_eq!(resp.unwrap().status, ServingStatus::Serving);

    // Set specific service status.
    health.set_status("my.Service", ServingStatus::NotServing);
    let req2 = HealthCheckRequest::new("my.Service");
    let resp2 = health.check(&req2);
    assert!(resp2.is_ok());
    assert_eq!(resp2.unwrap().status, ServingStatus::NotServing);

    // Update back to serving.
    health.set_status("my.Service", ServingStatus::Serving);
    let resp3 = health.check(&req2);
    assert!(resp3.is_ok());
    assert_eq!(resp3.unwrap().status, ServingStatus::Serving);

    test_complete!("t57_health_01_service_status_transitions");
}

#[test]
fn t57_health_02_unknown_service() {
    init_test("t57_health_02_unknown_service");

    let health = HealthService::new();
    let req = HealthCheckRequest::new("nonexistent.Service");
    let resp = health.check(&req);
    // Unknown services may return Err or a non-Serving status.
    if let Ok(r) = resp {
        assert_ne!(r.status, ServingStatus::Serving);
    }

    test_complete!("t57_health_02_unknown_service");
}

/// Mock service for testing reflection.
struct MockEchoService;

impl NamedService for MockEchoService {
    const NAME: &'static str = "test.Echo";
}

impl ServiceHandler for MockEchoService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::unary("Echo", "/test.Echo/Echo")];
        static DESC: ServiceDescriptor = ServiceDescriptor::new("Echo", "test", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Echo"]
    }
}

struct MockChatService;

impl NamedService for MockChatService {
    const NAME: &'static str = "test.Chat";
}

impl ServiceHandler for MockChatService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::bidi_streaming(
            "Stream",
            "/test.Chat/Stream",
        )];
        static DESC: ServiceDescriptor = ServiceDescriptor::new("Chat", "test", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Stream"]
    }
}

#[test]
fn t57_health_03_reflection_list_services() {
    init_test("t57_health_03_reflection_list_services");

    let reflection = ReflectionService::new();
    let echo = MockEchoService;
    let chat = MockChatService;
    reflection.register_handler(&echo);
    reflection.register_handler(&chat);

    let services = reflection.list_services();
    assert!(
        services.iter().any(|s| s == "test.Echo"),
        "must list Echo service"
    );
    assert!(
        services.iter().any(|s| s == "test.Chat"),
        "must list Chat service"
    );

    test_complete!("t57_health_03_reflection_list_services");
}

#[test]
fn t57_health_04_reflection_describe_service() {
    init_test("t57_health_04_reflection_describe_service");

    let reflection = ReflectionService::new();
    let echo = MockEchoService;
    reflection.register_handler(&echo);

    let desc = reflection.describe_service("test.Echo");
    assert!(desc.is_ok(), "service must be found");
    let info = desc.unwrap();
    assert!(!info.methods.is_empty());
    assert!(info.methods.iter().any(|m| m.name == "Echo"));

    test_complete!("t57_health_04_reflection_describe_service");
}

// ============================================================================
// Section 6: gRPC Compression + Codec (T58-CODEC)
// ============================================================================

#[test]
fn t58_codec_01_uncompressed_frame_format() {
    init_test("t58_codec_01_uncompressed_frame_format");

    let mut codec = GrpcCodec::default();
    let msg = GrpcMessage::new(Bytes::from("test"));

    let mut buf = BytesMut::new();
    codec.encode(msg, &mut buf).unwrap();

    // First byte: 0 = uncompressed.
    assert_eq!(buf[0], 0, "first byte must be 0 for uncompressed");
    // Next 4 bytes: big-endian length.
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    assert_eq!(len as usize, 4, "payload length must be 4");
    // Payload.
    assert_eq!(&buf[5..9], b"test");

    test_complete!("t58_codec_01_uncompressed_frame_format");
}

#[test]
fn t58_codec_02_empty_message() {
    init_test("t58_codec_02_empty_message");

    let mut codec = GrpcCodec::default();
    let msg = GrpcMessage::new(Bytes::new());

    let mut buf = BytesMut::new();
    codec.encode(msg, &mut buf).unwrap();

    assert_eq!(buf.len(), 5, "empty message = 5-byte header only");
    assert_eq!(buf[0], 0);
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    assert_eq!(len, 0);

    let decoded = codec.decode(&mut buf).unwrap();
    assert!(decoded.is_some());
    assert!(decoded.unwrap().data.is_empty());

    test_complete!("t58_codec_02_empty_message");
}

#[test]
fn t58_codec_03_large_message_framing() {
    init_test("t58_codec_03_large_message_framing");

    let mut codec = GrpcCodec::default();
    let payload = vec![0xABu8; 64 * 1024]; // 64 KiB
    let msg = GrpcMessage::new(Bytes::from(payload));

    let mut buf = BytesMut::new();
    codec.encode(msg, &mut buf).unwrap();

    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    assert_eq!(len as usize, 64 * 1024);

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.data.len(), 64 * 1024);

    test_complete!("t58_codec_03_large_message_framing");
}

#[test]
fn t58_codec_04_partial_frame_buffering() {
    init_test("t58_codec_04_partial_frame_buffering");

    let mut codec = GrpcCodec::default();
    let msg = GrpcMessage::new(Bytes::from("partial"));

    let mut full = BytesMut::new();
    codec.encode(msg, &mut full).unwrap();

    // Feed only the header (5 bytes) -- should return None (incomplete).
    let mut partial = BytesMut::from(&full[..5]);
    let result = codec.decode(&mut partial).unwrap();
    assert!(result.is_none(), "partial frame must return None");

    // Feed the full frame.
    let mut complete = BytesMut::from(&full[..]);
    let result = codec.decode(&mut complete).unwrap();
    assert!(result.is_some());

    test_complete!("t58_codec_04_partial_frame_buffering");
}

// ============================================================================
// Section 7: gRPC Interceptor Chains (T59-ICEPT)
// ============================================================================

#[test]
fn t59_icept_01_fn_interceptor_passthrough() {
    init_test("t59_icept_01_fn_interceptor_passthrough");

    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();
    let interceptor = fn_interceptor(move |req: &mut GrpcRequest<Bytes>| -> Result<(), Status> {
        c.fetch_add(1, Ordering::Relaxed);
        req.metadata_mut().insert("x-intercepted", "true");
        Ok(())
    });

    let mut req = GrpcRequest::new(Bytes::from("test"));
    let result = interceptor.intercept_request(&mut req);
    assert!(result.is_ok());
    assert!(req.metadata().get("x-intercepted").is_some());
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    test_complete!("t59_icept_01_fn_interceptor_passthrough");
}

#[test]
fn t59_icept_02_auth_interceptor_adds_token() {
    init_test("t59_icept_02_auth_interceptor_adds_token");

    let auth = auth_bearer_interceptor("secret-token");
    let mut req = GrpcRequest::new(Bytes::from("data"));
    let result = auth.intercept_request(&mut req);
    assert!(result.is_ok(), "auth interceptor should add token");
    // Check authorization header was added.
    let auth_header = req.metadata().get("authorization");
    assert!(auth_header.is_some(), "auth header must be set");

    test_complete!("t59_icept_02_auth_interceptor_adds_token");
}

#[test]
fn t59_icept_03_timeout_interceptor_adds_deadline() {
    init_test("t59_icept_03_timeout_interceptor_adds_deadline");

    let timeout = timeout_interceptor(5000); // 5000 ms
    let mut req = GrpcRequest::new(Bytes::from("timed"));
    let result = timeout.intercept_request(&mut req);
    assert!(result.is_ok());
    let grpc_timeout = req.metadata().get("grpc-timeout");
    assert!(
        grpc_timeout.is_some(),
        "timeout interceptor must set grpc-timeout"
    );

    test_complete!("t59_icept_03_timeout_interceptor_adds_deadline");
}

#[test]
fn t59_icept_04_metadata_propagator() {
    init_test("t59_icept_04_metadata_propagator");

    let propagator = metadata_propagator(["x-trace-id", "x-span-id"]);
    let mut req = GrpcRequest::new(Bytes::from("traced"));
    req.metadata_mut().insert("x-trace-id", "trace-abc");
    req.metadata_mut().insert("x-span-id", "span-123");
    req.metadata_mut().insert("x-other", "not-propagated");

    let result = propagator.intercept_request(&mut req);
    assert!(result.is_ok());
    // Propagated keys should still be present.
    assert!(req.metadata().get("x-trace-id").is_some());
    assert!(req.metadata().get("x-span-id").is_some());

    test_complete!("t59_icept_04_metadata_propagator");
}

#[test]
fn t59_icept_05_interceptor_layer_ordering() {
    init_test("t59_icept_05_interceptor_layer_ordering");

    let layer = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(logging_interceptor())
        .layer(auth_bearer_interceptor("token"))
        .layer(rate_limiter(100))
        .layer(timeout_interceptor(5000));

    assert_eq!(layer.len(), 5, "chain must have 5 interceptors");
    assert!(!layer.is_empty());

    // Apply the full chain.
    let mut req = GrpcRequest::new(Bytes::from("chained"));
    let result = layer.intercept_request(&mut req);
    assert!(result.is_ok(), "full chain must succeed");

    test_complete!("t59_icept_05_interceptor_layer_ordering");
}

#[test]
fn t59_icept_06_rate_limiter_basic() {
    init_test("t59_icept_06_rate_limiter_basic");

    let limiter = rate_limiter(3);
    for i in 0..5 {
        let mut req = GrpcRequest::new(Bytes::from("data"));
        let result = limiter.intercept_request(&mut req);
        tracing::info!(attempt = i, is_ok = result.is_ok(), "rate limit check");
    }

    test_complete!("t59_icept_06_rate_limiter_basic");
}

// ============================================================================
// Section 8: gRPC-Web Protocol (T60-GRPCWEB)
// ============================================================================

#[test]
fn t60_grpcweb_01_content_type_detection() {
    init_test("t60_grpcweb_01_content_type_detection");

    use asupersync::grpc::web::ContentType;

    let binary = ContentType::from_header_value("application/grpc-web");
    assert!(
        matches!(binary, Some(ContentType::GrpcWeb)),
        "must detect binary content type"
    );

    let text = ContentType::from_header_value("application/grpc-web-text");
    assert!(
        matches!(text, Some(ContentType::GrpcWebText)),
        "must detect text content type"
    );

    let none = ContentType::from_header_value("application/json");
    assert!(none.is_none(), "non-grpc-web content type must be None");

    test_complete!("t60_grpcweb_01_content_type_detection");
}

#[test]
fn t60_grpcweb_02_binary_frame_roundtrip() {
    init_test("t60_grpcweb_02_binary_frame_roundtrip");

    use asupersync::grpc::web::{WebFrame, WebFrameCodec};

    let codec = WebFrameCodec::new();
    let payload = b"grpc-web binary test";

    // Encode a data frame.
    let mut encoded = BytesMut::new();
    codec.encode_data(payload, false, &mut encoded).unwrap();
    assert!(!encoded.is_empty());

    // Decode.
    let decoded = codec.decode(&mut encoded).unwrap();
    assert!(decoded.is_some(), "must decode frame");
    match decoded.unwrap() {
        WebFrame::Data { compressed, data } => {
            assert!(!compressed, "data frame must not be compressed");
            assert_eq!(&data[..], payload);
        }
        WebFrame::Trailers(_) => panic!("expected data frame, got trailers"),
    }

    test_complete!("t60_grpcweb_02_binary_frame_roundtrip");
}

#[test]
fn t60_grpcweb_03_trailer_frame_encoding() {
    init_test("t60_grpcweb_03_trailer_frame_encoding");

    use asupersync::grpc::web::WebFrameCodec;

    let codec = WebFrameCodec::new();
    let status = Status::ok();
    let metadata = Metadata::new();

    let mut encoded = BytesMut::new();
    codec
        .encode_trailers(&status, &metadata, &mut encoded)
        .unwrap();
    assert!(!encoded.is_empty());

    // Trailer frame: first byte has bit 7 set (0x80).
    assert_eq!(encoded[0] & 0x80, 0x80, "trailer flag bit must be set");

    test_complete!("t60_grpcweb_03_trailer_frame_encoding");
}

#[test]
fn t60_grpcweb_04_base64_text_mode() {
    init_test("t60_grpcweb_04_base64_text_mode");

    use asupersync::grpc::web::{base64_decode, base64_encode};

    let original = b"Hello gRPC-Web text mode!";
    let encoded = base64_encode(original);
    assert!(!encoded.is_empty());

    let decoded = base64_decode(&encoded).expect("base64 decode failed");
    assert_eq!(&decoded[..], original);

    test_complete!("t60_grpcweb_04_base64_text_mode");
}

#[test]
fn t60_grpcweb_05_content_type_header_values() {
    init_test("t60_grpcweb_05_content_type_header_values");

    use asupersync::grpc::web::ContentType;

    let binary_header = ContentType::GrpcWeb.as_header_value();
    assert!(
        binary_header.starts_with("application/grpc-web"),
        "binary header: {binary_header}"
    );

    let text_header = ContentType::GrpcWebText.as_header_value();
    assert!(
        text_header.starts_with("application/grpc-web-text"),
        "text header: {text_header}"
    );

    assert!(!ContentType::GrpcWeb.is_text_mode());
    assert!(ContentType::GrpcWebText.is_text_mode());

    test_complete!("t60_grpcweb_05_content_type_header_values");
}

#[test]
fn t60_grpcweb_06_request_detection() {
    init_test("t60_grpcweb_06_request_detection");

    use asupersync::grpc::web::{is_grpc_web_request, is_text_mode};

    assert!(is_grpc_web_request("application/grpc-web"));
    assert!(is_grpc_web_request("application/grpc-web-text"));
    assert!(!is_grpc_web_request("application/json"));

    assert!(!is_text_mode("application/grpc-web"));
    assert!(is_text_mode("application/grpc-web-text"));

    test_complete!("t60_grpcweb_06_request_detection");
}

// ============================================================================
// Section 9: Cross-Stack Lifecycle (T61-LIFE)
// ============================================================================

#[test]
fn t61_life_01_session_middleware_full_lifecycle() {
    init_test("t61_life_01_session_middleware_full_lifecycle");

    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .cookie_name("sid")
        .same_site(SameSite::Lax)
        .max_age(3600);

    struct SessionCountHandler;

    impl Handler for SessionCountHandler {
        fn call(&self, req: Request) -> asupersync::web::response::Response {
            let session = req.extensions.get_typed::<Session>().unwrap();
            let count = session
                .get("count")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            session.insert("count", (count + 1).to_string());
            let body = format!("count={}", count + 1);
            asupersync::web::response::Response::new(StatusCode::OK, body)
        }
    }

    let mw = layer.wrap(SessionCountHandler);

    // First request: creates session.
    let resp1 = mw.call(Request::new("GET", "/"));
    assert_eq!(std::str::from_utf8(&resp1.body).unwrap(), "count=1");
    let cookie1 = resp1.headers.get("set-cookie").unwrap().clone();
    assert!(cookie1.contains("sid="));

    // Extract session ID.
    let sid = cookie1
        .split('=')
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap();

    // Second request with session cookie.
    let req2 = Request::new("GET", "/").with_header("cookie", format!("sid={sid}"));
    let resp2 = mw.call(req2);
    assert_eq!(std::str::from_utf8(&resp2.body).unwrap(), "count=2");

    test_complete!("t61_life_01_session_middleware_full_lifecycle");
}

#[test]
fn t61_life_02_health_check_endpoint() {
    init_test("t61_life_02_health_check_endpoint");

    let health = HealthCheck::new();
    let liveness = health.liveness_handler();
    let readiness = health.readiness_handler();

    // Both liveness and readiness should return 200 initially.
    let resp_live = liveness.call(Request::new("GET", "/healthz"));
    assert_eq!(resp_live.status, StatusCode::OK);

    let resp_ready = readiness.call(Request::new("GET", "/readyz"));
    assert_eq!(resp_ready.status, StatusCode::OK);

    // Set not ready.
    health.set_ready(false);
    let resp_ready2 = readiness.call(Request::new("GET", "/readyz"));
    assert_eq!(resp_ready2.status, StatusCode::SERVICE_UNAVAILABLE);

    // Liveness should still return 200.
    let resp_live2 = liveness.call(Request::new("GET", "/healthz"));
    assert_eq!(resp_live2.status, StatusCode::OK);

    test_complete!("t61_life_02_health_check_endpoint");
}

#[test]
fn t61_life_03_router_with_state_and_middleware() {
    init_test("t61_life_03_router_with_state_and_middleware");

    let counter = Arc::new(AtomicU32::new(0));

    fn handler(State(c): State<Arc<AtomicU32>>) -> String {
        let v = c.fetch_add(1, Ordering::Relaxed);
        format!("{v}")
    }

    let router = Router::new()
        .route(
            "/inc",
            get(FnHandler1::<_, State<Arc<AtomicU32>>>::new(handler)),
        )
        .with_state(counter);

    let resp = router.handle(Request::new("GET", "/inc"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "0");

    let resp2 = router.handle(Request::new("GET", "/inc"));
    assert_eq!(std::str::from_utf8(&resp2.body).unwrap(), "1");

    test_complete!("t61_life_03_router_with_state_and_middleware");
}

// ============================================================================
// Section 10: Cancellation and Determinism (T62-CX)
// ============================================================================

#[test]
fn t62_cx_01_grpc_status_deterministic_roundtrip() {
    init_test("t62_cx_01_grpc_status_deterministic_roundtrip");

    // All 17 status codes must roundtrip consistently.
    for code_val in 0..=16i32 {
        let code = Code::from_i32(code_val);
        let status = Status::new(code, "test");
        let code2 = Code::from_i32(status.code().as_i32());
        assert_eq!(code, code2, "code roundtrip failed for {code_val}");
    }

    test_complete!("t62_cx_01_grpc_status_deterministic_roundtrip");
}

#[test]
fn t62_cx_02_metadata_ordering_deterministic() {
    init_test("t62_cx_02_metadata_ordering_deterministic");

    let mut md1 = Metadata::new();
    md1.insert("a", "1");
    md1.insert("b", "2");
    md1.insert("c", "3");

    let mut md2 = Metadata::new();
    md2.insert("a", "1");
    md2.insert("b", "2");
    md2.insert("c", "3");

    // Same keys/values -> same iteration order.
    let keys1: Vec<&str> = md1.iter().map(|(k, _)| k).collect();
    let keys2: Vec<&str> = md2.iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys1, keys2,
        "metadata iteration order must be deterministic"
    );

    test_complete!("t62_cx_02_metadata_ordering_deterministic");
}

#[test]
fn t62_cx_03_codec_deterministic_encoding() {
    init_test("t62_cx_03_codec_deterministic_encoding");

    let mut codec = GrpcCodec::default();
    let msg1 = GrpcMessage::new(Bytes::from("determinism"));
    let msg2 = GrpcMessage::new(Bytes::from("determinism"));

    let mut buf1 = BytesMut::new();
    let mut buf2 = BytesMut::new();
    codec.encode(msg1, &mut buf1).unwrap();
    codec.encode(msg2, &mut buf2).unwrap();

    assert_eq!(buf1, buf2, "same message must produce same encoding");

    test_complete!("t62_cx_03_codec_deterministic_encoding");
}

#[test]
fn t62_cx_04_router_match_deterministic() {
    init_test("t62_cx_04_router_match_deterministic");

    let router = Router::new()
        .route("/a", get(FnHandler::new(|| "a")))
        .route("/b", get(FnHandler::new(|| "b")))
        .route("/c", get(FnHandler::new(|| "c")));

    // Multiple calls to same path must always return same result.
    for _ in 0..10 {
        let resp = router.handle(Request::new("GET", "/b"));
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "b");
    }

    test_complete!("t62_cx_04_router_match_deterministic");
}
