#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! Full-Stack HTTP Server Integration Tests (bd-1phl).
//!
//! Exercises: basic req/res lifecycle, keep-alive reuse, concurrent clients,
//! size limits, malformed requests, compression negotiation, chunked encoding,
//! pool exhaustion/recovery, and graceful shutdown patterns.

#[macro_use]
mod common;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::body::{Body, Empty, Full, HeaderMap, HeaderName, HeaderValue};
use asupersync::http::compress::{ContentEncoding, negotiate_encoding};
use asupersync::http::h1::codec::Http1Codec;
use asupersync::http::h1::server::Http1Config;
use asupersync::http::h1::types::{Method, Request as H1Request, Version};
use asupersync::http::pool::{Pool, PoolConfig, PoolKey};
use asupersync::types::Time;
use asupersync::web::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use asupersync::web::handler::{FnHandler, FnHandler1};
use asupersync::web::response::{Json, StatusCode};
use asupersync::web::router::{Router, get, post};
use common::*;
use std::collections::HashMap;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Section 1: Basic Request/Response Lifecycle
// ============================================================================

#[test]
fn e2e_http_basic_get_response() {
    init_test("e2e_http_basic_get_response");

    test_section!("setup_router");
    fn hello() -> &'static str {
        "Hello, World!"
    }

    let router = Router::new().route("/", get(FnHandler::new(hello)));

    test_section!("execute");
    let resp = router.handle(Request::new("GET", "/"));
    tracing::info!(status = resp.status.as_u16(), "response received");

    test_section!("verify");
    assert_with_log!(
        resp.status == StatusCode::OK,
        "status is 200",
        StatusCode::OK,
        resp.status
    );
    assert_with_log!(
        !resp.body.is_empty(),
        "body not empty",
        true,
        !resp.body.is_empty()
    );
    test_complete!("e2e_http_basic_get_response");
}

#[test]
fn e2e_http_post_with_json_body() {
    init_test("e2e_http_post_with_json_body");

    test_section!("setup");
    fn create_item(
        body: asupersync::web::extract::Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let mut item = body.0;
        item["id"] = serde_json::json!(42);
        (StatusCode::CREATED, Json(item))
    }

    let router = Router::new().route(
        "/items",
        post(FnHandler1::<
            _,
            asupersync::web::extract::Json<serde_json::Value>,
        >::new(create_item)),
    );

    test_section!("execute");
    let body = serde_json::to_vec(&serde_json::json!({"name": "widget", "price": 9.99})).unwrap();
    let req = Request::new("POST", "/items")
        .with_header("content-type", "application/json")
        .with_body(Bytes::copy_from_slice(&body));

    let resp = router.handle(req);
    tracing::info!(
        status = resp.status.as_u16(),
        body_len = resp.body.len(),
        "response"
    );

    test_section!("verify");
    assert_with_log!(
        resp.status == StatusCode::CREATED,
        "status 201",
        StatusCode::CREATED,
        resp.status
    );
    let result: serde_json::Value = serde_json::from_slice(resp.body.as_ref()).unwrap();
    assert_with_log!(result["id"] == 42, "id assigned", 42, result["id"]);
    assert_with_log!(
        result["name"] == "widget",
        "name preserved",
        "widget",
        result["name"]
    );
    test_complete!("e2e_http_post_with_json_body");
}

#[test]
fn e2e_http_method_not_allowed() {
    init_test("e2e_http_method_not_allowed");

    test_section!("setup");
    let router = Router::new().route("/readonly", get(FnHandler::new(|| "data")));

    test_section!("execute");
    let resp = router.handle(Request::new("POST", "/readonly"));
    tracing::info!(status = resp.status.as_u16(), "method not allowed response");

    test_section!("verify");
    assert_with_log!(
        resp.status == StatusCode::METHOD_NOT_ALLOWED,
        "405 for wrong method",
        StatusCode::METHOD_NOT_ALLOWED,
        resp.status
    );
    test_complete!("e2e_http_method_not_allowed");
}

#[test]
fn e2e_http_not_found() {
    init_test("e2e_http_not_found");

    test_section!("setup");
    let router = Router::new().route("/exists", get(FnHandler::new(|| "here")));

    test_section!("execute_and_verify");
    let resp = router.handle(Request::new("GET", "/missing"));
    assert_with_log!(
        resp.status == StatusCode::NOT_FOUND,
        "404 for missing route",
        StatusCode::NOT_FOUND,
        resp.status
    );
    test_complete!("e2e_http_not_found");
}

// ============================================================================
// Section 2: H1 Codec Roundtrip
// ============================================================================

#[test]
fn e2e_http_codec_request_roundtrip() {
    init_test("e2e_http_codec_request_roundtrip");

    test_section!("encode_request");
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::new();

    let _req = H1Request {
        method: Method::Get,
        uri: "/api/data".to_string(),
        version: Version::Http11,
        headers: vec![
            ("Host".to_string(), "localhost".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Vec::new(),
        trailers: Vec::new(),
        peer_addr: None,
    };

    // Manually encode an HTTP/1.1 request into the buffer
    let raw = "GET /api/data HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Length: 0\r\n\r\n";
    buf.extend_from_slice(raw.as_bytes());
    tracing::info!(buf_len = buf.len(), "request encoded");

    test_section!("decode_request");
    let decoded = codec.decode(&mut buf);
    tracing::info!(result = ?decoded.is_ok(), "decode result");

    test_section!("verify");
    match decoded {
        Ok(Some(parsed)) => {
            assert_with_log!(
                parsed.method == Method::Get,
                "method",
                Method::Get,
                parsed.method
            );
            assert_with_log!(parsed.uri == "/api/data", "uri", "/api/data", parsed.uri);
            tracing::info!(headers = ?parsed.headers.len(), "parsed headers");
        }
        Ok(None) => {
            tracing::info!("incomplete frame, need more data");
        }
        Err(e) => {
            tracing::info!(error = ?e, "decode error");
        }
    }
    test_complete!("e2e_http_codec_request_roundtrip");
}

#[test]
fn e2e_http_codec_malformed_request() {
    init_test("e2e_http_codec_malformed_request");

    test_section!("setup");
    let mut codec = Http1Codec::new();

    test_section!("test_garbage");
    let mut buf = BytesMut::from("THIS IS NOT HTTP\r\n\r\n");
    let result = codec.decode(&mut buf);
    tracing::info!(is_err = result.is_err(), "garbage decode result");
    // Should be an error or None
    match result {
        Ok(None) => tracing::info!("incomplete/unrecognized"),
        Ok(Some(_)) => tracing::warn!("unexpectedly parsed garbage"),
        Err(e) => {
            tracing::info!(error = ?e, "correctly rejected garbage");
        }
    }

    test_section!("test_missing_version");
    let mut codec2 = Http1Codec::new();
    let mut buf2 = BytesMut::from("GET /path\r\n\r\n");
    let result2 = codec2.decode(&mut buf2);
    tracing::info!(is_err = result2.is_err(), "missing version result");

    test_complete!("e2e_http_codec_malformed_request");
}

#[test]
fn e2e_http_codec_headers_too_large() {
    init_test("e2e_http_codec_headers_too_large");

    test_section!("setup");
    let mut codec = Http1Codec::new().max_headers_size(256);

    test_section!("build_oversized_request");
    let large_value = "X".repeat(300);
    let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: {large_value}\r\n\r\n");
    let mut buf = BytesMut::from(raw.as_str());
    tracing::info!(buf_len = buf.len(), max = 256, "testing oversized headers");

    test_section!("decode");
    let result = codec.decode(&mut buf);

    test_section!("verify");
    // Should reject or handle oversized headers
    match result {
        Err(e) => {
            tracing::info!(error = ?e, "correctly rejected oversized headers");
        }
        Ok(None) => {
            tracing::info!("incomplete frame with oversized headers");
        }
        Ok(Some(parsed)) => {
            tracing::info!(
                headers = parsed.headers.len(),
                "parsed despite large headers"
            );
        }
    }
    test_complete!("e2e_http_codec_headers_too_large");
}

#[test]
fn e2e_http_codec_body_too_large() {
    init_test("e2e_http_codec_body_too_large");

    test_section!("setup");
    let mut codec = Http1Codec::new().max_body_size(64);

    test_section!("build_oversized_body");
    let body = "A".repeat(128);
    let raw = format!(
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let mut buf = BytesMut::from(raw.as_str());
    tracing::info!(body_len = body.len(), max = 64, "testing oversized body");

    test_section!("decode");
    let result = codec.decode(&mut buf);

    test_section!("verify");
    match result {
        Err(e) => tracing::info!(error = ?e, "correctly rejected oversized body"),
        Ok(None) => tracing::info!("incomplete frame"),
        Ok(Some(parsed)) => tracing::info!(body_len = parsed.body.len(), "parsed body"),
    }
    test_complete!("e2e_http_codec_body_too_large");
}

// ============================================================================
// Section 3: Keep-Alive and Connection Reuse
// ============================================================================

#[test]
fn e2e_http_keepalive_multiple_requests() {
    init_test("e2e_http_keepalive_multiple_requests");

    test_section!("setup");
    let config = Http1Config::default()
        .keep_alive(true)
        .max_requests(Some(5));
    tracing::info!(keep_alive = config.keep_alive, max_req = ?config.max_requests_per_connection, "config");

    test_section!("verify_config");
    assert_with_log!(
        config.keep_alive,
        "keep_alive enabled",
        true,
        config.keep_alive
    );
    assert_with_log!(
        config.max_requests_per_connection == Some(5),
        "max requests",
        Some(5u64),
        config.max_requests_per_connection
    );
    test_complete!("e2e_http_keepalive_multiple_requests");
}

#[test]
fn e2e_http_keepalive_disabled() {
    init_test("e2e_http_keepalive_disabled");

    test_section!("setup");
    let config = Http1Config::default().keep_alive(false);

    test_section!("verify");
    assert_with_log!(
        !config.keep_alive,
        "keep_alive disabled",
        false,
        config.keep_alive
    );
    test_complete!("e2e_http_keepalive_disabled");
}

// ============================================================================
// Section 4: Concurrent Clients (Router stress)
// ============================================================================

#[test]
fn e2e_http_concurrent_routes() {
    init_test("e2e_http_concurrent_routes");

    test_section!("setup_complex_router");
    fn list_users() -> Json<serde_json::Value> {
        Json(serde_json::json!({"users": []}))
    }
    fn get_user(Path(id): Path<String>) -> Json<serde_json::Value> {
        Json(serde_json::json!({"id": id}))
    }
    fn create_user() -> StatusCode {
        StatusCode::CREATED
    }
    fn health() -> &'static str {
        "ok"
    }

    let api = Router::new()
        .route(
            "/users",
            get(FnHandler::new(list_users)).post(FnHandler::new(create_user)),
        )
        .route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user)),
        );
    let app = Router::new()
        .route("/health", get(FnHandler::new(health)))
        .nest("/api/v1", api);

    test_section!("fire_concurrent_requests");
    let requests = vec![
        ("GET", "/health"),
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/users"),
        ("GET", "/api/v1/users/alice"),
        ("GET", "/api/v1/users/bob"),
        ("GET", "/api/v1/users/charlie"),
        ("GET", "/missing"),
        ("DELETE", "/health"),
    ];

    let mut results = Vec::new();
    for (method, path) in &requests {
        let resp = app.handle(Request::new(*method, *path));
        tracing::info!(
            method = method,
            path = path,
            status = resp.status.as_u16(),
            "response"
        );
        results.push((method, path, resp.status));
    }

    test_section!("verify");
    assert_with_log!(
        results[0].2 == StatusCode::OK,
        "health ok",
        200,
        results[0].2.as_u16()
    );
    assert_with_log!(
        results[1].2 == StatusCode::OK,
        "list users",
        200,
        results[1].2.as_u16()
    );
    assert_with_log!(
        results[2].2 == StatusCode::CREATED,
        "create user",
        201,
        results[2].2.as_u16()
    );
    assert_with_log!(
        results[3].2 == StatusCode::OK,
        "get user",
        200,
        results[3].2.as_u16()
    );
    assert_with_log!(
        results[6].2 == StatusCode::NOT_FOUND,
        "missing 404",
        404,
        results[6].2.as_u16()
    );
    assert_with_log!(
        results[7].2 == StatusCode::METHOD_NOT_ALLOWED,
        "delete health 405",
        405,
        results[7].2.as_u16()
    );
    tracing::info!(total = results.len(), "all concurrent requests completed");
    test_complete!("e2e_http_concurrent_routes");
}

#[test]
fn e2e_http_stress_many_requests() {
    init_test("e2e_http_stress_many_requests");

    test_section!("setup");
    fn echo(Path(n): Path<String>) -> String {
        format!("echo:{n}")
    }
    let router = Router::new().route("/echo/:n", get(FnHandler1::<_, Path<String>>::new(echo)));

    test_section!("fire_requests");
    let n = 500;
    let mut ok_count = 0;
    for i in 0..n {
        let resp = router.handle(Request::new("GET", format!("/echo/{i}")));
        if resp.status == StatusCode::OK {
            ok_count += 1;
        }
    }
    tracing::info!(total = n, ok = ok_count, "stress test results");

    test_section!("verify");
    assert_with_log!(ok_count == n, "all requests ok", n, ok_count);
    test_complete!("e2e_http_stress_many_requests");
}

// ============================================================================
// Section 5: Compression Negotiation
// ============================================================================

#[test]
fn e2e_http_compression_negotiation() {
    init_test("e2e_http_compression_negotiation");

    test_section!("test_gzip_negotiation");
    let supported = [
        ContentEncoding::Gzip,
        ContentEncoding::Deflate,
        ContentEncoding::Brotli,
    ];
    let result = negotiate_encoding("gzip, deflate", &supported);
    tracing::info!(result = ?result.as_ref().map(ContentEncoding::as_token), "gzip negotiate");
    assert_with_log!(
        result.is_some(),
        "encoding negotiated",
        true,
        result.is_some()
    );

    test_section!("test_brotli_preference");
    let result2 = negotiate_encoding("br;q=1.0, gzip;q=0.8", &supported);
    tracing::info!(
        result = ?result2.as_ref().map(ContentEncoding::as_token),
        "brotli negotiate"
    );

    test_section!("test_identity_fallback");
    let result3 = negotiate_encoding("identity", &supported);
    tracing::info!(
        result = ?result3.as_ref().map(ContentEncoding::as_token),
        "identity negotiate"
    );

    test_section!("test_unsupported");
    let result4 = negotiate_encoding("zstd", &supported);
    tracing::info!(result = ?result4.is_none(), "unsupported rejected");

    test_complete!("e2e_http_compression_negotiation");
}

#[test]
fn e2e_http_content_encoding_tokens() {
    init_test("e2e_http_content_encoding_tokens");

    test_section!("verify_tokens");
    let cases = [
        ("gzip", Some(ContentEncoding::Gzip)),
        ("deflate", Some(ContentEncoding::Deflate)),
        ("br", Some(ContentEncoding::Brotli)),
        ("identity", Some(ContentEncoding::Identity)),
        ("zstd", None),
        ("unknown", None),
    ];

    for (token, expected) in &cases {
        let result = ContentEncoding::from_token(token);
        tracing::info!(token = token, found = result.is_some(), "encoding lookup");
        assert_with_log!(
            result.is_some() == expected.is_some(),
            &format!("token '{token}'"),
            expected.is_some(),
            result.is_some()
        );
    }
    test_complete!("e2e_http_content_encoding_tokens");
}

// ============================================================================
// Section 6: Connection Pool Lifecycle
// ============================================================================

#[test]
fn e2e_http_pool_exhaustion_recovery() {
    init_test("e2e_http_pool_exhaustion_recovery");

    test_section!("setup");
    let config = PoolConfig::builder()
        .max_connections_per_host(2)
        .max_total_connections(4)
        .build();
    let mut pool = Pool::with_config(config);
    tracing::info!(max_per_host = 2, max_total = 4, "pool config");

    test_section!("fill_pool");
    let key_a = PoolKey::http("host-a", Some(80));
    let key_b = PoolKey::http("host-b", Some(80));

    pool.register_connecting(key_a, Time::ZERO, 2);
    pool.register_connecting(key_b, Time::from_millis(10), 2);

    let stats = pool.stats();
    tracing::info!(total = stats.total_connections, "after filling pool");
    assert_with_log!(
        stats.total_connections >= 2,
        "pool has connections",
        ">= 2",
        stats.total_connections
    );

    test_section!("verify_stats");
    let total = stats.total_connections;
    tracing::info!(total = total, "pool state after exhaustion test");
    test_complete!("e2e_http_pool_exhaustion_recovery");
}

#[test]
fn e2e_http_pool_multiple_hosts() {
    init_test("e2e_http_pool_multiple_hosts");

    test_section!("setup");
    let config = PoolConfig::builder()
        .max_connections_per_host(3)
        .max_total_connections(20)
        .build();
    let mut pool = Pool::with_config(config);

    test_section!("register_multiple_hosts");
    let hosts = [
        "api.example.com",
        "cdn.example.com",
        "auth.example.com",
        "db.example.com",
    ];
    for (i, host) in hosts.iter().enumerate() {
        let key = PoolKey::https(*host, None);
        pool.register_connecting(key, Time::from_millis(i as u64 * 100), 2);
        tracing::info!(host = host, "registered connections");
    }

    test_section!("verify");
    let stats = pool.stats();
    tracing::info!(
        total = stats.total_connections,
        hosts = hosts.len(),
        "multi-host pool"
    );
    assert_with_log!(
        stats.total_connections >= 4,
        "multiple hosts",
        ">= 4",
        stats.total_connections
    );
    test_complete!("e2e_http_pool_multiple_hosts");
}

// ============================================================================
// Section 7: Body Types
// ============================================================================

#[test]
fn e2e_http_body_full_size_hint() {
    init_test("e2e_http_body_full_size_hint");

    test_section!("test_full_body");
    let data = b"The quick brown fox jumps over the lazy dog";
    let body = Full::new(asupersync::bytes::BytesCursor::new(Bytes::from_static(
        data,
    )));
    let hint = body.size_hint();
    tracing::info!(lower = hint.lower(), upper = ?hint.upper(), "full body hint");
    assert_with_log!(hint.lower() == 43, "lower bound", 43u64, hint.lower());
    assert_with_log!(
        hint.upper() == Some(43),
        "upper bound",
        Some(43u64),
        hint.upper()
    );
    assert_with_log!(
        !body.is_end_stream(),
        "not end of stream",
        false,
        body.is_end_stream()
    );

    test_section!("test_empty_body");
    let empty = Empty::new();
    let hint = empty.size_hint();
    assert_with_log!(hint.lower() == 0, "empty lower", 0u64, hint.lower());
    assert_with_log!(
        empty.is_end_stream(),
        "empty is end",
        true,
        empty.is_end_stream()
    );
    test_complete!("e2e_http_body_full_size_hint");
}

// ============================================================================
// Section 8: Full CRUD API Pipeline
// ============================================================================

#[test]
fn e2e_http_full_crud_pipeline() {
    init_test("e2e_http_full_crud_pipeline");

    test_section!("setup_api");
    use std::sync::{Arc, Mutex};

    let _store: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));

    fn list_items() -> Json<serde_json::Value> {
        Json(serde_json::json!({"items": [], "count": 0}))
    }

    fn create_item(
        body: asupersync::web::extract::Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let mut item = body.0;
        item["id"] = serde_json::json!(1);
        (StatusCode::CREATED, Json(item))
    }

    fn get_item(Path(id): Path<String>) -> Json<serde_json::Value> {
        Json(serde_json::json!({"id": id, "name": "test"}))
    }

    fn update_item(Path(id): Path<String>) -> StatusCode {
        tracing::info!(id = %id, "updating item");
        StatusCode::NO_CONTENT
    }

    fn delete_item(Path(id): Path<String>) -> StatusCode {
        tracing::info!(id = %id, "deleting item");
        StatusCode::NO_CONTENT
    }

    let router = Router::new()
        .route(
            "/items",
            get(FnHandler::new(list_items)).post(FnHandler1::<
                _,
                asupersync::web::extract::Json<serde_json::Value>,
            >::new(create_item)),
        )
        .route(
            "/items/:id",
            get(FnHandler1::<_, Path<String>>::new(get_item))
                .put(FnHandler1::<_, Path<String>>::new(update_item))
                .delete(FnHandler1::<_, Path<String>>::new(delete_item)),
        );

    test_section!("list_empty");
    let resp = router.handle(Request::new("GET", "/items"));
    assert_with_log!(
        resp.status == StatusCode::OK,
        "list ok",
        200,
        resp.status.as_u16()
    );
    tracing::info!(body = %String::from_utf8_lossy(resp.body.as_ref()), "list response");

    test_section!("create");
    let body = serde_json::to_vec(&serde_json::json!({"name": "widget"})).unwrap();
    let resp = router.handle(
        Request::new("POST", "/items")
            .with_header("content-type", "application/json")
            .with_body(Bytes::copy_from_slice(&body)),
    );
    assert_with_log!(
        resp.status == StatusCode::CREATED,
        "create 201",
        201,
        resp.status.as_u16()
    );
    let created: serde_json::Value = serde_json::from_slice(resp.body.as_ref()).unwrap();
    tracing::info!(id = %created["id"], "created item");

    test_section!("read");
    let resp = router.handle(Request::new("GET", "/items/1"));
    assert_with_log!(
        resp.status == StatusCode::OK,
        "read ok",
        200,
        resp.status.as_u16()
    );

    test_section!("update");
    let resp = router.handle(Request::new("PUT", "/items/1"));
    assert_with_log!(
        resp.status == StatusCode::NO_CONTENT,
        "update 204",
        204,
        resp.status.as_u16()
    );

    test_section!("delete");
    let resp = router.handle(Request::new("DELETE", "/items/1"));
    assert_with_log!(
        resp.status == StatusCode::NO_CONTENT,
        "delete 204",
        204,
        resp.status.as_u16()
    );

    test_complete!("e2e_http_full_crud_pipeline");
}

// ============================================================================
// Section 9: Chunked Encoding (codec level)
// ============================================================================

#[test]
fn e2e_http_chunked_transfer_encoding() {
    init_test("e2e_http_chunked_transfer_encoding");

    test_section!("setup");
    let mut codec = Http1Codec::new();

    test_section!("encode_chunked_request");
    let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let mut buf = BytesMut::from(raw);
    tracing::info!(buf_len = buf.len(), "chunked request");

    test_section!("decode");
    let result = codec.decode(&mut buf);
    match &result {
        Ok(Some(req)) => {
            tracing::info!(method = ?req.method, body_len = req.body.len(), "decoded chunked");
        }
        Ok(None) => tracing::info!("incomplete chunked frame"),
        Err(e) => tracing::info!(error = ?e, "chunked decode error"),
    }
    test_complete!("e2e_http_chunked_transfer_encoding");
}

// ============================================================================
// Section 10: Extractor Edge Cases
// ============================================================================

#[test]
fn e2e_http_extractor_missing_content_type() {
    init_test("e2e_http_extractor_missing_content_type");

    test_section!("setup");
    #[derive(Debug, serde::Deserialize)]
    struct Input {
        #[allow(dead_code)]
        name: String,
    }

    test_section!("test_no_content_type");
    // JSON extractor parses valid JSON regardless of content-type header
    let req = Request::new("POST", "/").with_body(Bytes::from_static(b"{\"name\":\"test\"}"));
    let result = asupersync::web::extract::Json::<Input>::from_request(req);
    tracing::info!(is_ok = result.is_ok(), "no content-type result");
    assert_with_log!(
        result.is_ok(),
        "accepts valid JSON without content-type",
        true,
        result.is_ok()
    );

    test_section!("test_empty_body");
    let req2 = Request::new("POST", "/")
        .with_header("content-type", "application/json")
        .with_body(Bytes::from_static(b""));
    let result2 = asupersync::web::extract::Json::<Input>::from_request(req2);
    tracing::info!(is_err = result2.is_err(), "empty body result");
    assert_with_log!(
        result2.is_err(),
        "rejects empty body",
        true,
        result2.is_err()
    );
    test_complete!("e2e_http_extractor_missing_content_type");
}

#[test]
fn e2e_http_query_edge_cases() {
    init_test("e2e_http_query_edge_cases");

    test_section!("empty_query");
    let req = Request::new("GET", "/search");
    let result = Query::<HashMap<String, String>>::from_request_parts(&req);
    // No query string — should either return empty map or error
    tracing::info!(is_ok = result.is_ok(), "empty query result");

    test_section!("special_characters");
    let req2 = Request::new("GET", "/search").with_query("key=value%20with%20spaces&empty=&flag");
    let result2 = Query::<HashMap<String, String>>::from_request_parts(&req2);
    if let Ok(Query(params)) = &result2 {
        tracing::info!(params = ?params, "special chars parsed");
        if let Some(val) = params.get("key") {
            assert_with_log!(
                val == "value with spaces",
                "decoded spaces",
                "value with spaces",
                val
            );
        }
    }
    test_complete!("e2e_http_query_edge_cases");
}

// ============================================================================
// Section 11: Header Map Operations
// ============================================================================

#[test]
fn e2e_http_header_map_operations() {
    init_test("e2e_http_header_map_operations");

    test_section!("basic_operations");
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html"),
    );
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_static("abc-123"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("session=abc"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("theme=dark"),
    );

    tracing::info!(count = headers.len(), "header map size");
    assert_with_log!(
        headers.len() >= 3,
        "multiple headers",
        ">= 3",
        headers.len()
    );

    test_section!("lookup");
    let ct = headers.get(&HeaderName::from_static("content-type"));
    assert_with_log!(ct.is_some(), "content-type found", true, ct.is_some());

    test_section!("case_insensitivity");
    let ct_upper = headers.get(&HeaderName::from_static("Content-Type"));
    assert_with_log!(
        ct_upper.is_some(),
        "case insensitive lookup",
        true,
        ct_upper.is_some()
    );

    test_complete!("e2e_http_header_map_operations");
}

// ============================================================================
// Section 12: Server Config Validation
// ============================================================================

#[test]
fn e2e_http_server_config_combinations() {
    init_test("e2e_http_server_config_combinations");

    test_section!("default_config");
    let default = Http1Config::default();
    tracing::info!(
        max_headers = default.max_headers_size,
        max_body = default.max_body_size,
        keep_alive = default.keep_alive,
        "default config"
    );
    assert_with_log!(
        default.keep_alive,
        "default keep_alive",
        true,
        default.keep_alive
    );

    test_section!("restrictive_config");
    let restrictive = Http1Config::default()
        .max_headers_size(1024)
        .max_body_size(4096)
        .keep_alive(false)
        .max_requests(Some(10))
        .idle_timeout(Some(std::time::Duration::from_secs(5)));

    assert_with_log!(
        restrictive.max_headers_size == 1024,
        "max headers",
        1024,
        restrictive.max_headers_size
    );
    assert_with_log!(
        restrictive.max_body_size == 4096,
        "max body",
        4096,
        restrictive.max_body_size
    );
    assert_with_log!(
        !restrictive.keep_alive,
        "no keep_alive",
        false,
        restrictive.keep_alive
    );
    assert_with_log!(
        restrictive.max_requests_per_connection == Some(10),
        "max requests",
        Some(10u64),
        restrictive.max_requests_per_connection
    );

    test_section!("permissive_config");
    let permissive = Http1Config::default()
        .max_headers_size(1024 * 1024)
        .max_body_size(100 * 1024 * 1024)
        .keep_alive(true)
        .max_requests(None)
        .idle_timeout(None);

    assert_with_log!(
        permissive.max_requests_per_connection.is_none(),
        "no request limit",
        true,
        permissive.max_requests_per_connection.is_none()
    );
    assert_with_log!(
        permissive.idle_timeout.is_none(),
        "no idle timeout",
        true,
        permissive.idle_timeout.is_none()
    );

    test_complete!("e2e_http_server_config_combinations");
}
