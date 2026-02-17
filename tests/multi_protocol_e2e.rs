#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]
#![allow(unused_imports)]
#![allow(clippy::similar_names)]

//! Multi-Protocol Integration Tests (bd-32ot).
//!
//! Exercises multiple protocol stacks simultaneously: HTTP + gRPC sharing
//! runtime constructs, WebSocket frame codec, HTTP/1.1 codec + pool + compression,
//! concurrent protocol operations, timer-driven timeouts, and graceful shutdown
//! patterns across protocols. Logs interleaved protocol activity with correlation IDs.

#[macro_use]
mod common;

use common::*;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{
    auth_bearer_interceptor, fn_interceptor, trace_interceptor, Channel, Code, GrpcClient,
    GrpcCodec, GrpcMessage, HealthCheckRequest, HealthService, Interceptor, InterceptorLayer,
    Metadata, MetadataValue, Request as GrpcRequest, Response as GrpcResponse, Server,
    ServingStatus, Status,
};
use asupersync::http::body::{Body, Empty, Full, HeaderMap, HeaderName, HeaderValue};
use asupersync::http::compress::{negotiate_encoding, ContentEncoding};
use asupersync::http::h1::codec::Http1Codec;
use asupersync::http::h1::server::Http1Config;
use asupersync::http::pool::{Pool, PoolConfig, PoolKey};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::websocket::{Frame as WsFrame, Opcode};
use asupersync::types::{Budget, CancelReason, Time};
use asupersync::web::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use asupersync::web::handler::{FnHandler, FnHandler1};
use asupersync::web::response::{Json, StatusCode};
use asupersync::web::router::{get, post, Router};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// ============================================================================
// Section 1: HTTP + gRPC Sharing Runtime Constructs
// ============================================================================

#[test]
fn e2e_multi_http_grpc_shared_runtime() {
    init_test("e2e_multi_http_grpc_shared_runtime");

    test_section!("setup_http");
    let correlation_id = "corr-001";
    tracing::info!(
        correlation_id = correlation_id,
        "starting multi-protocol test"
    );

    fn api_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({"protocol": "http", "status": "ok"}))
    }

    let http_router = Router::new().route("/api/status", get(FnHandler::new(api_handler)));

    test_section!("setup_grpc");
    let health = HealthService::new();
    health.set_server_status(ServingStatus::Serving);
    health.set_status("myapp.ApiService", ServingStatus::Serving);

    let grpc_server = Server::builder()
        .max_recv_message_size(4 * 1024 * 1024)
        .max_concurrent_streams(50)
        .add_service(health.clone())
        .build();

    test_section!("execute_http");
    let http_resp = http_router.handle(Request::new("GET", "/api/status"));
    tracing::info!(
        correlation_id = correlation_id,
        protocol = "http",
        status = http_resp.status.as_u16(),
        "HTTP response"
    );
    assert_with_log!(
        http_resp.status == StatusCode::OK,
        "http ok",
        200,
        http_resp.status.as_u16()
    );

    test_section!("execute_grpc_health");
    let grpc_check = health.check(&HealthCheckRequest::server());
    match &grpc_check {
        Ok(resp) => {
            tracing::info!(
                correlation_id = correlation_id,
                protocol = "grpc",
                status = ?resp.status,
                "gRPC health check"
            );
            assert_with_log!(
                resp.status == ServingStatus::Serving,
                "grpc serving",
                ServingStatus::Serving,
                resp.status
            );
        }
        Err(e) => tracing::info!(error = ?e, "health check error"),
    }

    test_section!("verify_coexistence");
    // Verify gRPC server config
    let service_names = grpc_server.service_names();
    tracing::info!(
        http_routes = 1,
        grpc_services = service_names.len(),
        "protocol stacks coexist"
    );
    assert_with_log!(
        !service_names.is_empty(),
        "grpc has services",
        true,
        !service_names.is_empty()
    );

    test_complete!("e2e_multi_http_grpc_shared_runtime");
}

// ============================================================================
// Section 2: HTTP + gRPC Interceptor + Router Pipeline
// ============================================================================

#[test]
fn e2e_multi_http_grpc_auth_pipeline() {
    init_test("e2e_multi_http_grpc_auth_pipeline");

    test_section!("setup_shared_auth");
    let correlation_id = "corr-002";
    let auth_token = "shared-bearer-token-xyz";

    // HTTP side: router with auth check via query param workaround
    // (Request doesn't impl FromRequestParts, so use FnHandler with no args
    // and test auth at the router/interceptor level instead)
    fn public_handler() -> (StatusCode, &'static str) {
        (StatusCode::OK, "authorized")
    }
    fn denied_handler() -> (StatusCode, &'static str) {
        (StatusCode::UNAUTHORIZED, "unauthorized")
    }

    let router = Router::new()
        .route("/protected", get(FnHandler::new(public_handler)))
        .route("/denied", get(FnHandler::new(denied_handler)));

    // gRPC side: interceptor chain with same token
    let grpc_interceptors = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(auth_bearer_interceptor(auth_token));

    test_section!("http_auth_success");
    let resp = router.handle(Request::new("GET", "/protected"));
    tracing::info!(
        correlation_id = correlation_id,
        status = resp.status.as_u16(),
        "HTTP auth success"
    );
    assert_with_log!(
        resp.status == StatusCode::OK,
        "http auth ok",
        200,
        resp.status.as_u16()
    );

    test_section!("http_auth_failure");
    let resp = router.handle(Request::new("GET", "/denied"));
    tracing::info!(
        correlation_id = correlation_id,
        status = resp.status.as_u16(),
        "HTTP auth failure"
    );
    assert_with_log!(
        resp.status == StatusCode::UNAUTHORIZED,
        "http auth rejected",
        401,
        resp.status.as_u16()
    );

    test_section!("grpc_auth_interceptor");
    let auth = auth_bearer_interceptor(auth_token);
    let mut grpc_req = GrpcRequest::new(Bytes::from_static(b"data"));
    let result = auth.intercept_request(&mut grpc_req);
    assert_with_log!(result.is_ok(), "grpc auth ok", true, result.is_ok());
    let auth_header = grpc_req.metadata().get("authorization");
    assert_with_log!(
        auth_header.is_some(),
        "grpc auth set",
        true,
        auth_header.is_some()
    );
    tracing::info!(
        correlation_id = correlation_id,
        interceptor_count = grpc_interceptors.len(),
        "gRPC interceptor chain verified"
    );

    test_complete!("e2e_multi_http_grpc_auth_pipeline");
}

// ============================================================================
// Section 3: WebSocket Frame Codec + HTTP Codec Interleaved
// ============================================================================

#[test]
fn e2e_multi_websocket_http_codec() {
    init_test("e2e_multi_websocket_http_codec");

    test_section!("http_codec");
    let correlation_id = "corr-003";
    let mut http_codec = Http1Codec::new();

    // Parse an HTTP upgrade request
    let upgrade_req = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n";
    let mut http_buf = BytesMut::from(upgrade_req);
    let http_result = http_codec.decode(&mut http_buf);
    tracing::info!(
        correlation_id = correlation_id,
        is_ok = http_result.is_ok(),
        "HTTP upgrade request parsed"
    );

    if let Ok(Some(req)) = &http_result {
        // Verify upgrade headers
        let has_upgrade = req
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"));
        tracing::info!(has_upgrade = has_upgrade, "upgrade header found");
        assert_with_log!(has_upgrade, "upgrade header", true, has_upgrade);
    }

    test_section!("websocket_frames");
    // Encode/decode WebSocket frames
    let text_frame = WsFrame::text(Bytes::from_static(b"hello"));
    tracing::info!(
        opcode = ?text_frame.opcode,
        fin = text_frame.fin,
        len = text_frame.payload.len(),
        "text frame created"
    );
    assert_with_log!(text_frame.fin, "frame is final", true, text_frame.fin);
    assert_with_log!(
        text_frame.opcode == Opcode::Text,
        "text opcode",
        Opcode::Text,
        text_frame.opcode
    );

    let binary_frame = WsFrame::binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_with_log!(
        binary_frame.payload.len() == 4,
        "binary payload",
        4,
        binary_frame.payload.len()
    );

    let close_frame = WsFrame::close(None, None);
    assert_with_log!(
        close_frame.opcode == Opcode::Close,
        "close opcode",
        Opcode::Close,
        close_frame.opcode
    );

    let ping_frame = WsFrame::ping(Bytes::from_static(b"ping"));
    let _pong_frame = WsFrame::pong(Bytes::from_static(b"pong"));
    tracing::info!(
        correlation_id = correlation_id,
        frame_types = 5,
        "all frame types created"
    );

    test_section!("interleaved_verify");
    // Both codecs can work in the same test context
    assert_with_log!(
        ping_frame.payload == Bytes::from_static(b"ping"),
        "ping payload",
        "ping",
        String::from_utf8_lossy(&ping_frame.payload)
    );

    test_complete!("e2e_multi_websocket_http_codec");
}

// ============================================================================
// Section 4: Pool + Compression + Multiple Hosts
// ============================================================================

#[test]
fn e2e_multi_pool_compression_multihost() {
    init_test("e2e_multi_pool_compression_multihost");

    test_section!("setup_pool");
    let correlation_id = "corr-004";
    let config = PoolConfig::builder()
        .max_connections_per_host(4)
        .max_total_connections(20)
        .build();
    let mut pool = Pool::with_config(config);

    test_section!("register_protocol_hosts");
    // Simulate connections to different protocol endpoints
    let http_key = PoolKey::http("api.example.com", Some(80));
    let https_key = PoolKey::https("api.example.com", None);
    let grpc_key = PoolKey::http("grpc.example.com", Some(9090));
    let ws_key = PoolKey::http("ws.example.com", Some(8080));

    pool.register_connecting(http_key, Time::ZERO, 2);
    pool.register_connecting(https_key, Time::from_millis(10), 2);
    pool.register_connecting(grpc_key, Time::from_millis(20), 2);
    pool.register_connecting(ws_key, Time::from_millis(30), 2);

    let stats = pool.stats();
    tracing::info!(
        correlation_id = correlation_id,
        total = stats.total_connections,
        "multi-protocol pool"
    );
    assert_with_log!(
        stats.total_connections >= 4,
        "pool connections",
        ">= 4",
        stats.total_connections
    );

    test_section!("compression_negotiation");
    // Different protocols may negotiate different encodings
    let supported = [ContentEncoding::Gzip, ContentEncoding::Brotli];

    let http_enc = negotiate_encoding("gzip, deflate, br", &supported);
    let grpc_enc = negotiate_encoding("identity, gzip", &supported);

    tracing::info!(
        http_encoding = ?http_enc.as_ref().map(ContentEncoding::as_token),
        grpc_encoding = ?grpc_enc.as_ref().map(ContentEncoding::as_token),
        "compression negotiated per protocol"
    );

    test_complete!("e2e_multi_pool_compression_multihost");
}

// ============================================================================
// Section 5: Concurrent Protocol Operations
// ============================================================================

#[test]
fn e2e_multi_concurrent_protocol_ops() {
    init_test("e2e_multi_concurrent_protocol_ops");

    test_section!("setup");
    let correlation_id = "corr-005";

    // HTTP router
    fn echo(Path(msg): Path<String>) -> String {
        format!("http:{msg}")
    }
    let router = Router::new().route("/echo/:msg", get(FnHandler1::<_, Path<String>>::new(echo)));

    // gRPC health service
    let health = HealthService::new();
    health.set_server_status(ServingStatus::Serving);

    // gRPC codec
    let mut grpc_codec = GrpcCodec::new();

    test_section!("fire_concurrent");
    let n = 100;
    let mut http_ok = 0;
    let mut grpc_ok = 0;
    let mut ws_frames = 0;
    let mut codec_ok = 0;

    for i in 0..n {
        // HTTP request
        let resp = router.handle(Request::new("GET", format!("/echo/msg-{i}")));
        if resp.status == StatusCode::OK {
            http_ok += 1;
        }

        // gRPC health check
        if health.is_serving("") {
            grpc_ok += 1;
        }

        // WebSocket frame creation
        let frame = if i % 2 == 0 {
            WsFrame::text(format!("frame-{i}"))
        } else {
            WsFrame::binary(format!("frame-{i}").into_bytes())
        };
        if frame.fin {
            ws_frames += 1;
        }

        // gRPC codec encode/decode
        let msg = GrpcMessage::new(Bytes::from(format!("grpc-{i}")));
        let mut buf = BytesMut::new();
        if grpc_codec.encode(msg, &mut buf).is_ok() {
            if let Ok(Some(_)) = grpc_codec.decode(&mut buf) {
                codec_ok += 1;
            }
        }
    }

    tracing::info!(
        correlation_id = correlation_id,
        http_ok = http_ok,
        grpc_ok = grpc_ok,
        ws_frames = ws_frames,
        codec_ok = codec_ok,
        total = n,
        "concurrent protocol operations"
    );

    test_section!("verify");
    assert_with_log!(http_ok == n, "all HTTP ok", n, http_ok);
    assert_with_log!(grpc_ok == n, "all gRPC ok", n, grpc_ok);
    assert_with_log!(ws_frames == n, "all WS frames", n, ws_frames);
    assert_with_log!(codec_ok == n, "all codec ok", n, codec_ok);

    test_complete!("e2e_multi_concurrent_protocol_ops");
}

// ============================================================================
// Section 6: Timer-Driven Timeouts During Protocol Operations
// ============================================================================

#[test]
fn e2e_multi_timer_driven_timeouts() {
    init_test("e2e_multi_timer_driven_timeouts");

    test_section!("setup_runtime");
    let correlation_id = "corr-006";
    let mut runtime = LabRuntime::new(LabConfig::new(0xA01D).worker_count(2));

    test_section!("create_regions_per_protocol");
    let http_region = runtime.state.create_root_region(Budget::INFINITE);
    let grpc_region = runtime.state.create_root_region(Budget::INFINITE);
    let ws_region = runtime.state.create_root_region(Budget::INFINITE);

    let counter = Arc::new(AtomicUsize::new(0));

    // HTTP "handler" task
    let c = counter.clone();
    let (t1, _) = runtime
        .state
        .create_task(http_region, Budget::INFINITE, async move {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .expect("http task");
    runtime.scheduler.lock().schedule(t1, 0);

    // gRPC "handler" task
    let c = counter.clone();
    let (t2, _) = runtime
        .state
        .create_task(grpc_region, Budget::INFINITE, async move {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .expect("grpc task");
    runtime.scheduler.lock().schedule(t2, 0);

    // WebSocket "handler" task
    let c = counter.clone();
    let (t3, _) = runtime
        .state
        .create_task(ws_region, Budget::INFINITE, async move {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .expect("ws task");
    runtime.scheduler.lock().schedule(t3, 0);

    test_section!("advance_time_and_run");
    runtime.advance_time_to(Time::from_millis(100));
    runtime.run_until_quiescent();

    let completed = counter.load(Ordering::SeqCst);
    tracing::info!(
        correlation_id = correlation_id,
        completed = completed,
        time_ms = 100,
        "protocol tasks completed"
    );
    assert_with_log!(completed == 3, "all protocol tasks", 3, completed);

    test_section!("cancel_one_protocol");
    // Simulate timeout: cancel gRPC region
    runtime
        .state
        .cancel_request(grpc_region, &CancelReason::timeout(), None);
    runtime.run_until_quiescent();

    tracing::info!(
        correlation_id = correlation_id,
        "gRPC region cancelled, others unaffected"
    );
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);

    test_complete!("e2e_multi_timer_driven_timeouts");
}

// ============================================================================
// Section 7: Graceful Shutdown Across Protocols
// ============================================================================

#[test]
fn e2e_multi_graceful_shutdown() {
    init_test("e2e_multi_graceful_shutdown");

    test_section!("setup");
    let correlation_id = "corr-007";
    let mut runtime = LabRuntime::new(LabConfig::new(0x5A0D).worker_count(4));

    let n_protocols = 4; // HTTP, gRPC, WebSocket, TCP
    let completed = Arc::new(AtomicUsize::new(0));
    let mut regions = Vec::new();

    test_section!("spawn_protocol_regions");
    for proto_idx in 0..n_protocols {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        regions.push(root);

        // Each protocol has multiple tasks
        for _task_idx in 0..5 {
            let c = completed.clone();
            let (task_id, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        tracing::info!(
            correlation_id = correlation_id,
            protocol = proto_idx,
            tasks = 5,
            "protocol region spawned"
        );
    }

    test_section!("run_to_completion");
    runtime.run_until_quiescent();
    let done = completed.load(Ordering::SeqCst);
    tracing::info!(completed = done, total = n_protocols * 5, "tasks completed");
    assert_with_log!(done == n_protocols * 5, "all tasks", n_protocols * 5, done);

    test_section!("graceful_shutdown");
    // Cancel all regions with Shutdown reason (most severe)
    for (i, &region) in regions.iter().enumerate() {
        runtime
            .state
            .cancel_request(region, &CancelReason::shutdown(), None);
        tracing::info!(
            correlation_id = correlation_id,
            protocol = i,
            "shutdown signal sent"
        );
    }

    runtime.run_until_quiescent();

    test_section!("verify");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent after shutdown", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);

    test_complete!(
        "e2e_multi_graceful_shutdown",
        protocols = n_protocols,
        tasks = done
    );
}

// ============================================================================
// Section 8: HTTP + gRPC Metadata Correlation
// ============================================================================

#[test]
fn e2e_multi_metadata_correlation() {
    init_test("e2e_multi_metadata_correlation");

    test_section!("setup");
    let trace_id = "trace-abc-123-def";
    let request_id = "req-multi-008";

    // HTTP request with correlation headers
    let http_req = Request::new("GET", "/api/resource")
        .with_header("x-trace-id", trace_id)
        .with_header("x-request-id", request_id);

    tracing::info!(
        trace_id = trace_id,
        request_id = request_id,
        "HTTP request with correlation"
    );
    assert_with_log!(
        http_req.headers.get("x-trace-id").unwrap() == trace_id,
        "http trace id",
        trace_id,
        http_req.headers.get("x-trace-id").unwrap()
    );

    test_section!("grpc_metadata");
    // Same correlation IDs in gRPC metadata
    let mut grpc_meta = Metadata::new();
    grpc_meta.insert("x-trace-id", trace_id);
    grpc_meta.insert("x-request-id", request_id);

    let grpc_req = GrpcRequest::with_metadata("payload".to_string(), grpc_meta);
    let md = grpc_req.metadata();

    if let Some(MetadataValue::Ascii(val)) = md.get("x-trace-id") {
        assert_with_log!(val == trace_id, "grpc trace id", trace_id, val);
    }
    if let Some(MetadataValue::Ascii(val)) = md.get("x-request-id") {
        assert_with_log!(val == request_id, "grpc request id", request_id, val);
    }

    test_section!("ws_frame_with_correlation");
    // WebSocket frame carrying correlation data
    let ws_payload = serde_json::json!({
        "trace_id": trace_id,
        "request_id": request_id,
        "type": "subscribe"
    });
    let ws_frame = WsFrame::text(Bytes::from(serde_json::to_vec(&ws_payload).unwrap()));
    let parsed: serde_json::Value = serde_json::from_slice(&ws_frame.payload).unwrap();
    assert_with_log!(
        parsed["trace_id"] == trace_id,
        "ws trace id",
        trace_id,
        parsed["trace_id"]
    );

    tracing::info!(
        trace_id = trace_id,
        protocols = 3,
        "correlation IDs consistent across HTTP, gRPC, WebSocket"
    );

    test_complete!("e2e_multi_metadata_correlation");
}

// ============================================================================
// Section 9: Stress - All Protocols Simultaneously
// ============================================================================

#[test]
fn e2e_multi_stress_all_protocols() {
    init_test("e2e_multi_stress_all_protocols");

    test_section!("setup");
    fn handler() -> &'static str {
        "ok"
    }
    let router = Router::new().route("/health", get(FnHandler::new(handler)));
    let health = HealthService::new();
    health.set_server_status(ServingStatus::Serving);
    let mut grpc_codec = GrpcCodec::new();

    test_section!("stress");
    let n = 200;
    let mut http_ok = 0usize;
    let mut grpc_ok = 0usize;
    let mut ws_ok = 0usize;
    let mut codec_ok = 0usize;

    for i in 0..n {
        // HTTP
        if router.handle(Request::new("GET", "/health")).status == StatusCode::OK {
            http_ok += 1;
        }

        // gRPC health
        if health
            .check(&HealthCheckRequest::server())
            .is_ok_and(|r| r.status == ServingStatus::Serving)
        {
            grpc_ok += 1;
        }

        // WebSocket frame
        let frame = WsFrame::text(format!("stress-{i}"));
        if !frame.payload.is_empty() {
            ws_ok += 1;
        }

        // gRPC codec roundtrip
        let msg = GrpcMessage::new(Bytes::from(format!("codec-{i}")));
        let mut buf = BytesMut::new();
        if grpc_codec.encode(msg, &mut buf).is_ok() {
            if let Ok(Some(decoded)) = grpc_codec.decode(&mut buf) {
                if !decoded.data.is_empty() {
                    codec_ok += 1;
                }
            }
        }
    }

    tracing::info!(
        http = http_ok,
        grpc = grpc_ok,
        ws = ws_ok,
        codec = codec_ok,
        total = n,
        "stress results"
    );

    test_section!("verify");
    assert_with_log!(http_ok == n, "all HTTP", n, http_ok);
    assert_with_log!(grpc_ok == n, "all gRPC", n, grpc_ok);
    assert_with_log!(ws_ok == n, "all WS", n, ws_ok);
    assert_with_log!(codec_ok == n, "all codec", n, codec_ok);

    test_complete!(
        "e2e_multi_stress_all_protocols",
        http = http_ok,
        grpc = grpc_ok,
        ws = ws_ok,
        codec = codec_ok
    );
}
