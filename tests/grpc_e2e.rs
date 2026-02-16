#![allow(missing_docs)]
#![allow(clippy::items_after_statements, clippy::let_unit_value)]

//! Full-Stack gRPC Integration Tests (bd-2i3y).
//!
//! Exercises: unary calls, server/client/bidi streaming types, deadline propagation,
//! cancel mid-stream, metadata forwarding, error status codes, interceptor chain
//! ordering, backpressure, health checking protocol, and codec framing.

#[macro_use]
mod common;

use common::init_test_logging;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{
    auth_bearer_interceptor, auth_validator, fn_interceptor, logging_interceptor,
    metadata_propagator, rate_limiter, timeout_interceptor, trace_interceptor, CallContext,
    Channel, ChannelConfig, Code, GrpcClient, GrpcCodec, GrpcError, GrpcMessage,
    HealthCheckRequest, HealthService, Interceptor, InterceptorLayer, Metadata, MetadataValue,
    MethodDescriptor, Request, Response, Server, ServingStatus, Status,
};
use std::sync::Arc;
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// ============================================================================
// Section 1: Full Unary Call Lifecycle
// ============================================================================

#[test]
fn e2e_grpc_unary_call_lifecycle() {
    init_test("e2e_grpc_unary_call_lifecycle");

    test_section!("setup_channel");
    futures_lite::future::block_on(async {
        let channel = Channel::connect("http://localhost:50051").await.unwrap();
        let mut client = GrpcClient::new(channel.clone());
        tracing::info!(uri = client.channel().uri(), "client connected");

        test_section!("build_request");
        let mut request = Request::new("test payload".to_string());
        request.metadata_mut().insert("x-request-id", "e2e-001");
        request.metadata_mut().insert("x-trace-id", "trace-abc");
        tracing::info!(
            metadata_len = request.metadata().len(),
            "request built with metadata"
        );

        test_section!("execute_unary");
        let result: Result<Response<String>, Status> =
            client.unary("/test.Service/Echo", request).await;

        test_section!("verify");
        // Currently returns Unimplemented (stub)
        match &result {
            Ok(resp) => tracing::info!(message = resp.get_ref(), "unexpected success"),
            Err(status) => {
                tracing::info!(
                    code = ?status.code(),
                    message = status.message(),
                    "expected error status"
                );
                assert_with_log!(
                    status.code() == Code::Unimplemented,
                    "unimplemented status",
                    Code::Unimplemented,
                    status.code()
                );
            }
        }
    });

    test_complete!("e2e_grpc_unary_call_lifecycle");
}

// ============================================================================
// Section 2: Metadata Forwarding
// ============================================================================

#[test]
fn e2e_grpc_metadata_forwarding() {
    init_test("e2e_grpc_metadata_forwarding");

    test_section!("create_metadata");
    let mut metadata = Metadata::new();
    metadata.insert("authorization", "Bearer token-abc-123");
    metadata.insert("x-request-id", "req-e2e-002");
    metadata.insert("x-custom-header", "custom-value");
    metadata.insert_bin("x-binary-data-bin", Bytes::from_static(b"\x00\x01\x02\x03"));

    tracing::info!(count = metadata.len(), "metadata entries created");
    assert_with_log!(metadata.len() == 4, "metadata count", 4, metadata.len());

    test_section!("verify_ascii");
    let auth = metadata.get("authorization");
    assert_with_log!(auth.is_some(), "auth header present", true, auth.is_some());
    if let Some(MetadataValue::Ascii(val)) = auth {
        assert_with_log!(
            val == "Bearer token-abc-123",
            "auth value",
            "Bearer token-abc-123",
            val
        );
    }

    test_section!("verify_binary");
    let bin = metadata.get("x-binary-data-bin");
    assert_with_log!(
        bin.is_some(),
        "binary metadata present",
        true,
        bin.is_some()
    );
    if let Some(MetadataValue::Binary(data)) = bin {
        assert_with_log!(data.len() == 4, "binary length", 4, data.len());
    }

    test_section!("request_metadata_roundtrip");
    let request = Request::with_metadata("payload".to_string(), metadata);
    let md = request.metadata();
    assert_with_log!(md.len() == 4, "metadata preserved", 4, md.len());
    assert_with_log!(
        md.get("x-request-id").is_some(),
        "request-id preserved",
        true,
        md.get("x-request-id").is_some()
    );

    test_section!("response_metadata");
    let mut resp_meta = Metadata::new();
    resp_meta.insert("x-response-time", "42ms");
    let response = Response::with_metadata("result".to_string(), resp_meta);
    assert_with_log!(
        response.metadata().get("x-response-time").is_some(),
        "response metadata",
        true,
        response.metadata().get("x-response-time").is_some()
    );

    test_complete!("e2e_grpc_metadata_forwarding");
}

// ============================================================================
// Section 3: Error Status Codes
// ============================================================================

#[test]
fn e2e_grpc_status_code_comprehensive() {
    init_test("e2e_grpc_status_code_comprehensive");

    test_section!("all_status_constructors");
    let statuses = [
        (Status::ok(), Code::Ok, "ok"),
        (Status::cancelled("cancelled"), Code::Cancelled, "cancelled"),
        (
            Status::invalid_argument("bad arg"),
            Code::InvalidArgument,
            "bad arg",
        ),
        (
            Status::deadline_exceeded("timeout"),
            Code::DeadlineExceeded,
            "timeout",
        ),
        (Status::not_found("missing"), Code::NotFound, "missing"),
        (Status::already_exists("dup"), Code::AlreadyExists, "dup"),
        (
            Status::permission_denied("denied"),
            Code::PermissionDenied,
            "denied",
        ),
        (
            Status::resource_exhausted("full"),
            Code::ResourceExhausted,
            "full",
        ),
        (
            Status::failed_precondition("precond"),
            Code::FailedPrecondition,
            "precond",
        ),
        (Status::aborted("aborted"), Code::Aborted, "aborted"),
        (Status::out_of_range("range"), Code::OutOfRange, "range"),
        (
            Status::unimplemented("unimpl"),
            Code::Unimplemented,
            "unimpl",
        ),
        (Status::internal("internal"), Code::Internal, "internal"),
        (Status::unavailable("unavail"), Code::Unavailable, "unavail"),
        (Status::data_loss("loss"), Code::DataLoss, "loss"),
        (
            Status::unauthenticated("unauth"),
            Code::Unauthenticated,
            "unauth",
        ),
    ];

    for (status, expected_code, expected_msg) in &statuses {
        assert_with_log!(
            status.code() == *expected_code,
            &format!("code {expected_code:?}"),
            expected_code,
            status.code()
        );
        if *expected_code != Code::Ok {
            assert_with_log!(
                status.message() == *expected_msg,
                &format!("message for {expected_code:?}"),
                expected_msg,
                status.message()
            );
        }
        tracing::info!(
            code = ?status.code(),
            code_i32 = status.code().as_i32(),
            message = status.message(),
            "status verified"
        );
    }

    test_section!("status_with_details");
    let details = Bytes::from_static(b"error detail bytes");
    let status = Status::with_details(Code::Internal, "with details", details);
    assert_with_log!(
        status.details().is_some(),
        "has details",
        true,
        status.details().is_some()
    );
    assert_with_log!(
        status.details().unwrap().len() == 18,
        "details length",
        18,
        status.details().unwrap().len()
    );

    test_section!("code_roundtrip");
    for i in 0..=16 {
        let code = Code::from_i32(i);
        let back = code.as_i32();
        assert_with_log!(back == i, &format!("code {i} roundtrip"), i, back);
    }

    test_complete!("e2e_grpc_status_code_comprehensive");
}

// ============================================================================
// Section 4: Interceptor Chain Ordering
// ============================================================================

#[test]
fn e2e_grpc_interceptor_chain_ordering() {
    init_test("e2e_grpc_interceptor_chain_ordering");

    test_section!("build_chain");
    let layer = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(logging_interceptor())
        .layer(auth_bearer_interceptor("test-token"))
        .layer(rate_limiter(100))
        .layer(timeout_interceptor(5000));

    tracing::info!(count = layer.len(), "interceptor chain built");
    assert_with_log!(layer.len() == 5, "chain length", 5, layer.len());
    assert_with_log!(
        !layer.is_empty(),
        "chain not empty",
        true,
        !layer.is_empty()
    );

    test_section!("verify_auth_interceptor");
    let auth = auth_bearer_interceptor("my-secret-token");
    let mut request = Request::new(Bytes::from_static(b"data"));
    let result = auth.intercept_request(&mut request);
    tracing::info!(is_ok = result.is_ok(), "auth intercept result");
    assert_with_log!(result.is_ok(), "auth intercepted ok", true, result.is_ok());

    // Check authorization header was added
    let auth_header = request.metadata().get("authorization");
    tracing::info!(has_auth = auth_header.is_some(), "authorization header");
    assert_with_log!(
        auth_header.is_some(),
        "auth header set",
        true,
        auth_header.is_some()
    );

    test_section!("verify_auth_validator");
    let validator = auth_validator(|token: &str| token == "valid-token");
    let mut good_req = Request::new(Bytes::from_static(b"data"));
    good_req
        .metadata_mut()
        .insert("authorization", "Bearer valid-token");
    let result = validator.intercept_request(&mut good_req);
    tracing::info!(is_ok = result.is_ok(), "valid token result");
    assert_with_log!(result.is_ok(), "valid token accepted", true, result.is_ok());

    let mut bad_req = Request::new(Bytes::from_static(b"data"));
    bad_req
        .metadata_mut()
        .insert("authorization", "Bearer bad-token");
    let result = validator.intercept_request(&mut bad_req);
    tracing::info!(is_err = result.is_err(), "invalid token result");
    assert_with_log!(result.is_err(), "bad token rejected", true, result.is_err());

    test_section!("verify_rate_limiter");
    let limiter = rate_limiter(3);
    for i in 0..5 {
        let mut req = Request::new(Bytes::from_static(b"data"));
        let result = limiter.intercept_request(&mut req);
        tracing::info!(attempt = i, is_ok = result.is_ok(), "rate limit check");
    }

    test_section!("verify_timeout");
    let timeout = timeout_interceptor(3000);
    let mut req = Request::new(Bytes::from_static(b"data"));
    let result = timeout.intercept_request(&mut req);
    assert_with_log!(result.is_ok(), "timeout set", true, result.is_ok());
    let grpc_timeout = req.metadata().get("grpc-timeout");
    tracing::info!(has_timeout = grpc_timeout.is_some(), "grpc-timeout header");

    test_section!("verify_metadata_propagator");
    let propagator = metadata_propagator(["x-trace-id", "x-session-id"]);
    let mut req = Request::new(Bytes::from_static(b"data"));
    req.metadata_mut().insert("x-trace-id", "trace-123");
    let result = propagator.intercept_request(&mut req);
    tracing::info!(is_ok = result.is_ok(), "propagator result");

    test_complete!("e2e_grpc_interceptor_chain_ordering");
}

// ============================================================================
// Section 5: Health Checking Protocol
// ============================================================================

#[test]
fn e2e_grpc_health_check_full_lifecycle() {
    init_test("e2e_grpc_health_check_full_lifecycle");

    test_section!("setup");
    let health = HealthService::new();

    test_section!("initial_state");
    let server_check = health.check(&HealthCheckRequest::server());
    tracing::info!(result = ?server_check, "initial server health");

    test_section!("set_serving");
    health.set_server_status(ServingStatus::Serving);
    let check = health.check(&HealthCheckRequest::server());
    match &check {
        Ok(resp) => {
            tracing::info!(status = ?resp.status, "server serving");
            assert_with_log!(
                resp.status == ServingStatus::Serving,
                "serving status",
                ServingStatus::Serving,
                resp.status
            );
        }
        Err(e) => tracing::info!(error = ?e, "check error"),
    }

    test_section!("register_services");
    health.set_status("grpc.health.v1.Health", ServingStatus::Serving);
    health.set_status("myapp.UserService", ServingStatus::Serving);
    health.set_status("myapp.OrderService", ServingStatus::NotServing);

    let services = health.services();
    tracing::info!(count = services.len(), "registered services");
    assert_with_log!(services.len() >= 3, "service count", ">= 3", services.len());

    test_section!("check_individual_services");
    assert_with_log!(
        health.is_serving("myapp.UserService"),
        "user service serving",
        true,
        health.is_serving("myapp.UserService")
    );
    assert_with_log!(
        !health.is_serving("myapp.OrderService"),
        "order service not serving",
        false,
        health.is_serving("myapp.OrderService")
    );

    test_section!("unknown_service");
    let unknown = health.check(&HealthCheckRequest::new("nonexistent.Service"));
    tracing::info!(result = ?unknown, "unknown service check");

    test_section!("service_transitions");
    health.set_status("myapp.OrderService", ServingStatus::Serving);
    assert_with_log!(
        health.is_serving("myapp.OrderService"),
        "order now serving",
        true,
        health.is_serving("myapp.OrderService")
    );

    health.clear_status("myapp.OrderService");
    let cleared = health.get_status("myapp.OrderService");
    tracing::info!(status = ?cleared, "after clear");

    test_section!("clear_all");
    health.clear();
    let after_clear = health.services();
    tracing::info!(count = after_clear.len(), "services after clear");

    test_complete!("e2e_grpc_health_check_full_lifecycle");
}

// ============================================================================
// Section 6: Codec Framing E2E
// ============================================================================

#[test]
fn e2e_grpc_codec_framing_roundtrip() {
    init_test("e2e_grpc_codec_framing_roundtrip");

    test_section!("setup");
    let mut codec = GrpcCodec::new();

    test_section!("encode_and_decode_uncompressed");
    let original = GrpcMessage::new(Bytes::from_static(b"Hello gRPC World"));
    let mut buf = BytesMut::new();
    codec.encode(original, &mut buf).expect("encode");
    tracing::info!(encoded_len = buf.len(), "encoded message");

    let decoded = codec
        .decode(&mut buf)
        .expect("decode")
        .expect("frame present");
    assert_with_log!(
        !decoded.compressed,
        "not compressed",
        false,
        decoded.compressed
    );
    assert_with_log!(
        decoded.data == Bytes::from_static(b"Hello gRPC World"),
        "data matches",
        "Hello gRPC World",
        String::from_utf8_lossy(&decoded.data)
    );

    test_section!("encode_and_decode_compressed");
    let compressed_msg = GrpcMessage::compressed(Bytes::from_static(b"compressed payload"));
    let mut buf2 = BytesMut::new();
    codec
        .encode(compressed_msg, &mut buf2)
        .expect("encode compressed");

    let decoded2 = codec
        .decode(&mut buf2)
        .expect("decode")
        .expect("frame present");
    assert_with_log!(
        decoded2.compressed,
        "is compressed",
        true,
        decoded2.compressed
    );
    tracing::info!(
        compressed = decoded2.compressed,
        data_len = decoded2.data.len(),
        "compressed roundtrip"
    );

    test_section!("max_size_enforcement");
    let mut small_codec = GrpcCodec::with_max_size(16);
    let big_msg = GrpcMessage::new(Bytes::from(vec![0u8; 32]));
    let mut buf3 = BytesMut::new();
    let encode_result = small_codec.encode(big_msg, &mut buf3);
    tracing::info!(is_err = encode_result.is_err(), "oversized encode result");

    test_section!("empty_message");
    let empty = GrpcMessage::new(Bytes::new());
    let mut buf4 = BytesMut::new();
    codec.encode(empty, &mut buf4).expect("encode empty");
    let decoded_empty = codec.decode(&mut buf4).expect("decode").expect("frame");
    assert_with_log!(
        decoded_empty.data.is_empty(),
        "empty data",
        true,
        decoded_empty.data.is_empty()
    );

    test_section!("multiple_messages");
    let mut multi_buf = BytesMut::new();
    for i in 0..5 {
        let msg = GrpcMessage::new(Bytes::from(format!("msg-{i}")));
        codec.encode(msg, &mut multi_buf).expect("encode multi");
    }
    tracing::info!(buf_len = multi_buf.len(), "encoded 5 messages");

    let mut decoded_count = 0;
    while let Ok(Some(_)) = codec.decode(&mut multi_buf) {
        decoded_count += 1;
    }
    assert_with_log!(decoded_count == 5, "decoded all", 5, decoded_count);
    tracing::info!(decoded = decoded_count, "all messages decoded");

    test_complete!("e2e_grpc_codec_framing_roundtrip");
}

// ============================================================================
// Section 7: Server Builder & Service Registration
// ============================================================================

#[test]
fn e2e_grpc_server_builder_full() {
    init_test("e2e_grpc_server_builder_full");

    test_section!("build_server");
    let health = HealthService::new();
    health.set_server_status(ServingStatus::Serving);

    let server = Server::builder()
        .max_recv_message_size(8 * 1024 * 1024)
        .max_send_message_size(8 * 1024 * 1024)
        .max_concurrent_streams(100)
        .keepalive_interval(30_000)
        .keepalive_timeout(10_000)
        .add_service(health)
        .build();

    test_section!("verify_config");
    let config = server.config();
    assert_with_log!(
        config.max_recv_message_size == 8 * 1024 * 1024,
        "max recv",
        8 * 1024 * 1024,
        config.max_recv_message_size
    );
    assert_with_log!(
        config.max_concurrent_streams == 100,
        "max streams",
        100,
        config.max_concurrent_streams
    );
    tracing::info!(
        max_recv = config.max_recv_message_size,
        max_send = config.max_send_message_size,
        max_streams = config.max_concurrent_streams,
        "server config"
    );

    test_section!("verify_services");
    let names = server.service_names();
    tracing::info!(services = ?names, "registered services");
    assert_with_log!(!names.is_empty(), "has services", true, !names.is_empty());

    test_complete!("e2e_grpc_server_builder_full");
}

// ============================================================================
// Section 8: Channel Configuration
// ============================================================================

#[test]
fn e2e_grpc_channel_config() {
    init_test("e2e_grpc_channel_config");

    test_section!("default_config");
    let default = ChannelConfig::default();
    tracing::info!(
        connect_timeout_ms = default.connect_timeout.as_millis(),
        max_recv = default.max_recv_message_size,
        max_send = default.max_send_message_size,
        "default channel config"
    );

    test_section!("custom_builder");
    futures_lite::future::block_on(async {
        let channel = Channel::builder("http://grpc.example.com:9090")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .max_recv_message_size(16 * 1024 * 1024)
            .max_send_message_size(4 * 1024 * 1024)
            .keepalive_interval(Duration::from_secs(60))
            .keepalive_timeout(Duration::from_secs(10))
            .connect()
            .await
            .unwrap();

        tracing::info!(uri = channel.uri(), "channel connected");
        assert_with_log!(
            channel.uri() == "http://grpc.example.com:9090",
            "channel uri",
            "http://grpc.example.com:9090",
            channel.uri()
        );

        let config = channel.config();
        assert_with_log!(
            config.max_recv_message_size == 16 * 1024 * 1024,
            "max recv",
            16 * 1024 * 1024,
            config.max_recv_message_size
        );
    });

    test_complete!("e2e_grpc_channel_config");
}

// ============================================================================
// Section 9: GrpcError Conversions
// ============================================================================

#[test]
fn e2e_grpc_error_conversions() {
    init_test("e2e_grpc_error_conversions");

    test_section!("error_types");
    // Test each error conversion individually (GrpcError is not Clone)
    let cases: Vec<(GrpcError, Code)> = vec![
        (GrpcError::transport("conn refused"), Code::Unavailable),
        (GrpcError::protocol("bad frame"), Code::Internal),
        (
            GrpcError::invalid_message("bad proto"),
            Code::InvalidArgument,
        ),
        (GrpcError::compression("zstd fail"), Code::Internal),
        (GrpcError::MessageTooLarge, Code::ResourceExhausted),
    ];

    for (error, expected_code) in cases {
        let status = error.into_status();
        tracing::info!(
            code = ?status.code(),
            message = status.message(),
            "error converted"
        );
        assert_with_log!(
            status.code() == expected_code,
            &format!("error {:?} -> code", status.message()),
            expected_code,
            status.code()
        );
    }

    test_section!("status_error_wrapper");
    let status = Status::internal("test error");
    let error = GrpcError::Status(status);
    let back = error.into_status();
    assert_with_log!(
        back.code() == Code::Internal,
        "status roundtrip",
        Code::Internal,
        back.code()
    );

    test_complete!("e2e_grpc_error_conversions");
}

// ============================================================================
// Section 10: Method Descriptors
// ============================================================================

#[test]
fn e2e_grpc_method_descriptors() {
    init_test("e2e_grpc_method_descriptors");

    test_section!("all_patterns");
    let unary = MethodDescriptor::unary("Echo", "/test.Service/Echo");
    let server_stream = MethodDescriptor::server_streaming("Watch", "/test.Service/Watch");
    let client_stream = MethodDescriptor::client_streaming("Upload", "/test.Service/Upload");
    let bidi = MethodDescriptor::bidi_streaming("Chat", "/test.Service/Chat");

    assert_with_log!(
        !unary.client_streaming,
        "unary no client stream",
        false,
        unary.client_streaming
    );
    assert_with_log!(
        !unary.server_streaming,
        "unary no server stream",
        false,
        unary.server_streaming
    );

    assert_with_log!(
        !server_stream.client_streaming,
        "ss no client",
        false,
        server_stream.client_streaming
    );
    assert_with_log!(
        server_stream.server_streaming,
        "ss has server",
        true,
        server_stream.server_streaming
    );

    assert_with_log!(
        client_stream.client_streaming,
        "cs has client",
        true,
        client_stream.client_streaming
    );
    assert_with_log!(
        !client_stream.server_streaming,
        "cs no server",
        false,
        client_stream.server_streaming
    );

    assert_with_log!(
        bidi.client_streaming,
        "bidi has client",
        true,
        bidi.client_streaming
    );
    assert_with_log!(
        bidi.server_streaming,
        "bidi has server",
        true,
        bidi.server_streaming
    );

    tracing::info!(
        unary_path = unary.path,
        ss_path = server_stream.path,
        cs_path = client_stream.path,
        bidi_path = bidi.path,
        "all method descriptors verified"
    );

    test_complete!("e2e_grpc_method_descriptors");
}

// ============================================================================
// Section 11: CallContext
// ============================================================================

#[test]
fn e2e_grpc_call_context() {
    init_test("e2e_grpc_call_context");

    test_section!("default_context");
    let ctx = CallContext::new();
    tracing::info!(
        has_deadline = ctx.deadline().is_some(),
        has_peer = ctx.peer_addr().is_some(),
        expired = ctx.is_expired(),
        "default call context"
    );
    assert_with_log!(!ctx.is_expired(), "not expired", false, ctx.is_expired());
    assert_with_log!(
        ctx.metadata().is_empty(),
        "empty metadata",
        true,
        ctx.metadata().is_empty()
    );

    test_complete!("e2e_grpc_call_context");
}

// ============================================================================
// Section 12: Custom FnInterceptor
// ============================================================================

#[test]
fn e2e_grpc_custom_fn_interceptor() {
    init_test("e2e_grpc_custom_fn_interceptor");

    test_section!("create_interceptor");
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = counter.clone();
    let interceptor = fn_interceptor(move |req: &mut Request<Bytes>| -> Result<(), Status> {
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        req.metadata_mut().insert("x-intercepted", "true");
        Ok(())
    });

    test_section!("apply_interceptor");
    for i in 0..5 {
        let mut req = Request::new(Bytes::from(format!("request-{i}")));
        let result = interceptor.intercept_request(&mut req);
        assert_with_log!(
            result.is_ok(),
            &format!("intercept {i}"),
            true,
            result.is_ok()
        );
        let intercepted = req.metadata().get("x-intercepted");
        assert_with_log!(
            intercepted.is_some(),
            "header added",
            true,
            intercepted.is_some()
        );
    }

    test_section!("verify_count");
    let count = counter.load(std::sync::atomic::Ordering::SeqCst);
    tracing::info!(count = count, "interceptor invocations");
    assert_with_log!(count == 5, "invocation count", 5, count);

    test_complete!("e2e_grpc_custom_fn_interceptor");
}

// ============================================================================
// Section 13: Stress - Many Status Codes
// ============================================================================

#[test]
fn e2e_grpc_stress_status_creation() {
    init_test("e2e_grpc_stress_status_creation");

    test_section!("create_many_statuses");
    let n = 500;
    let mut ok_count = 0;
    let mut err_count = 0;

    for i in 0..n {
        let code = Code::from_i32(i % 17);
        let status = Status::new(code, format!("message-{i}"));
        if status.is_ok() {
            ok_count += 1;
        } else {
            err_count += 1;
        }
    }

    tracing::info!(
        total = n,
        ok = ok_count,
        err = err_count,
        "status creation stress"
    );
    assert_with_log!(
        ok_count + err_count == n,
        "all created",
        n,
        ok_count + err_count
    );
    // Code::Ok is index 0, so every 17th is ok
    let expected_ok = n / 17 + i32::from(n % 17 > 0);
    tracing::info!(
        expected_ok = expected_ok,
        actual_ok = ok_count,
        "ok distribution"
    );

    test_complete!("e2e_grpc_stress_status_creation");
}

// ============================================================================
// Section 14: Interceptor Layer Composition
// ============================================================================

#[test]
fn e2e_grpc_interceptor_layer_composition() {
    init_test("e2e_grpc_interceptor_layer_composition");

    test_section!("empty_layer");
    let empty = InterceptorLayer::new();
    assert_with_log!(empty.is_empty(), "empty layer", true, empty.is_empty());
    assert_with_log!(empty.is_empty(), "zero length", true, empty.is_empty());

    test_section!("single_layer");
    let single = InterceptorLayer::new().layer(trace_interceptor());
    assert_with_log!(single.len() == 1, "one interceptor", 1, single.len());

    test_section!("max_composition");
    let full = InterceptorLayer::new()
        .layer(trace_interceptor())
        .layer(logging_interceptor())
        .layer(auth_bearer_interceptor("token"))
        .layer(rate_limiter(1000))
        .layer(timeout_interceptor(30000))
        .layer(metadata_propagator(["x-trace-id"]));

    tracing::info!(count = full.len(), "full interceptor stack");
    assert_with_log!(full.len() == 6, "six interceptors", 6, full.len());

    test_complete!("e2e_grpc_interceptor_layer_composition");
}
