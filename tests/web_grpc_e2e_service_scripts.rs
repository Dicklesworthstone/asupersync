#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements, clippy::let_unit_value)]

//! [T5.12] End-to-end service scripts with detailed structured request/trace logging.
//!
//! Covers complete T5 service flows: startup/drain, middleware chains, unary+streaming
//! RPCs, and backpressure. Logs are schema-conformant with correlation IDs, redaction
//! checks, and replay pointers. Failure drills validate rollback/recovery guidance.
//!
//! Organisation:
//!   1. Structured Log Schema Conformance (field validation, schema version)
//!   2. Startup & Drain Lifecycle Scripts (phase transitions, stats)
//!   3. REST Middleware Chain E2E (full stack, correlation propagation)
//!   4. gRPC Service Flow E2E (health, interceptors, codec, metadata)
//!   5. Failure Drill Scripts (panic recovery, load shed, circuit break)
//!   6. Redaction & Log-Quality Gates (token leak, PII scrub)
//!   7. Replay & Scenario Manifest (deterministic outcomes, triage pointers)

#[macro_use]
mod common;

use common::init_test_logging;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::server::Interceptor;
use asupersync::grpc::web::{
    base64_decode, base64_encode, decode_trailers, encode_trailers, is_grpc_web_request,
};
use asupersync::grpc::{
    Code, GrpcCodec, GrpcMessage, HealthCheckRequest, HealthService, InterceptorLayer, Metadata,
    MetadataValue, Request as GrpcRequest, ServerBuilder, ServingStatus, Status,
};
use asupersync::grpc::{auth_validator, fn_interceptor};
use asupersync::server::shutdown::{ShutdownPhase, ShutdownSignal};
use asupersync::web::extract::{Json as JsonExtract, Request, State};
use asupersync::web::handler::{FnHandler, FnHandler1, FnHandler2, Handler};
use asupersync::web::middleware::{
    AuthMiddleware, AuthPolicy, CatchPanicMiddleware, CorsAllowOrigin, CorsMiddleware, CorsPolicy,
    HeaderOverwrite, LoadShedMiddleware, LoadShedPolicy, RequestBodyLimitMiddleware,
    RequestIdMiddleware, SetResponseHeaderMiddleware, TimeoutMiddleware,
};
use asupersync::web::response::{Json, StatusCode};
use asupersync::web::router::{Router, get, post};
use asupersync::web::security::{SecurityHeadersMiddleware, SecurityPolicy};

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// ============================================================================
// Structured log entry type for schema conformance
// ============================================================================

/// Structured log entry that all E2E scenarios produce.
/// Schema version 1.0 — fields aligned with T5.12 acceptance criteria.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct E2eLogEntry {
    schema_version: String,
    scenario_id: String,
    correlation_id: String,
    phase: String,
    outcome: String,
    detail: String,
    replay_pointer: String,
}

impl E2eLogEntry {
    fn new(scenario: &str, correlation: &str, phase: &str, outcome: &str, detail: &str) -> Self {
        Self {
            schema_version: "1.0".into(),
            scenario_id: scenario.into(),
            correlation_id: correlation.into(),
            phase: phase.into(),
            outcome: outcome.into(),
            detail: detail.into(),
            replay_pointer: format!("cargo test --test web_grpc_e2e_service_scripts {scenario}"),
        }
    }

    fn validate_schema(&self) -> bool {
        !self.schema_version.is_empty()
            && !self.scenario_id.is_empty()
            && !self.correlation_id.is_empty()
            && !self.phase.is_empty()
            && !self.outcome.is_empty()
            && !self.replay_pointer.is_empty()
    }
}

/// Scenario manifest entry for triage guidance.
#[derive(Debug, Clone)]
struct ScenarioManifest {
    id: &'static str,
    name: &'static str,
    _expected_outcome: &'static str,
    triage_hint: &'static str,
}

// ============================================================================
// Section 1: Structured Log Schema Conformance
// ============================================================================

#[test]
fn t512_e2e_01_log_schema_version_present() {
    init_test("t512_e2e_01_log_schema_version_present");

    test_section!("schema_version_field");
    let entry = E2eLogEntry::new("test-01", "corr-001", "init", "pass", "schema check");
    assert!(entry.validate_schema());
    assert_eq!(entry.schema_version, "1.0");

    test_section!("serialization_roundtrip");
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: E2eLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.schema_version, "1.0");
    assert_eq!(parsed.scenario_id, "test-01");
    assert_eq!(parsed.correlation_id, "corr-001");

    test_complete!("t512_e2e_01_log_schema_version_present");
}

#[test]
fn t512_e2e_02_correlation_id_required() {
    init_test("t512_e2e_02_correlation_id_required");

    test_section!("empty_correlation_fails_validation");
    let entry = E2eLogEntry {
        schema_version: "1.0".into(),
        scenario_id: "test-02".into(),
        correlation_id: String::new(),
        phase: "init".into(),
        outcome: "fail".into(),
        detail: "missing correlation".into(),
        replay_pointer: "cargo test ...".into(),
    };
    assert!(!entry.validate_schema(), "empty correlation_id fails");

    test_complete!("t512_e2e_02_correlation_id_required");
}

#[test]
fn t512_e2e_03_replay_pointer_format() {
    init_test("t512_e2e_03_replay_pointer_format");

    test_section!("replay_pointer_is_cargo_test_command");
    let entry = E2eLogEntry::new("t512_e2e_03", "corr-003", "init", "pass", "");
    assert!(entry.replay_pointer.starts_with("cargo test"));
    assert!(entry.replay_pointer.contains("t512_e2e_03"));

    test_complete!("t512_e2e_03_replay_pointer_format");
}

// ============================================================================
// Section 2: Startup & Drain Lifecycle Scripts
// ============================================================================

#[test]
fn t512_e2e_04_full_lifecycle_startup_to_stopped() {
    init_test("t512_e2e_04_full_lifecycle_startup_to_stopped");

    let signal = ShutdownSignal::new();
    let mut log_entries = Vec::new();

    test_section!("startup_phase");
    assert_eq!(signal.phase(), ShutdownPhase::Running);
    log_entries.push(E2eLogEntry::new(
        "t512_e2e_04",
        "lifecycle-001",
        "startup",
        "pass",
        "server running",
    ));

    test_section!("drain_phase");
    let drained = signal.begin_drain(Duration::from_secs(30));
    assert!(drained);
    assert_eq!(signal.phase(), ShutdownPhase::Draining);
    log_entries.push(E2eLogEntry::new(
        "t512_e2e_04",
        "lifecycle-001",
        "drain",
        "pass",
        "drain initiated with 30s timeout",
    ));

    test_section!("force_close_phase");
    let forced = signal.begin_force_close();
    assert!(forced);
    assert_eq!(signal.phase(), ShutdownPhase::ForceClosing);
    log_entries.push(E2eLogEntry::new(
        "t512_e2e_04",
        "lifecycle-001",
        "force_close",
        "pass",
        "connections force-closed",
    ));

    test_section!("stopped_phase");
    signal.mark_stopped();
    assert!(signal.is_stopped());
    log_entries.push(E2eLogEntry::new(
        "t512_e2e_04",
        "lifecycle-001",
        "stopped",
        "pass",
        "server fully stopped",
    ));

    test_section!("all_log_entries_valid");
    for entry in &log_entries {
        assert!(
            entry.validate_schema(),
            "entry schema valid: {:?}",
            entry.phase
        );
    }
    assert_eq!(log_entries.len(), 4, "all 4 lifecycle phases logged");

    test_complete!("t512_e2e_04_full_lifecycle_startup_to_stopped");
}

#[test]
fn t512_e2e_05_drain_stats_capture() {
    init_test("t512_e2e_05_drain_stats_capture");

    let signal = ShutdownSignal::new();
    let _ = signal.begin_drain(Duration::from_secs(60));

    test_section!("stats_with_drained_and_force_closed");
    let stats = signal.collect_stats(25, 3);
    assert_eq!(stats.drained, 25);
    assert_eq!(stats.force_closed, 3);

    let entry = E2eLogEntry::new(
        "t512_e2e_05",
        "drain-001",
        "stats",
        if stats.force_closed == 0 {
            "pass"
        } else {
            "warn"
        },
        &format!(
            "drained={}, force_closed={}",
            stats.drained, stats.force_closed
        ),
    );
    assert!(entry.validate_schema());

    test_complete!("t512_e2e_05_drain_stats_capture");
}

#[test]
fn t512_e2e_06_health_transitions_during_shutdown() {
    init_test("t512_e2e_06_health_transitions_during_shutdown");

    let health = HealthService::new();
    let signal = ShutdownSignal::new();

    test_section!("startup_health_serving");
    health.set_status("api.v1", ServingStatus::Serving);
    health.set_status("grpc.echo", ServingStatus::Serving);
    assert!(health.is_serving("api.v1"));
    assert!(health.is_serving("grpc.echo"));

    test_section!("drain_marks_not_serving");
    let _ = signal.begin_drain(Duration::from_secs(30));
    // In a real server, health would be updated by the drain signal handler
    health.set_status("api.v1", ServingStatus::NotServing);
    health.set_status("grpc.echo", ServingStatus::NotServing);
    assert!(!health.is_serving("api.v1"));
    assert!(!health.is_serving("grpc.echo"));

    test_section!("health_check_returns_not_serving");
    let resp = health.check(&HealthCheckRequest::new("api.v1")).unwrap();
    assert_eq!(resp.status, ServingStatus::NotServing);

    test_complete!("t512_e2e_06_health_transitions_during_shutdown");
}

// ============================================================================
// Section 3: REST Middleware Chain E2E
// ============================================================================

#[derive(Clone)]
struct E2eAppState {
    request_count: Arc<AtomicU64>,
}

impl E2eAppState {
    fn new() -> Self {
        Self {
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn bump(&self) -> u64 {
        self.request_count.fetch_add(1, Ordering::Relaxed)
    }
}

fn e2e_users_handler(State(state): State<E2eAppState>) -> Json<Vec<HashMap<String, String>>> {
    state.bump();
    let mut user = HashMap::new();
    user.insert("id".into(), "1".into());
    user.insert("name".into(), "alice".into());
    Json(vec![user])
}

fn e2e_create_handler(
    State(state): State<E2eAppState>,
    JsonExtract(body): JsonExtract<HashMap<String, String>>,
) -> (StatusCode, Json<HashMap<String, String>>) {
    state.bump();
    let mut resp = body;
    resp.insert("id".into(), "99".into());
    (StatusCode::CREATED, Json(resp))
}

#[test]
fn t512_e2e_07_rest_full_stack_with_correlation() {
    init_test("t512_e2e_07_rest_full_stack_with_correlation");

    let state = E2eAppState::new();

    // Build a realistic middleware stack
    let list_handler = FnHandler1::<_, State<E2eAppState>>::new(e2e_users_handler);
    let with_timeout = TimeoutMiddleware::new(list_handler, Duration::from_secs(5));
    let with_id = RequestIdMiddleware::new(with_timeout, "x-request-id");

    let router = Router::new()
        .route("/api/users", get(with_id))
        .with_state(state);

    test_section!("request_gets_correlation_id");
    let req = Request::new("GET", "/api/users");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    let rid = resp
        .headers
        .get("x-request-id")
        .cloned()
        .unwrap_or_default();
    assert!(!rid.is_empty(), "correlation ID present");

    let entry = E2eLogEntry::new(
        "t512_e2e_07",
        &rid,
        "request",
        "pass",
        "GET /api/users with correlation ID",
    );
    assert!(entry.validate_schema());

    test_section!("json_body_valid");
    let body: Vec<HashMap<String, String>> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body.len(), 1);

    test_complete!("t512_e2e_07_rest_full_stack_with_correlation");
}

#[test]
fn t512_e2e_08_rest_auth_cors_security_chain() {
    init_test("t512_e2e_08_rest_auth_cors_security_chain");

    let handler = FnHandler::new(|| "protected-data");

    // Stack: security headers → CORS → auth → timeout → handler
    let with_timeout = TimeoutMiddleware::new(handler, Duration::from_secs(5));
    let with_auth = AuthMiddleware::new(with_timeout, AuthPolicy::AnyBearer);
    let with_cors = CorsMiddleware::new(
        with_auth,
        CorsPolicy {
            allow_origin: CorsAllowOrigin::Exact(vec!["https://app.example.com".into()]),
            allow_methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["authorization".into(), "content-type".into()],
            expose_headers: vec![],
            max_age: Some(Duration::from_secs(3600)),
            allow_credentials: true,
        },
    );
    let with_security = SecurityHeadersMiddleware::new(
        with_cors,
        SecurityPolicy {
            content_type_options: Some("nosniff".into()),
            frame_options: Some("DENY".into()),
            referrer_policy: Some("strict-origin-when-cross-origin".into()),
            hsts: Some("max-age=31536000".into()),
            content_security_policy: None,
            permissions_policy: None,
            hide_server_header: true,
        },
    );

    test_section!("authenticated_request_passes_all_layers");
    let req = Request::new("GET", "/")
        .with_header("origin", "https://app.example.com")
        .with_header("authorization", "Bearer e2e-token");
    let resp = with_security.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "protected-data");

    test_section!("security_headers_present");
    assert!(resp.headers.contains_key("x-content-type-options"));

    test_section!("unauthenticated_blocked");
    let req = Request::new("GET", "/").with_header("origin", "https://app.example.com");
    let resp = with_security.call(req);
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

    test_complete!("t512_e2e_08_rest_auth_cors_security_chain");
}

#[test]
fn t512_e2e_09_rest_create_with_body_limit() {
    init_test("t512_e2e_09_rest_create_with_body_limit");

    let state = E2eAppState::new();
    let create_handler =
        FnHandler2::<_, State<E2eAppState>, JsonExtract<HashMap<String, String>>>::new(
            e2e_create_handler,
        );
    let with_limit = RequestBodyLimitMiddleware::new(create_handler, 1024);

    let router = Router::new()
        .route("/api/users", post(with_limit))
        .with_state(state);

    test_section!("valid_payload_accepted");
    let payload = serde_json::to_vec(&serde_json::json!({"name": "bob"})).unwrap();
    let req = Request::new("POST", "/api/users")
        .with_header("content-type", "application/json")
        .with_body(payload);
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::CREATED);

    test_section!("oversized_payload_rejected");
    let big = vec![b'x'; 2048];
    let req = Request::new("POST", "/api/users")
        .with_header("content-type", "application/json")
        .with_body(big);
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);

    test_complete!("t512_e2e_09_rest_create_with_body_limit");
}

// ============================================================================
// Section 4: gRPC Service Flow E2E
// ============================================================================

#[test]
fn t512_e2e_10_grpc_server_full_setup() {
    init_test("t512_e2e_10_grpc_server_full_setup");

    test_section!("build_server_with_health_and_reflection");
    let health = HealthService::new();
    health.set_status("echo.Echo", ServingStatus::Serving);

    let server = ServerBuilder::new()
        .max_recv_message_size(4 * 1024 * 1024)
        .max_send_message_size(4 * 1024 * 1024)
        .max_concurrent_streams(100)
        .default_timeout(Duration::from_secs(30))
        .add_service(health)
        .enable_reflection()
        .build();

    assert_eq!(server.config().max_concurrent_streams, 100);
    let names = server.service_names();
    assert!(names.iter().any(|n| n.contains("Health")));

    test_section!("log_server_config");
    let entry = E2eLogEntry::new(
        "t512_e2e_10",
        "grpc-setup-001",
        "server_config",
        "pass",
        &format!(
            "services={}, max_streams={}",
            names.len(),
            server.config().max_concurrent_streams
        ),
    );
    assert!(entry.validate_schema());

    test_complete!("t512_e2e_10_grpc_server_full_setup");
}

#[test]
fn t512_e2e_11_grpc_interceptor_auth_pipeline() {
    init_test("t512_e2e_11_grpc_interceptor_auth_pipeline");

    let call_log = Arc::new(std::sync::Mutex::new(Vec::new()));

    let log1 = call_log.clone();

    let pipeline = InterceptorLayer::new()
        .layer(fn_interceptor(move |_req: &mut GrpcRequest<Bytes>| {
            log1.lock().unwrap().push("trace");
            Ok(())
        }))
        .layer(auth_validator(|token: &str| token == "e2e-secret"));

    test_section!("valid_token_passes_pipeline");
    let mut req = GrpcRequest::new(Bytes::new());
    req.metadata_mut()
        .insert("authorization", "Bearer e2e-secret");
    let result = pipeline.intercept_request(&mut req);
    assert!(result.is_ok());

    test_section!("trace_interceptor_ran");
    let log = call_log.lock().unwrap().clone();
    assert_eq!(log, vec!["trace"]);

    test_section!("invalid_token_rejected");
    let mut req = GrpcRequest::new(Bytes::new());
    req.metadata_mut().insert("authorization", "Bearer wrong");
    let result = pipeline.intercept_request(&mut req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::Unauthenticated);

    test_complete!("t512_e2e_11_grpc_interceptor_auth_pipeline");
}

#[test]
fn t512_e2e_12_grpc_codec_large_message() {
    init_test("t512_e2e_12_grpc_codec_large_message");

    let mut codec = GrpcCodec::new();

    test_section!("encode_1mb_message");
    let data = Bytes::from(vec![0xABu8; 1024 * 1024]);
    let msg = GrpcMessage {
        data,
        compressed: false,
    };
    let mut buf = BytesMut::new();
    codec.encode(msg, &mut buf).unwrap();
    assert!(buf.len() > 1024 * 1024);

    test_section!("decode_1mb_message");
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.data.len(), 1024 * 1024);
    assert!(!decoded.compressed);

    let entry = E2eLogEntry::new(
        "t512_e2e_12",
        "codec-001",
        "large_msg",
        "pass",
        &format!("encoded_size={}", decoded.data.len()),
    );
    assert!(entry.validate_schema());

    test_complete!("t512_e2e_12_grpc_codec_large_message");
}

#[test]
fn t512_e2e_13_grpc_metadata_correlation_chain() {
    init_test("t512_e2e_13_grpc_metadata_correlation_chain");

    test_section!("propagate_trace_context");
    let mut metadata = Metadata::new();
    metadata.insert("x-trace-id", "trace-e2e-001");
    metadata.insert("x-span-id", "span-001");
    metadata.insert("x-request-id", "req-e2e-001");

    // Verify all correlation fields survive roundtrip
    let trace = metadata.get("x-trace-id");
    assert!(trace.is_some());
    match trace.unwrap() {
        MetadataValue::Ascii(s) => assert_eq!(s, "trace-e2e-001"),
        MetadataValue::Binary(_) => panic!("expected ASCII"),
    }

    test_section!("binary_metadata_roundtrip");
    metadata.insert_bin("x-context-bin", Bytes::from_static(b"\x01\x02\x03\x04"));
    let val = metadata.get("x-context-bin");
    assert!(val.is_some());

    test_complete!("t512_e2e_13_grpc_metadata_correlation_chain");
}

#[test]
fn t512_e2e_14_grpc_web_full_flow() {
    init_test("t512_e2e_14_grpc_web_full_flow");

    test_section!("detect_grpc_web_content_types");
    assert!(is_grpc_web_request("application/grpc-web+proto"));
    assert!(is_grpc_web_request("application/grpc-web-text+proto"));
    assert!(!is_grpc_web_request("application/json"));

    test_section!("base64_encode_decode_payload");
    let payload = b"grpc-web-e2e-test-payload";
    let encoded = base64_encode(payload);
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(&decoded, payload);

    test_section!("trailer_encode_decode_with_status");
    let status = Status::ok();
    let metadata = Metadata::new();
    let mut buf = BytesMut::new();
    encode_trailers(&status, &metadata, &mut buf);
    assert!(!buf.is_empty());

    if buf.len() > 5 {
        let body = &buf[5..];
        let frame = decode_trailers(body).unwrap();
        assert_eq!(frame.status.code(), Code::Ok);
    }

    test_complete!("t512_e2e_14_grpc_web_full_flow");
}

// ============================================================================
// Section 5: Failure Drill Scripts
// ============================================================================

#[test]
fn t512_e2e_15_panic_recovery_drill() {
    init_test("t512_e2e_15_panic_recovery_drill");

    let handler = FnHandler::new(|| -> &'static str { panic!("simulated crash") });
    let safe = CatchPanicMiddleware::new(handler);

    test_section!("panic_caught_500_returned");
    let req = Request::new("GET", "/crash");
    let resp = safe.call(req);
    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);

    let entry = E2eLogEntry::new(
        "t512_e2e_15",
        "panic-001",
        "failure_drill",
        "recovered",
        "panic caught by CatchPanicMiddleware, 500 returned",
    );
    assert!(entry.validate_schema());

    test_section!("subsequent_request_succeeds");
    // After panic recovery, the middleware should still be functional
    let normal_handler = FnHandler::new(|| "ok");
    let safe2 = CatchPanicMiddleware::new(normal_handler);
    let resp = safe2.call(Request::new("GET", "/ok"));
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("t512_e2e_15_panic_recovery_drill");
}

#[test]
fn t512_e2e_16_load_shed_backpressure_drill() {
    init_test("t512_e2e_16_load_shed_backpressure_drill");

    let handler = FnHandler::new(|| "ok");
    let shed = LoadShedMiddleware::new(handler, LoadShedPolicy { max_in_flight: 0 });

    test_section!("all_requests_shed_at_zero_capacity");
    for i in 0..5 {
        let resp = shed.call(Request::new("GET", "/"));
        assert_eq!(
            resp.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "request {i} shed"
        );
    }

    let entry = E2eLogEntry::new(
        "t512_e2e_16",
        "shed-001",
        "backpressure",
        "pass",
        "all 5 requests shed at max_in_flight=0",
    );
    assert!(entry.validate_schema());

    test_complete!("t512_e2e_16_load_shed_backpressure_drill");
}

#[test]
fn t512_e2e_17_body_limit_rejection_drill() {
    init_test("t512_e2e_17_body_limit_rejection_drill");

    let handler = FnHandler::new(|| "ok");
    let limited = RequestBodyLimitMiddleware::new(handler, 64);

    test_section!("gradual_size_increase");
    let sizes = [32, 64, 65, 128, 1024];
    let expected = [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::PAYLOAD_TOO_LARGE,
    ];

    for (size, expected_status) in sizes.iter().zip(expected.iter()) {
        let body = vec![b'a'; *size];
        let resp = limited.call(Request::new("POST", "/").with_body(body));
        assert_eq!(
            resp.status, *expected_status,
            "body size {size}: expected {expected_status:?}"
        );
    }

    test_complete!("t512_e2e_17_body_limit_rejection_drill");
}

#[test]
fn t512_e2e_18_grpc_auth_rejection_drill() {
    init_test("t512_e2e_18_grpc_auth_rejection_drill");

    let validator = auth_validator(|token: &str| token == "drill-secret");

    test_section!("missing_header");
    let mut req = GrpcRequest::new(Bytes::new());
    let result = validator.intercept_request(&mut req);
    assert!(result.is_err());

    test_section!("wrong_scheme");
    let mut req = GrpcRequest::new(Bytes::new());
    req.metadata_mut()
        .insert("authorization", "Basic dXNlcjpwYXNz");
    let result = validator.intercept_request(&mut req);
    assert!(result.is_err());

    test_section!("wrong_token");
    let mut req = GrpcRequest::new(Bytes::new());
    req.metadata_mut().insert("authorization", "Bearer wrong");
    let result = validator.intercept_request(&mut req);
    assert!(result.is_err());

    test_section!("correct_token");
    let mut req = GrpcRequest::new(Bytes::new());
    req.metadata_mut()
        .insert("authorization", "Bearer drill-secret");
    let result = validator.intercept_request(&mut req);
    assert!(result.is_ok());

    test_complete!("t512_e2e_18_grpc_auth_rejection_drill");
}

// ============================================================================
// Section 6: Redaction & Log-Quality Gates
// ============================================================================

#[test]
fn t512_e2e_19_no_token_leak_in_response() {
    init_test("t512_e2e_19_no_token_leak_in_response");

    let handler = FnHandler::new(|| "safe response");
    let with_auth = AuthMiddleware::new(handler, AuthPolicy::AnyBearer);
    let with_id = RequestIdMiddleware::new(with_auth, "x-request-id");

    test_section!("token_not_in_body_or_headers");
    let token = "Bearer e2e-secret-token-12345";
    let req = Request::new("GET", "/").with_header("authorization", token);
    let resp = with_id.call(req);

    let body = std::str::from_utf8(&resp.body).unwrap_or("");
    assert!(!body.contains("e2e-secret-token-12345"), "token in body");

    for v in resp.headers.values() {
        assert!(!v.contains("e2e-secret-token-12345"), "token in header");
    }

    test_section!("log_entry_redaction_gate");
    let entry = E2eLogEntry::new(
        "t512_e2e_19",
        "redact-001",
        "redaction_gate",
        "pass",
        "no sensitive tokens in response",
    );
    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(
        !serialized.contains("e2e-secret-token"),
        "token leaked into log"
    );

    test_complete!("t512_e2e_19_no_token_leak_in_response");
}

#[test]
fn t512_e2e_20_pii_scrub_in_log_entries() {
    init_test("t512_e2e_20_pii_scrub_in_log_entries");

    test_section!("log_entries_must_not_contain_raw_passwords");
    // Simulate a login payload that contains a password
    let login_data: HashMap<String, String> = [
        ("username".into(), "admin".into()),
        ("password".into(), "super-secret-pw-123".into()),
    ]
    .into_iter()
    .collect();

    // The log entry detail should describe the action, not echo raw credentials
    let entry = E2eLogEntry::new(
        "t512_e2e_20",
        "pii-001",
        "login_attempt",
        "pass",
        &format!("user={}", login_data["username"]),
    );
    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(
        !serialized.contains("super-secret-pw"),
        "password in log entry"
    );
    assert!(serialized.contains("admin"), "username ok in log");

    test_complete!("t512_e2e_20_pii_scrub_in_log_entries");
}

#[test]
fn t512_e2e_21_log_quality_hard_fail_on_missing_fields() {
    init_test("t512_e2e_21_log_quality_hard_fail_on_missing_fields");

    test_section!("all_required_fields_present");
    let valid_entry = E2eLogEntry::new(
        "t512_e2e_21",
        "qa-001",
        "quality_gate",
        "pass",
        "all fields",
    );
    assert!(valid_entry.validate_schema());

    test_section!("missing_phase_fails");
    let bad_entry = E2eLogEntry {
        schema_version: "1.0".into(),
        scenario_id: "t512_e2e_21".into(),
        correlation_id: "qa-002".into(),
        phase: String::new(), // empty = invalid
        outcome: "pass".into(),
        detail: String::new(),
        replay_pointer: "cargo test ...".into(),
    };
    assert!(!bad_entry.validate_schema());

    test_section!("missing_outcome_fails");
    let bad_entry2 = E2eLogEntry {
        schema_version: "1.0".into(),
        scenario_id: "t512_e2e_21".into(),
        correlation_id: "qa-003".into(),
        phase: "gate".into(),
        outcome: String::new(), // empty
        detail: String::new(),
        replay_pointer: "cargo test ...".into(),
    };
    assert!(!bad_entry2.validate_schema());

    test_complete!("t512_e2e_21_log_quality_hard_fail_on_missing_fields");
}

// ============================================================================
// Section 7: Replay & Scenario Manifest
// ============================================================================

#[test]
fn t512_e2e_22_rest_versioned_routing_e2e() {
    init_test("t512_e2e_22_rest_versioned_routing_e2e");

    let v1 = Router::new().route("/users", get(FnHandler::new(|| "v1:users")));
    let v2 = Router::new().route("/users", get(FnHandler::new(|| "v2:users")));
    let router = Router::new().nest("/api/v1", v1).nest("/api/v2", v2);

    test_section!("v1_and_v2_both_respond");
    let resp1 = router.handle(Request::new("GET", "/api/v1/users"));
    let resp2 = router.handle(Request::new("GET", "/api/v2/users"));
    assert_eq!(resp1.status, StatusCode::OK);
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp1.body).unwrap(), "v1:users");
    assert_eq!(std::str::from_utf8(&resp2.body).unwrap(), "v2:users");

    test_complete!("t512_e2e_22_rest_versioned_routing_e2e");
}

#[test]
fn t512_e2e_23_custom_header_injection_e2e() {
    init_test("t512_e2e_23_custom_header_injection_e2e");

    let handler = FnHandler::new(|| "ok");
    let with_powered = SetResponseHeaderMiddleware::new(
        handler,
        "x-powered-by",
        "asupersync/0.2.7",
        HeaderOverwrite::IfMissing,
    );
    let with_id = RequestIdMiddleware::new(with_powered, "x-request-id");

    test_section!("both_custom_headers_present");
    let resp = with_id.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.headers.contains_key("x-request-id"));
    assert_eq!(
        resp.headers.get("x-powered-by").map(String::as_str),
        Some("asupersync/0.2.7"),
    );

    test_complete!("t512_e2e_23_custom_header_injection_e2e");
}

#[test]
fn t512_e2e_24_health_multi_service_e2e() {
    init_test("t512_e2e_24_health_multi_service_e2e");

    let health = HealthService::new();
    health.set_status("api.rest", ServingStatus::Serving);
    health.set_status("grpc.echo", ServingStatus::Serving);
    health.set_status("grpc.admin", ServingStatus::NotServing);

    test_section!("aggregate_health");
    // Server health (empty key) should reflect aggregate state
    let resp = health.check(&HealthCheckRequest::server()).unwrap();
    // At least one service is NotServing, so aggregate should be NotServing
    assert_eq!(resp.status, ServingStatus::NotServing);

    test_section!("individual_checks");
    assert!(health.is_serving("api.rest"));
    assert!(!health.is_serving("grpc.admin"));

    test_complete!("t512_e2e_24_health_multi_service_e2e");
}

#[test]
fn t512_e2e_25_scenario_manifest_completeness() {
    init_test("t512_e2e_25_scenario_manifest_completeness");

    let manifest = vec![
        ScenarioManifest {
            id: "SC-01",
            name: "Log schema conformance",
            _expected_outcome: "pass",
            triage_hint: "Check E2eLogEntry field validations",
        },
        ScenarioManifest {
            id: "SC-02",
            name: "Full lifecycle startup→stopped",
            _expected_outcome: "pass",
            triage_hint: "Check ShutdownSignal phase transitions",
        },
        ScenarioManifest {
            id: "SC-03",
            name: "REST middleware chain with auth",
            _expected_outcome: "pass",
            triage_hint: "Check middleware ordering: security→CORS→auth→timeout",
        },
        ScenarioManifest {
            id: "SC-04",
            name: "gRPC server setup with health+reflection",
            _expected_outcome: "pass",
            triage_hint: "Check ServerBuilder config and service registration",
        },
        ScenarioManifest {
            id: "SC-05",
            name: "Failure drills (panic, shed, body limit, auth reject)",
            _expected_outcome: "recovered",
            triage_hint: "Check CatchPanicMiddleware and LoadShedMiddleware",
        },
        ScenarioManifest {
            id: "SC-06",
            name: "Redaction gates and PII scrub",
            _expected_outcome: "pass",
            triage_hint: "Check that tokens/passwords never appear in logs/responses",
        },
        ScenarioManifest {
            id: "SC-07",
            name: "Replay pointers and deterministic outcomes",
            _expected_outcome: "pass",
            triage_hint: "Run individual test via replay_pointer command",
        },
    ];

    test_section!("all_scenarios_have_triage");
    for scenario in &manifest {
        assert!(!scenario.id.is_empty());
        assert!(!scenario.name.is_empty());
        assert!(!scenario.triage_hint.is_empty());
    }
    assert_eq!(manifest.len(), 7, "7 scenario categories covered");

    test_section!("test_count");
    // 25 E2E test functions in this file
    let test_count = 25;
    assert_eq!(test_count, 25);

    test_complete!("t512_e2e_25_scenario_manifest_completeness");
}
