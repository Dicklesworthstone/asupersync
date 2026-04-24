#![allow(warnings)]
#![allow(clippy::all)]
//! T5.7 — gRPC production features test suite.
//!
//! Verifies deadline enforcement, compression plumbing, interceptor chains,
//! health check Watch, reflection RPC helpers, and timeout header parsing.
#![allow(unused_imports)] // T5.7 in-progress: imports reserved for upcoming tests

use std::time::{Duration, Instant};

use asupersync::bytes::Bytes;
use asupersync::grpc::server::Interceptor;
use asupersync::grpc::service::{NamedService, ServiceDescriptor, ServiceHandler};
use asupersync::grpc::{
    BearerAuthInterceptor,
    BearerAuthValidator,
    // Server
    CallContext,
    // Client
    Channel,
    ChannelBuilder,
    ChannelConfig,
    Code,
    CompressionEncoding,
    FnInterceptor,
    HealthCheckRequest,
    HealthCheckResponse,
    HealthReporter,
    // Health
    HealthService,
    HealthServiceBuilder,
    HealthWatcher,
    // Interceptors
    InterceptorLayer,
    LoggingInterceptor,
    // Types
    Metadata,
    MetadataPropagator,
    RateLimitInterceptor,
    ReflectedMethod,
    ReflectedService,
    ReflectionDescribeServiceRequest,
    ReflectionDescribeServiceResponse,
    ReflectionListServicesRequest,
    ReflectionListServicesResponse,
    // Reflection
    ReflectionService,
    Request,
    Response,
    Server,
    ServerBuilder,
    ServerConfig,
    ServingStatus,
    Status,
    TimeoutInterceptor,
    TracingInterceptor,
    format_grpc_timeout,
    parse_grpc_timeout,
};
use insta::assert_json_snapshot;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Test service stubs
// ---------------------------------------------------------------------------

struct GreeterService;

impl NamedService for GreeterService {
    const NAME: &'static str = "helloworld.Greeter";
}

impl ServiceHandler for GreeterService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[asupersync::grpc::service::MethodDescriptor] = &[
            asupersync::grpc::service::MethodDescriptor::unary(
                "SayHello",
                "/helloworld.Greeter/SayHello",
            ),
            asupersync::grpc::service::MethodDescriptor::server_streaming(
                "SayHelloStream",
                "/helloworld.Greeter/SayHelloStream",
            ),
        ];
        static DESC: ServiceDescriptor = ServiceDescriptor::new("Greeter", "helloworld", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["SayHello", "SayHelloStream"]
    }
}

struct RouteGuideService;

impl NamedService for RouteGuideService {
    const NAME: &'static str = "routeguide.RouteGuide";
}

impl ServiceHandler for RouteGuideService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[asupersync::grpc::service::MethodDescriptor] = &[
            asupersync::grpc::service::MethodDescriptor::unary(
                "GetFeature",
                "/routeguide.RouteGuide/GetFeature",
            ),
            asupersync::grpc::service::MethodDescriptor::client_streaming(
                "RecordRoute",
                "/routeguide.RouteGuide/RecordRoute",
            ),
            asupersync::grpc::service::MethodDescriptor::bidi_streaming(
                "RouteChat",
                "/routeguide.RouteGuide/RouteChat",
            ),
        ];
        static DESC: ServiceDescriptor =
            ServiceDescriptor::new("RouteGuide", "routeguide", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["GetFeature", "RecordRoute", "RouteChat"]
    }
}

#[derive(Debug, Serialize)]
struct ReflectionRegistrySnapshot {
    list_response: ReflectionListSnapshot,
    describe_responses: Vec<ReflectionDescribeSnapshot>,
}

#[derive(Debug, Serialize)]
struct ReflectionListSnapshot {
    services: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReflectionDescribeSnapshot {
    service: ReflectionServiceSnapshot,
}

#[derive(Debug, Serialize)]
struct ReflectionServiceSnapshot {
    name: String,
    methods: Vec<ReflectionMethodSnapshot>,
}

#[derive(Debug, Serialize)]
struct ReflectionMethodSnapshot {
    name: String,
    path: String,
    client_streaming: bool,
    server_streaming: bool,
}

#[derive(Debug, Serialize)]
struct ReflectionErrorSnapshot {
    code: String,
    message: String,
    details_len: usize,
}

fn reflection_registry_snapshot(reflection: &ReflectionService) -> ReflectionRegistrySnapshot {
    let list_response = futures_lite::future::block_on(
        reflection.list_services_async(&Request::new(ReflectionListServicesRequest)),
    )
    .expect("list should succeed");
    let services = list_response.get_ref().services.clone();

    let describe_responses = services
        .iter()
        .map(|service| {
            futures_lite::future::block_on(reflection.describe_service_async(&Request::new(
                ReflectionDescribeServiceRequest::new(service.clone()),
            )))
            .unwrap_or_else(|_| panic!("describe should succeed for {service}"))
        })
        .map(|response| ReflectionDescribeSnapshot::from(response.get_ref()))
        .collect();

    ReflectionRegistrySnapshot {
        list_response: ReflectionListSnapshot::from(list_response.get_ref()),
        describe_responses,
    }
}

fn reflection_error_snapshot(status: &Status) -> ReflectionErrorSnapshot {
    ReflectionErrorSnapshot {
        code: status.code().to_string(),
        message: status.message().to_string(),
        details_len: status.details().map_or(0, Bytes::len),
    }
}

impl From<&ReflectionListServicesResponse> for ReflectionListSnapshot {
    fn from(response: &ReflectionListServicesResponse) -> Self {
        Self {
            services: response.services.clone(),
        }
    }
}

impl From<&ReflectionDescribeServiceResponse> for ReflectionDescribeSnapshot {
    fn from(response: &ReflectionDescribeServiceResponse) -> Self {
        Self {
            service: ReflectionServiceSnapshot::from(&response.service),
        }
    }
}

impl From<&ReflectedService> for ReflectionServiceSnapshot {
    fn from(service: &ReflectedService) -> Self {
        Self {
            name: service.name.clone(),
            methods: service
                .methods
                .iter()
                .map(ReflectionMethodSnapshot::from)
                .collect(),
        }
    }
}

impl From<&ReflectedMethod> for ReflectionMethodSnapshot {
    fn from(method: &ReflectedMethod) -> Self {
        Self {
            name: method.name.clone(),
            path: method.path.clone(),
            client_streaming: method.client_streaming,
            server_streaming: method.server_streaming,
        }
    }
}

// ===========================================================================
// 1. grpc-timeout header parsing
// ===========================================================================

#[test]
fn parse_grpc_timeout_hours() {
    assert_eq!(parse_grpc_timeout("2H"), Some(Duration::from_secs(7200)));
}

#[test]
fn parse_grpc_timeout_minutes() {
    assert_eq!(parse_grpc_timeout("5M"), Some(Duration::from_secs(300)));
}

#[test]
fn parse_grpc_timeout_seconds() {
    assert_eq!(parse_grpc_timeout("30S"), Some(Duration::from_secs(30)));
}

#[test]
fn parse_grpc_timeout_millis() {
    assert_eq!(
        parse_grpc_timeout("5000m"),
        Some(Duration::from_millis(5000))
    );
}

#[test]
fn parse_grpc_timeout_micros() {
    assert_eq!(parse_grpc_timeout("100u"), Some(Duration::from_micros(100)));
}

#[test]
fn parse_grpc_timeout_nanos() {
    assert_eq!(
        parse_grpc_timeout("999999n"),
        Some(Duration::from_nanos(999_999))
    );
}

#[test]
fn parse_grpc_timeout_zero() {
    assert_eq!(parse_grpc_timeout("0S"), Some(Duration::ZERO));
    assert_eq!(parse_grpc_timeout("0m"), Some(Duration::ZERO));
}

#[test]
fn parse_grpc_timeout_empty() {
    assert_eq!(parse_grpc_timeout(""), None);
}

#[test]
fn parse_grpc_timeout_invalid_unit() {
    assert_eq!(parse_grpc_timeout("100x"), None);
}

#[test]
fn parse_grpc_timeout_no_digits() {
    assert_eq!(parse_grpc_timeout("S"), None);
}

#[test]
fn parse_grpc_timeout_negative() {
    // "-1S" — digits part is "-1" which is not a valid u64
    assert_eq!(parse_grpc_timeout("-1S"), None);
}

#[test]
fn format_grpc_timeout_roundtrip() {
    let d = Duration::from_millis(3500);
    let header = format_grpc_timeout(d);
    assert_eq!(header, "3500m");
    assert_eq!(parse_grpc_timeout(&header), Some(d));
}

// ===========================================================================
// 2. CallContext deadline from metadata
// ===========================================================================

#[test]
fn call_context_from_metadata_with_timeout_header() {
    let mut metadata = Metadata::new();
    metadata.insert("grpc-timeout", "5000m");
    let now = Instant::now();
    let ctx = CallContext::from_metadata_at(metadata, None, None, now);
    let deadline = ctx.deadline().expect("deadline should be set");
    assert_eq!(
        deadline,
        now.checked_add(Duration::from_secs(5))
            .expect("5s timeout should fit in Instant range")
    );
}

#[test]
fn call_context_from_metadata_uses_default_timeout_when_no_header() {
    let metadata = Metadata::new();
    let now = Instant::now();
    let ctx = CallContext::from_metadata_at(metadata, Some(Duration::from_secs(10)), None, now);
    let deadline = ctx.deadline().expect("deadline should be set");
    assert_eq!(
        deadline,
        now.checked_add(Duration::from_secs(10))
            .expect("10s timeout should fit in Instant range")
    );
}

#[test]
fn call_context_from_metadata_header_overrides_default() {
    let mut metadata = Metadata::new();
    metadata.insert("grpc-timeout", "1000m"); // 1 second
    let now = Instant::now();
    let ctx = CallContext::from_metadata_at(
        metadata,
        Some(Duration::from_secs(60)), // default 60s, should be overridden
        None,
        now,
    );
    let deadline = ctx.deadline().expect("deadline should be set");
    assert_eq!(
        deadline,
        now.checked_add(Duration::from_secs(1))
            .expect("1s timeout should fit in Instant range"),
        "header timeout must override default timeout"
    );
}

#[test]
fn call_context_from_metadata_no_timeout_no_default() {
    let metadata = Metadata::new();
    let ctx = CallContext::from_metadata(metadata, None, None);
    assert!(ctx.deadline().is_none());
}

#[test]
fn call_context_from_metadata_preserves_peer_addr() {
    let metadata = Metadata::new();
    let ctx = CallContext::from_metadata(metadata, None, Some("10.0.0.1:443".to_string()));
    assert_eq!(ctx.peer_addr(), Some("10.0.0.1:443"));
}

#[test]
fn call_context_remaining_before_deadline() {
    let now = Instant::now();
    let ctx = CallContext::with_deadline(now + Duration::from_secs(10));
    assert_eq!(ctx.remaining_at(now), Some(Duration::from_secs(10)));
}

#[test]
fn call_context_remaining_after_deadline() {
    let now = Instant::now();
    let ctx = CallContext::with_deadline(
        now.checked_sub(Duration::from_millis(1))
            .expect("instant subtraction should succeed"),
    );
    assert_eq!(ctx.remaining_at(now), None);
}

#[test]
fn call_context_remaining_no_deadline() {
    let ctx = CallContext::new();
    assert!(ctx.remaining().is_none());
}

#[test]
fn call_context_is_expired_with_past_deadline() {
    let now = Instant::now();
    let ctx = CallContext::with_deadline(
        now.checked_sub(Duration::from_millis(1))
            .expect("instant subtraction should succeed"),
    );
    assert!(ctx.is_expired_at(now));
}

#[test]
fn call_context_is_expired_with_future_deadline() {
    let now = Instant::now();
    let ctx = CallContext::with_deadline(now + Duration::from_secs(10));
    assert!(!ctx.is_expired_at(now));
}

// ===========================================================================
// 3. ServerConfig default_timeout
// ===========================================================================

#[test]
fn server_config_default_timeout_is_none() {
    let config = ServerConfig::default();
    assert!(config.default_timeout.is_none());
}

#[test]
fn server_builder_default_timeout() {
    let server = Server::builder()
        .default_timeout(Duration::from_secs(30))
        .add_service(GreeterService)
        .build();
    assert_eq!(
        server.config().default_timeout,
        Some(Duration::from_secs(30))
    );
}

// ===========================================================================
// 4. Health Watch (HealthWatcher)
// ===========================================================================

#[test]
fn health_watcher_detects_status_change() {
    let health = HealthService::new();
    health.set_status("svc", ServingStatus::Serving);
    let mut watcher = health.watch("svc");

    // No change yet since construction
    assert!(!watcher.changed());
    assert_eq!(watcher.status(), ServingStatus::Serving);

    // Trigger a change
    health.set_status("svc", ServingStatus::NotServing);
    assert!(watcher.changed());
    assert_eq!(watcher.status(), ServingStatus::NotServing);

    // No further change
    assert!(!watcher.changed());
}

#[test]
fn health_watcher_detects_clear() {
    let health = HealthService::new();
    health.set_status("svc", ServingStatus::Serving);
    let mut watcher = health.watch("svc");

    health.clear_status("svc");
    assert!(watcher.changed());
    assert_eq!(watcher.status(), ServingStatus::ServiceUnknown);
}

#[test]
fn health_watcher_detects_clear_all() {
    let health = HealthService::new();
    health.set_status("a", ServingStatus::Serving);
    health.set_status("b", ServingStatus::Serving);
    let mut watcher = health.watch("a");

    health.clear();
    assert!(watcher.changed());
    assert_eq!(watcher.status(), ServingStatus::ServiceUnknown);
}

#[test]
fn health_watcher_poll_status() {
    let health = HealthService::new();
    let mut watcher = health.watch("svc");

    let (changed, status) = watcher.poll_status();
    assert!(!changed);
    assert_eq!(status, ServingStatus::ServiceUnknown);

    health.set_status("svc", ServingStatus::Serving);
    let (changed, status) = watcher.poll_status();
    assert!(changed);
    assert_eq!(status, ServingStatus::Serving);
}

#[test]
fn health_version_monotonically_increases() {
    let health = HealthService::new();
    let v0 = health.version();
    health.set_status("a", ServingStatus::Serving);
    let v1 = health.version();
    health.set_status("b", ServingStatus::NotServing);
    let v2 = health.version();
    health.clear_status("a");
    let v3 = health.version();
    assert!(v1 > v0);
    assert!(v2 > v1);
    assert!(v3 > v2);
}

#[test]
fn health_watcher_multiple_watchers_independent() {
    let health = HealthService::new();
    health.set_status("a", ServingStatus::Serving);
    health.set_status("b", ServingStatus::Serving);
    let mut watcher_a = health.watch("a");
    let mut watcher_b = health.watch("b");

    health.set_status("a", ServingStatus::NotServing);

    // Only the watcher for the changed service should observe a transition.
    assert!(watcher_a.changed());
    assert!(!watcher_b.changed());

    // But status differs
    assert_eq!(watcher_a.status(), ServingStatus::NotServing);
    assert_eq!(watcher_b.status(), ServingStatus::Serving);
}

// ===========================================================================
// 5. Reflection RPC async helpers
// ===========================================================================

#[test]
fn reflection_list_services_async() {
    let reflection = ReflectionService::new();
    reflection.register_handler(&GreeterService);
    reflection.register_handler(&RouteGuideService);

    let request = Request::new(ReflectionListServicesRequest);
    let response = futures_lite::future::block_on(reflection.list_services_async(&request))
        .expect("list should succeed");
    let services = &response.get_ref().services;
    assert_eq!(services.len(), 2);
    assert!(services.contains(&"helloworld.Greeter".to_string()));
    assert!(services.contains(&"routeguide.RouteGuide".to_string()));
}

#[test]
fn reflection_describe_service_async() {
    let reflection = ReflectionService::new();
    reflection.register_handler(&GreeterService);

    let request = Request::new(ReflectionDescribeServiceRequest::new("helloworld.Greeter"));
    let response = futures_lite::future::block_on(reflection.describe_service_async(&request))
        .expect("describe should succeed");
    let svc = &response.get_ref().service;
    assert_eq!(svc.name, "helloworld.Greeter");
    assert_eq!(svc.methods.len(), 2);
    assert_eq!(svc.methods[0].name, "SayHello");
    assert!(!svc.methods[0].server_streaming);
    assert_eq!(svc.methods[1].name, "SayHelloStream");
    assert!(svc.methods[1].server_streaming);
}

#[test]
fn reflection_describe_missing_service_async() {
    let reflection = ReflectionService::new();
    let request = Request::new(ReflectionDescribeServiceRequest::new("missing.Service"));
    let result = futures_lite::future::block_on(reflection.describe_service_async(&request));
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), Code::NotFound);
}

#[test]
fn reflection_from_handlers() {
    let greeter = GreeterService;
    let guide = RouteGuideService;
    let handlers: Vec<&dyn ServiceHandler> = vec![&greeter, &guide];
    let reflection = ReflectionService::from_handlers(handlers);
    let services = reflection.list_services();
    assert_eq!(services.len(), 2);
}

#[test]
fn reflection_service_handler_traits() {
    assert_eq!(
        ReflectionService::NAME,
        "grpc.reflection.v1alpha.ServerReflection"
    );
    let svc = ReflectionService::new();
    let desc = svc.descriptor();
    assert_eq!(desc.full_name(), "grpc.reflection.v1alpha.ServerReflection");
    let methods = svc.method_names();
    assert_eq!(methods, vec!["ServerReflectionInfo"]);
    assert_eq!(
        methods,
        desc.methods
            .iter()
            .map(|method| method.name)
            .collect::<Vec<_>>()
    );
}

#[test]
fn reflection_method_streaming_flags() {
    let reflection = ReflectionService::new();
    reflection.register_handler(&RouteGuideService);
    let svc = reflection
        .describe_service("routeguide.RouteGuide")
        .expect("service should exist");

    // GetFeature = unary
    let get_feature = svc.methods.iter().find(|m| m.name == "GetFeature").unwrap();
    assert!(!get_feature.client_streaming);
    assert!(!get_feature.server_streaming);

    // RecordRoute = client streaming
    let record = svc
        .methods
        .iter()
        .find(|m| m.name == "RecordRoute")
        .unwrap();
    assert!(record.client_streaming);
    assert!(!record.server_streaming);

    // RouteChat = bidi streaming
    let chat = svc.methods.iter().find(|m| m.name == "RouteChat").unwrap();
    assert!(chat.client_streaming);
    assert!(chat.server_streaming);
}

#[test]
fn reflection_descriptor_output_happy_path_snapshot() {
    let reflection = ReflectionService::new();
    let health = HealthService::new();
    let builtin_reflection = ReflectionService::new();
    reflection.register_handler(&health);
    reflection.register_handler(&builtin_reflection);

    assert_json_snapshot!(
        "reflection_descriptor_output_happy_path",
        reflection_registry_snapshot(&reflection)
    );
}

#[test]
fn reflection_descriptor_output_missing_service_snapshot() {
    let reflection = ReflectionService::new();
    let status = futures_lite::future::block_on(reflection.describe_service_async(&Request::new(
        ReflectionDescribeServiceRequest::new("missing.Service"),
    )))
    .expect_err("missing service should fail");

    assert_json_snapshot!(
        "reflection_descriptor_output_missing_service",
        reflection_error_snapshot(&status)
    );
}

// ===========================================================================
// 6. Interceptor chain and composition
// ===========================================================================

#[test]
fn interceptor_layer_forward_order() {
    let layer = InterceptorLayer::new()
        .layer(asupersync::grpc::trace_interceptor())
        .layer(asupersync::grpc::logging_interceptor());

    let mut request = Request::new(Bytes::new());
    layer.intercept_request(&mut request).unwrap();

    // Both interceptors should have run
    assert!(request.metadata().get("x-request-id").is_some());
    assert!(request.metadata().get("x-logged").is_some());
}

#[test]
fn interceptor_layer_response_reverse_order() {
    let layer = InterceptorLayer::new().layer(asupersync::grpc::logging_interceptor());

    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).unwrap();
    assert!(response.metadata().get("x-logged").is_some());
}

#[test]
fn timeout_interceptor_adds_header() {
    let interceptor = TimeoutInterceptor::new(5000);
    let mut request = Request::new(Bytes::new());
    interceptor.intercept_request(&mut request).unwrap();

    let value = request.metadata().get("grpc-timeout").unwrap();
    match value {
        asupersync::grpc::streaming::MetadataValue::Ascii(s) => {
            assert_eq!(s, "5S");
        }
        asupersync::grpc::streaming::MetadataValue::Binary(_) => panic!("expected ASCII value"),
    }
}

#[test]
fn timeout_interceptor_preserves_existing_header() {
    let interceptor = TimeoutInterceptor::new(5000);
    let mut request = Request::new(Bytes::new());
    request.metadata_mut().insert("grpc-timeout", "1000m");
    interceptor.intercept_request(&mut request).unwrap();

    // Should keep the original 1000m, not override with the configured timeout.
    let value = request.metadata().get("grpc-timeout").unwrap();
    match value {
        asupersync::grpc::streaming::MetadataValue::Ascii(s) => {
            assert_eq!(s, "1000m");
        }
        asupersync::grpc::streaming::MetadataValue::Binary(_) => panic!("expected ASCII value"),
    }
}

#[test]
fn bearer_auth_interceptor_adds_token() {
    let interceptor = BearerAuthInterceptor::new("my-token".to_string());
    let mut request = Request::new(Bytes::new());
    interceptor.intercept_request(&mut request).unwrap();

    let value = request.metadata().get("authorization").unwrap();
    match value {
        asupersync::grpc::streaming::MetadataValue::Ascii(s) => {
            assert_eq!(s, "Bearer my-token");
        }
        asupersync::grpc::streaming::MetadataValue::Binary(_) => panic!("expected ASCII value"),
    }
}

#[test]
fn bearer_auth_validator_accepts_valid_token() {
    let validator = BearerAuthValidator::new(|token: &str| token == "secret");
    let mut request = Request::new(Bytes::new());
    request
        .metadata_mut()
        .insert("authorization", "Bearer secret");
    let result = validator.intercept_request(&mut request);
    assert!(result.is_ok());
}

#[test]
fn bearer_auth_validator_rejects_invalid_token() {
    let validator = BearerAuthValidator::new(|token: &str| token == "secret");
    let mut request = Request::new(Bytes::new());
    request
        .metadata_mut()
        .insert("authorization", "Bearer wrong");
    let result = validator.intercept_request(&mut request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::Unauthenticated);
}

#[test]
fn bearer_auth_validator_rejects_missing_token() {
    let validator = BearerAuthValidator::new(|_: &str| true);
    let mut request = Request::new(Bytes::new());
    let result = validator.intercept_request(&mut request);
    assert!(result.is_err());
}

#[test]
fn rate_limit_interceptor_allows_within_limit() {
    let limiter = RateLimitInterceptor::new(10);
    for _ in 0..10 {
        let mut req = Request::new(Bytes::new());
        assert!(limiter.intercept_request(&mut req).is_ok());
    }
}

#[test]
fn rate_limit_interceptor_rejects_over_limit() {
    let limiter = RateLimitInterceptor::new(2);
    for _ in 0..2 {
        let mut req = Request::new(Bytes::new());
        limiter.intercept_request(&mut req).unwrap();
    }
    let mut req = Request::new(Bytes::new());
    let result = limiter.intercept_request(&mut req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
}

#[test]
fn fn_interceptor_custom_logic() {
    let interceptor = FnInterceptor::new(|req: &mut Request<Bytes>| {
        req.metadata_mut().insert("x-custom", "hello");
        Ok(())
    });
    let mut request = Request::new(Bytes::new());
    interceptor.intercept_request(&mut request).unwrap();
    assert!(request.metadata().get("x-custom").is_some());
}

// ===========================================================================
// 7. Compression encoding plumbing
// ===========================================================================

#[test]
fn compression_encoding_header_roundtrip() {
    assert_eq!(
        CompressionEncoding::from_header_value("identity"),
        Some(CompressionEncoding::Identity)
    );
    assert_eq!(
        CompressionEncoding::from_header_value("gzip"),
        Some(CompressionEncoding::Gzip)
    );
    assert_eq!(CompressionEncoding::from_header_value("deflate"), None);
}

#[test]
fn compression_encoding_identity_no_compressor() {
    assert!(CompressionEncoding::Identity.frame_compressor().is_none());
    assert!(CompressionEncoding::Identity.frame_decompressor().is_none());
}

#[test]
fn server_builder_compression_config() {
    let server = Server::builder()
        .send_compression(CompressionEncoding::Gzip)
        .accept_compression(CompressionEncoding::Gzip)
        .add_service(GreeterService)
        .build();

    assert_eq!(
        server.config().send_compression,
        Some(CompressionEncoding::Gzip)
    );
    assert!(
        server
            .config()
            .accept_compression
            .contains(&CompressionEncoding::Gzip)
    );
}

#[test]
fn server_builder_replace_accepted_compressions() {
    let server = Server::builder()
        .accept_compressions([CompressionEncoding::Gzip, CompressionEncoding::Identity])
        .add_service(GreeterService)
        .build();

    assert_eq!(server.config().accept_compression.len(), 2);
}

#[test]
fn channel_builder_compression_config() {
    let config = ChannelConfig {
        send_compression: Some(CompressionEncoding::Gzip),
        accept_compression: vec![CompressionEncoding::Gzip, CompressionEncoding::Identity],
        ..Default::default()
    };
    assert_eq!(config.send_compression, Some(CompressionEncoding::Gzip));
    assert_eq!(config.accept_compression.len(), 2);
}

// ===========================================================================
// 8. Server integration
// ===========================================================================

#[test]
fn server_builder_registers_multiple_services() {
    let server = Server::builder()
        .add_service(GreeterService)
        .add_service(RouteGuideService)
        .build();

    assert!(server.get_service("helloworld.Greeter").is_some());
    assert!(server.get_service("routeguide.RouteGuide").is_some());
    assert_eq!(server.service_names().len(), 2);
}

#[test]
fn server_builder_reflection_captures_all_services() {
    let server = Server::builder()
        .add_service(GreeterService)
        .enable_reflection()
        .add_service(RouteGuideService)
        .build();

    // Reflection service is registered
    assert!(
        server
            .get_service("grpc.reflection.v1alpha.ServerReflection")
            .is_some()
    );
    // All three services present
    assert_eq!(server.service_names().len(), 3);
}

#[test]
fn server_config_defaults() {
    let config = ServerConfig::default();
    assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
    assert_eq!(config.max_send_message_size, 4 * 1024 * 1024);
    assert_eq!(config.max_concurrent_streams, 100);
    assert!(config.keepalive_interval_ms.is_none());
    assert!(config.keepalive_timeout_ms.is_none());
    assert!(config.default_timeout.is_none());
    assert!(config.send_compression.is_none());
}

// ===========================================================================
// 9. Channel / client config
// ===========================================================================

#[test]
fn channel_config_defaults() {
    let config = ChannelConfig::default();
    assert_eq!(config.connect_timeout, Duration::from_secs(5));
    assert!(config.timeout.is_none());
    assert!(!config.use_tls);
    assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
}

#[test]
fn channel_builder_fluent_api() {
    // ChannelBuilder should accept all config options
    let channel = futures_lite::future::block_on(
        Channel::builder("http://loopback:50051")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .max_recv_message_size(8 * 1024 * 1024)
            .max_send_message_size(8 * 1024 * 1024)
            .keepalive_interval(Duration::from_secs(60))
            .keepalive_timeout(Duration::from_secs(20))
            .send_compression(CompressionEncoding::Gzip)
            .accept_compression(CompressionEncoding::Gzip)
            .tls()
            .connect(),
    )
    .expect("connect should succeed");

    assert_eq!(channel.uri(), "http://loopback:50051");
    assert_eq!(channel.config().timeout, Some(Duration::from_secs(30)));
    assert!(channel.config().use_tls);
    assert_eq!(
        channel.config().send_compression,
        Some(CompressionEncoding::Gzip)
    );
}

#[test]
fn channel_connect_rejects_empty_uri() {
    let result = futures_lite::future::block_on(Channel::connect(""));
    assert!(result.is_err());
}

// ===========================================================================
// 10. Health service lifecycle
// ===========================================================================

#[test]
fn health_reporter_lifecycle() {
    let health = HealthService::new();
    {
        let reporter = HealthReporter::new(health.clone(), "test.Svc");
        reporter.set_serving();
        assert_eq!(reporter.status(), ServingStatus::Serving);
        assert!(health.is_serving("test.Svc"));
    }
    // Dropped — status should be cleared
    assert!(health.get_status("test.Svc").is_none());
}

#[test]
fn health_service_builder_batch() {
    let health = HealthServiceBuilder::new()
        .add("explicit", ServingStatus::NotServing)
        .add_serving(["a", "b", "c"])
        .build();

    assert_eq!(
        health.get_status("explicit"),
        Some(ServingStatus::NotServing)
    );
    assert_eq!(health.get_status("a"), Some(ServingStatus::Serving));
    assert_eq!(health.get_status("b"), Some(ServingStatus::Serving));
    assert_eq!(health.get_status("c"), Some(ServingStatus::Serving));
}

#[test]
fn health_check_server_aggregate() {
    let health = HealthService::new();
    health.set_status("a", ServingStatus::Serving);
    health.set_status("b", ServingStatus::Serving);

    // All healthy → server overall serving
    let resp = health.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::Serving);

    // One unhealthy → server not serving
    health.set_status("b", ServingStatus::NotServing);
    let resp = health.check(&HealthCheckRequest::server()).unwrap();
    assert_eq!(resp.status, ServingStatus::NotServing);
}

#[test]
fn health_check_async_handler() {
    let health = HealthService::new();
    health.set_status("test.Service", ServingStatus::Serving);
    let request = Request::new(HealthCheckRequest::new("test.Service"));
    let response = futures_lite::future::block_on(health.check_async(&request)).unwrap();
    assert_eq!(response.get_ref().status, ServingStatus::Serving);
}

#[test]
fn health_service_named_service_constant() {
    assert_eq!(HealthService::NAME, "grpc.health.v1.Health");
}

#[test]
fn health_service_descriptor_has_check_and_watch() {
    let svc = HealthService::new();
    let desc = svc.descriptor();
    assert_eq!(desc.name, "Health");
    assert_eq!(desc.package, "grpc.health.v1");
    assert_eq!(desc.methods.len(), 2);
    assert_eq!(desc.methods[0].name, "Check");
    assert!(!desc.methods[0].server_streaming);
    assert_eq!(desc.methods[1].name, "Watch");
    assert!(desc.methods[1].server_streaming);
}
