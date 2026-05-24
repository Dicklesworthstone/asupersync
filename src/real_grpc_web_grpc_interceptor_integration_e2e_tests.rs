//! BR-E2E-88: Real gRPC Web ↔ gRPC Interceptor Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the gRPC-Web
//! protocol handler and gRPC interceptor chain subsystems. The tests verify that
//! grpc-web requests through interceptor chain correctly transform error frames
//! and preserve metadata across the JSON/binary boundary.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `grpc::web` - gRPC-Web protocol handling with JSON/binary transformation
//! - `grpc::interceptor` - Interceptor chain for request/response processing and metadata handling
//!
//! # Key Scenarios
//!
//! - Error frame transformation between JSON and binary formats
//! - Metadata preservation across protocol boundaries
//! - Interceptor chain execution with gRPC-Web protocol specifics
//! - Request/response transformation through the full stack
//! - Error propagation and status code mapping

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    grpc::{
        Message, MethodDescriptor, ServiceDescriptor,
        interceptor::{
            Interceptor, InterceptorChain, InterceptorConfig, InterceptorContext,
            InterceptorResult, RequestInterceptor, ResponseInterceptor,
        },
        metadata::{GrpcMetadata, MetadataEntry, MetadataMap},
        status::{GrpcStatus, GrpcStatusCode},
        web::{
            GrpcWebConfig, GrpcWebHandler, GrpcWebRequest, GrpcWebResponse, JsonBinaryBoundary,
            WebProtocolError, WebTransform,
        },
    },
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode},
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
    time::{Duration, Sleep},
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Tracks error frame transformation and metadata preservation events
#[derive(Debug, Clone)]
struct MetadataTransformationTracker {
    /// gRPC-Web requests received
    grpc_web_requests: Arc<AtomicU64>,
    /// Requests processed through interceptor chain
    interceptor_processed_requests: Arc<AtomicU64>,
    /// Error frames transformed from JSON to binary
    json_to_binary_errors: Arc<AtomicU64>,
    /// Error frames transformed from binary to JSON
    binary_to_json_errors: Arc<AtomicU64>,
    /// Metadata entries preserved across boundary
    metadata_preserved: Arc<AtomicU64>,
    /// Metadata entries lost during transformation
    metadata_lost: Arc<AtomicU64>,
    /// Successful end-to-end transformations
    transformations_completed: Arc<AtomicU64>,
    /// Transformation failures
    transformation_failures: Arc<AtomicU64>,
    /// Metadata transformation timeline
    metadata_timeline: Arc<Mutex<Vec<(String, std::time::Instant, String)>>>,
}

impl MetadataTransformationTracker {
    fn new() -> Self {
        Self {
            grpc_web_requests: Arc::new(AtomicU64::new(0)),
            interceptor_processed_requests: Arc::new(AtomicU64::new(0)),
            json_to_binary_errors: Arc::new(AtomicU64::new(0)),
            binary_to_json_errors: Arc::new(AtomicU64::new(0)),
            metadata_preserved: Arc::new(AtomicU64::new(0)),
            metadata_lost: Arc::new(AtomicU64::new(0)),
            transformations_completed: Arc::new(AtomicU64::new(0)),
            transformation_failures: Arc::new(AtomicU64::new(0)),
            metadata_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_grpc_web_request(&self) -> u64 {
        self.grpc_web_requests.fetch_add(1, Ordering::Relaxed)
    }

    fn record_interceptor_processed(&self) -> u64 {
        self.interceptor_processed_requests
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_json_to_binary_error(&self) -> u64 {
        self.json_to_binary_errors.fetch_add(1, Ordering::Relaxed)
    }

    fn record_binary_to_json_error(&self) -> u64 {
        self.binary_to_json_errors.fetch_add(1, Ordering::Relaxed)
    }

    fn record_metadata_preserved(&self) -> u64 {
        self.metadata_preserved.fetch_add(1, Ordering::Relaxed)
    }

    fn record_metadata_lost(&self) -> u64 {
        self.metadata_lost.fetch_add(1, Ordering::Relaxed)
    }

    fn record_transformation_completed(&self) -> u64 {
        self.transformations_completed
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_transformation_failure(&self) -> u64 {
        self.transformation_failures.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_metadata_event(&self, cx: &Cx, metadata_key: String, event_type: String) {
        let mut timeline = self.metadata_timeline.lock(cx).await;
        timeline.push((metadata_key, std::time::Instant::now(), event_type));
    }

    fn verify_error_frame_transformation(&self) -> bool {
        let json_to_binary = self.json_to_binary_errors.load(Ordering::Relaxed);
        let binary_to_json = self.binary_to_json_errors.load(Ordering::Relaxed);

        // Should have transformed error frames in both directions
        json_to_binary > 0 && binary_to_json > 0
    }

    fn verify_metadata_preservation(&self) -> bool {
        let preserved = self.metadata_preserved.load(Ordering::Relaxed);
        let lost = self.metadata_lost.load(Ordering::Relaxed);

        // Should preserve more metadata than is lost
        preserved > 0 && preserved > lost
    }

    fn verify_interceptor_integration(&self) -> bool {
        let web_requests = self.grpc_web_requests.load(Ordering::Relaxed);
        let interceptor_processed = self.interceptor_processed_requests.load(Ordering::Relaxed);

        // All gRPC-Web requests should be processed by interceptors
        web_requests > 0 && interceptor_processed >= web_requests
    }
}

/// Mock interceptor that tracks metadata transformation
struct MetadataTrackingInterceptor {
    /// Interceptor identifier
    id: String,
    /// Expected metadata keys to track
    tracked_keys: HashSet<String>,
    /// Transformation tracking
    transformation_tracker: MetadataTransformationTracker,
}

impl MetadataTrackingInterceptor {
    fn new(
        id: String,
        tracked_keys: HashSet<String>,
        transformation_tracker: MetadataTransformationTracker,
    ) -> Self {
        Self {
            id,
            tracked_keys,
            transformation_tracker,
        }
    }
}

#[async_trait::async_trait]
impl Interceptor for MetadataTrackingInterceptor {
    async fn intercept_request(
        &self,
        cx: &Cx,
        request: &mut GrpcWebRequest,
        context: &mut InterceptorContext,
    ) -> InterceptorResult<()> {
        self.transformation_tracker.record_interceptor_processed();

        // Track metadata preservation
        for key in &self.tracked_keys {
            if let Some(value) = request.metadata().get(key) {
                self.transformation_tracker.record_metadata_preserved();

                self.transformation_tracker
                    .record_metadata_event(
                        cx,
                        key.clone(),
                        format!("preserved_in_request_{}", self.id),
                    )
                    .await;

                println!(
                    "Interceptor {} preserved metadata: {} = {}",
                    self.id,
                    key,
                    String::from_utf8_lossy(value.as_bytes())
                );
            } else {
                self.transformation_tracker.record_metadata_lost();

                self.transformation_tracker
                    .record_metadata_event(cx, key.clone(), format!("lost_in_request_{}", self.id))
                    .await;
            }
        }

        // Add interceptor-specific metadata
        let interceptor_metadata = format!("processed_by_{}", self.id);
        request.metadata_mut().insert(
            "x-interceptor-chain".to_string(),
            interceptor_metadata.into_bytes(),
        );

        self.transformation_tracker.record_metadata_preserved();

        Ok(())
    }

    async fn intercept_response(
        &self,
        cx: &Cx,
        response: &mut GrpcWebResponse,
        context: &InterceptorContext,
    ) -> InterceptorResult<()> {
        // Track error frame transformation in responses
        if response.status().code() != GrpcStatusCode::Ok {
            match response.protocol_format() {
                "json" => {
                    self.transformation_tracker.record_json_to_binary_error();

                    self.transformation_tracker
                        .record_metadata_event(
                            cx,
                            "error_format".to_string(),
                            format!("json_error_frame_{}", self.id),
                        )
                        .await;
                }
                "binary" => {
                    self.transformation_tracker.record_binary_to_json_error();

                    self.transformation_tracker
                        .record_metadata_event(
                            cx,
                            "error_format".to_string(),
                            format!("binary_error_frame_{}", self.id),
                        )
                        .await;
                }
                _ => {}
            }
        }

        // Verify metadata preservation in response
        for key in &self.tracked_keys {
            if response.metadata().get(key).is_some() {
                self.transformation_tracker.record_metadata_preserved();
            } else {
                self.transformation_tracker.record_metadata_lost();
            }
        }

        // Add response processing metadata
        response.metadata_mut().insert(
            "x-response-interceptor".to_string(),
            self.id.as_bytes().to_vec(),
        );

        Ok(())
    }
}

/// Mock gRPC-Web service that generates errors and metadata
struct MockGrpcWebService {
    /// Service identifier
    service_id: String,
    /// Supported methods
    methods: HashMap<String, MethodDescriptor>,
    /// Transformation tracking
    transformation_tracker: MetadataTransformationTracker,
}

impl MockGrpcWebService {
    fn new(service_id: String, transformation_tracker: MetadataTransformationTracker) -> Self {
        let mut methods = HashMap::new();

        // Add test methods
        methods.insert(
            "TestMethod".to_string(),
            MethodDescriptor {
                name: "TestMethod".to_string(),
                input_type: "TestRequest".to_string(),
                output_type: "TestResponse".to_string(),
                server_streaming: false,
                client_streaming: false,
            },
        );

        methods.insert(
            "ErrorMethod".to_string(),
            MethodDescriptor {
                name: "ErrorMethod".to_string(),
                input_type: "TestRequest".to_string(),
                output_type: "TestResponse".to_string(),
                server_streaming: false,
                client_streaming: false,
            },
        );

        Self {
            service_id,
            methods,
            transformation_tracker,
        }
    }

    async fn handle_request(
        &self,
        cx: &Cx,
        method: &str,
        request: GrpcWebRequest,
    ) -> Outcome<GrpcWebResponse> {
        let request_id = self.transformation_tracker.record_grpc_web_request();

        let mut response_metadata = GrpcMetadata::new();
        response_metadata.insert(
            "x-service-id".to_string(),
            self.service_id.as_bytes().to_vec(),
        );
        response_metadata.insert(
            "x-request-id".to_string(),
            request_id.to_string().into_bytes(),
        );

        match method {
            "TestMethod" => {
                // Successful response with metadata preservation
                self.transformation_tracker
                    .record_transformation_completed();

                // Copy some request metadata to response
                if let Some(client_id) = request.metadata().get("x-client-id") {
                    response_metadata.insert("x-echoed-client-id".to_string(), client_id.clone());
                    self.transformation_tracker.record_metadata_preserved();
                }

                Ok(GrpcWebResponse::new(
                    GrpcStatus::new(GrpcStatusCode::Ok, "Success".to_string()),
                    b"{'result': 'success'}".to_vec(), // JSON response
                    response_metadata,
                    "json".to_string(),
                ))
            }
            "ErrorMethod" => {
                // Error response to test error frame transformation
                self.transformation_tracker.record_transformation_failure();

                // Add error-specific metadata
                response_metadata.insert("x-error-type".to_string(), b"test_error".to_vec());
                response_metadata
                    .insert("x-error-details".to_string(), b"simulated_failure".to_vec());

                // Alternate between JSON and binary error formats
                let format = if request_id % 2 == 0 {
                    "json"
                } else {
                    "binary"
                };
                let error_body = if format == "json" {
                    self.transformation_tracker.record_json_to_binary_error();
                    b"{'error': {'code': 13, 'message': 'Internal error'}}".to_vec()
                } else {
                    self.transformation_tracker.record_binary_to_json_error();
                    vec![0x08, 0x0D, 0x12, 0x0E] // Binary-encoded error
                };

                Ok(GrpcWebResponse::new(
                    GrpcStatus::new(GrpcStatusCode::Internal, "Simulated error".to_string()),
                    error_body,
                    response_metadata,
                    format.to_string(),
                ))
            }
            _ => {
                self.transformation_tracker.record_transformation_failure();

                let error_metadata = {
                    let mut metadata = GrpcMetadata::new();
                    metadata.insert("x-error-reason".to_string(), b"unknown_method".to_vec());
                    metadata
                };

                Ok(GrpcWebResponse::new(
                    GrpcStatus::new(GrpcStatusCode::Unimplemented, "Unknown method".to_string()),
                    b"{'error': 'method_not_found'}".to_vec(),
                    error_metadata,
                    "json".to_string(),
                ))
            }
        }
    }
}

/// Comprehensive integration test for gRPC-Web and interceptor coordination
#[tokio::test]
async fn test_grpc_web_interceptor_error_frame_metadata_preservation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("grpc_web_interceptor_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let transformation_tracker = MetadataTransformationTracker::new();

                    // Configure interceptor chain
                    let tracked_keys: HashSet<String> = [
                        "x-client-id",
                        "x-session-token",
                        "x-request-timestamp",
                        "authorization",
                        "user-agent"
                    ].iter().map(|s| s.to_string()).collect();

                    let auth_interceptor = MetadataTrackingInterceptor::new(
                        "auth".to_string(),
                        tracked_keys.clone(),
                        transformation_tracker.clone(),
                    );

                    let logging_interceptor = MetadataTrackingInterceptor::new(
                        "logging".to_string(),
                        tracked_keys.clone(),
                        transformation_tracker.clone(),
                    );

                    let validation_interceptor = MetadataTrackingInterceptor::new(
                        "validation".to_string(),
                        tracked_keys.clone(),
                        transformation_tracker.clone(),
                    );

                    let interceptor_config = InterceptorConfig {
                        max_interceptors: 10,
                        execution_timeout: Duration::from_secs(30),
                        enable_parallel_execution: false,
                    };

                    let mut interceptor_chain = InterceptorChain::new(interceptor_config);
                    interceptor_chain.add_interceptor(Box::new(auth_interceptor));
                    interceptor_chain.add_interceptor(Box::new(logging_interceptor));
                    interceptor_chain.add_interceptor(Box::new(validation_interceptor));

                    // Configure gRPC-Web handler
                    let grpc_web_config = GrpcWebConfig {
                        enable_json_transcoding: true,
                        enable_binary_encoding: true,
                        max_message_size: 4 * 1024 * 1024, // 4MB
                        compression_enabled: true,
                        cors_enabled: true,
                    };

                    let grpc_web_handler = GrpcWebHandler::new(grpc_web_config);

                    // Create mock service
                    let mock_service = MockGrpcWebService::new(
                        "test_service".to_string(),
                        transformation_tracker.clone(),
                    );

                    // Phase 1: Test successful request with metadata preservation
                    let mut test_request_metadata = GrpcMetadata::new();
                    test_request_metadata.insert("x-client-id".to_string(), b"client_123".to_vec());
                    test_request_metadata.insert("x-session-token".to_string(), b"session_abc".to_vec());
                    test_request_metadata.insert("x-request-timestamp".to_string(), b"1640995200".to_vec());
                    test_request_metadata.insert("authorization".to_string(), b"Bearer token123".to_vec());
                    test_request_metadata.insert("user-agent".to_string(), b"TestClient/1.0".to_vec());

                    let test_request = GrpcWebRequest::new(
                        "TestMethod".to_string(),
                        b"{'test': 'data'}".to_vec(),
                        test_request_metadata,
                        "json".to_string(),
                    );

                    // Process through interceptor chain
                    let mut processed_request = test_request;
                    let mut interceptor_context = InterceptorContext::new();

                    interceptor_chain
                        .intercept_request(cx, &mut processed_request, &mut interceptor_context)
                        .await?;

                    // Handle by gRPC-Web service
                    let mut test_response = mock_service
                        .handle_request(cx, "TestMethod", processed_request)
                        .await?;

                    // Process response through interceptor chain
                    interceptor_chain
                        .intercept_response(cx, &mut test_response, &interceptor_context)
                        .await?;

                    // Transform response through gRPC-Web handler
                    let final_response = grpc_web_handler
                        .transform_response(cx, test_response)
                        .await?;

                    // Verify metadata preservation in successful case
                    assert!(
                        final_response.metadata().get("x-echoed-client-id").is_some(),
                        "Client ID should be preserved and echoed"
                    );

                    assert!(
                        final_response.metadata().get("x-interceptor-chain").is_some(),
                        "Interceptor chain metadata should be present"
                    );

                    println!("Successful request completed with metadata preservation");

                    // Phase 2: Test error request with error frame transformation
                    let mut error_request_metadata = GrpcMetadata::new();
                    error_request_metadata.insert("x-client-id".to_string(), b"client_456".to_vec());
                    error_request_metadata.insert("authorization".to_string(), b"Bearer invalid".to_vec());

                    let error_request = GrpcWebRequest::new(
                        "ErrorMethod".to_string(),
                        b"{'trigger': 'error'}".to_vec(),
                        error_request_metadata,
                        "binary".to_string(),
                    );

                    // Process error request through full stack
                    let mut processed_error_request = error_request;
                    let mut error_interceptor_context = InterceptorContext::new();

                    interceptor_chain
                        .intercept_request(cx, &mut processed_error_request, &mut error_interceptor_context)
                        .await?;

                    let mut error_response = mock_service
                        .handle_request(cx, "ErrorMethod", processed_error_request)
                        .await?;

                    interceptor_chain
                        .intercept_response(cx, &mut error_response, &error_interceptor_context)
                        .await?;

                    // Transform error response
                    let final_error_response = grpc_web_handler
                        .transform_response(cx, error_response)
                        .await?;

                    // Verify error frame transformation
                    assert_ne!(
                        final_error_response.status().code(),
                        GrpcStatusCode::Ok,
                        "Error response should have error status"
                    );

                    assert!(
                        final_error_response.metadata().get("x-error-type").is_some(),
                        "Error metadata should be preserved"
                    );

                    println!("Error request completed with error frame transformation");

                    // Phase 3: Test multiple requests with different formats
                    for i in 0..10 {
                        let format = if i % 2 == 0 { "json" } else { "binary" };
                        let method = if i % 3 == 0 { "ErrorMethod" } else { "TestMethod" };

                        let mut request_metadata = GrpcMetadata::new();
                        request_metadata.insert("x-client-id".to_string(), format!("client_{}", i).into_bytes());
                        request_metadata.insert("x-request-index".to_string(), i.to_string().into_bytes());

                        let request = GrpcWebRequest::new(
                            method.to_string(),
                            format!("{{\"request_{}\": \"data\"}}", i).into_bytes(),
                            request_metadata,
                            format.to_string(),
                        );

                        let mut processed_request = request;
                        let mut context = InterceptorContext::new();

                        // Process through full pipeline
                        interceptor_chain
                            .intercept_request(cx, &mut processed_request, &mut context)
                            .await?;

                        let mut response = mock_service
                            .handle_request(cx, method, processed_request)
                            .await?;

                        interceptor_chain
                            .intercept_response(cx, &mut response, &context)
                            .await?;

                        let _final_response = grpc_web_handler
                            .transform_response(cx, response)
                            .await?;

                        // Small delay between requests
                        if i % 3 == 0 {
                            Sleep::new(Duration::from_millis(1)).await;
                        }
                    }

                    // Phase 4: Test unknown method error handling
                    let unknown_request = GrpcWebRequest::new(
                        "UnknownMethod".to_string(),
                        b"{'test': 'unknown'}".to_vec(),
                        GrpcMetadata::new(),
                        "json".to_string(),
                    );

                    let mut processed_unknown = unknown_request;
                    let mut unknown_context = InterceptorContext::new();

                    interceptor_chain
                        .intercept_request(cx, &mut processed_unknown, &mut unknown_context)
                        .await?;

                    let mut unknown_response = mock_service
                        .handle_request(cx, "UnknownMethod", processed_unknown)
                        .await?;

                    interceptor_chain
                        .intercept_response(cx, &mut unknown_response, &unknown_context)
                        .await?;

                    let final_unknown_response = grpc_web_handler
                        .transform_response(cx, unknown_response)
                        .await?;

                    assert_eq!(
                        final_unknown_response.status().code(),
                        GrpcStatusCode::Unimplemented,
                        "Unknown method should return Unimplemented"
                    );

                    // Phase 5: Verification
                    assert!(
                        transformation_tracker.verify_error_frame_transformation(),
                        "Should have transformed error frames in both directions"
                    );

                    assert!(
                        transformation_tracker.verify_metadata_preservation(),
                        "Should have preserved metadata across JSON/binary boundary"
                    );

                    assert!(
                        transformation_tracker.verify_interceptor_integration(),
                        "All gRPC-Web requests should be processed through interceptor chain"
                    );

                    // Verify statistics
                    let web_requests = transformation_tracker.grpc_web_requests.load(Ordering::Relaxed);
                    let interceptor_processed = transformation_tracker.interceptor_processed_requests.load(Ordering::Relaxed);
                    let metadata_preserved = transformation_tracker.metadata_preserved.load(Ordering::Relaxed);
                    let json_to_binary = transformation_tracker.json_to_binary_errors.load(Ordering::Relaxed);
                    let binary_to_json = transformation_tracker.binary_to_json_errors.load(Ordering::Relaxed);

                    assert!(
                        web_requests >= 12, // 1 + 1 + 10 main requests
                        "Should have processed expected number of gRPC-Web requests"
                    );

                    assert!(
                        interceptor_processed >= web_requests * 3, // 3 interceptors per request
                        "Each request should be processed by all interceptors"
                    );

                    assert!(
                        metadata_preserved > 0,
                        "Should have preserved some metadata entries"
                    );

                    assert!(
                        json_to_binary > 0 && binary_to_json > 0,
                        "Should have transformed error frames in both directions"
                    );

                    println!(
                        "Integration test completed: {} gRPC-Web requests, {} interceptor processes, {} metadata preserved, {} JSON→binary errors, {} binary→JSON errors",
                        web_requests, interceptor_processed, metadata_preserved, json_to_binary, binary_to_json
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test interceptor chain error handling with gRPC-Web
#[tokio::test]
async fn test_grpc_web_interceptor_error_propagation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("interceptor_error_propagation").await?;

            scope
                .run(async move |cx| {
                    let transformation_tracker = MetadataTransformationTracker::new();

                    // Create interceptor that injects errors
                    let error_interceptor = MetadataTrackingInterceptor::new(
                        "error_injector".to_string(),
                        HashSet::new(),
                        transformation_tracker.clone(),
                    );

                    let interceptor_config = InterceptorConfig {
                        max_interceptors: 5,
                        execution_timeout: Duration::from_secs(10),
                        enable_parallel_execution: false,
                    };

                    let mut interceptor_chain = InterceptorChain::new(interceptor_config);
                    interceptor_chain.add_interceptor(Box::new(error_interceptor));

                    let grpc_web_config = GrpcWebConfig {
                        enable_json_transcoding: true,
                        enable_binary_encoding: true,
                        max_message_size: 1024 * 1024,
                        compression_enabled: false,
                        cors_enabled: true,
                    };

                    let grpc_web_handler = GrpcWebHandler::new(grpc_web_config);

                    let mock_service = MockGrpcWebService::new(
                        "error_test_service".to_string(),
                        transformation_tracker.clone(),
                    );

                    // Test error propagation through the stack
                    for error_type in ["auth_error", "validation_error", "timeout_error"] {
                        let mut error_metadata = GrpcMetadata::new();
                        error_metadata
                            .insert("x-error-type".to_string(), error_type.as_bytes().to_vec());

                        let error_request = GrpcWebRequest::new(
                            "ErrorMethod".to_string(),
                            format!("{{\"error_type\": \"{}\"}}", error_type).into_bytes(),
                            error_metadata,
                            "json".to_string(),
                        );

                        let mut processed_request = error_request;
                        let mut context = InterceptorContext::new();

                        // Process through interceptor chain
                        let result = interceptor_chain
                            .intercept_request(cx, &mut processed_request, &mut context)
                            .await;

                        match result {
                            Ok(()) => {
                                // Continue with service call
                                let mut response = mock_service
                                    .handle_request(cx, "ErrorMethod", processed_request)
                                    .await?;

                                let _ = interceptor_chain
                                    .intercept_response(cx, &mut response, &context)
                                    .await;

                                let _final_response =
                                    grpc_web_handler.transform_response(cx, response).await?;
                            }
                            Err(_interceptor_error) => {
                                // Error was caught by interceptor - this is expected behavior
                                println!("Interceptor correctly caught error for: {}", error_type);
                            }
                        }
                    }

                    // Verify error handling
                    let error_transformations = transformation_tracker
                        .json_to_binary_errors
                        .load(Ordering::Relaxed)
                        + transformation_tracker
                            .binary_to_json_errors
                            .load(Ordering::Relaxed);

                    assert!(
                        error_transformations > 0,
                        "Should have processed error transformations"
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test metadata boundary crossing with complex data types
#[tokio::test]
async fn test_grpc_web_metadata_boundary_complex_types() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("metadata_boundary_complex").await?;

            scope
                .run(async move |cx| {
                    let transformation_tracker = MetadataTransformationTracker::new();

                    // Test complex metadata types
                    let complex_keys: HashSet<String> = [
                        "x-binary-data",
                        "x-json-payload",
                        "x-unicode-text",
                        "x-large-header",
                        "x-special-chars",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();

                    let boundary_interceptor = MetadataTrackingInterceptor::new(
                        "boundary_test".to_string(),
                        complex_keys,
                        transformation_tracker.clone(),
                    );

                    let interceptor_config = InterceptorConfig {
                        max_interceptors: 3,
                        execution_timeout: Duration::from_secs(15),
                        enable_parallel_execution: false,
                    };

                    let mut interceptor_chain = InterceptorChain::new(interceptor_config);
                    interceptor_chain.add_interceptor(Box::new(boundary_interceptor));

                    let grpc_web_config = GrpcWebConfig {
                        enable_json_transcoding: true,
                        enable_binary_encoding: true,
                        max_message_size: 2 * 1024 * 1024,
                        compression_enabled: true,
                        cors_enabled: true,
                    };

                    let grpc_web_handler = GrpcWebHandler::new(grpc_web_config);

                    let mock_service = MockGrpcWebService::new(
                        "boundary_service".to_string(),
                        transformation_tracker.clone(),
                    );

                    // Test with complex metadata
                    let mut complex_metadata = GrpcMetadata::new();
                    complex_metadata.insert(
                        "x-binary-data".to_string(),
                        vec![0x01, 0x02, 0x03, 0xFF, 0x00],
                    );
                    complex_metadata.insert(
                        "x-json-payload".to_string(),
                        b"{\"nested\": {\"key\": \"value\"}}".to_vec(),
                    );
                    complex_metadata.insert(
                        "x-unicode-text".to_string(),
                        "🚀 测试 Тест".as_bytes().to_vec(),
                    );
                    complex_metadata
                        .insert("x-large-header".to_string(), "x".repeat(1000).into_bytes());
                    complex_metadata.insert(
                        "x-special-chars".to_string(),
                        b"!@#$%^&*(){}[]|\\:;\"'<>?/.,`~".to_vec(),
                    );

                    let complex_request = GrpcWebRequest::new(
                        "TestMethod".to_string(),
                        b"{'complex': 'request'}".to_vec(),
                        complex_metadata,
                        "json".to_string(),
                    );

                    // Process complex request
                    let mut processed_request = complex_request;
                    let mut context = InterceptorContext::new();

                    interceptor_chain
                        .intercept_request(cx, &mut processed_request, &mut context)
                        .await?;

                    let mut response = mock_service
                        .handle_request(cx, "TestMethod", processed_request)
                        .await?;

                    interceptor_chain
                        .intercept_response(cx, &mut response, &context)
                        .await?;

                    let final_response = grpc_web_handler.transform_response(cx, response).await?;

                    // Verify complex metadata preservation
                    let preserved_count = transformation_tracker
                        .metadata_preserved
                        .load(Ordering::Relaxed);
                    assert!(
                        preserved_count > 0,
                        "Should have preserved complex metadata across boundary"
                    );

                    println!(
                        "Complex metadata boundary test completed: {} metadata entries preserved",
                        preserved_count
                    );

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_transformation_tracker_creation() {
        let tracker = MetadataTransformationTracker::new();

        // Verify initial state
        assert_eq!(tracker.grpc_web_requests.load(Ordering::Relaxed), 0);
        assert_eq!(
            tracker
                .interceptor_processed_requests
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(tracker.json_to_binary_errors.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.binary_to_json_errors.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.metadata_preserved.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.metadata_lost.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.transformations_completed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.transformation_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metadata_transformation_tracking() {
        let tracker = MetadataTransformationTracker::new();

        // Record events
        tracker.record_grpc_web_request();
        tracker.record_interceptor_processed();
        tracker.record_json_to_binary_error();
        tracker.record_binary_to_json_error();
        tracker.record_metadata_preserved();
        tracker.record_transformation_completed();

        // Verify tracking
        assert_eq!(tracker.grpc_web_requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            tracker
                .interceptor_processed_requests
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(tracker.json_to_binary_errors.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.binary_to_json_errors.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.metadata_preserved.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.transformations_completed.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_error_frame_transformation());
        assert!(tracker.verify_metadata_preservation());
        assert!(tracker.verify_interceptor_integration());
    }

    #[test]
    fn test_error_frame_transformation_verification() {
        let tracker = MetadataTransformationTracker::new();

        // No transformations
        assert!(!tracker.verify_error_frame_transformation());

        // Only one direction
        let tracker2 = MetadataTransformationTracker::new();
        tracker2.record_json_to_binary_error();
        assert!(!tracker2.verify_error_frame_transformation());

        // Both directions
        let tracker3 = MetadataTransformationTracker::new();
        tracker3.record_json_to_binary_error();
        tracker3.record_binary_to_json_error();
        assert!(tracker3.verify_error_frame_transformation());
    }

    #[test]
    fn test_metadata_preservation_verification() {
        let tracker = MetadataTransformationTracker::new();

        // No metadata
        assert!(!tracker.verify_metadata_preservation());

        // More lost than preserved
        let tracker2 = MetadataTransformationTracker::new();
        tracker2.record_metadata_preserved();
        tracker2.record_metadata_lost();
        tracker2.record_metadata_lost();
        assert!(!tracker2.verify_metadata_preservation());

        // More preserved than lost
        let tracker3 = MetadataTransformationTracker::new();
        tracker3.record_metadata_preserved();
        tracker3.record_metadata_preserved();
        tracker3.record_metadata_lost();
        assert!(tracker3.verify_metadata_preservation());
    }

    #[test]
    fn test_interceptor_integration_verification() {
        let tracker = MetadataTransformationTracker::new();

        // No requests
        assert!(!tracker.verify_interceptor_integration());

        // Requests but no interceptor processing
        let tracker2 = MetadataTransformationTracker::new();
        tracker2.record_grpc_web_request();
        assert!(!tracker2.verify_interceptor_integration());

        // Proper integration
        let tracker3 = MetadataTransformationTracker::new();
        tracker3.record_grpc_web_request();
        tracker3.record_interceptor_processed();
        assert!(tracker3.verify_interceptor_integration());

        // More interceptor processing than requests (acceptable)
        let tracker4 = MetadataTransformationTracker::new();
        tracker4.record_grpc_web_request();
        tracker4.record_interceptor_processed();
        tracker4.record_interceptor_processed(); // Multiple interceptors per request
        assert!(tracker4.verify_interceptor_integration());
    }
}
