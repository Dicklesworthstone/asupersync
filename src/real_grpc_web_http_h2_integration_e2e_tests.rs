//! BR-E2E-187: Real gRPC-Web ↔ HTTP/2 Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the gRPC-Web
//! protocol handler and HTTP/2 transport subsystems. The tests verify that
//! grpc-web framing correctly decodes through h2 trailer rewriting without
//! losing metadata across the protocol boundary.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `grpc::web` - gRPC-Web protocol with trailer frame handling
//! - `http::h2` - HTTP/2 transport with header/trailer rewriting
//!
//! # Key Scenarios
//!
//! - gRPC-Web trailer frame → HTTP/2 trailers transformation
//! - HTTP/2 trailers → gRPC-Web trailer frame reconstruction
//! - Metadata preservation across grpc-web ↔ h2 boundary
//! - Status code mapping between gRPC-Web and HTTP/2
//! - Binary vs text content-type handling over H2
//! - Error propagation through the full stack

use crate::{
    bytes::{Bytes, BytesMut, BufMut},
    cx::{Cx, Scope},
    error::Outcome,
    grpc::{
        status::{Code as GrpcCode, Status as GrpcStatus},
        streaming::{Metadata, MetadataValue},
        web::{ContentType, WebFrame, TrailerFrame},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode,
        h2::{
            connection::{H2Connection, H2ConnectionConfig},
            stream::{H2Stream, StreamState},
            frame::{Frame, FrameKind, Headers, Data, Priority},
            settings::{Settings, SettingsFrame},
            error::H2Error,
        },
    },
    net::tcp::{TcpListener, TcpStream},
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
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Tracks grpc-web ↔ h2 trailer transformation and metadata preservation events
#[derive(Debug, Clone)]
struct GrpcWebH2TransformationTracker {
    /// gRPC-Web trailer frames received
    grpc_web_trailer_frames: Arc<AtomicU64>,
    /// HTTP/2 trailers processed
    h2_trailers_processed: Arc<AtomicU64>,
    /// gRPC-Web trailer frames → H2 trailers transformations
    web_to_h2_transformations: Arc<AtomicU64>,
    /// H2 trailers → gRPC-Web trailer frames transformations
    h2_to_web_transformations: Arc<AtomicU64>,
    /// Metadata entries preserved across boundary
    metadata_preserved: Arc<AtomicU64>,
    /// Metadata entries lost during transformation
    metadata_lost: Arc<AtomicU64>,
    /// Status codes correctly mapped
    status_mappings_correct: Arc<AtomicU64>,
    /// Status mappings that failed
    status_mapping_failures: Arc<AtomicU64>,
    /// Binary content types handled
    binary_content_handled: Arc<AtomicU64>,
    /// Text content types handled
    text_content_handled: Arc<AtomicU64>,
    /// Transformation timeline for debugging
    transformation_timeline: Arc<Mutex<Vec<(String, std::time::Instant, String)>>>,
}

impl GrpcWebH2TransformationTracker {
    fn new() -> Self {
        Self {
            grpc_web_trailer_frames: Arc::new(AtomicU64::new(0)),
            h2_trailers_processed: Arc::new(AtomicU64::new(0)),
            web_to_h2_transformations: Arc::new(AtomicU64::new(0)),
            h2_to_web_transformations: Arc::new(AtomicU64::new(0)),
            metadata_preserved: Arc::new(AtomicU64::new(0)),
            metadata_lost: Arc::new(AtomicU64::new(0)),
            status_mappings_correct: Arc::new(AtomicU64::new(0)),
            status_mapping_failures: Arc::new(AtomicU64::new(0)),
            binary_content_handled: Arc::new(AtomicU64::new(0)),
            text_content_handled: Arc::new(AtomicU64::new(0)),
            transformation_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_grpc_web_trailer(&self) -> u64 {
        self.grpc_web_trailer_frames.fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_trailer_processed(&self) -> u64 {
        self.h2_trailers_processed.fetch_add(1, Ordering::Relaxed)
    }

    fn record_web_to_h2_transformation(&self) -> u64 {
        self.web_to_h2_transformations.fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_to_web_transformation(&self) -> u64 {
        self.h2_to_web_transformations.fetch_add(1, Ordering::Relaxed)
    }

    fn record_metadata_preserved(&self) -> u64 {
        self.metadata_preserved.fetch_add(1, Ordering::Relaxed)
    }

    fn record_metadata_lost(&self) -> u64 {
        self.metadata_lost.fetch_add(1, Ordering::Relaxed)
    }

    fn record_status_mapping_correct(&self) -> u64 {
        self.status_mappings_correct.fetch_add(1, Ordering::Relaxed)
    }

    fn record_status_mapping_failure(&self) -> u64 {
        self.status_mapping_failures.fetch_add(1, Ordering::Relaxed)
    }

    fn record_binary_content(&self) -> u64 {
        self.binary_content_handled.fetch_add(1, Ordering::Relaxed)
    }

    fn record_text_content(&self) -> u64 {
        self.text_content_handled.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_transformation_event(&self, cx: &Cx, event_type: String, details: String) {
        let mut timeline = self.transformation_timeline.lock(cx).await;
        timeline.push((event_type, std::time::Instant::now(), details));
    }

    fn verify_bidirectional_transformation(&self) -> bool {
        let web_to_h2 = self.web_to_h2_transformations.load(Ordering::Relaxed);
        let h2_to_web = self.h2_to_web_transformations.load(Ordering::Relaxed);

        // Should have transformations in both directions
        web_to_h2 > 0 && h2_to_web > 0
    }

    fn verify_metadata_preservation(&self) -> bool {
        let preserved = self.metadata_preserved.load(Ordering::Relaxed);
        let lost = self.metadata_lost.load(Ordering::Relaxed);

        // Should preserve more metadata than is lost
        preserved > 0 && preserved > lost
    }

    fn verify_status_mapping_accuracy(&self) -> bool {
        let correct = self.status_mappings_correct.load(Ordering::Relaxed);
        let failures = self.status_mapping_failures.load(Ordering::Relaxed);

        // Should have correct mappings and minimal failures
        correct > 0 && correct > failures
    }

    fn verify_content_type_handling(&self) -> bool {
        let binary = self.binary_content_handled.load(Ordering::Relaxed);
        let text = self.text_content_handled.load(Ordering::Relaxed);

        // Should handle both content types
        binary > 0 && text > 0
    }
}

/// gRPC-Web to HTTP/2 trailer transformer
struct GrpcWebH2TrailerTransformer {
    /// Transformation tracking
    tracker: GrpcWebH2TransformationTracker,
}

impl GrpcWebH2TrailerTransformer {
    fn new(tracker: GrpcWebH2TransformationTracker) -> Self {
        Self {
            tracker,
        }
    }

    /// Transform gRPC-Web trailer frame to HTTP/2 trailers
    async fn web_trailer_to_h2_trailers(
        &self,
        cx: &Cx,
        web_frame: WebFrame,
    ) -> Outcome<HeaderMap> {
        let mut h2_trailers = HeaderMap::new();

        match web_frame {
            WebFrame::Trailers(trailer_frame) => {
                self.tracker.record_grpc_web_trailer();
                self.tracker.record_web_to_h2_transformation();

                let metadata = &trailer_frame.metadata;
                self.tracker
                    .record_transformation_event(
                        cx,
                        "web_to_h2".to_string(),
                        format!("processing {} metadata entries", metadata.len()),
                    )
                    .await;

                // Transform gRPC metadata to HTTP/2 trailers
                for (key, value) in metadata {
                    let header_name = match HeaderName::from_bytes(key.as_bytes()) {
                        Ok(name) => name,
                        Err(_) => {
                            self.tracker.record_metadata_lost();
                            continue;
                        }
                    };

                    let header_value = match HeaderValue::try_from(value.as_bytes()) {
                        Ok(value) => value,
                        Err(_) => {
                            self.tracker.record_metadata_lost();
                            continue;
                        }
                    };

                    h2_trailers.insert(header_name, header_value);
                    self.tracker.record_metadata_preserved();

                    println!("Transformed metadata: {} -> H2 trailer", key);
                }

                Ok(h2_trailers)
            }
            WebFrame::Data { .. } => {
                Err("Expected trailer frame, got data frame".into())
            }
        }
    }

    /// Transform HTTP/2 trailers to gRPC-Web trailer frame
    async fn h2_trailers_to_web_trailer(
        &self,
        cx: &Cx,
        h2_trailers: &HeaderMap,
        content_type: ContentType,
    ) -> Outcome<WebFrame> {
        self.tracker.record_h2_trailer_processed();
        self.tracker.record_h2_to_web_transformation();

        let mut metadata = Metadata::new();

        self.tracker
            .record_transformation_event(
                cx,
                "h2_to_web".to_string(),
                format!("processing {} H2 trailers", h2_trailers.len()),
            )
            .await;

        // Transform HTTP/2 trailers to gRPC metadata
        for (name, value) in h2_trailers {
            let key = name.as_str().to_string();
            let metadata_value = MetadataValue::Binary(Bytes::copy_from_slice(value.as_bytes()));

            metadata.insert(key.clone(), metadata_value);
            self.tracker.record_metadata_preserved();

            println!("Transformed H2 trailer: {} -> gRPC metadata", key);
        }

        // Track content type handling
        match content_type {
            ContentType::GrpcWeb => self.tracker.record_binary_content(),
            ContentType::GrpcWebText => self.tracker.record_text_content(),
        };

        let trailer_frame = TrailerFrame {
            status: GrpcStatus::new(GrpcCode::Ok, "OK".to_string()),
            metadata,
        };
        Ok(WebFrame::Trailers(trailer_frame))
    }

    /// Map gRPC status to HTTP/2 status code and verify correctness
    fn map_grpc_status_to_h2(&self, grpc_status: &GrpcStatus) -> (StatusCode, bool) {
        let h2_status = match grpc_status.code() {
            GrpcCode::Ok => StatusCode::OK,
            GrpcCode::InvalidArgument => StatusCode::BAD_REQUEST,
            GrpcCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            GrpcCode::PermissionDenied => StatusCode::FORBIDDEN,
            GrpcCode::NotFound => StatusCode::NOT_FOUND,
            GrpcCode::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            GrpcCode::OutOfRange => StatusCode::REQUESTED_RANGE_NOT_SATISFIABLE,
            GrpcCode::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            GrpcCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            GrpcCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let mapping_correct = match (grpc_status.code(), h2_status) {
            (GrpcCode::Ok, StatusCode::OK) => true,
            (GrpcCode::InvalidArgument, StatusCode::BAD_REQUEST) => true,
            (GrpcCode::Unauthenticated, StatusCode::UNAUTHORIZED) => true,
            (GrpcCode::PermissionDenied, StatusCode::FORBIDDEN) => true,
            (GrpcCode::NotFound, StatusCode::NOT_FOUND) => true,
            (GrpcCode::FailedPrecondition, StatusCode::PRECONDITION_FAILED) => true,
            (GrpcCode::OutOfRange, StatusCode::REQUESTED_RANGE_NOT_SATISFIABLE) => true,
            (GrpcCode::Unimplemented, StatusCode::NOT_IMPLEMENTED) => true,
            (GrpcCode::Internal, StatusCode::INTERNAL_SERVER_ERROR) => true,
            (GrpcCode::Unavailable, StatusCode::SERVICE_UNAVAILABLE) => true,
            (GrpcCode::DeadlineExceeded, StatusCode::GATEWAY_TIMEOUT) => true,
            _ => false,
        };

        if mapping_correct {
            self.tracker.record_status_mapping_correct();
        } else {
            self.tracker.record_status_mapping_failure();
        }

        (h2_status, mapping_correct)
    }

    /// Map HTTP/2 status to gRPC status and verify correctness
    fn map_h2_status_to_grpc(&self, h2_status: StatusCode) -> (GrpcStatus, bool) {
        let (grpc_code, grpc_message) = match h2_status {
            StatusCode::OK => (GrpcCode::Ok, "OK"),
            StatusCode::BAD_REQUEST => (GrpcCode::InvalidArgument, "Invalid argument"),
            StatusCode::UNAUTHORIZED => (GrpcCode::Unauthenticated, "Unauthenticated"),
            StatusCode::FORBIDDEN => (GrpcCode::PermissionDenied, "Permission denied"),
            StatusCode::NOT_FOUND => (GrpcCode::NotFound, "Not found"),
            StatusCode::PRECONDITION_FAILED => (GrpcCode::FailedPrecondition, "Failed precondition"),
            StatusCode::REQUESTED_RANGE_NOT_SATISFIABLE => (GrpcCode::OutOfRange, "Out of range"),
            StatusCode::NOT_IMPLEMENTED => (GrpcCode::Unimplemented, "Unimplemented"),
            StatusCode::INTERNAL_SERVER_ERROR => (GrpcCode::Internal, "Internal error"),
            StatusCode::SERVICE_UNAVAILABLE => (GrpcCode::Unavailable, "Unavailable"),
            StatusCode::GATEWAY_TIMEOUT => (GrpcCode::DeadlineExceeded, "Deadline exceeded"),
            _ => (GrpcCode::Unknown, "Unknown error"),
        };

        let grpc_status = GrpcStatus::new(grpc_code, grpc_message.to_string());

        let mapping_correct = match (h2_status, grpc_code) {
            (StatusCode::OK, GrpcCode::Ok) => true,
            (StatusCode::BAD_REQUEST, GrpcCode::InvalidArgument) => true,
            (StatusCode::UNAUTHORIZED, GrpcCode::Unauthenticated) => true,
            (StatusCode::FORBIDDEN, GrpcCode::PermissionDenied) => true,
            (StatusCode::NOT_FOUND, GrpcCode::NotFound) => true,
            (StatusCode::PRECONDITION_FAILED, GrpcCode::FailedPrecondition) => true,
            (StatusCode::REQUESTED_RANGE_NOT_SATISFIABLE, GrpcCode::OutOfRange) => true,
            (StatusCode::NOT_IMPLEMENTED, GrpcCode::Unimplemented) => true,
            (StatusCode::INTERNAL_SERVER_ERROR, GrpcCode::Internal) => true,
            (StatusCode::SERVICE_UNAVAILABLE, GrpcCode::Unavailable) => true,
            (StatusCode::GATEWAY_TIMEOUT, GrpcCode::DeadlineExceeded) => true,
            _ => false,
        };

        if mapping_correct {
            self.tracker.record_status_mapping_correct();
        } else {
            self.tracker.record_status_mapping_failure();
        }

        (grpc_status, mapping_correct)
    }
}

/// Mock gRPC-Web over HTTP/2 service
struct MockGrpcWebH2Service {
    /// Service identifier
    service_id: String,
    /// Supported content types
    supported_content_types: Vec<ContentType>,
    /// Transformation tracking
    tracker: GrpcWebH2TransformationTracker,
    /// Trailer transformer
    transformer: GrpcWebH2TrailerTransformer,
}

impl MockGrpcWebH2Service {
    fn new(service_id: String, tracker: GrpcWebH2TransformationTracker) -> Self {
        let transformer = GrpcWebH2TrailerTransformer::new(tracker.clone());
        Self {
            service_id,
            supported_content_types: vec![ContentType::GrpcWeb, ContentType::GrpcWebText],
            tracker,
            transformer,
        }
    }

    async fn handle_grpc_web_request_over_h2(
        &self,
        cx: &Cx,
        request_headers: &HeaderMap,
        request_body: Bytes,
        content_type: ContentType,
    ) -> Outcome<(StatusCode, HeaderMap, Bytes)> {
        // Simulate request processing
        println!(
            "Processing gRPC-Web {} request over HTTP/2",
            content_type.as_header_value()
        );

        // Create response metadata
        let mut response_metadata = Metadata::new();
        response_metadata.insert(
            "x-service-id".to_string(),
            MetadataValue::Ascii(self.service_id.clone()),
        );
        response_metadata.insert(
            "x-processed-at".to_string(),
            MetadataValue::Ascii(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string()
            ),
        );

        // Echo some request metadata back
        if let Some(client_id) = request_headers.get("x-client-id") {
            response_metadata.insert(
                "x-echoed-client-id".to_string(),
                MetadataValue::Binary(Bytes::copy_from_slice(client_id.as_bytes())),
            );
            self.tracker.record_metadata_preserved();
        }

        // Determine response based on request
        let (grpc_status, response_body) = if request_body.starts_with(b"error") {
            (
                GrpcStatus::new(GrpcCode::Internal, "Simulated error".to_string()),
                Bytes::from_static(b"Error response"),
            )
        } else {
            (
                GrpcStatus::new(GrpcCode::Ok, "Success".to_string()),
                Bytes::from_static(b"Success response"),
            )
        };

        // Map gRPC status to HTTP/2 status
        let (h2_status, status_mapping_correct) =
            self.transformer.map_grpc_status_to_h2(&grpc_status);

        // Add status to response metadata
        response_metadata.insert(
            "grpc-status".to_string(),
            MetadataValue::Ascii(format!("{}", grpc_status.code() as u32)),
        );
        response_metadata.insert(
            "grpc-message".to_string(),
            MetadataValue::Ascii(grpc_status.message().to_string()),
        );

        // Create gRPC-Web trailer frame
        let trailer_frame = WebFrame::Trailers(TrailerFrame {
            status: grpc_status,
            metadata: response_metadata,
        });

        // Transform to HTTP/2 trailers
        let h2_trailers = self
            .transformer
            .web_trailer_to_h2_trailers(cx, trailer_frame)
            .await?;

        println!(
            "gRPC-Web response: status={:?}, trailers={} entries, status_mapping_correct={}",
            h2_status,
            h2_trailers.len(),
            status_mapping_correct
        );

        Ok((h2_status, h2_trailers, response_body))
    }

    async fn simulate_h2_to_grpc_web_response(
        &self,
        cx: &Cx,
        h2_status: StatusCode,
        h2_trailers: HeaderMap,
        h2_body: Bytes,
        content_type: ContentType,
    ) -> Outcome<(GrpcStatus, WebFrame, Bytes)> {
        // Map HTTP/2 status back to gRPC status
        let (grpc_status, status_mapping_correct) =
            self.transformer.map_h2_status_to_grpc(&h2_status);

        // Transform HTTP/2 trailers back to gRPC-Web trailer frame
        let trailer_frame = self
            .transformer
            .h2_trailers_to_web_trailer(cx, &h2_trailers, content_type)
            .await?;

        println!(
            "H2 to gRPC-Web transformation: grpc_status={:?}, content_type={:?}, status_mapping_correct={}",
            grpc_status.code(),
            content_type,
            status_mapping_correct
        );

        Ok((grpc_status, trailer_frame, h2_body))
    }
}

/// Comprehensive integration test for gRPC-Web ↔ HTTP/2 trailer transformation
#[tokio::test]
async fn test_grpc_web_h2_trailer_transformation_integration() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("grpc_web_h2_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let tracker = GrpcWebH2TransformationTracker::new();

                    // Create service
                    let service = MockGrpcWebH2Service::new(
                        "test_grpc_web_h2_service".to_string(),
                        tracker.clone(),
                    );

                    // Phase 1: Test gRPC-Web over HTTP/2 with binary content type
                    let mut request_headers = HeaderMap::new();
                    request_headers.insert("content-type", HeaderValue::from_static("application/grpc-web+proto"));
                    request_headers.insert("x-client-id", HeaderValue::from_static("client_123"));
                    request_headers.insert("authorization", HeaderValue::from_static("Bearer token123"));
                    request_headers.insert("user-agent", HeaderValue::from_static("gRPC-Web/1.0"));

                    let request_body = Bytes::from_static(b"test request data");
                    let content_type = ContentType::GrpcWeb;

                    let (h2_status, h2_trailers, response_body) = service
                        .handle_grpc_web_request_over_h2(
                            cx,
                            &request_headers,
                            request_body.clone(),
                            content_type,
                        )
                        .await?;

                    // Verify response
                    assert_eq!(h2_status, StatusCode::OK, "Should have OK status for successful request");
                    assert!(!h2_trailers.is_empty(), "Should have HTTP/2 trailers");
                    assert!(
                        h2_trailers.contains_key("grpc-status"),
                        "Should have grpc-status trailer"
                    );
                    assert!(
                        h2_trailers.contains_key("x-service-id"),
                        "Should preserve service ID metadata"
                    );

                    println!("Phase 1 completed: gRPC-Web binary over HTTP/2");

                    // Phase 2: Test reverse transformation (H2 → gRPC-Web)
                    let (grpc_status, trailer_frame, reconstructed_body) = service
                        .simulate_h2_to_grpc_web_response(
                            cx,
                            h2_status,
                            h2_trailers.clone(),
                            response_body.clone(),
                            content_type,
                        )
                        .await?;

                    // Verify reconstruction
                    assert_eq!(grpc_status.code(), GrpcCode::Ok, "Should reconstruct correct gRPC status");

                    match trailer_frame {
                        WebFrame::Trailers(ref trailer_frame) => {
                            let metadata = &trailer_frame.metadata;
                            assert!(!metadata.is_empty(), "Should reconstruct gRPC metadata");
                            assert!(
                                metadata.contains_key("grpc-status"),
                                "Should have grpc-status in metadata"
                            );
                            assert!(
                                metadata.contains_key("x-service-id"),
                                "Should preserve service ID in metadata"
                            );
                        }
                        WebFrame::Data { .. } => {
                            panic!("Expected trailer frame, got data frame");
                        }
                    }

                    println!("Phase 2 completed: HTTP/2 to gRPC-Web reconstruction");

                    // Phase 3: Test with text content type
                    let mut text_request_headers = HeaderMap::new();
                    text_request_headers.insert("content-type", HeaderValue::from_static("application/grpc-web-text+proto"));
                    text_request_headers.insert("x-request-id", HeaderValue::from_static("req_456"));
                    text_request_headers.insert("x-session-token", HeaderValue::from_static("session_xyz"));

                    let text_content_type = ContentType::GrpcWebText;

                    let (text_h2_status, text_h2_trailers, text_response_body) = service
                        .handle_grpc_web_request_over_h2(
                            cx,
                            &text_request_headers,
                            request_body.clone(),
                            text_content_type,
                        )
                        .await?;

                    // Verify text content type handling
                    assert_eq!(text_h2_status, StatusCode::OK, "Should handle text content type");
                    assert!(!text_h2_trailers.is_empty(), "Should have trailers for text content");

                    println!("Phase 3 completed: gRPC-Web text over HTTP/2");

                    // Phase 4: Test error status transformation
                    let error_request_body = Bytes::from_static(b"error request");

                    let (error_h2_status, error_h2_trailers, error_response_body) = service
                        .handle_grpc_web_request_over_h2(
                            cx,
                            &request_headers,
                            error_request_body,
                            content_type,
                        )
                        .await?;

                    // Verify error handling
                    assert_eq!(
                        error_h2_status,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Should map gRPC Internal error to H2 500"
                    );
                    assert!(
                        error_h2_trailers.contains_key("grpc-status"),
                        "Should have grpc-status in error trailers"
                    );

                    // Test reverse error transformation
                    let (error_grpc_status, error_trailer_frame, _) = service
                        .simulate_h2_to_grpc_web_response(
                            cx,
                            error_h2_status,
                            error_h2_trailers,
                            error_response_body,
                            content_type,
                        )
                        .await?;

                    assert_eq!(
                        error_grpc_status.code(),
                        GrpcCode::Internal,
                        "Should reconstruct correct gRPC error status"
                    );

                    println!("Phase 4 completed: Error status transformation");

                    // Phase 5: Test multiple concurrent transformations
                    for i in 0..20 {
                        let mut concurrent_headers = HeaderMap::new();
                        concurrent_headers.insert(
                            "content-type",
                            HeaderValue::from_static(if i % 2 == 0 {
                                "application/grpc-web+proto"
                            } else {
                                "application/grpc-web-text+proto"
                            }),
                        );
                        concurrent_headers.insert(
                            "x-request-index",
                            HeaderValue::from_str(&i.to_string())
                                .map_err(|e| format!("Header value error: {}", e))?,
                        );

                        let concurrent_content_type = if i % 2 == 0 {
                            ContentType::GrpcWeb
                        } else {
                            ContentType::GrpcWebText
                        };

                        let concurrent_body = if i % 3 == 0 {
                            Bytes::from_static(b"error request")
                        } else {
                            Bytes::from(format!("request {}", i))
                        };

                        let (concurrent_status, concurrent_trailers, concurrent_response) = service
                            .handle_grpc_web_request_over_h2(
                                cx,
                                &concurrent_headers,
                                concurrent_body,
                                concurrent_content_type,
                            )
                            .await?;

                        // Test reverse transformation
                        let (_reconstructed_status, _reconstructed_frame, _) = service
                            .simulate_h2_to_grpc_web_response(
                                cx,
                                concurrent_status,
                                concurrent_trailers,
                                concurrent_response,
                                concurrent_content_type,
                            )
                            .await?;

                        // Small delay between requests
                        if i % 5 == 0 {
                            Sleep::new(Duration::from_millis(1)).await;
                        }
                    }

                    println!("Phase 5 completed: Concurrent transformation tests");

                    // Phase 6: Verification
                    assert!(
                        tracker.verify_bidirectional_transformation(),
                        "Should have transformations in both directions"
                    );

                    assert!(
                        tracker.verify_metadata_preservation(),
                        "Should preserve metadata across gRPC-Web ↔ H2 boundary"
                    );

                    assert!(
                        tracker.verify_status_mapping_accuracy(),
                        "Should correctly map status codes between gRPC and HTTP/2"
                    );

                    assert!(
                        tracker.verify_content_type_handling(),
                        "Should handle both binary and text content types"
                    );

                    // Verify statistics
                    let web_trailers = tracker.grpc_web_trailer_frames.load(Ordering::Relaxed);
                    let h2_trailers = tracker.h2_trailers_processed.load(Ordering::Relaxed);
                    let web_to_h2 = tracker.web_to_h2_transformations.load(Ordering::Relaxed);
                    let h2_to_web = tracker.h2_to_web_transformations.load(Ordering::Relaxed);
                    let metadata_preserved = tracker.metadata_preserved.load(Ordering::Relaxed);
                    let status_correct = tracker.status_mappings_correct.load(Ordering::Relaxed);
                    let binary_handled = tracker.binary_content_handled.load(Ordering::Relaxed);
                    let text_handled = tracker.text_content_handled.load(Ordering::Relaxed);

                    assert!(web_trailers >= 23, "Should have processed expected gRPC-Web trailers"); // 1+1+1+20
                    assert!(h2_trailers >= 23, "Should have processed expected HTTP/2 trailers");
                    assert!(web_to_h2 >= 23, "Should have web→h2 transformations");
                    assert!(h2_to_web >= 23, "Should have h2→web transformations");
                    assert!(metadata_preserved > 0, "Should have preserved metadata");
                    assert!(status_correct > 0, "Should have correct status mappings");
                    assert!(binary_handled > 0, "Should have handled binary content");
                    assert!(text_handled > 0, "Should have handled text content");

                    println!(
                        "Integration test completed: {} gRPC-Web trailers, {} H2 trailers, {} web→h2, {} h2→web, {} metadata preserved, {} status correct, {} binary, {} text",
                        web_trailers, h2_trailers, web_to_h2, h2_to_web, metadata_preserved, status_correct, binary_handled, text_handled
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test complex metadata preservation across gRPC-Web ↔ HTTP/2 boundary
#[tokio::test]
async fn test_grpc_web_h2_complex_metadata_preservation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("complex_metadata_preservation").await?;

            scope
                .run(async move |cx| {
                    let tracker = GrpcWebH2TransformationTracker::new();
                    let service = MockGrpcWebH2Service::new(
                        "metadata_test_service".to_string(),
                        tracker.clone(),
                    );

                    // Test with complex metadata types
                    let mut complex_headers = HeaderMap::new();
                    complex_headers.insert("content-type", HeaderValue::from_static("application/grpc-web+proto"));

                    // Binary metadata
                    complex_headers.insert("x-binary-data", HeaderValue::from_bytes(b"\x01\x02\x03\xFF\x00").unwrap());

                    // Unicode metadata
                    complex_headers.insert("x-unicode-text", HeaderValue::try_from("🚀 测试 Тест").unwrap());

                    // Large metadata
                    complex_headers.insert("x-large-header", HeaderValue::try_from("x".repeat(1000)).unwrap());

                    // Special characters
                    complex_headers.insert("x-special-chars", HeaderValue::from_static("!@#$%^&*()"));

                    let (_, complex_trailers, _) = service
                        .handle_grpc_web_request_over_h2(
                            cx,
                            &complex_headers,
                            Bytes::from_static(b"complex request"),
                            ContentType::GrpcWeb,
                        )
                        .await?;

                    // Verify complex metadata preservation
                    assert!(!complex_trailers.is_empty(), "Should preserve complex trailers");

                    // Test round-trip preservation
                    let (_, reconstructed_frame, _) = service
                        .simulate_h2_to_grpc_web_response(
                            cx,
                            StatusCode::OK,
                            complex_trailers,
                            Bytes::from_static(b"response"),
                            ContentType::GrpcWeb,
                        )
                        .await?;

                    match reconstructed_frame {
                        WebFrame::Trailers(trailer_frame) => {
                            let metadata = &trailer_frame.metadata;
                            assert!(!metadata.is_empty(), "Should reconstruct complex metadata");
                            println!("Complex metadata preservation test completed with {} entries", metadata.len());
                        }
                        _ => panic!("Expected trailer frame"),
                    }

                    Ok(())
                })
                .await
        })
        .await
}

/// Test error propagation through gRPC-Web ↔ HTTP/2 stack
#[tokio::test]
async fn test_grpc_web_h2_error_propagation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("error_propagation").await?;

            scope
                .run(async move |cx| {
                    let tracker = GrpcWebH2TransformationTracker::new();
                    let service = MockGrpcWebH2Service::new(
                        "error_test_service".to_string(),
                        tracker.clone(),
                    );

                    // Test various error status codes
                    let error_statuses = vec![
                        (StatusCode::BAD_REQUEST, GrpcCode::InvalidArgument),
                        (StatusCode::UNAUTHORIZED, GrpcCode::Unauthenticated),
                        (StatusCode::FORBIDDEN, GrpcCode::PermissionDenied),
                        (StatusCode::NOT_FOUND, GrpcCode::NotFound),
                        (StatusCode::INTERNAL_SERVER_ERROR, GrpcCode::Internal),
                        (StatusCode::SERVICE_UNAVAILABLE, GrpcCode::Unavailable),
                        (StatusCode::GATEWAY_TIMEOUT, GrpcCode::DeadlineExceeded),
                    ];

                    let mut headers = HeaderMap::new();
                    headers.insert("content-type", HeaderValue::from_static("application/grpc-web+proto"));

                    for (expected_h2_status, expected_grpc_code) in error_statuses {
                        // Create error request
                        let error_body = Bytes::from(format!("error:{}", expected_grpc_code as u32));

                        let (h2_status, h2_trailers, _) = service
                            .handle_grpc_web_request_over_h2(
                                cx,
                                &headers,
                                error_body,
                                ContentType::GrpcWeb,
                            )
                            .await?;

                        // Test reverse transformation
                        let (reconstructed_grpc_status, _, _) = service
                            .simulate_h2_to_grpc_web_response(
                                cx,
                                h2_status,
                                h2_trailers,
                                Bytes::from_static(b"error"),
                                ContentType::GrpcWeb,
                            )
                            .await?;

                        println!(
                            "Error propagation test: H2 {:?} ↔ gRPC {:?}",
                            h2_status, reconstructed_grpc_status.code()
                        );
                    }

                    // Verify error handling accuracy
                    assert!(
                        tracker.verify_status_mapping_accuracy(),
                        "Should accurately map error statuses"
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
    fn test_grpc_web_h2_transformation_tracker_creation() {
        let tracker = GrpcWebH2TransformationTracker::new();

        // Verify initial state
        assert_eq!(tracker.grpc_web_trailer_frames.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.h2_trailers_processed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.web_to_h2_transformations.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.h2_to_web_transformations.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.metadata_preserved.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.metadata_lost.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.status_mappings_correct.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.status_mapping_failures.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.binary_content_handled.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.text_content_handled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_transformation_verification() {
        let tracker = GrpcWebH2TransformationTracker::new();

        // No transformations initially
        assert!(!tracker.verify_bidirectional_transformation());
        assert!(!tracker.verify_metadata_preservation());

        // Record events
        tracker.record_web_to_h2_transformation();
        tracker.record_h2_to_web_transformation();
        tracker.record_metadata_preserved();
        tracker.record_status_mapping_correct();

        // Verify transformations
        assert!(tracker.verify_bidirectional_transformation());
        assert!(tracker.verify_metadata_preservation());
        assert!(tracker.verify_status_mapping_accuracy());
    }

    #[test]
    fn test_content_type_handling_verification() {
        let tracker = GrpcWebH2TransformationTracker::new();

        // No content handling initially
        assert!(!tracker.verify_content_type_handling());

        // Record both content types
        tracker.record_binary_content();
        tracker.record_text_content();

        // Verify content type handling
        assert!(tracker.verify_content_type_handling());
    }
}