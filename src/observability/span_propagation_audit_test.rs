//! End-to-end audit test for span context propagation across runtime boundaries.
//!
//! **CRITICAL AUDIT**: This test verifies that span_id flows correctly from
//! HTTP server → gRPC client to enable distributed trace stitching.
//!
//! **Test Coverage**:
//! - W3C traceparent extraction from HTTP requests
//! - Span context propagation to downstream gRPC calls
//! - Parent-child span relationship preservation
//! - Trace stitching across service boundaries
//!
//! **Failure Impact**: Without proper span propagation, distributed traces
//! appear as disconnected fragments, making production debugging impossible.

#![cfg(test)]

use crate::observability::w3c_trace_context::*;
use std::collections::HashMap;
use std::str::FromStr;

/// HTTP request fixture with W3C trace context headers.
struct HeaderFixtureRequest {
    headers: HashMap<String, String>,
}

impl HeaderFixtureRequest {
    fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    fn with_traceparent(mut self, traceparent: &str) -> Self {
        self.headers
            .insert("traceparent".to_string(), traceparent.to_string());
        self
    }

    fn with_tracestate(mut self, tracestate: &str) -> Self {
        self.headers
            .insert("tracestate".to_string(), tracestate.to_string());
        self
    }
}

/// gRPC request fixture with metadata.
struct GrpcMetadataFixture {
    metadata: HashMap<String, String>,
}

impl GrpcMetadataFixture {
    fn new() -> Self {
        Self {
            metadata: HashMap::new(),
        }
    }

    fn metadata_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.metadata
    }
}

/// **AUDIT TEST**: Verifies end-to-end span context propagation.
///
/// Scenario: HTTP request → Service A → gRPC call → Service B
/// Requirement: Span context MUST flow correctly for trace stitching.
#[test]
fn audit_http_to_grpc_span_context_propagation() {
    // GIVEN: HTTP request with valid W3C trace context
    let original_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let original_span_id = "00f067aa0ba902b7";
    let original_traceparent = format!("00-{}-{}-01", original_trace_id, original_span_id);

    let http_request = HeaderFixtureRequest::new()
        .with_traceparent(&original_traceparent)
        .with_tracestate("vendor1=value1,vendor2=value2");

    // WHEN: Extract trace context from HTTP request
    let extracted_context = extract_from_http(&http_request.headers)
        .expect("failed to extract trace context")
        .expect("trace context should be present");

    // THEN: Extracted context preserves trace ID and span ID
    assert_eq!(extracted_context.trace_id.to_hex(), original_trace_id);
    assert_eq!(extracted_context.span_id.to_hex(), original_span_id);
    assert!(extracted_context.flags.is_sampled());
    assert_eq!(
        extracted_context.tracestate.as_deref(),
        Some("vendor1=value1,vendor2=value2")
    );

    // WHEN: Create child span for downstream gRPC call
    let child_context = extracted_context.create_child();

    // THEN: Child preserves trace ID but creates new span ID
    assert_eq!(
        child_context.trace_id.to_hex(),
        original_trace_id,
        "child must preserve trace ID"
    );
    assert_ne!(
        child_context.span_id.to_hex(),
        original_span_id,
        "child must have new span ID"
    );
    assert_eq!(
        child_context.parent_span_id.to_hex(),
        original_span_id,
        "child's parent must be original span"
    );

    // WHEN: Inject child context into gRPC request
    let mut grpc_request = GrpcMetadataFixture::new();
    inject_to_grpc(&child_context, grpc_request.metadata_mut());

    // THEN: gRPC metadata contains correct traceparent
    let grpc_traceparent = grpc_request
        .metadata
        .get("traceparent")
        .expect("grpc request must contain traceparent");

    // Parse injected traceparent
    let injected_context =
        W3CTraceContext::from_str(grpc_traceparent).expect("injected traceparent must be valid");

    assert_eq!(
        injected_context.trace_id.to_hex(),
        original_trace_id,
        "gRPC call must preserve trace ID"
    );
    assert_eq!(
        injected_context.span_id, child_context.span_id,
        "gRPC call must use child span ID"
    );

    // CRITICAL: Verify trace stitching capability
    // In a real tracing system, Service B can reconstruct the call chain:
    // HTTP Request (span: original_span_id) → Service A (span: child.span_id) → Service B
    assert_ne!(
        injected_context.span_id.to_hex(),
        original_span_id,
        "spans must be unique for stitching"
    );

    println!("✅ AUDIT PASSED: Span context flows correctly from HTTP → gRPC");
    println!("   Trace ID: {} (preserved)", original_trace_id);
    println!(
        "   HTTP span: {} → gRPC span: {}",
        original_span_id,
        injected_context.span_id.to_hex()
    );
}

/// **AUDIT TEST**: Graceful handling of missing trace context.
///
/// Scenario: HTTP request without trace context → Service creates root span
/// Requirement: System MUST NOT fail on missing context.
#[test]
fn audit_graceful_handling_of_missing_trace_context() {
    // GIVEN: HTTP request without trace context headers
    let http_request = HeaderFixtureRequest::new();

    // WHEN: Attempt to extract trace context
    let extracted_context = extract_from_http(&http_request.headers)
        .expect("extraction must not fail on missing headers");

    // THEN: No context extracted (graceful degradation)
    assert!(
        extracted_context.is_none(),
        "missing context should return None"
    );

    // WHEN: Service creates new root context
    let root_context = W3CTraceContext::new_root();

    // THEN: Root context is valid for downstream propagation
    let mut grpc_request = GrpcMetadataFixture::new();
    inject_to_grpc(&root_context, grpc_request.metadata_mut());

    assert!(
        grpc_request.metadata.contains_key("traceparent"),
        "root context must propagate"
    );

    println!("✅ AUDIT PASSED: Graceful degradation on missing trace context");
}

/// **AUDIT TEST**: Security bounds prevent amplification attacks.
///
/// Scenario: Malicious HTTP request with oversized trace context
/// Requirement: System MUST reject oversized context to prevent log amplification.
#[test]
fn audit_security_bounds_prevent_amplification() {
    // GIVEN: HTTP request with maliciously large traceparent
    let malicious_traceparent = "00-".to_string() + &"a".repeat(200);
    let http_request = HeaderFixtureRequest::new().with_traceparent(&malicious_traceparent);

    // WHEN: Attempt to extract oversized context
    let result = extract_from_http(&http_request.headers);

    // THEN: Extraction fails with security error
    assert!(result.is_err(), "oversized context must be rejected");

    if let Err(TraceContextError::ValueTooLong(len)) = result {
        assert!(len > 128, "error should report actual length");
    } else {
        panic!("expected ValueTooLong error");
    }

    println!("✅ AUDIT PASSED: Security bounds prevent amplification attacks");
}

/// **AUDIT TEST**: Malformed trace context handling.
///
/// Scenario: HTTP request with invalid traceparent format
/// Requirement: System MUST handle malformed context gracefully.
#[test]
fn audit_malformed_trace_context_handling() {
    let test_cases = vec![
        ("invalid-format", "malformed traceparent"),
        (
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "zero trace ID",
        ),
        (
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "zero span ID",
        ),
        (
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "unsupported version",
        ),
        (
            "00-invalid-hex-chars-here-00f067aa0ba902b7-01",
            "invalid hex",
        ),
    ];

    for (invalid_traceparent, description) in test_cases {
        let http_request = HeaderFixtureRequest::new().with_traceparent(invalid_traceparent);

        let result = extract_from_http(&http_request.headers);

        assert!(
            result.is_err(),
            "malformed context must be rejected: {}",
            description
        );
        println!("✅ Rejected {}: {}", description, invalid_traceparent);
    }

    println!("✅ AUDIT PASSED: Malformed trace contexts handled gracefully");
}

/// **INTEGRATION TEST**: Full HTTP → gRPC → HTTP round trip.
///
/// Exercises: Client → API Gateway → Service A → Service B → Response
/// Verifies: Complete trace chain with proper parent-child relationships.
#[test]
fn integration_test_full_trace_round_trip() {
    // STEP 1: Client request to API Gateway
    let client_trace_id = "1234567890abcdef1234567890abcdef";
    let client_span_id = "abcdef1234567890";
    let client_traceparent = format!("00-{}-{}-01", client_trace_id, client_span_id);

    // STEP 2: API Gateway extracts context
    let gateway_request = HeaderFixtureRequest::new().with_traceparent(&client_traceparent);
    let gateway_context = extract_from_http(&gateway_request.headers)
        .unwrap()
        .unwrap();

    // STEP 3: API Gateway → Service A (gRPC call)
    let service_a_context = gateway_context.create_child();
    let mut service_a_request = GrpcMetadataFixture::new();
    inject_to_grpc(&service_a_context, service_a_request.metadata_mut());

    // STEP 4: Service A → Service B (another gRPC call)
    let service_a_extracted = extract_from_http(&service_a_request.metadata)
        .unwrap()
        .unwrap();
    let service_b_context = service_a_extracted.create_child();
    let mut service_b_request = GrpcMetadataFixture::new();
    inject_to_grpc(&service_b_context, service_b_request.metadata_mut());

    // VERIFICATION: Complete trace chain
    assert_eq!(
        gateway_context.trace_id.to_hex(),
        client_trace_id,
        "trace ID preserved through gateway"
    );
    assert_eq!(
        service_a_context.trace_id.to_hex(),
        client_trace_id,
        "trace ID preserved in service A"
    );
    assert_eq!(
        service_b_context.trace_id.to_hex(),
        client_trace_id,
        "trace ID preserved in service B"
    );

    // Parent-child relationships
    assert_eq!(
        service_a_context.parent_span_id, gateway_context.span_id,
        "service A parent is gateway span"
    );
    assert_eq!(
        service_b_context.parent_span_id, service_a_context.span_id,
        "service B parent is service A span"
    );

    println!("✅ INTEGRATION PASSED: Full trace chain preserved");
    println!("   Client → Gateway → Service A → Service B");
    println!("   Trace: {}", client_trace_id);
    println!(
        "   Spans: {} → {} → {} → {}",
        client_span_id,
        gateway_context.span_id.to_hex(),
        service_a_context.span_id.to_hex(),
        service_b_context.span_id.to_hex()
    );
}
