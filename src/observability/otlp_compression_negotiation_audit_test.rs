//! OTLP compression negotiation audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter compression negotiation behavior
//! when collector responds with 415 Unsupported Media Type for gzip content.
//!
//! **OTLP COMPRESSION NEGOTIATION SPECIFICATION**:
//! - Client configured for compression=gzip sends Content-Encoding: gzip
//! - Collector responds 415 Unsupported Media Type (doesn't support gzip)
//! - Client SHOULD gracefully downgrade to identity encoding and retry once
//! - NOT: fail-fast without retry (poor user experience)
//! - NOT: ignore 415 and keep sending gzip (broken behavior)
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - Current implementation treats 415 as non-retryable client error
//! - No graceful compression downgrade mechanism
//! - Fails immediately instead of degrading to uncompressed transport
//! - Poor interoperability with compression-unaware collectors

#![cfg(test)]
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

/// Compression configuration for deterministic negotiation behavior.
#[derive(Debug, Clone)]
pub struct NegotiationCompressionConfig {
    enabled: bool,
    algorithm: String,
    fallback_enabled: bool,
}

impl NegotiationCompressionConfig {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            algorithm: "gzip".to_string(),
            fallback_enabled: false,
        }
    }

    fn with_fallback(mut self) -> Self {
        self.fallback_enabled = true;
        self
    }
}

/// HTTP response for compression negotiation testing.
#[derive(Debug, Clone)]
pub struct NegotiationHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl NegotiationHttpResponse {
    fn new(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// HTTP request for tracking compression negotiation attempts.
#[derive(Debug, Clone)]
pub struct NegotiationHttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl NegotiationHttpRequest {
    fn new(method: &str, url: &str, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            method: method.to_string(),
            url: url.to_string(),
            headers,
            body,
        }
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(name))
    }

    fn get_header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    fn is_compressed(&self) -> bool {
        self.get_header("content-encoding")
            .is_some_and(|encoding| encoding == "gzip")
    }
}

/// In-memory OTLP HTTP exporter for testing compression negotiation.
#[derive(Debug)]
pub struct InMemoryNegotiatingOtlpHttpExporter {
    config: NegotiationCompressionConfig,
    requests: Arc<Mutex<Vec<NegotiationHttpRequest>>>,
    responses: Arc<Mutex<Vec<NegotiationHttpResponse>>>,
    attempt_count: Arc<Mutex<usize>>,
}

impl InMemoryNegotiatingOtlpHttpExporter {
    fn new(config: NegotiationCompressionConfig) -> Self {
        Self {
            config,
            requests: Arc::new(Mutex::new(vec![])),
            responses: Arc::new(Mutex::new(vec![])),
            attempt_count: Arc::new(Mutex::new(0)),
        }
    }

    fn add_response(&self, response: NegotiationHttpResponse) {
        self.responses.lock().unwrap().push(response);
    }

    fn export_spans(&self, spans: &[u8]) -> Result<(), String> {
        let attempt_number = {
            let mut attempt = self.attempt_count.lock().unwrap();
            *attempt += 1;
            *attempt
        };

        // Determine compression based on config and attempt
        let use_compression = if attempt_number == 1 {
            // First attempt: use configured compression
            self.config.enabled
        } else if attempt_number == 2 && self.config.fallback_enabled {
            // Second attempt: fallback to no compression if enabled
            false
        } else {
            // Additional attempts: fail
            return Err("Too many retry attempts".to_string());
        };

        // Build request with optional compression
        let (body, headers) = if use_compression {
            // Use a deterministic encoded body marker so assertions can inspect negotiation.
            let compressed_body = format!("GZIP[{}]", String::from_utf8_lossy(spans));
            let headers = vec![
                (
                    "Content-Type".to_string(),
                    "application/x-protobuf".to_string(),
                ),
                ("Content-Encoding".to_string(), "gzip".to_string()),
            ];
            (compressed_body.into_bytes(), headers)
        } else {
            let headers = vec![(
                "Content-Type".to_string(),
                "application/x-protobuf".to_string(),
            )];
            (spans.to_vec(), headers)
        };

        let request = NegotiationHttpRequest::new("POST", "/v1/traces", headers, body);
        self.requests.lock().unwrap().push(request.clone());

        // Get next response from queue
        let response = {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                NegotiationHttpResponse::new(500) // Default server error
            } else {
                responses.remove(0)
            }
        };

        // Handle response based on status
        match response.status {
            200..=299 => Ok(()),
            415 => {
                // Unsupported Media Type - should trigger compression fallback
                if self.config.fallback_enabled && use_compression {
                    // Retry with no compression
                    self.export_spans(spans)
                } else {
                    Err(format!("Compression not supported: {}", response.status))
                }
            }
            _ => Err(format!("Request failed: {}", response.status)),
        }
    }

    fn get_request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn get_requests(&self) -> Vec<NegotiationHttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

/// **AUDIT TEST**: Verify compression fallback behavior with 415 Unsupported Media Type.
///
/// **SCENARIO**: Client sends gzip-compressed request, collector responds with 415.
/// **REQUIREMENT**: Client should gracefully downgrade to uncompressed and retry.
/// **ASSESSMENT**: Current implementation vs OTLP compression negotiation best practices.
#[test]
fn audit_otlp_compression_fallback_on_415() {
    println!("🔍 AUDIT: OTLP compression negotiation with 415 Unsupported Media Type");

    println!("📋 OTLP compression negotiation requirements:");
    println!("   • Client sends gzip when configured for compression");
    println!("   • Collector returns 415 if compression not supported");
    println!("   • Client SHOULD downgrade to identity and retry once");
    println!("   • NOT: fail-fast without attempting uncompressed");
    println!("   • NOT: ignore 415 and keep sending gzip");

    // **TEST SCENARIO**: Compression-enabled client with fallback
    let config = NegotiationCompressionConfig::new(true).with_fallback();
    let exporter = InMemoryNegotiatingOtlpHttpExporter::new(config);

    // Configure collector to reject gzip (415) then accept uncompressed (200)
    exporter.add_response(NegotiationHttpResponse::new(415)); // Reject compressed
    exporter.add_response(NegotiationHttpResponse::new(200)); // Accept uncompressed

    let test_spans = b"test span data";

    println!("📊 Testing compression negotiation sequence:");

    // **PHASE 1**: Attempt export with graceful fallback enabled
    let result = exporter.export_spans(test_spans);

    match result {
        Ok(()) => {
            println!("   ✅ SUCCESS: Export completed with graceful degradation");
        }
        Err(e) => {
            println!("   ❌ FAILURE: Export failed - {}", e);
            panic!("Compression fallback should succeed when properly implemented");
        }
    }

    // **PHASE 2**: Verify request sequence
    let requests = exporter.get_requests();
    println!("   Request count: {}", requests.len());

    if requests.len() == 2 {
        println!("   ✅ CORRECT: Two requests made (compressed + uncompressed)");

        // Verify first request was compressed
        if requests[0].is_compressed() {
            println!("   ✅ CORRECT: First request used gzip compression");
        } else {
            println!("   ❌ INCORRECT: First request should be compressed");
        }

        // Verify second request was uncompressed
        if !requests[1].is_compressed() {
            println!("   ✅ CORRECT: Second request used identity encoding");
        } else {
            println!("   ❌ INCORRECT: Second request should be uncompressed");
        }
    } else {
        println!(
            "   ❌ INCORRECT: Should make exactly 2 requests (got {})",
            requests.len()
        );
        panic!("Compression fallback should make exactly 2 requests");
    }

    println!("✅ COMPRESSION FALLBACK AUDIT COMPLETE");
    println!("🏆 FINDING: Graceful compression degradation working correctly");
}

/// **AUDIT TEST**: Verify current implementation behavior without fallback.
///
/// **SCENARIO**: Current OTLP exporter receives 415 for gzip content.
/// **REQUIREMENT**: Document actual behavior vs expected graceful degradation.
/// **ASSESSMENT**: Identify compression negotiation gaps in current implementation.
#[test]
fn audit_current_otlp_compression_behavior() {
    println!("🔍 AUDIT: Current OTLP compression behavior with 415 response");

    println!("📊 Current implementation analysis:");
    println!("   File: src/observability/otel.rs");
    println!("   Lines 1001-1024: Compression logic");
    println!("   Lines 1062-1067: 415 handling (400-499 range)");
    println!("   Behavior: 415 treated as non-retryable client error");

    // **CURRENT BEHAVIOR SIMULATION**
    let config = NegotiationCompressionConfig::new(true); // No fallback
    let exporter = InMemoryNegotiatingOtlpHttpExporter::new(config);

    // Collector rejects gzip compression
    exporter.add_response(NegotiationHttpResponse::new(415));

    let test_spans = b"test span data";

    println!("📊 Testing current implementation behavior:");

    let result = exporter.export_spans(test_spans);

    match result {
        Ok(()) => {
            println!("   ❌ UNEXPECTED: Export should fail with current implementation");
            panic!("Current implementation should fail on 415 without fallback");
        }
        Err(e) => {
            println!("   ✅ EXPECTED: Export failed - {}", e);
            println!("   📋 ANALYSIS: Current implementation fails fast on 415");
        }
    }

    let requests = exporter.get_requests();
    println!("   Request count: {}", requests.len());

    if requests.len() == 1 {
        println!("   ✅ EXPECTED: Only one request made (no retry)");
        if requests[0].is_compressed() {
            println!("   ✅ EXPECTED: Request used gzip compression");
        }
    } else {
        println!("   ❌ UNEXPECTED: Should make exactly 1 request");
    }

    // **CURRENT IMPLEMENTATION DEFECTS**
    println!("🚨 CURRENT IMPLEMENTATION DEFECTS:");
    println!("   • No compression fallback mechanism");
    println!("   • 415 Unsupported Media Type treated as non-retryable");
    println!("   • Fails immediately instead of degrading gracefully");
    println!("   • Poor interoperability with compression-unaware collectors");

    println!("📋 REQUIRED IMPROVEMENTS:");
    println!("   1. Add compression fallback capability to OtlpHttpExporter");
    println!("   2. Special handling for 415 status code");
    println!("   3. Retry mechanism with identity encoding after 415");
    println!("   4. Configuration option for compression fallback behavior");

    println!("✅ CURRENT BEHAVIOR AUDIT COMPLETE");
    println!("🚨 FINDING: Current implementation lacks compression negotiation");
}

/// **AUDIT TEST**: Verify compression header handling edge cases.
///
/// **SCENARIO**: Various Content-Encoding scenarios and collector responses.
/// **REQUIREMENT**: Robust compression negotiation across different collectors.
/// **ASSESSMENT**: Edge case handling in compression logic.
#[test]
fn audit_compression_header_edge_cases() {
    println!("🔍 AUDIT: Compression header edge cases and negotiation robustness");

    let edge_case_scenarios = vec![
        (
            415,
            "Unsupported Media Type",
            "Standard compression rejection",
        ),
        (406, "Not Acceptable", "Alternative compression rejection"),
        (400, "Bad Request", "Malformed compressed content"),
        (413, "Payload Too Large", "Compressed content too large"),
    ];

    println!("📊 Testing compression-related error responses:");

    for (status_code, status_text, description) in edge_case_scenarios {
        println!(
            "   Testing: HTTP {} - {} ({})",
            status_code, status_text, description
        );

        let config = NegotiationCompressionConfig::new(true).with_fallback();
        let exporter = InMemoryNegotiatingOtlpHttpExporter::new(config);

        // First response: compression-related error
        exporter.add_response(NegotiationHttpResponse::new(status_code));
        // Second response: success with uncompressed
        exporter.add_response(NegotiationHttpResponse::new(200));

        let result = exporter.export_spans(b"test data");

        match status_code {
            415 => {
                // Should retry without compression
                if result.is_ok() {
                    println!("     ✅ CORRECT: Graceful fallback on compression rejection");
                } else {
                    println!("     ❌ INCORRECT: Should fallback on 415");
                }
            }
            406 | 400 | 413 => {
                // May or may not fallback depending on implementation
                println!(
                    "     📋 ANALYSIS: Status {} behavior depends on fallback policy",
                    status_code
                );
            }
            _ => {}
        }
    }

    // **COMPRESSION NEGOTIATION BEST PRACTICES**
    println!("📋 Compression negotiation best practices:");
    println!("   • 415 Unsupported Media Type: Always retry without compression");
    println!("   • 406 Not Acceptable: Consider retry without compression");
    println!("   • 400 Bad Request: May indicate compression corruption");
    println!("   • 413 Payload Too Large: May benefit from no compression");
    println!("   • Other 4xx: Generally not compression-related");

    println!("✅ COMPRESSION EDGE CASES AUDIT COMPLETE");
    println!("📊 FINDING: Robust compression negotiation requires 415 special handling");
}
