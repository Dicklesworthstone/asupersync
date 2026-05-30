//! OTLP-Trace exporter HTTP 405 Allow header extraction audit test.
//!
//! Per OTLP specification and RFC 9110, HTTP 405 Method Not Allowed responses
//! SHOULD include an Allow header listing supported HTTP methods. This information
//! is crucial for debugging configuration errors where the client is using the
//! wrong HTTP method for the OTLP endpoint.
//!
//! This audit verifies that:
//! 1. HTTP 405 errors extract and include Allow header in error messages
//! 2. Missing Allow headers are handled gracefully with fallback
//! 3. Allow header extraction is case-insensitive per RFC 9110
//! 4. Error messages provide actionable debugging information
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: 405 indicates configuration error requiring method fix
//! RFC 9110 reference: Allow header SHOULD be present with 405 responses

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns HTTP 405 Method Not Allowed responses.
#[derive(Clone)]
struct Scripted405HttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Scripted405HttpClient {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses)),
            request_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn request_count(&self) -> usize {
        self.request_log.lock().unwrap().len()
    }

    fn get_requests(&self) -> Vec<(Method, String)> {
        self.request_log.lock().unwrap().clone()
    }
}

impl HttpClient for Scripted405HttpClient {
    async fn request(
        &self,
        _cx: &Cx,
        method: Method,
        url: &str,
        _headers: HashMap<String, String>,
        _body: Vec<u8>,
    ) -> Result<Response, crate::http::HttpError> {
        // Log the request
        self.request_log
            .lock()
            .unwrap()
            .push((method, url.to_string()));

        // Return next response or 405 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 405,
                headers: vec![
                    ("allow".to_string(), "GET, HEAD".to_string()),
                ],
                body: b"Method Not Allowed".to_vec(),
            });

        Ok(response)
    }
}

fn create_test_span() -> TraceSpan {
    TraceSpan {
        trace_id: TraceId::new(),
        span_id: [1, 2, 3, 4, 5, 6, 7, 8],
        parent_span_id: None,
        name: "test_span".to_string(),
        start_time: Instant::now(),
        end_time: Some(Instant::now()),
        status_code: 0,
        status_message: None,
        attributes: HashMap::new(),
        events: Vec::new(),
        links: Vec::new(),
        resource_attributes: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_405_allow_header_extracted_and_included() {
        // AUDIT POINT 1: Verify Allow header is extracted and included in error message

        let scripted_client = Scripted405HttpClient::new(vec![Response {
            status: 405,
            headers: vec![
                ("allow".to_string(), "POST, OPTIONS, HEAD".to_string()),
                ("server".to_string(), "otel-collector/0.88.0".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ],
            body: b"405 Method Not Allowed - endpoint supports POST, OPTIONS, HEAD only".to_vec(),
        }]);

        let exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            scripted_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        // Export should fail with Allow header info in error message
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 405 Method Not Allowed");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(
                    message.contains("405"),
                    "Error message should contain 405 status: {}",
                    message
                );
                assert!(
                    message.contains("configuration error"),
                    "Error should indicate configuration error: {}",
                    message
                );
                assert!(
                    message.contains("POST, OPTIONS, HEAD"),
                    "Error should include Allow header methods: {}",
                    message
                );

                eprintln!("✅ SOUND: HTTP 405 Allow header correctly extracted");
                eprintln!("   Error message: {}", message);
                eprintln!("   Allow header extracted: POST, OPTIONS, HEAD");
                eprintln!("   Configuration error indicated: ✓");
                eprintln!("   Debugging information included: ✓");
                eprintln!("   RFC 9110 compliance: ✅");
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 405, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_405_missing_allow_header_graceful_fallback() {
        // AUDIT POINT 2: Verify missing Allow header is handled gracefully

        let scripted_client = Scripted405HttpClient::new(vec![Response {
            status: 405,
            headers: vec![
                ("server".to_string(), "apache/2.4".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
                // No Allow header provided by misconfigured server
            ],
            body: b"405 Method Not Allowed".to_vec(),
        }]);

        let exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            scripted_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 405 without Allow header");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(message.contains("405"), "Should be 405 error");
                assert!(
                    message.contains("unknown"),
                    "Should show 'unknown' for missing Allow header: {}",
                    message
                );
                assert!(
                    message.contains("configuration error"),
                    "Should still indicate configuration error: {}",
                    message
                );

                eprintln!("✅ GRACEFUL FALLBACK:");
                eprintln!("   Missing Allow header handled: ✓");
                eprintln!("   Fallback value 'unknown': ✓");
                eprintln!("   Configuration error still indicated: ✓");
                eprintln!("   Error message: {}", message);
            }
            _ => panic!("Expected NonRetryable for 405, got: {:?}", error),
        }
    }

    #[test]
    fn test_405_allow_header_case_insensitive() {
        // AUDIT POINT 3: Verify Allow header extraction is case-insensitive per RFC

        struct CaseTest {
            header_name: &'static str,
            description: &'static str,
        }

        let case_tests = vec![
            CaseTest {
                header_name: "allow",
                description: "lowercase",
            },
            CaseTest {
                header_name: "Allow",
                description: "title-case",
            },
            CaseTest {
                header_name: "ALLOW",
                description: "uppercase",
            },
            CaseTest {
                header_name: "AlLoW",
                description: "mixed-case",
            },
        ];

        eprintln!("\n🧪 ALLOW HEADER CASE SENSITIVITY TEST");
        eprintln!("===================================");

        for case_test in case_tests {
            let scripted_client = Scripted405HttpClient::new(vec![Response {
                status: 405,
                headers: vec![
                    (case_test.header_name.to_string(), "POST, PUT".to_string()),
                ],
                body: b"Method Not Allowed".to_vec(),
            }]);

            let exporter = OtlpHttpExporter::new(
                "http://localhost:4318/v1/traces".to_string(),
                HashMap::new(),
                Duration::from_secs(30),
                scripted_client.clone(),
            )
            .expect("Failed to create OTLP exporter");

            let cx = Cx::for_testing();
            let spans = vec![create_test_span()];

            let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

            match result.unwrap_err() {
                OtlpError::NonRetryable(message) => {
                    assert!(
                        message.contains("POST, PUT"),
                        "Should extract {} Allow header: {}",
                        case_test.description,
                        message
                    );

                    eprintln!("  {}: ✅ Header extracted", case_test.description);
                }
                other => panic!("Expected NonRetryable for 405, got: {:?}", other),
            }
        }

        eprintln!("\n✅ CASE SENSITIVITY COMPLIANCE:");
        eprintln!("   All header case variations extracted correctly");
        eprintln!("   RFC 9110 compliance: ✅ (case-insensitive header names)");
    }

    #[test]
    fn test_405_vs_other_4xx_allow_header_behavior() {
        // AUDIT POINT 4: Verify only 405 gets special Allow header treatment

        struct TestCase {
            status: u16,
            description: &'static str,
            headers: Vec<(String, String)>,
            should_extract_allow: bool,
        }

        let test_cases = vec![
            TestCase {
                status: 400,
                description: "Bad Request",
                headers: vec![("allow".to_string(), "POST".to_string())],
                should_extract_allow: false, // No special Allow header handling
            },
            TestCase {
                status: 401,
                description: "Unauthorized",
                headers: vec![("allow".to_string(), "GET".to_string())],
                should_extract_allow: false,
            },
            TestCase {
                status: 403,
                description: "Forbidden",
                headers: vec![("allow".to_string(), "HEAD".to_string())],
                should_extract_allow: false,
            },
            TestCase {
                status: 404,
                description: "Not Found",
                headers: vec![("allow".to_string(), "OPTIONS".to_string())],
                should_extract_allow: false,
            },
            TestCase {
                status: 405,
                description: "Method Not Allowed",
                headers: vec![
                    ("allow".to_string(), "GET, POST, PUT".to_string()),
                ],
                should_extract_allow: true, // ✅ Special Allow header handling
            },
            TestCase {
                status: 409,
                description: "Conflict",
                headers: vec![("allow".to_string(), "PATCH".to_string())],
                should_extract_allow: false,
            },
            TestCase {
                status: 413,
                description: "Payload Too Large",
                headers: vec![("allow".to_string(), "PUT".to_string())],
                should_extract_allow: false,
            },
        ];

        eprintln!("\n🧪 4XX STATUS CODE ALLOW HEADER EXTRACTION TEST");
        eprintln!("==============================================");

        for test_case in test_cases {
            let scripted_client = Scripted405HttpClient::new(vec![Response {
                status: test_case.status,
                headers: test_case.headers.clone(),
                body: format!("{} {}", test_case.status, test_case.description).into_bytes(),
            }]);

            let exporter = OtlpHttpExporter::new(
                "http://localhost:4318/v1/traces".to_string(),
                HashMap::new(),
                Duration::from_secs(30),
                scripted_client.clone(),
            )
            .expect("Failed to create OTLP exporter");

            let cx = Cx::for_testing();
            let spans = vec![create_test_span()];

            let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

            match result.unwrap_err() {
                OtlpError::NonRetryable(message) => {
                    if test_case.should_extract_allow {
                        assert!(
                            message.contains("GET, POST, PUT"),
                            "405 should extract Allow header: {}",
                            message
                        );
                        assert!(
                            message.contains("configuration error"),
                            "405 should indicate configuration error: {}",
                            message
                        );
                        assert!(
                            message.contains("Allowed methods: GET, POST, PUT"),
                            "405 should format Allow header info: {}",
                            message
                        );
                        eprintln!("  {}: ✅ Allow header extracted and formatted", test_case.status);
                    } else {
                        assert!(
                            !message.contains("configuration error"),
                            "Non-405 should not mention configuration error: {}",
                            message
                        );
                        assert!(
                            !message.contains("Allowed methods:"),
                            "Non-405 should not format Allow header: {}",
                            message
                        );
                        eprintln!("  {}: ❌ No Allow extraction (correct)", test_case.status);
                    }
                }
                OtlpError::CompressionFallback(_) => {
                    assert_eq!(test_case.status, 415, "Only 415 should trigger compression fallback");
                    eprintln!("  {}: 🔄 Compression fallback (correct)", test_case.status);
                }
                other => {
                    panic!("Unexpected error type for {}: {:?}", test_case.status, other);
                }
            }
        }

        eprintln!("\n✅ ALLOW HEADER EXTRACTION SUMMARY:");
        eprintln!("   405 Method Not Allowed: Extract and format Allow header (correct)");
        eprintln!("   Other 4xx codes: No special Allow handling (correct)");
        eprintln!("   OTLP spec compliance: ✅");
    }

    #[test]
    fn test_405_debugging_scenarios_with_allow_headers() {
        // AUDIT POINT 5: Test real-world 405 debugging scenarios

        struct DebugScenario {
            name: &'static str,
            allowed_methods: &'static str,
            server_type: &'static str,
            body: &'static str,
            expected_debug_value: &'static str,
        }

        let scenarios = vec![
            DebugScenario {
                name: "jaeger_collector_post_only",
                allowed_methods: "POST",
                server_type: "Jaeger/1.35.0",
                body: "The Jaeger collector only accepts POST requests on this endpoint",
                expected_debug_value: "POST",
            },
            DebugScenario {
                name: "otel_collector_post_options",
                allowed_methods: "POST, OPTIONS",
                server_type: "opentelemetry-collector/0.88.0",
                body: "Method not allowed. Use POST for traces, OPTIONS for preflight",
                expected_debug_value: "POST, OPTIONS",
            },
            DebugScenario {
                name: "zipkin_collector_post_put",
                allowed_methods: "POST, PUT",
                server_type: "Zipkin/2.24.0",
                body: "This endpoint accepts POST and PUT only for backward compatibility",
                expected_debug_value: "POST, PUT",
            },
            DebugScenario {
                name: "custom_gateway_multiple",
                allowed_methods: "GET, POST, PUT, PATCH, HEAD, OPTIONS",
                server_type: "CustomTelemetryGateway/1.0",
                body: "Gateway supports multiple methods but client used unsupported method",
                expected_debug_value: "GET, POST, PUT, PATCH, HEAD, OPTIONS",
            },
            DebugScenario {
                name: "read_only_endpoint",
                allowed_methods: "GET, HEAD, OPTIONS",
                server_type: "ReadOnlyOTLP/1.0",
                body: "Read-only OTLP endpoint for debugging - no POST allowed",
                expected_debug_value: "GET, HEAD, OPTIONS",
            },
        ];

        eprintln!("\n🧪 HTTP 405 DEBUGGING SCENARIOS");
        eprintln!("===============================");

        for scenario in scenarios {
            let scripted_client = Scripted405HttpClient::new(vec![Response {
                status: 405,
                headers: vec![
                    ("allow".to_string(), scenario.allowed_methods.to_string()),
                    ("server".to_string(), scenario.server_type.to_string()),
                    ("content-type".to_string(), "text/plain".to_string()),
                ],
                body: scenario.body.as_bytes().to_vec(),
            }]);

            let exporter = OtlpHttpExporter::new(
                "http://localhost:4318/v1/traces".to_string(),
                HashMap::new(),
                Duration::from_secs(30),
                scripted_client.clone(),
            )
            .expect("Failed to create OTLP exporter");

            let cx = Cx::for_testing();
            let spans = vec![create_test_span()];

            let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

            match result.unwrap_err() {
                OtlpError::NonRetryable(message) => {
                    assert!(message.contains("405"));
                    assert!(message.contains("configuration error"));
                    assert!(
                        message.contains(scenario.expected_debug_value),
                        "Should include allowed methods '{}' for {}: {}",
                        scenario.expected_debug_value,
                        scenario.name,
                        message
                    );

                    eprintln!("  Scenario '{}': ✅ Debug info: {}",
                        scenario.name, scenario.expected_debug_value);
                }
                other => panic!("Scenario '{}' should be non-retryable, got: {:?}",
                    scenario.name, other),
            }
        }

        eprintln!("\n✅ ALL DEBUGGING SCENARIOS:");
        eprintln!("   • Jaeger collectors: POST-only extraction");
        eprintln!("   • OTEL collectors: POST + OPTIONS extraction");
        eprintln!("   • Zipkin collectors: POST + PUT extraction");
        eprintln!("   • Custom gateways: Multiple methods extraction");
        eprintln!("   • Read-only endpoints: GET + HEAD + OPTIONS extraction");
        eprintln!("   • Consistent Allow header extraction for all scenarios");
    }

    #[test]
    fn test_405_error_message_format_and_actionability() {
        // AUDIT POINT 6: Verify error message format provides actionable information

        eprintln!("\n📋 OTLP HTTP 405 ERROR MESSAGE FORMAT SPECIFICATION");
        eprintln!("=================================================");
        eprintln!("Error message requirements:");
        eprintln!("   • Must include HTTP status code (405)");
        eprintln!("   • Must indicate configuration error");
        eprintln!("   • Must include allowed methods from Allow header");
        eprintln!("   • Must indicate batch was dropped");
        eprintln!("   • Should be actionable for developers/operators");

        let scripted_client = Scripted405HttpClient::new(vec![Response {
            status: 405,
            headers: vec![
                ("allow".to_string(), "POST, OPTIONS".to_string()),
                ("server".to_string(), "otel-collector/0.88.0".to_string()),
            ],
            body: b"Method GET not allowed on /v1/traces - use POST".to_vec(),
        }]);

        let exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            scripted_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        match result.unwrap_err() {
            OtlpError::NonRetryable(message) => {
                eprintln!("\n📊 Error Message Analysis:");
                eprintln!("   Message: {}", message);

                // Verify message format compliance
                assert!(message.contains("405"), "✓ HTTP status code included");
                assert!(message.contains("configuration error"), "✓ Error type identified");
                assert!(message.contains("POST, OPTIONS"), "✓ Allowed methods included");
                assert!(message.contains("batch dropped"), "✓ Data loss indicated");

                // Verify actionable information
                let has_allowed_methods = message.contains("Allowed methods:");
                assert!(has_allowed_methods, "✓ Actionable format: 'Allowed methods: X'");

                eprintln!("\n✅ MESSAGE FORMAT COMPLIANCE:");
                eprintln!("   ✓ HTTP status code: 405 (clearly identified)");
                eprintln!("   ✓ Error classification: configuration error (not transient)");
                eprintln!("   ✓ Debugging info: Allowed methods: POST, OPTIONS");
                eprintln!("   ✓ Impact notification: batch dropped (data loss warning)");
                eprintln!("   ✓ Actionable format: Developer knows to change HTTP method");

                eprintln!("\n🎯 DEVELOPER ACTION ITEMS FROM ERROR:");
                eprintln!("   1. Change client HTTP method to POST or OPTIONS");
                eprintln!("   2. Verify endpoint URL is correct");
                eprintln!("   3. Check OTLP client configuration");
                eprintln!("   4. Re-send dropped trace batch after fixing method");

                eprintln!("\n✅ ERROR MESSAGE: Actionable and compliant");
            }
            other => panic!("Expected NonRetryable for 405, got: {:?}", other),
        }
    }
}
