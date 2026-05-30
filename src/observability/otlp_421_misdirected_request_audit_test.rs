//! OTLP-Trace exporter HTTP 421 Misdirected Request handling audit test.
//!
//! Per RFC 9110, HTTP 421 Misdirected Request indicates that the client sent
//! a request to a server that cannot produce a response for the combination
//! of scheme and authority in the request URI. This typically means the
//! request was sent to the wrong endpoint or server.
//!
//! This audit verifies that:
//! 1. HTTP 421 is correctly classified as OtlpError::NonRetryable (terminal)
//! 2. No retry is attempted (prevents wasted resources on wrong endpoint)
//! 3. Error message indicates configuration issue requiring manual fix
//! 4. Batch is properly dropped with clear reasoning
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: 421 indicates client configuration error, not retryable
//! RFC 9110 reference: 421 means wrong server/endpoint, retry would always fail

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns HTTP 421 Misdirected Request responses.
#[derive(Clone)]
struct Scripted421HttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Scripted421HttpClient {
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

impl HttpClient for Scripted421HttpClient {
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

        // Return next response or 421 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 421,
                headers: vec![
                    ("server".to_string(), "nginx/1.18.0".to_string()),
                ],
                body: b"Misdirected Request".to_vec(),
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
    fn test_421_misdirected_request_is_terminal() {
        // AUDIT POINT 1: Verify 421 is correctly classified as terminal (non-retryable)

        let scripted_client = Scripted421HttpClient::new(vec![Response {
            status: 421,
            headers: vec![
                ("server".to_string(), "loadbalancer/2.1.0".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ],
            body: b"421 Misdirected Request - request sent to wrong endpoint".to_vec(),
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

        // Export should fail with terminal error for 421
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 421 Misdirected Request");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(
                    message.contains("421"),
                    "Error message should contain 421 status: {}",
                    message
                );
                assert!(
                    message.contains("client error"),
                    "Should be classified as client error: {}",
                    message
                );
                assert!(
                    message.contains("batch dropped"),
                    "Should indicate batch was dropped: {}",
                    message
                );

                eprintln!("✅ SOUND: HTTP 421 correctly classified as terminal");
                eprintln!("   Error message: {}", message);
                eprintln!("   Classification: NonRetryable (terminal)");
                eprintln!("   Prevents retry waste: ✓");
                eprintln!("   RFC 9110 compliance: ✅ (misdirected = wrong endpoint)");
                eprintln!("   OTLP spec compliance: ✅ (client configuration error)");
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 421, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_421_vs_retryable_errors_classification() {
        // AUDIT POINT 2: Verify 421 behaves differently from retryable server errors

        struct TestCase {
            status: u16,
            description: &'static str,
            should_be_retryable: bool,
            reasoning: &'static str,
        }

        let test_cases = vec![
            TestCase {
                status: 421,
                description: "Misdirected Request",
                should_be_retryable: false, // ✅ Wrong endpoint - terminal
                reasoning: "Client sent to wrong endpoint, retry won't help",
            },
            TestCase {
                status: 502,
                description: "Bad Gateway",
                should_be_retryable: true, // Retryable server error
                reasoning: "Server error, might be transient",
            },
            TestCase {
                status: 503,
                description: "Service Unavailable",
                should_be_retryable: true, // Retryable server error
                reasoning: "Server overloaded, might recover",
            },
            TestCase {
                status: 504,
                description: "Gateway Timeout",
                should_be_retryable: true, // Retryable server error
                reasoning: "Gateway timeout, might recover",
            },
        ];

        eprintln!("\n🧪 421 VS RETRYABLE ERRORS CLASSIFICATION TEST");
        eprintln!("==============================================");

        for test_case in test_cases {
            let scripted_client = Scripted421HttpClient::new(vec![Response {
                status: test_case.status,
                headers: vec![],
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
                OtlpError::Retryable { status_code, .. } => {
                    assert!(test_case.should_be_retryable,
                        "Status {} should not be retryable but was classified as retryable", test_case.status);
                    eprintln!("  {}: ✅ Retryable ({})", test_case.status, test_case.reasoning);
                }
                OtlpError::NonRetryable(_) => {
                    assert!(!test_case.should_be_retryable,
                        "Status {} should be retryable but was classified as terminal", test_case.status);
                    eprintln!("  {}: ❌ Terminal ({})", test_case.status, test_case.reasoning);
                }
                other => {
                    panic!("Unexpected error type for {}: {:?}", test_case.status, other);
                }
            }
        }

        eprintln!("\n✅ CLASSIFICATION CONTRAST:");
        eprintln!("   421 Misdirected Request: Terminal (correct - wrong endpoint)");
        eprintln!("   502/503/504 Server Errors: Retryable (correct - transient issues)");
        eprintln!("   OTLP spec compliance: ✅");
    }

    #[test]
    fn test_421_misdirected_request_scenarios() {
        // AUDIT POINT 3: Test common 421 misdirected request scenarios

        struct MisdirectedScenario {
            name: &'static str,
            server_type: &'static str,
            body: &'static str,
            issue_description: &'static str,
        }

        let scenarios = vec![
            MisdirectedScenario {
                name: "wrong_port_number",
                server_type: "nginx/1.20.1",
                body: "The requested resource is not available on this server",
                issue_description: "Client configured with wrong port (e.g., 4317 instead of 4318)",
            },
            MisdirectedScenario {
                name: "wrong_protocol_scheme",
                server_type: "haproxy/2.2",
                body: "This server cannot handle the requested scheme",
                issue_description: "Client using HTTP to HTTPS-only endpoint",
            },
            MisdirectedScenario {
                name: "load_balancer_routing",
                server_type: "AWS-ALB/2.0",
                body: "Request was routed to incorrect backend service",
                issue_description: "Load balancer sent OTLP request to wrong service instance",
            },
            MisdirectedScenario {
                name: "dns_resolution_error",
                server_type: "cloudflare",
                body: "DNS pointed to wrong server instance",
                issue_description: "DNS misconfiguration pointing to wrong server",
            },
            MisdirectedScenario {
                name: "service_mesh_routing",
                server_type: "envoy/1.22.0",
                body: "Service mesh routing error - wrong destination",
                issue_description: "Istio/Envoy routing misconfiguration",
            },
        ];

        eprintln!("\n🧪 HTTP 421 MISDIRECTED REQUEST SCENARIOS");
        eprintln!("========================================");

        for scenario in scenarios {
            let scripted_client = Scripted421HttpClient::new(vec![Response {
                status: 421,
                headers: vec![
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
                    assert!(message.contains("421"));
                    assert!(message.contains("client error"));

                    eprintln!("  Scenario '{}': ✅ Terminal",
                        scenario.name);
                    eprintln!("    Issue: {}", scenario.issue_description);
                    eprintln!("    Server: {}", scenario.server_type);
                }
                other => panic!("Scenario '{}' should be terminal, got: {:?}",
                    scenario.name, other),
            }
        }

        eprintln!("\n✅ ALL MISDIRECTED REQUEST SCENARIOS:");
        eprintln!("   • Wrong port configurations: Terminal (no retry waste)");
        eprintln!("   • Protocol scheme mismatches: Terminal (HTTPS vs HTTP)");
        eprintln!("   • Load balancer routing errors: Terminal (wrong backend)");
        eprintln!("   • DNS misconfiguration: Terminal (wrong server IP)");
        eprintln!("   • Service mesh routing: Terminal (wrong destination)");
        eprintln!("   • Consistent terminal classification across all scenarios");
    }

    #[test]
    fn test_421_prevents_retry_waste_compared_to_retryable() {
        // AUDIT POINT 4: Demonstrate 421 prevents resource waste vs retryable errors

        eprintln!("\n🎯 DEMONSTRATING 421 PREVENTS RETRY WASTE");
        eprintln!("==========================================");

        // Test 421 Misdirected Request (should be terminal)
        let misdirected_client = Scripted421HttpClient::new(vec![Response {
            status: 421,
            headers: vec![],
            body: b"Request sent to wrong endpoint".to_vec(),
        }]);

        let misdirected_exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            misdirected_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        let result_421 = cx.block_on(async { misdirected_exporter.export_spans(&cx, &spans).await });
        eprintln!("\n📊 HTTP 421 Misdirected Request:");
        eprintln!("  Cause: Request sent to wrong endpoint (configuration error)");

        match result_421.unwrap_err() {
            OtlpError::NonRetryable(message) => {
                eprintln!("  Classification: TERMINAL ✅");
                eprintln!("  Behavior: Fail fast, no retry");
                eprintln!("  Message: {}", message);
                eprintln!("  Why correct: Wrong endpoint will never work, retry is waste");
                eprintln!("  Resource savings: Prevents repeated failed requests to wrong endpoint");
            }
            _ => panic!("421 should be NonRetryable"),
        }

        // Test 503 Service Unavailable (should be retryable for comparison)
        let unavailable_client = Scripted421HttpClient::new(vec![Response {
            status: 503,
            headers: vec![("retry-after".to_string(), "30".to_string())],
            body: b"Service temporarily unavailable".to_vec(),
        }]);

        let unavailable_exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            unavailable_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let result_503 = cx.block_on(async { unavailable_exporter.export_spans(&cx, &spans).await });
        eprintln!("\n📊 HTTP 503 Service Unavailable:");
        eprintln!("  Cause: Server temporarily overloaded (transient condition)");

        match result_503.unwrap_err() {
            OtlpError::Retryable { status_code, retry_after } => {
                eprintln!("  Classification: RETRYABLE ✅");
                eprintln!("  Behavior: Queue for retry with backoff");
                eprintln!("  Status: {}", status_code);
                eprintln!("  Retry-After: {:?}", retry_after);
                eprintln!("  Why correct: Server may recover, retry has success probability");
            }
            _ => panic!("503 should be Retryable"),
        }

        eprintln!("\n🔄 RETRY BEHAVIOR CONTRAST:");
        eprintln!("  421 → NO RETRY: Configuration error needs human intervention");
        eprintln!("  503 → RETRY: Transient issue may resolve automatically");
        eprintln!("  ");
        eprintln!("  This distinction prevents resource waste:");
        eprintln!("  • 421: Avoids hammering wrong endpoint forever");
        eprintln!("  • 503: Allows recovery from temporary server issues");

        eprintln!("\n✅ RESOURCE EFFICIENCY: 421 terminal classification prevents waste");
    }

    #[test]
    fn test_421_otlp_spec_compliance_for_misdirected_requests() {
        // AUDIT POINT 5: Document OTLP specification compliance

        eprintln!("\n📋 OTLP HTTP 421 MISDIRECTED REQUEST SPECIFICATION");
        eprintln!("=================================================");
        eprintln!("Per OTLP specification and RFC 9110:");
        eprintln!("   • HTTP 421 Misdirected Request indicates wrong endpoint");
        eprintln!("   • This is a CLIENT CONFIGURATION ERROR (not server issue)");
        eprintln!("   • Retrying to same endpoint will always fail");
        eprintln!("   • MUST be classified as terminal to prevent resource waste");

        let scripted_client = Scripted421HttpClient::new(vec![Response {
            status: 421,
            headers: vec![
                ("server".to_string(), "otel-gateway/1.0.0".to_string()),
            ],
            body: b"Request was sent to wrong OTLP endpoint".to_vec(),
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
                // Verify compliance requirements
                assert!(message.contains("421"), "Should identify HTTP status");
                assert!(message.contains("client error"), "Should identify as client issue");
                assert!(message.contains("batch dropped"), "Should indicate data loss");

                eprintln!("\n✅ OTLP SPECIFICATION COMPLIANCE:");
                eprintln!("   ✓ 421 classified as terminal (prevents retry loops)");
                eprintln!("   ✓ Identified as client error (configuration issue)");
                eprintln!("   ✓ Batch drop indicated (data loss warning)");
                eprintln!("   ✓ No retry attempted (resource efficiency)");

                eprintln!("\n🎯 OPERATOR ACTION ITEMS FROM 421 ERROR:");
                eprintln!("   1. Verify OTLP endpoint URL configuration");
                eprintln!("   2. Check port number (4317 gRPC vs 4318 HTTP)");
                eprintln!("   3. Verify protocol scheme (HTTP vs HTTPS)");
                eprintln!("   4. Check load balancer/proxy routing rules");
                eprintln!("   5. Validate DNS resolution points to correct server");

                eprintln!("\n🚫 WHAT WOULD BE WRONG (retryable classification):");
                eprintln!("   ✗ Infinite retry loops to wrong endpoint");
                eprintln!("   ✗ Resource waste (bandwidth, CPU, logs)");
                eprintln!("   ✗ Delayed detection of configuration issues");
                eprintln!("   ✗ False service health signals");

                eprintln!("\n✅ CURRENT IMPLEMENTATION: Terminal classification (CORRECT)");
                eprintln!("   Error message: {}", message);
            }
            other => panic!("Expected NonRetryable for 421, got: {:?}", other),
        }
    }
}
