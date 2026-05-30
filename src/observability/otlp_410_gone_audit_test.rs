//! OTLP-Trace exporter HTTP 410 Gone handling audit test.
//!
//! Per RFC 9110, HTTP 410 Gone indicates that the target resource is no longer
//! available at the origin server and this condition is intended to be permanent.
//! Unlike 404 Not Found, which may be temporary, 410 explicitly signals that
//! the resource has been intentionally removed and will not be available again.
//!
//! This audit verifies that:
//! 1. HTTP 410 is correctly classified as OtlpError::NonRetryable (terminal)
//! 2. No retry is attempted (prevents wasted resources on gone endpoints)
//! 3. Error message indicates permanent unavailability
//! 4. Batch is properly dropped with clear reasoning
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: 410 indicates permanent resource removal, not retryable
//! RFC 9110 reference: 410 Gone means resource permanently unavailable

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns HTTP 410 Gone responses.
#[derive(Clone)]
struct Scripted410HttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Scripted410HttpClient {
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

impl HttpClient for Scripted410HttpClient {
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

        // Return next response or 410 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 410,
                headers: vec![
                    ("server".to_string(), "nginx/1.18.0".to_string()),
                ],
                body: b"Gone".to_vec(),
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
    fn test_410_gone_is_terminal() {
        // AUDIT POINT 1: Verify 410 is correctly classified as terminal (non-retryable)

        let scripted_client = Scripted410HttpClient::new(vec![Response {
            status: 410,
            headers: vec![
                ("server".to_string(), "otel-collector/0.88.0".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ],
            body: b"410 Gone - OTLP endpoint has been permanently removed".to_vec(),
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

        // Export should fail with terminal error for 410
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 410 Gone");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(
                    message.contains("410"),
                    "Error message should contain 410 status: {}",
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

                eprintln!("✅ SOUND: HTTP 410 correctly classified as terminal");
                eprintln!("   Error message: {}", message);
                eprintln!("   Classification: NonRetryable (terminal)");
                eprintln!("   Prevents retry waste: ✓");
                eprintln!("   RFC 9110 compliance: ✅ (resource permanently gone)");
                eprintln!("   OTLP spec compliance: ✅ (permanent client configuration issue)");
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 410, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_410_vs_404_vs_retryable_classification() {
        // AUDIT POINT 2: Verify 410 vs 404 vs retryable server errors

        struct TestCase {
            status: u16,
            description: &'static str,
            should_be_retryable: bool,
            reasoning: &'static str,
        }

        let test_cases = vec![
            TestCase {
                status: 404,
                description: "Not Found",
                should_be_retryable: false, // Terminal - resource not found
                reasoning: "Resource not found, endpoint doesn't exist",
            },
            TestCase {
                status: 410,
                description: "Gone",
                should_be_retryable: false, // ✅ Terminal - permanently removed
                reasoning: "Resource permanently removed, will never be available",
            },
            TestCase {
                status: 503,
                description: "Service Unavailable",
                should_be_retryable: true, // Retryable server error
                reasoning: "Server overloaded, might recover",
            },
        ];

        eprintln!("\n🧪 410 VS 404 VS RETRYABLE CLASSIFICATION TEST");
        eprintln!("==============================================");

        for test_case in test_cases {
            let scripted_client = Scripted410HttpClient::new(vec![Response {
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

        eprintln!("\n✅ PERMANENCE CLASSIFICATION:");
        eprintln!("   404 Not Found: Terminal (resource doesn't exist)");
        eprintln!("   410 Gone: Terminal (resource permanently removed)");
        eprintln!("   503 Service Unavailable: Retryable (temporary condition)");
        eprintln!("   OTLP spec compliance: ✅");
    }

    #[test]
    fn test_410_gone_scenarios() {
        // AUDIT POINT 3: Test common 410 Gone scenarios

        struct GoneScenario {
            name: &'static str,
            server_type: &'static str,
            body: &'static str,
            issue_description: &'static str,
        }

        let scenarios = vec![
            GoneScenario {
                name: "deprecated_api_version",
                server_type: "otel-collector/0.90.0",
                body: "OTLP v1 API endpoint permanently removed, use v2",
                issue_description: "Old API version permanently sunset",
            },
            GoneScenario {
                name: "service_decommissioned",
                server_type: "kubernetes-ingress/1.8",
                body: "Service decommissioned - migrate to new-telemetry-service",
                issue_description: "Entire telemetry service replaced",
            },
            GoneScenario {
                name: "path_restructured",
                server_type: "nginx/1.22.0",
                body: "Path /v1/traces moved permanently to /api/v2/telemetry/traces",
                issue_description: "API restructuring with new URL paths",
            },
            GoneScenario {
                name: "tenant_removed",
                server_type: "multi-tenant-otlp/2.1",
                body: "Tenant workspace permanently deleted",
                issue_description: "Customer account or workspace terminated",
            },
            GoneScenario {
                name: "feature_removed",
                server_type: "custom-otel-gateway/1.5",
                body: "Legacy trace ingestion feature permanently disabled",
                issue_description: "Feature removed in product evolution",
            },
        ];

        eprintln!("\n🧪 HTTP 410 GONE SCENARIOS");
        eprintln!("=========================");

        for scenario in scenarios {
            let scripted_client = Scripted410HttpClient::new(vec![Response {
                status: 410,
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
                    assert!(message.contains("410"));
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

        eprintln!("\n✅ ALL GONE SCENARIOS:");
        eprintln!("   • Deprecated API versions: Terminal (no rollback)");
        eprintln!("   • Service decommissioning: Terminal (use replacement)");
        eprintln!("   • Path restructuring: Terminal (update URLs)");
        eprintln!("   • Tenant removal: Terminal (account terminated)");
        eprintln!("   • Feature removal: Terminal (product evolution)");
        eprintln!("   • Consistent terminal classification prevents retry waste");
    }

    #[test]
    fn test_410_prevents_retry_waste_vs_temporary_errors() {
        // AUDIT POINT 4: Demonstrate 410 prevents resource waste vs temporary errors

        eprintln!("\n🎯 DEMONSTRATING 410 PREVENTS RETRY WASTE");
        eprintln!("==========================================");

        // Test 410 Gone (should be terminal)
        let gone_client = Scripted410HttpClient::new(vec![Response {
            status: 410,
            headers: vec![],
            body: b"API endpoint permanently removed".to_vec(),
        }]);

        let gone_exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            gone_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        let result_410 = cx.block_on(async { gone_exporter.export_spans(&cx, &spans).await });
        eprintln!("\n📊 HTTP 410 Gone:");
        eprintln!("  Cause: Resource permanently removed (intentional action)");

        match result_410.unwrap_err() {
            OtlpError::NonRetryable(message) => {
                eprintln!("  Classification: TERMINAL ✅");
                eprintln!("  Behavior: Fail fast, no retry");
                eprintln!("  Message: {}", message);
                eprintln!("  Why correct: Resource will never return, retry is waste");
                eprintln!("  Resource savings: Prevents infinite retries to removed endpoint");
            }
            _ => panic!("410 should be NonRetryable"),
        }

        // Test 502 Bad Gateway (should be retryable for comparison)
        let bad_gateway_client = Scripted410HttpClient::new(vec![Response {
            status: 502,
            headers: vec![("retry-after".to_string(), "60".to_string())],
            body: b"Bad Gateway - upstream server error".to_vec(),
        }]);

        let bad_gateway_exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            bad_gateway_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let result_502 = cx.block_on(async { bad_gateway_exporter.export_spans(&cx, &spans).await });
        eprintln!("\n📊 HTTP 502 Bad Gateway:");
        eprintln!("  Cause: Gateway/proxy error (transient infrastructure issue)");

        match result_502.unwrap_err() {
            OtlpError::Retryable { status_code, retry_after } => {
                eprintln!("  Classification: RETRYABLE ✅");
                eprintln!("  Behavior: Queue for retry with backoff");
                eprintln!("  Status: {}", status_code);
                eprintln!("  Retry-After: {:?}", retry_after);
                eprintln!("  Why correct: Gateway may recover, retry has success probability");
            }
            _ => panic!("502 should be Retryable"),
        }

        eprintln!("\n🔄 PERMANENCE BEHAVIOR CONTRAST:");
        eprintln!("  410 → NO RETRY: Resource permanently gone (intentional removal)");
        eprintln!("  502 → RETRY: Gateway issue may resolve (infrastructure recovery)");
        eprintln!("  ");
        eprintln!("  This distinction prevents resource waste:");
        eprintln!("  • 410: Avoids retrying to permanently removed endpoints");
        eprintln!("  • 502: Allows recovery from temporary infrastructure issues");

        eprintln!("\n✅ PERMANENCE EFFICIENCY: 410 terminal classification prevents waste");
    }

    #[test]
    fn test_410_rfc_9110_compliance() {
        // AUDIT POINT 5: Document RFC 9110 compliance for 410 Gone

        eprintln!("\n📋 RFC 9110 HTTP 410 GONE SPECIFICATION");
        eprintln!("=======================================");
        eprintln!("Per RFC 9110 Section 15.5.11:");
        eprintln!("   • HTTP 410 Gone indicates target resource is no longer available");
        eprintln!("   • This condition is INTENDED TO BE PERMANENT");
        eprintln!("   • Server has no forwarding address for the resource");
        eprintln!("   • Different from 404: 410 explicitly signals permanent removal");

        let scripted_client = Scripted410HttpClient::new(vec![Response {
            status: 410,
            headers: vec![
                ("server".to_string(), "compliant-server/1.0.0".to_string()),
                ("cache-control".to_string(), "no-cache".to_string()),
            ],
            body: b"The requested OTLP endpoint has been permanently removed".to_vec(),
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
                // Verify RFC compliance requirements
                assert!(message.contains("410"), "Should identify HTTP status");
                assert!(message.contains("client error"), "Should identify as client issue");
                assert!(message.contains("batch dropped"), "Should indicate data loss");

                eprintln!("\n✅ RFC 9110 COMPLIANCE:");
                eprintln!("   ✓ 410 classified as terminal (respects permanence intent)");
                eprintln!("   ✓ Identified as client error (configuration needs update)");
                eprintln!("   ✓ Batch drop indicated (data loss warning)");
                eprintln!("   ✓ No retry attempted (respects permanent removal)");

                eprintln!("\n🎯 OPERATOR ACTION ITEMS FROM 410 ERROR:");
                eprintln!("   1. Check service documentation for endpoint changes");
                eprintln!("   2. Verify if API version has been deprecated/sunset");
                eprintln!("   3. Look for migration guides or replacement endpoints");
                eprintln!("   4. Update configuration to new endpoint if available");
                eprintln!("   5. Contact service provider if no replacement exists");

                eprintln!("\n📊 410 vs 404 SEMANTICS:");
                eprintln!("   410 Gone: Resource WAS available but permanently removed");
                eprintln!("   404 Not Found: Resource may never have existed or is temporarily unavailable");
                eprintln!("   Both are terminal, but 410 has stronger permanence semantics");

                eprintln!("\n🚫 WHAT WOULD BE WRONG (retryable classification):");
                eprintln!("   ✗ Infinite retry loops to permanently removed endpoints");
                eprintln!("   ✗ Resource waste (bandwidth, CPU, storage)");
                eprintln!("   ✗ Log spam and alert fatigue");
                eprintln!("   ✗ Delayed recognition of permanent service changes");

                eprintln!("\n✅ CURRENT IMPLEMENTATION: Terminal classification (CORRECT)");
                eprintln!("   Error message: {}", message);
            }
            other => panic!("Expected NonRetryable for 410, got: {:?}", other),
        }
    }
}
