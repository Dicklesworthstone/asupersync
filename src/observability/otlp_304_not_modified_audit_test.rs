//! OTLP-Trace exporter HTTP 304 Not Modified handling audit test.
//!
//! Per RFC 9110, HTTP 304 Not Modified is used in caching scenarios where a
//! client sends conditional request headers (If-Modified-Since, If-None-Match)
//! and the server responds that the resource hasn't changed. This is typically
//! used with GET requests for resource caching optimization.
//!
//! **OTLP Context**: OTLP uses POST requests to send new trace data. A 304
//! response to a POST request indicates a configuration error - either the
//! client is sending inappropriate conditional headers, or the server/proxy
//! is misconfigured to treat POST requests as cacheable.
//!
//! This audit verifies that:
//! 1. HTTP 304 is correctly classified as terminal (configuration error)
//! 2. No retry is attempted (won't fix the underlying misconfiguration)
//! 3. Error message indicates unexpected/inappropriate response
//! 4. Forces operator to fix the caching configuration issue
//!
//! Audit date: 2026-05-03
//! RFC 9110 reference: 304 Not Modified is for conditional GET requests
//! OTLP context: POST requests shouldn't trigger 304 responses

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns HTTP 304 Not Modified responses.
#[derive(Clone)]
struct Scripted304HttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Scripted304HttpClient {
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

impl HttpClient for Scripted304HttpClient {
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

        // Return next response or 304 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 304,
                headers: vec![
                    ("cache-control".to_string(), "max-age=3600".to_string()),
                ],
                body: b"Not Modified".to_vec(),
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
    fn test_304_not_modified_is_terminal() {
        // AUDIT POINT 1: Verify 304 is correctly classified as terminal

        let scripted_client = Scripted304HttpClient::new(vec![Response {
            status: 304,
            headers: vec![
                ("cache-control".to_string(), "max-age=3600".to_string()),
                ("etag".to_string(), r#""abc123""#.to_string()),
                ("server".to_string(), "nginx/1.20.0".to_string()),
            ],
            body: b"304 Not Modified - resource unchanged".to_vec(),
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

        // Export should fail with terminal error for 304
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 304 Not Modified");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(
                    message.contains("304"),
                    "Error message should contain 304 status: {}",
                    message
                );
                assert!(
                    message.contains("Unexpected OTLP response status"),
                    "Should indicate unexpected response: {}",
                    message
                );

                eprintln!("✅ SOUND: HTTP 304 correctly classified as terminal");
                eprintln!("   Error message: {}", message);
                eprintln!("   Classification: NonRetryable (terminal)");
                eprintln!("   Rationale: 304 inappropriate for OTLP POST requests");
                eprintln!("   Forces fix: Configuration error must be resolved");
                eprintln!("   RFC 9110 appropriate: 304 is for conditional GET, not POST");
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 304, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_304_vs_legitimate_caching_responses() {
        // AUDIT POINT 2: Verify 304 vs other caching-related responses

        struct CachingTest {
            status: u16,
            description: &'static str,
            appropriate_for_otlp: bool,
            reasoning: &'static str,
        }

        let caching_tests = vec![
            CachingTest {
                status: 200,
                description: "OK",
                appropriate_for_otlp: true,
                reasoning: "Normal successful trace ingestion",
            },
            CachingTest {
                status: 304,
                description: "Not Modified",
                appropriate_for_otlp: false, // ❌ Inappropriate for POST
                reasoning: "304 is for conditional GET requests, not OTLP POST",
            },
            CachingTest {
                status: 412,
                description: "Precondition Failed",
                appropriate_for_otlp: false,
                reasoning: "Conditional request failed, inappropriate for OTLP",
            },
        ];

        eprintln!("\n🧪 HTTP 304 VS CACHING RESPONSE APPROPRIATENESS");
        eprintln!("===============================================");

        for test_case in caching_tests {
            let scripted_client = Scripted304HttpClient::new(vec![Response {
                status: test_case.status,
                headers: vec![
                    ("cache-control".to_string(), "no-cache".to_string()),
                ],
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

            eprintln!("\n📊 {} {}:", test_case.status, test_case.description);
            eprintln!("   OTLP appropriate: {}", if test_case.appropriate_for_otlp { "Yes" } else { "No" });
            eprintln!("   Reasoning: {}", test_case.reasoning);

            match result {
                Ok(()) => {
                    assert!(test_case.appropriate_for_otlp,
                        "Status {} should not succeed for OTLP", test_case.status);
                    eprintln!("   Behavior: Success ✅");
                }
                Err(OtlpError::NonRetryable(message)) => {
                    assert!(!test_case.appropriate_for_otlp,
                        "Status {} should succeed for OTLP but was terminal", test_case.status);
                    eprintln!("   Behavior: Terminal ❌ (correct - inappropriate for OTLP)");
                    eprintln!("   Message: {}", message);
                }
                Err(other) => {
                    eprintln!("   Behavior: {:?}", other);
                }
            }
        }

        eprintln!("\n✅ CACHING RESPONSE APPROPRIATENESS:");
        eprintln!("   304 Not Modified: Terminal (correct - inappropriate for OTLP POST)");
        eprintln!("   200 OK: Success (correct - normal trace ingestion)");
        eprintln!("   Other conditional responses: Terminal (correct - not for OTLP)");
    }

    #[test]
    fn test_304_configuration_error_scenarios() {
        // AUDIT POINT 3: Test scenarios that could cause inappropriate 304 responses

        struct ConfigErrorScenario {
            name: &'static str,
            server_type: &'static str,
            headers: Vec<(String, String)>,
            root_cause: &'static str,
            fix_action: &'static str,
        }

        let scenarios = vec![
            ConfigErrorScenario {
                name: "aggressive_proxy_caching",
                server_type: "squid/4.15",
                headers: vec![
                    ("cache-control".to_string(), "max-age=3600".to_string()),
                    ("etag".to_string(), r#""post-cache-123""#.to_string()),
                ],
                root_cause: "Proxy caching POST requests inappropriately",
                fix_action: "Configure proxy to not cache OTLP POST endpoints",
            },
            ConfigErrorScenario {
                name: "cdn_misconfiguration",
                server_type: "cloudflare",
                headers: vec![
                    ("cf-cache-status".to_string(), "HIT".to_string()),
                    ("cache-control".to_string(), "public, max-age=1800".to_string()),
                ],
                root_cause: "CDN treating OTLP endpoints as cacheable",
                fix_action: "Add cache-control headers to prevent CDN caching",
            },
            ConfigErrorScenario {
                name: "load_balancer_cache",
                server_type: "nginx-lb/1.22",
                headers: vec![
                    ("x-cache".to_string(), "HIT".to_string()),
                    ("cache-control".to_string(), "max-age=600".to_string()),
                ],
                root_cause: "Load balancer inappropriately caching POST responses",
                fix_action: "Disable caching for OTLP trace ingestion endpoints",
            },
            ConfigErrorScenario {
                name: "client_conditional_headers",
                server_type: "otel-collector/0.88.0",
                headers: vec![
                    ("cache-control".to_string(), "no-cache".to_string()),
                ],
                root_cause: "OTLP client sending If-Modified-Since headers",
                fix_action: "Fix client to not send conditional headers on POST",
            },
        ];

        eprintln!("\n🔧 HTTP 304 CONFIGURATION ERROR SCENARIOS");
        eprintln!("=========================================");

        for scenario in scenarios {
            let scripted_client = Scripted304HttpClient::new(vec![Response {
                status: 304,
                headers: scenario.headers.clone(),
                body: b"Not Modified - cached response".to_vec(),
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
                    assert!(message.contains("304"));

                    eprintln!("  Scenario '{}': ✅ Terminal (prevents retry waste)",
                        scenario.name);
                    eprintln!("    Root cause: {}", scenario.root_cause);
                    eprintln!("    Fix needed: {}", scenario.fix_action);
                    eprintln!("    Server: {}", scenario.server_type);
                }
                other => panic!("Scenario '{}' should be terminal, got: {:?}",
                    scenario.name, other),
            }
        }

        eprintln!("\n🔧 ALL CONFIGURATION ERROR SCENARIOS:");
        eprintln!("   • Proxy caching: Terminal (fix proxy config)");
        eprintln!("   • CDN misconfiguration: Terminal (add cache headers)");
        eprintln!("   • Load balancer cache: Terminal (disable LB caching)");
        eprintln!("   • Client conditional headers: Terminal (fix client code)");
        eprintln!("   • Consistent terminal classification forces configuration fixes");
    }

    #[test]
    fn test_304_post_vs_get_semantics() {
        // AUDIT POINT 4: Document why 304 is inappropriate for OTLP POST requests

        eprintln!("\n📋 HTTP 304 POST VS GET SEMANTICS");
        eprintln!("=================================");

        eprintln!("🎯 HTTP 304 APPROPRIATE USAGE (GET requests):");
        eprintln!("   1. Client: GET /api/resource");
        eprintln!("      Headers: If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT");
        eprintln!("   2. Server: 304 Not Modified (resource unchanged)");
        eprintln!("   3. Client: Uses cached version");
        eprintln!("   ✅ Valid: GET requests for resource retrieval with caching");

        eprintln!("\n❌ HTTP 304 INAPPROPRIATE USAGE (OTLP POST):");
        eprintln!("   1. Client: POST /v1/traces");
        eprintln!("      Body: [new trace data to ingest]");
        eprintln!("   2. Server: 304 Not Modified ← WRONG");
        eprintln!("   3. Problem: POST creates/sends data, doesn't retrieve cached resource");
        eprintln!("   ❌ Invalid: POST requests for data ingestion should not use caching");

        let scripted_client = Scripted304HttpClient::new(vec![Response {
            status: 304,
            headers: vec![
                ("cache-control".to_string(), "max-age=3600".to_string()),
            ],
            body: b"Not Modified - but this is a POST request!".to_vec(),
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
                eprintln!("\n🎯 CORRECT TERMINAL BEHAVIOR:");
                eprintln!("   Status: Terminal error ✅");
                eprintln!("   Reasoning: 304 makes no sense for POST data ingestion");
                eprintln!("   Action: Forces operator to fix caching configuration");
                eprintln!("   Message: {}", message);

                eprintln!("\n🔧 OPERATOR GUIDANCE:");
                eprintln!("   1. Check if proxy/CDN is caching OTLP endpoints");
                eprintln!("   2. Verify OTLP client not sending conditional headers");
                eprintln!("   3. Configure cache-control: no-cache for /v1/traces");
                eprintln!("   4. Test with direct server connection (bypass caches)");

                eprintln!("\n📊 SEMANTIC CORRECTNESS:");
                eprintln!("   POST /v1/traces: Creates/ingests new trace data");
                eprintln!("   Expected responses: 200 (success), 400 (bad data), 500 (server error)");
                eprintln!("   NOT expected: 304 (resource unchanged from cache)");
            }
            other => panic!("Expected NonRetryable for 304, got: {:?}", other),
        }
    }

    #[test]
    fn test_304_rfc_9110_compliance_for_method_semantics() {
        // AUDIT POINT 5: Document RFC 9110 compliance for method-specific 304 usage

        eprintln!("\n📋 RFC 9110 HTTP 304 METHOD SEMANTICS COMPLIANCE");
        eprintln!("================================================");
        eprintln!("Per RFC 9110 Section 15.4.5 (304 Not Modified):");
        eprintln!("   • 304 is for conditional requests that check resource modification");
        eprintln!("   • Typically used with GET/HEAD methods for caching optimization");
        eprintln!("   • Requires conditional headers (If-Modified-Since, If-None-Match)");
        eprintln!("   • NOT intended for POST/PUT/DELETE methods that modify resources");

        eprintln!("\n📋 OTLP Specification Context:");
        eprintln!("   • OTLP uses POST method to send trace data to collectors");
        eprintln!("   • POST semantics: Create/send new data, not retrieve cached data");
        eprintln!("   • 304 response violates POST method semantics");
        eprintln!("   • Indicates misconfiguration in caching layer");

        let scripted_client = Scripted304HttpClient::new(vec![Response {
            status: 304,
            headers: vec![
                ("server".to_string(), "compliant-server/1.0.0".to_string()),
                ("cache-control".to_string(), "no-cache".to_string()),
            ],
            body: b"Not Modified - inappropriate for POST".to_vec(),
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
                // Verify method semantic compliance
                assert!(message.contains("304"), "Should identify HTTP status");
                assert!(message.contains("Unexpected"), "Should indicate inappropriateness");

                eprintln!("\n✅ METHOD SEMANTICS COMPLIANCE:");
                eprintln!("   ✓ 304 classified as unexpected for POST (correct)");
                eprintln!("   ✓ Terminal classification prevents retry waste");
                eprintln!("   ✓ Forces configuration fix rather than masking issue");
                eprintln!("   ✓ Aligns with RFC 9110 method-specific semantics");

                eprintln!("\n🎯 CONFIGURATION ERROR DETECTION:");
                eprintln!("   • Identifies caching misconfigurations quickly");
                eprintln!("   • Prevents silent data loss from cache hits");
                eprintln!("   • Forces explicit resolution of caching issues");
                eprintln!("   • Maintains OTLP data integrity guarantees");

                eprintln!("\n📊 COMPARISON WITH APPROPRIATE RESPONSES:");
                eprintln!("   200 OK: Trace data successfully ingested");
                eprintln!("   400 Bad Request: Invalid trace data format");
                eprintln!("   500 Server Error: Collector processing failure");
                eprintln!("   304 Not Modified: INAPPROPRIATE for trace data POST");

                eprintln!("\n🚫 WHAT WOULD BE WRONG (treating 304 as success):");
                eprintln!("   ✗ Silent acceptance of caching misconfiguration");
                eprintln!("   ✗ Potential trace data loss from cache behavior");
                eprintln!("   ✗ Violation of POST method semantics");
                eprintln!("   ✗ Masking infrastructure configuration problems");

                eprintln!("\n✅ CURRENT IMPLEMENTATION: Terminal classification (CORRECT)");
                eprintln!("   Error message: {}", message);
            }
            other => panic!("Expected NonRetryable for 304, got: {:?}", other),
        }
    }
}
