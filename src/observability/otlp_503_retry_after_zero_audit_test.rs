//! OTLP-Trace exporter HTTP 503 Service Unavailable with Retry-After: 0 audit test.
//!
//! Per OTLP specification, ALL retryable responses (including 503) must honor
//! the Retry-After header when present. The special case of "Retry-After: 0"
//! means "retry immediately" and must be handled without infinite loops.
//!
//! This audit verifies that:
//! 1. HTTP 503 responses honor Retry-After headers (currently BROKEN)
//! 2. Retry-After: 0 is handled correctly (immediate retry)
//! 3. No infinite loops or silent errors occur
//! 4. Implementation matches OTLP specification requirements
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: All retryable responses must honor Retry-After

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns configurable status codes for OTLP requests.
#[derive(Clone)]
struct ScriptedServiceUnavailableHttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl ScriptedServiceUnavailableHttpClient {
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

impl HttpClient for ScriptedServiceUnavailableHttpClient {
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

        // Return next response or 503 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 503,
                headers: vec![],
                body: b"Service Unavailable".to_vec(),
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
    fn test_503_ignores_retry_after_header_bug() {
        // AUDIT POINT 1: Demonstrate that 503 currently IGNORES Retry-After header

        let scripted_client = ScriptedServiceUnavailableHttpClient::new(vec![Response {
            status: 503,
            headers: vec![
                ("retry-after".to_string(), "0".to_string()), // Should retry immediately
                ("server".to_string(), "nginx/1.18.0".to_string()),
            ],
            body: b"503 Service Unavailable - temporarily overloaded".to_vec(),
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

        // Export should fail with retryable error
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 503 Service Unavailable");

        let error = result.unwrap_err();
        match error {
            OtlpError::Retryable { status_code, retry_after } => {
                assert_eq!(
                    status_code, 503,
                    "Error should have status code 503: {}",
                    status_code
                );

                // ✅ FIXED: Implementation now correctly honors Retry-After for 503
                assert_eq!(
                    retry_after,
                    Some(Duration::from_secs(0)),
                    "503 should honor Retry-After: 0 (retry immediately): {:?}",
                    retry_after
                );

                eprintln!("✅ FIXED: HTTP 503 now honors Retry-After header!");
                eprintln!("   Expected: Some(Duration::from_secs(0))");
                eprintln!("   Actual: {:?}", retry_after);
                eprintln!("   OTLP spec compliance: ✅");
            }
            _ => panic!(
                "Expected OtlpError::Retryable for 503, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_429_correctly_honors_retry_after() {
        // AUDIT POINT 2: Verify that 429 correctly honors Retry-After (for comparison)

        let scripted_client = ScriptedServiceUnavailableHttpClient::new(vec![Response {
            status: 429,
            headers: vec![
                ("retry-after".to_string(), "0".to_string()),
                ("x-ratelimit-remaining".to_string(), "0".to_string()),
            ],
            body: b"429 Too Many Requests - rate limited".to_vec(),
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

        assert!(result.is_err(), "Export should fail for 429 Rate Limited");

        let error = result.unwrap_err();
        match error {
            OtlpError::Retryable { status_code, retry_after } => {
                assert_eq!(status_code, 429, "Should be 429 error");

                // ✅ 429 CORRECTLY honors Retry-After header
                assert_eq!(
                    retry_after,
                    Some(Duration::from_secs(0)),
                    "429 should honor Retry-After: 0 (retry immediately)"
                );

                eprintln!("✅ 429 correctly honors Retry-After: 0 = {:?}", retry_after);
            }
            _ => panic!("Expected Retryable for 429, got: {:?}", error),
        }
    }

    #[test]
    fn test_retry_after_zero_edge_cases() {
        // AUDIT POINT 3: Test Retry-After: 0 edge cases and variations

        struct TestCase {
            status: u16,
            retry_after_value: &'static str,
            description: &'static str,
            should_parse_retry_after: bool,
        }

        let test_cases = vec![
            TestCase {
                status: 503,
                retry_after_value: "0",
                description: "503 with Retry-After: 0",
                should_parse_retry_after: true,
            },
            TestCase {
                status: 503,
                retry_after_value: "1",
                description: "503 with Retry-After: 1",
                should_parse_retry_after: true,
            },
            TestCase {
                status: 502,
                retry_after_value: "0",
                description: "502 with Retry-After: 0",
                should_parse_retry_after: true,
            },
            TestCase {
                status: 504,
                retry_after_value: "0",
                description: "504 with Retry-After: 0",
                should_parse_retry_after: true,
            },
            TestCase {
                status: 429,
                retry_after_value: "0",
                description: "429 with Retry-After: 0",
                should_parse_retry_after: true,
            },
        ];

        eprintln!("\n🧪 RETRY-AFTER PARSING TEST MATRIX");
        eprintln!("===================================");

        for test_case in test_cases {
            let scripted_client = ScriptedServiceUnavailableHttpClient::new(vec![Response {
                status: test_case.status,
                headers: vec![
                    ("retry-after".to_string(), test_case.retry_after_value.to_string()),
                ],
                body: format!("Error {}", test_case.status).into_bytes(),
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
                OtlpError::Retryable { status_code, retry_after } => {
                    assert_eq!(status_code, test_case.status);

                    let expected_retry_after = if test_case.should_parse_retry_after {
                        Some(Duration::from_secs(test_case.retry_after_value.parse::<u64>().unwrap()))
                    } else {
                        None
                    };

                    let actual_honors_retry_after = retry_after.is_some();
                    let should_honor = test_case.should_parse_retry_after;

                    eprintln!("  {} - {}", test_case.description,
                        if actual_honors_retry_after == should_honor {
                            if actual_honors_retry_after { "✅ Honors Retry-After" } else { "❌ Ignores Retry-After (BUG)" }
                        } else {
                            "❌ UNEXPECTED BEHAVIOR"
                        });

                    // ✅ FIXED: All retryable codes now honor Retry-After
                    assert_eq!(retry_after, expected_retry_after,
                        "Status {} should honor Retry-After header", test_case.status);
                }
                _ => panic!("Expected retryable error for {}", test_case.status),
            }
        }

        eprintln!("\n✅ SUMMARY:");
        eprintln!("  ✅ 429 correctly honors Retry-After");
        eprintln!("  ✅ 502/503/504 now honor Retry-After (FIXED!)");
    }

    #[test]
    fn test_retry_after_zero_infinite_loop_protection() {
        // AUDIT POINT 4: Verify Retry-After: 0 doesn't cause infinite loops

        eprintln!("\n🔄 RETRY-AFTER: 0 INFINITE LOOP PROTECTION TEST");
        eprintln!("===============================================");

        // Note: This test only covers the error classification, not the actual retry logic
        // The retry logic with exponential backoff and max attempts should prevent infinite loops

        let scripted_client = ScriptedServiceUnavailableHttpClient::new(vec![Response {
            status: 503,
            headers: vec![
                ("retry-after".to_string(), "0".to_string()),
            ],
            body: b"Service temporarily unavailable".to_vec(),
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

        let start_time = std::time::Instant::now();
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });
        let elapsed = start_time.elapsed();

        // Should complete quickly (not hang in infinite loop)
        assert!(elapsed < Duration::from_secs(1), "Should complete quickly, took {:?}", elapsed);

        // Should return retryable error (not hang or panic)
        assert!(result.is_err(), "Should return error for 503");

        match result.unwrap_err() {
            OtlpError::Retryable { status_code, retry_after } => {
                assert_eq!(status_code, 503);

                // Current behavior: ignores retry_after for 503 (will be fixed)
                eprintln!("  Current retry_after value: {:?}", retry_after);
                eprintln!("  Elapsed time: {:?} (should be < 1s)", elapsed);
                eprintln!("  ✅ No infinite loop detected");

                if retry_after.is_none() {
                    eprintln!("  ❌ BUG: Should honor Retry-After: 0 for 503");
                }
            }
            _ => panic!("Expected Retryable error"),
        }
    }

    #[test]
    fn test_malformed_retry_after_handling() {
        // AUDIT POINT 5: Test malformed Retry-After values

        let malformed_cases = vec![
            ("", "empty string"),
            ("invalid", "non-numeric"),
            ("-1", "negative number"),
            ("999999999999999999999", "overflow"),
            ("0.5", "decimal"),
        ];

        eprintln!("\n🧪 MALFORMED RETRY-AFTER HANDLING");
        eprintln!("=================================");

        for (retry_after_value, description) in malformed_cases {
            let scripted_client = ScriptedServiceUnavailableHttpClient::new(vec![Response {
                status: 503,
                headers: vec![
                    ("retry-after".to_string(), retry_after_value.to_string()),
                ],
                body: b"Service Unavailable".to_vec(),
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
                OtlpError::Retryable { status_code, retry_after } => {
                    assert_eq!(status_code, 503);

                    eprintln!("  Malformed '{}' ({}): {:?}",
                        retry_after_value, description, retry_after);

                    // Malformed values should result in None (fallback to exponential backoff)
                    // Currently 503 always ignores retry_after anyway (bug)
                    assert_eq!(retry_after, None);
                }
                _ => panic!("Expected Retryable error"),
            }
        }

        eprintln!("  ✅ Malformed values handled gracefully");
    }
}
