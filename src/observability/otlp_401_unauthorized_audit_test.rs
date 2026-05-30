//! OTLP-Trace exporter HTTP 401 Unauthorized handling audit test.
//!
//! Per OTLP specification, HTTP 401 Unauthorized responses indicate that
//! authentication is required and must be treated as terminal (non-retryable)
//! errors. Retrying without providing proper authentication credentials is
//! wasteful and violates the OTLP retry semantics.
//!
//! This audit verifies that:
//! 1. HTTP 401 is correctly classified as OtlpError::NonRetryable
//! 2. No retry attempts are made for authentication failures
//! 3. The error message indicates the batch was dropped (terminal)
//! 4. Related auth errors (403 Forbidden) are also handled correctly
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: Client error responses (4xx) should not be retried
//!
//! ## AUDIT SUMMARY: HTTP 401 UNAUTHORIZED - SOUND
//!
//! **Date**: 2026-05-03
//! **Auditor**: Claude (asupersync OTLP audit)
//! **Scope**: HTTP 401 Unauthorized response classification in OTLP-Trace exporter
//!
//! ### COMPLIANCE VERIFICATION ✅
//!
//! The implementation correctly treats HTTP 401 Unauthorized as a **terminal error**:
//! - Falls into `400..=499` client error range (line 1136-1142 in otel.rs)
//! - Classified as `OtlpError::NonRetryable` (non-retryable)
//! - No retry attempts are made for authentication failures
//! - Error message indicates "batch dropped" for proper telemetry
//!
//! ### OTLP SPECIFICATION COMPLIANCE ✅
//!
//! Per OTLP specification:
//! - Client errors (4xx) should not be retried
//! - 401 Unauthorized indicates authentication is required
//! - Retrying without providing proper auth credentials is wasteful
//! - The caller must provide authentication before any retry attempt
//!
//! ### AUDIT TEST COVERAGE
//!
//! This audit test suite verifies:
//! 1. **HTTP 401 is terminal** - No retries attempted
//! 2. **Related auth errors** - 403 Forbidden also terminal
//! 3. **Classification correctness** - Auth vs retryable error distinction
//! 4. **Realistic scenarios** - WWW-Authenticate header present
//! 5. **Sequence behavior** - 401 terminates even after previous successes
//! 6. **Complete 4xx coverage** - All client errors are terminal (except special cases)
//!
//! ### CONCLUSION
//!
//! **BEHAVIOR: SOUND** ✅
//!
//! The OTLP-Trace exporter correctly handles HTTP 401 Unauthorized responses
//! per OTLP specification requirements. This audit test pins the expected
//! behavior to prevent future regressions.

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
struct ScriptedAuthHttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl ScriptedAuthHttpClient {
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

impl HttpClient for ScriptedAuthHttpClient {
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

        // Return next response or 401 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 401,
                headers: vec![],
                body: b"Unauthorized".to_vec(),
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
    fn test_401_unauthorized_is_terminal() {
        // AUDIT POINT 1: HTTP 401 must be treated as terminal (non-retryable)

        let scripted_client = ScriptedAuthHttpClient::new(vec![Response {
            status: 401,
            headers: vec![("www-authenticate".to_string(), "Bearer".to_string())],
            body: b"Authentication required".to_vec(),
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

        // Export should fail immediately with non-retryable error
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 401 Unauthorized");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable { message } => {
                assert!(
                    message.contains("401"),
                    "Error message should include 401 status: {}",
                    message
                );
                assert!(
                    message.contains("batch dropped"),
                    "Error message should indicate batch was dropped: {}",
                    message
                );
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 401, got: {:?}",
                error
            ),
        }

        // Should only make one request - no retries for auth failures
        assert_eq!(
            scripted_client.request_count(),
            1,
            "Should make exactly one request for 401 (no retries)"
        );
    }

    #[test]
    fn test_403_forbidden_also_terminal() {
        // AUDIT POINT 2: HTTP 403 Forbidden should also be terminal
        // (falls into same 400..=499 client error range)

        let scripted_client = ScriptedAuthHttpClient::new(vec![Response {
            status: 403,
            headers: vec![],
            body: b"Access denied".to_vec(),
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

        assert!(result.is_err(), "Export should fail for 403 Forbidden");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable { message } => {
                assert!(
                    message.contains("403"),
                    "Error message should include 403 status: {}",
                    message
                );
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 403, got: {:?}",
                error
            ),
        }

        assert_eq!(
            scripted_client.request_count(),
            1,
            "Should make exactly one request for 403 (no retries)"
        );
    }

    #[test]
    fn test_auth_vs_retryable_errors() {
        // AUDIT POINT 3: Compare auth errors (terminal) vs retryable errors

        struct TestCase {
            status: u16,
            description: &'static str,
            should_be_retryable: bool,
        }

        let test_cases = vec![
            TestCase {
                status: 401,
                description: "Unauthorized (auth required)",
                should_be_retryable: false,
            },
            TestCase {
                status: 403,
                description: "Forbidden (access denied)",
                should_be_retryable: false,
            },
            TestCase {
                status: 404,
                description: "Not Found (wrong endpoint)",
                should_be_retryable: false,
            },
            TestCase {
                status: 408,
                description: "Request Timeout (server timeout)",
                should_be_retryable: true,
            },
            TestCase {
                status: 429,
                description: "Rate Limited",
                should_be_retryable: true,
            },
            TestCase {
                status: 502,
                description: "Bad Gateway",
                should_be_retryable: true,
            },
            TestCase {
                status: 503,
                description: "Service Unavailable",
                should_be_retryable: true,
            },
        ];

        for test_case in test_cases {
            let scripted_client = ScriptedAuthHttpClient::new(vec![Response {
                status: test_case.status,
                headers: vec![],
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

            assert!(
                result.is_err(),
                "Export should fail for {}: {}",
                test_case.status,
                test_case.description
            );

            let error = result.unwrap_err();
            match (error, test_case.should_be_retryable) {
                (OtlpError::NonRetryable { .. }, false) => {
                    // Correct: non-retryable error for terminal status codes
                }
                (OtlpError::Retryable { .. }, true) => {
                    // Correct: retryable error for temporary failures
                }
                (OtlpError::CompressionFallback { .. }, _) => {
                    // Special case for 415 - not tested here
                }
                (actual_error, expected_retryable) => {
                    panic!(
                        "Incorrect classification for {} ({}): got {:?}, expected retryable={}",
                        test_case.status,
                        test_case.description,
                        actual_error,
                        expected_retryable
                    );
                }
            }
        }
    }

    #[test]
    fn test_401_with_www_authenticate_header() {
        // AUDIT POINT 4: WWW-Authenticate header present (realistic 401 scenario)

        let scripted_client = ScriptedAuthHttpClient::new(vec![Response {
            status: 401,
            headers: vec![
                ("www-authenticate".to_string(), "Bearer realm=\"OTLP\"".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            body: br#"{"error":"Authentication required","code":"UNAUTHENTICATED"}"#.to_vec(),
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

        // Should still be terminal despite realistic headers/body
        match result.unwrap_err() {
            OtlpError::NonRetryable { message } => {
                assert!(
                    message.contains("OTLP client error: 401"),
                    "Error should identify as client error: {}",
                    message
                );
            }
            err => panic!("Expected NonRetryable error, got: {:?}", err),
        }

        // Verify only one request was made (no retries)
        assert_eq!(scripted_client.request_count(), 1);

        let requests = scripted_client.get_requests();
        assert_eq!(requests[0].0, Method::Post);
        assert!(requests[0].1.contains("/v1/traces"));
    }

    #[test]
    fn test_401_after_success_sequence() {
        // AUDIT POINT 5: 401 terminates sequence even after previous successes
        // (e.g., auth token expired between requests)

        let scripted_client = ScriptedAuthHttpClient::new(vec![
            // Responses are popped in reverse order
            Response {
                status: 401,
                headers: vec![("www-authenticate".to_string(), "Bearer".to_string())],
                body: b"Token expired".to_vec(),
            },
            Response {
                status: 200,
                headers: vec![],
                body: Vec::new(),
            },
        ]);

        let exporter = OtlpHttpExporter::new(
            "http://localhost:4318/v1/traces".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            scripted_client.clone(),
        )
        .expect("Failed to create OTLP exporter");

        let cx = Cx::for_testing();
        let spans = vec![create_test_span()];

        // First export succeeds
        let result1 = cx.block_on(async { exporter.export_spans(&cx, &spans).await });
        assert!(result1.is_ok(), "First export should succeed");

        // Second export fails with 401 and should be terminal
        let result2 = cx.block_on(async { exporter.export_spans(&cx, &spans).await });
        assert!(result2.is_err(), "Second export should fail with 401");

        match result2.unwrap_err() {
            OtlpError::NonRetryable { message } => {
                assert!(message.contains("401"), "Should indicate 401 error: {}", message);
            }
            err => panic!("Expected NonRetryable for 401, got: {:?}", err),
        }

        // Should have made exactly 2 requests (no retries on the 401)
        assert_eq!(scripted_client.request_count(), 2);
    }

    #[test]
    fn test_client_error_range_coverage() {
        // AUDIT POINT 6: All 4xx client errors are terminal per OTLP spec

        let client_error_statuses = [400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 413, 414, 416, 417, 422, 423, 424, 426, 428, 431, 451];

        for &status in &client_error_statuses {
            // Skip 408 (Request Timeout) and 415 (Unsupported Media Type)
            // as they have special handling
            if status == 408 || status == 415 || status == 429 {
                continue;
            }

            let scripted_client = ScriptedAuthHttpClient::new(vec![Response {
                status,
                headers: vec![],
                body: format!("Client error {}", status).into_bytes(),
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
                OtlpError::NonRetryable { message } => {
                    assert!(
                        message.contains(&status.to_string()),
                        "Error should include status {}: {}",
                        status,
                        message
                    );
                    assert!(
                        message.contains("OTLP client error"),
                        "Error should identify as client error: {}",
                        message
                    );
                }
                err => panic!("Expected NonRetryable for {}, got: {:?}", status, err),
            }

            assert_eq!(
                scripted_client.request_count(),
                1,
                "Should make exactly one request for status {} (no retries)",
                status
            );
        }
    }
}
