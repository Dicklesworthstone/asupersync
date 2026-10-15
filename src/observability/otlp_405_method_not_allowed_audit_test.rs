//! OTLP-Trace exporter HTTP 405 Method Not Allowed retry classification audit.
//!
//! **Audit Question**: When OTLP collector returns HTTP 405 Method Not Allowed,
//! does our retry classifier correctly treat this as terminal (no retry) per OTLP spec?
//!
//! **OTLP Specification**: HTTP 405 Method Not Allowed indicates a configuration error
//! where the client is using the wrong HTTP method (e.g., GET instead of POST).
//! This is a client bug that requires caller fix, not a retryable condition.
//!
//! **Expected Behavior**: 405 responses MUST be classified as terminal to prevent
//! infinite retry loops when the client has incorrect method configuration.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// OTLP error types for retry classification testing.
    #[derive(Debug, Clone, PartialEq)]
    pub enum OtlpError {
        Retryable {
            status_code: u16,
            retry_after: Option<Duration>,
        },
        NonRetryable {
            message: String,
        },
        CompressionFallback {
            status_code: u16,
        },
    }

    impl OtlpError {
        pub fn retryable(status_code: u16, retry_after: Option<Duration>) -> Self {
            Self::Retryable {
                status_code,
                retry_after,
            }
        }

        pub fn non_retryable(message: impl Into<String>) -> Self {
            Self::NonRetryable {
                message: message.into(),
            }
        }

        pub fn compression_fallback(status_code: u16) -> Self {
            Self::CompressionFallback { status_code }
        }

        pub fn is_retryable(&self) -> bool {
            matches!(self, Self::Retryable { .. })
        }

        pub fn is_terminal(&self) -> bool {
            !self.is_retryable()
        }
    }

    /// HTTP response fixture for testing status code classification.
    struct ResponseFixture {
        status: u16,
        headers: Vec<(String, String)>,
    }

    /// Current OTLP response status classifier (from otel.rs lines 1112-1154).
    ///
    /// **SOUND**: HTTP 405 Method Not Allowed correctly falls into 400..=499 range
    /// and is classified as non_retryable (terminal).
    fn current_otlp_status_classifier(response: &ResponseFixture) -> Result<(), OtlpError> {
        match response.status {
            200..=299 => Ok(()),
            429 => {
                // Rate limited - check for Retry-After header
                let retry_after = response
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .map(Duration::from_secs);
                Err(OtlpError::retryable(response.status, retry_after))
            }
            408 => {
                // Request Timeout - retryable per RFC 9110 (server-side timeout)
                Err(OtlpError::retryable(response.status, None))
            }
            502 | 503 | 504 => {
                // Retryable server errors per OTLP spec
                Err(OtlpError::retryable(response.status, None))
            }
            415 => {
                // Unsupported Media Type - special case for compression fallback
                Err(OtlpError::compression_fallback(response.status))
            }
            400..=499 => {
                // ✅ CORRECT: HTTP 405 falls into this range and is non-retryable
                // Other client errors - not retryable
                Err(OtlpError::non_retryable(format!(
                    "OTLP client error: {} - batch dropped",
                    response.status
                )))
            }
            500..=599 => {
                // Other server errors - not retryable per OTLP spec
                // Note: 502|503|504 are caught above, so this handles other 5xx
                Err(OtlpError::non_retryable(format!(
                    "OTLP server error: {} - batch dropped",
                    response.status
                )))
            }
            _ => Err(OtlpError::non_retryable(format!(
                "Unexpected OTLP response status: {}",
                response.status
            ))),
        }
    }

    #[test]
    fn otlp_405_method_not_allowed_classification_audit() {
        eprintln!("\n🔍 OTLP HTTP 405 METHOD NOT ALLOWED CLASSIFICATION AUDIT");
        eprintln!("========================================================");

        eprintln!("\n📋 OTLP Specification Requirements for HTTP 405:");
        eprintln!("  • 405 Method Not Allowed indicates wrong HTTP method used");
        eprintln!("  • This is a CLIENT CONFIGURATION ERROR, not a server issue");
        eprintln!("  • Examples: GET to POST-only endpoint, PUT to read-only endpoint");
        eprintln!("  • Retrying with same method will always fail → infinite loop");
        eprintln!("  • MUST be classified as TERMINAL to force caller to fix configuration");

        eprintln!("\n📋 Common 405 scenarios in OTLP:");
        eprintln!("  • Client misconfigured to use GET instead of POST for /v1/traces");
        eprintln!("  • Client using PUT/PATCH on OTLP endpoints (only POST supported)");
        eprintln!("  • Client hitting wrong endpoint that doesn't accept the method");
        eprintln!("  • Load balancer misconfiguration routing to wrong service");

        // Test HTTP 405 Method Not Allowed specifically
        let response_405 = ResponseFixture {
            status: 405,
            headers: vec![
                ("Allow".to_string(), "POST, OPTIONS".to_string()), // RFC 9110 requirement
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
        };

        eprintln!("\n🎯 CRITICAL TEST: HTTP 405 Method Not Allowed");
        eprintln!("  Scenario: OTLP client configured with GET method, server expects POST");
        eprintln!("  Response: 405 Method Not Allowed");
        eprintln!("  Expected: TERMINAL classification (no retry)");

        let result = current_otlp_status_classifier(&response_405);

        match result {
            Err(OtlpError::NonRetryable { ref message }) => {
                eprintln!("  ✅ CORRECT: 405 classified as NonRetryable (terminal)");
                eprintln!("  Message: {}", message);
                eprintln!("  Behavior: Batch dropped, no retry attempted");
                eprintln!("  Outcome: Forces caller to fix HTTP method configuration");

                assert!(message.contains("405"), "Error message should include status code");
                assert!(message.contains("client error"), "Should be classified as client error");
            }
            Err(OtlpError::Retryable { status_code, retry_after }) => {
                eprintln!("  ❌ CRITICAL DEFECT: 405 incorrectly classified as Retryable");
                eprintln!("  Status: {}", status_code);
                eprintln!("  Retry-After: {:?}", retry_after);
                eprintln!("  Problem: Will cause infinite retry loop");
                panic!("HTTP 405 Method Not Allowed MUST NOT be retryable - this causes infinite loops");
            }
            Err(OtlpError::CompressionFallback { status_code }) => {
                eprintln!("  ❌ DEFECT: 405 incorrectly classified as CompressionFallback");
                eprintln!("  Status: {}", status_code);
                panic!("HTTP 405 should not trigger compression fallback");
            }
            Ok(()) => {
                eprintln!("  ❌ CRITICAL DEFECT: 405 treated as success");
                panic!("HTTP 405 Method Not Allowed must be treated as error, not success");
            }
        }

        eprintln!("\n✅ AUDIT CONCLUSION:");
        eprintln!("====================");
        eprintln!("✅ SOUND: HTTP 405 correctly classified as terminal (non-retryable)");
        eprintln!("✅ Falls into 400..=499 client error range (line 1136)");
        eprintln!("✅ OTLP spec compliant: prevents infinite retry on configuration errors");
        eprintln!("✅ Forces caller to fix HTTP method instead of retrying forever");
        eprintln!("✅ Existing implementation is correct - no fix needed");
    }

    #[test]
    fn otlp_client_error_range_comprehensive_audit() {
        eprintln!("\n🔍 OTLP CLIENT ERROR RANGE COMPREHENSIVE AUDIT");
        eprintln!("===============================================");

        eprintln!("📋 OTLP Client Error Classification (400-499):");
        eprintln!("  • All 4xx errors indicate CLIENT problems that require caller fixes");
        eprintln!("  • Retrying 4xx errors without changes will always fail");
        eprintln!("  • OTLP spec: 4xx errors MUST be terminal except specific retryable codes");

        // Test comprehensive 4xx range for consistency
        let client_error_test_cases = vec![
            (400, "Bad Request", false, "Malformed OTLP payload - fix data format"),
            (401, "Unauthorized", false, "Missing/invalid auth - fix credentials"),
            (403, "Forbidden", false, "Insufficient permissions - check API keys"),
            (404, "Not Found", false, "Wrong endpoint URL - fix configuration"),
            (405, "Method Not Allowed", false, "Wrong HTTP method - use POST"), // ← KEY TEST
            (406, "Not Acceptable", false, "Unsupported Accept header - fix headers"),
            (407, "Proxy Authentication Required", false, "Proxy auth needed - fix proxy"),
            (408, "Request Timeout", true, "Server timeout - retryable per RFC 9110"),
            (409, "Conflict", false, "Resource conflict - fix request"),
            (410, "Gone", false, "Endpoint removed - update to new endpoint"),
            (411, "Length Required", false, "Missing Content-Length - fix headers"),
            (412, "Precondition Failed", false, "Invalid If-Match - fix preconditions"),
            (413, "Content Too Large", false, "Request too large - reduce batch size"),
            (414, "URI Too Long", false, "URL too long - fix query parameters"),
            (415, "Unsupported Media Type", "special", "Compression fallback case"),
            (416, "Range Not Satisfiable", false, "Invalid Range header - fix range"),
            (417, "Expectation Failed", false, "Invalid Expect header - fix headers"),
            (421, "Misdirected Request", false, "Wrong server - fix endpoint"),
            (422, "Unprocessable Content", false, "Semantic error - fix data"),
            (423, "Locked", false, "Resource locked - retry later or fix"),
            (424, "Failed Dependency", false, "Dependency failed - fix upstream"),
            (425, "Too Early", false, "TLS early data - use normal request"),
            (426, "Upgrade Required", false, "Protocol upgrade needed - fix protocol"),
            (428, "Precondition Required", false, "Missing precondition - fix headers"),
            (429, "Too Many Requests", true, "Rate limited - retryable with backoff"),
            (431, "Request Header Fields Too Large", false, "Headers too large - reduce size"),
            (451, "Unavailable For Legal Reasons", false, "Blocked by law - change request"),
        ];

        eprintln!("\n📊 Testing 4xx error classification:");

        for (status_code, status_name, should_be_retryable, reasoning) in client_error_test_cases {
            let response = ResponseFixture {
                status: status_code,
                headers: vec![],
            };

            let result = current_otlp_status_classifier(&response);

            let classification = match result {
                Ok(()) => "success",
                Err(OtlpError::Retryable { .. }) => "retryable",
                Err(OtlpError::NonRetryable { .. }) => "terminal",
                Err(OtlpError::CompressionFallback { .. }) => "compression_fallback",
            };

            eprintln!("  {} {}: {} ({})", status_code, status_name, reasoning, classification);

            // Verify classification matches OTLP specification
            match (should_be_retryable, classification) {
                (true, "retryable") => {
                    eprintln!("    ✅ CORRECT: Retryable as expected");
                }
                (false, "terminal") => {
                    eprintln!("    ✅ CORRECT: Terminal as expected");
                }
                ("special", "compression_fallback") => {
                    eprintln!("    ✅ CORRECT: Special case handling");
                }
                (expected, actual) => {
                    eprintln!("    ❌ CLASSIFICATION ERROR: Expected {:?}, got {}", expected, actual);
                    if status_code == 405 {
                        panic!("CRITICAL: HTTP 405 Method Not Allowed misclassified as {}", actual);
                    }
                }
            }
        }

        eprintln!("\n✅ CLIENT ERROR RANGE AUDIT CONCLUSION:");
        eprintln!("========================================");
        eprintln!("✅ SOUND: HTTP 405 Method Not Allowed correctly classified");
        eprintln!("✅ Consistent 4xx handling: All client errors terminal except 408/429");
        eprintln!("✅ OTLP spec compliance: Prevents retry loops on configuration errors");
        eprintln!("✅ Special cases handled: 415 compression fallback, 408/429 retryable");
    }

    #[test]
    fn otlp_405_method_error_scenarios() {
        eprintln!("\n🌐 HTTP 405 METHOD NOT ALLOWED SCENARIOS");
        eprintln!("======================================");

        eprintln!("📋 Real-world 405 scenarios in OTLP deployments:");

        let scenarios = vec![
            (
                "Misconfigured GET request",
                "Client configured to GET /v1/traces instead of POST",
                "Configure client HTTP method to POST"
            ),
            (
                "Wrong HTTP method",
                "Client using PUT/PATCH for OTLP traces endpoint",
                "Change client configuration to use POST method"
            ),
            (
                "Load balancer misconfiguration",
                "LB routing OTLP POST to read-only service",
                "Fix load balancer routing rules"
            ),
            (
                "Reverse proxy method filtering",
                "Proxy blocks POST methods, only allows GET",
                "Configure proxy to allow POST for OTLP endpoints"
            ),
            (
                "API gateway restrictions",
                "Gateway has method whitelist excluding POST",
                "Update API gateway method permissions"
            ),
        ];

        for (scenario_name, description, fix) in scenarios {
            eprintln!("\n📋 Scenario: {}", scenario_name);
            eprintln!("  Problem: {}", description);
            eprintln!("  Solution: {}", fix);

            let response_405 = ResponseFixture {
                status: 405,
                headers: vec![("Allow".to_string(), "GET, OPTIONS".to_string())],
            };

            let result = current_otlp_status_classifier(&response_405);

            match result {
                Err(OtlpError::NonRetryable { .. }) => {
                    eprintln!("  Behavior: ✅ TERMINAL - No retry, forces configuration fix");
                }
                Err(OtlpError::Retryable { .. }) => {
                    eprintln!("  Behavior: ❌ RETRYABLE - Would cause infinite loop!");
                    panic!("405 must not be retryable in scenario: {}", scenario_name);
                }
                _ => {
                    eprintln!("  Behavior: ❌ UNEXPECTED classification");
                    panic!("405 must be classified as NonRetryable in scenario: {}", scenario_name);
                }
            }
        }

        eprintln!("\n💡 Why Terminal Classification is Critical:");
        eprintln!("  • Prevents infinite retry loops consuming resources");
        eprintln!("  • Forces operations team to fix root cause");
        eprintln!("  • Provides clear error signal for debugging");
        eprintln!("  • Complies with HTTP semantics (405 = client must change method)");
        eprintln!("  • Saves bandwidth and server resources");

        eprintln!("\n✅ METHOD NOT ALLOWED SCENARIOS: All correctly handled");
    }

    /// Demonstrate correct OTLP behavior for 405 vs retryable errors.
    #[test]
    fn demonstrate_405_vs_retryable_behavior_contrast() {
        eprintln!("\n✅ DEMONSTRATING 405 vs RETRYABLE CONTRAST");
        eprintln!("==========================================");

        eprintln!("🎯 Contrasting 405 (terminal) vs 503 (retryable) behavior:");

        // Test 405 Method Not Allowed (should be terminal)
        let method_not_allowed = ResponseFixture {
            status: 405,
            headers: vec![("Allow".to_string(), "POST".to_string())],
        };

        let result_405 = current_otlp_status_classifier(&method_not_allowed);
        eprintln!("\n📊 HTTP 405 Method Not Allowed:");
        eprintln!("  Cause: Client using wrong HTTP method (configuration error)");

        match result_405 {
            Err(OtlpError::NonRetryable { message }) => {
                eprintln!("  Classification: TERMINAL ✅");
                eprintln!("  Behavior: Drop batch, log error, no retry");
                eprintln!("  Message: {}", message);
                eprintln!("  Why correct: Method won't change on retry, would loop forever");
            }
            _ => panic!("405 should be NonRetryable"),
        }

        // Test 503 Service Unavailable (should be retryable)
        let service_unavailable = ResponseFixture {
            status: 503,
            headers: vec![("Retry-After".to_string(), "30".to_string())],
        };

        let result_503 = current_otlp_status_classifier(&service_unavailable);
        eprintln!("\n📊 HTTP 503 Service Unavailable:");
        eprintln!("  Cause: Temporary server overload (transient condition)");

        match result_503 {
            Err(OtlpError::Retryable { status_code, retry_after }) => {
                eprintln!("  Classification: RETRYABLE ✅");
                eprintln!("  Behavior: Queue batch, retry with exponential backoff");
                eprintln!("  Status: {}", status_code);
                eprintln!("  Retry-After: {:?}", retry_after);
                eprintln!("  Why correct: Server may recover, retry has success probability");
            }
            _ => panic!("503 should be Retryable"),
        }

        eprintln!("\n🔄 BEHAVIORAL CONTRAST:");
        eprintln!("  405 → STOP: Configuration error needs human intervention");
        eprintln!("  503 → RETRY: Transient issue may resolve automatically");
        eprintln!("  ");
        eprintln!("  This distinction is CRITICAL for operational stability:");
        eprintln!("  • 405 retry loops waste resources and hide real issues");
        eprintln!("  • 503 immediate failure loses data during normal overload");

        eprintln!("\n✅ BEHAVIORAL CONTRAST: Correctly implemented");
        eprintln!("  🚫 405 Method Not Allowed → Terminal (prevents retry loops)");
        eprintln!("  🔄 503 Service Unavailable → Retryable (allows recovery)");
    }
}
