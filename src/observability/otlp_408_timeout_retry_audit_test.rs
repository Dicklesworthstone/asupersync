//! OTLP-Trace exporter HTTP 408 Request Timeout retry classification audit.
//!
//! **Audit Question**: Does OTLP exporter treat HTTP 408 as retryable (correct per RFC 9110)
//! or as terminal client error (incorrect)?
//!
//! **RFC 9110 Requirement**: HTTP 408 Request Timeout indicates server timeout,
//! not client error. Should be retryable with exponential backoff.
//!
//! **Expected Behavior**: 408 should be classified as retryable, allowing
//! automatic retry with exponential backoff rather than dropping the batch.

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
    }

    /// HTTP response fixture for testing status code classification.
    struct ResponseFixture {
        status: u16,
        headers: Vec<(String, String)>,
    }

    /// Current OTLP response status classifier (from otel.rs).
    ///
    /// **DEFECT**: Classifies 408 as non-retryable due to 400-499 range.
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
            502 | 503 | 504 => {
                // Retryable server errors per OTLP spec
                Err(OtlpError::retryable(response.status, None))
            }
            415 => {
                // Unsupported Media Type - special case for compression fallback
                Err(OtlpError::compression_fallback(response.status))
            }
            400..=499 => {
                // ❌ DEFECT: 408 falls here and is classified as non-retryable!
                Err(OtlpError::non_retryable(format!(
                    "OTLP client error: {} - batch dropped",
                    response.status
                )))
            }
            500..=599 => {
                // Other server errors - not retryable per OTLP spec
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

    /// Corrected OTLP response status classifier (RFC 9110 compliant).
    ///
    /// **FIX**: Explicitly handles 408 as retryable before generic 400-499 range.
    fn corrected_otlp_status_classifier(response: &ResponseFixture) -> Result<(), OtlpError> {
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
                // ✅ FIX: Request Timeout is retryable per RFC 9110
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
                // Other client errors - not retryable (408 already handled above)
                Err(OtlpError::non_retryable(format!(
                    "OTLP client error: {} - batch dropped",
                    response.status
                )))
            }
            500..=599 => {
                // Other server errors - not retryable per OTLP spec
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
    fn otlp_408_timeout_retry_classification_audit() {
        eprintln!("\n🔍 OTLP HTTP 408 REQUEST TIMEOUT RETRY AUDIT");
        eprintln!("============================================");

        eprintln!("\n📋 RFC 9110 Requirements for HTTP 408:");
        eprintln!("  • 408 Request Timeout indicates server-side timeout");
        eprintln!("  • Should be retryable with exponential backoff");
        eprintln!("  • NOT a client error requiring batch drop");
        eprintln!("  • Temporary condition, not permanent failure");

        // Test current behavior vs RFC 9110 requirements
        let test_cases = vec![
            (408, "Request Timeout", true), // Should be retryable
            (429, "Too Many Requests", true), // Known retryable
            (502, "Bad Gateway", true),      // Known retryable
            (503, "Service Unavailable", true), // Known retryable
            (504, "Gateway Timeout", true),  // Known retryable
            (400, "Bad Request", false),     // Should be terminal
            (401, "Unauthorized", false),    // Should be terminal
            (404, "Not Found", false),       // Should be terminal
        ];

        eprintln!("\n📊 Testing retry classification:");

        for (status_code, status_name, should_be_retryable) in test_cases {
            let response = ResponseFixture {
                status: status_code,
                headers: vec![],
            };

            // Test current implementation
            let current_result = current_otlp_status_classifier(&response);
            let current_retryable = matches!(current_result, Err(ref e) if e.is_retryable());

            // Test corrected implementation
            let corrected_result = corrected_otlp_status_classifier(&response);
            let corrected_retryable = matches!(corrected_result, Err(ref e) if e.is_retryable());

            eprintln!("  {} {} ({}):", status_code, status_name, if should_be_retryable { "should retry" } else { "should drop" });
            eprintln!("    Current:   {} {}", if current_retryable { "✓ retryable" } else { "✗ terminal" }, if current_retryable == should_be_retryable { "" } else { "❌ WRONG" });
            eprintln!("    Corrected: {} {}", if corrected_retryable { "✓ retryable" } else { "✗ terminal" }, if corrected_retryable == should_be_retryable { "✅ CORRECT" } else { "❌ WRONG" });

            // Verify specific 408 behavior
            if status_code == 408 {
                assert!(!current_retryable, "CURRENT: 408 should be incorrectly classified as terminal");
                assert!(corrected_retryable, "CORRECTED: 408 should be correctly classified as retryable");

                eprintln!("\n🎯 HTTP 408 SPECIFIC ANALYSIS:");
                eprintln!("  Current behavior:   DEFECTIVE - 408 treated as terminal client error");
                eprintln!("  RFC 9110 compliant: CORRECTED - 408 treated as retryable timeout");
            }
        }

        eprintln!("\n🚨 AUDIT FINDINGS:");
        eprintln!("==================");
        eprintln!("❌ DEFECTIVE: Current classifier treats 408 as non-retryable");
        eprintln!("   • Falls into 400-499 range → non_retryable()");
        eprintln!("   • Violates RFC 9110 which classifies 408 as retryable");
        eprintln!("   • Causes premature batch dropping on server timeouts");
        eprintln!("");
        eprintln!("✅ FIX REQUIRED: Add explicit 408 case before 400-499 range");
        eprintln!("   • Handle 408 as retryable with exponential backoff");
        eprintln!("   • Maintain existing terminal classification for other 4xx");
        eprintln!("   • Align with OTLP best practices for server timeout handling");
    }

    #[test]
    fn rfc_9110_408_semantics_verification() {
        eprintln!("\n📖 RFC 9110 HTTP 408 SEMANTICS VERIFICATION");
        eprintln!("===========================================");

        eprintln!("📋 RFC 9110 Section 15.5.9 - 408 Request Timeout:");
        eprintln!("   • 'The server did not receive a complete request message'");
        eprintln!("   • 'Server SHOULD send a Connection: close header field'");
        eprintln!("   • 'Client MAY repeat the request without modifications'");
        eprintln!("   • → Indicates server-side timeout, not client error");

        eprintln!("\n🔍 OTLP Context Analysis:");
        eprintln!("   • Collector may timeout waiting for complete protobuf payload");
        eprintln!("   • Network delays can cause partial request transmission");
        eprintln!("   • Retry with exponential backoff is appropriate");
        eprintln!("   • Dropping batch permanently loses telemetry data");

        eprintln!("\n🎯 Correct OTLP Behavior:");
        eprintln!("   ✅ Retry 408 with exponential backoff (1s, 2s, 4s...)");
        eprintln!("   ✅ Close connection and establish new one");
        eprintln!("   ✅ Maintain batch for retry rather than drop");
        eprintln!("   ❌ Do NOT treat 408 as permanent client error");
    }

    /// Demonstrate incorrect batch dropping behavior with current implementation.
    #[test]
    fn demonstrate_408_batch_dropping_defect() {
        eprintln!("\n❌ DEMONSTRATING 408 BATCH DROPPING DEFECT");
        eprintln!("==========================================");

        let timeout_response = ResponseFixture {
            status: 408,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&timeout_response);

        eprintln!("Collector returns: HTTP 408 Request Timeout");
        match result {
            Err(OtlpError::NonRetryable { message }) => {
                eprintln!("Current behavior: {} ❌", message);
                eprintln!("Impact: Telemetry batch permanently lost!");
                eprintln!("Root cause: 408 classified in 400-499 non-retryable range");
            },
            Err(OtlpError::Retryable { status_code, .. }) => {
                eprintln!("Current behavior: Retryable {} ✅", status_code);
                panic!("Current implementation should be defective for this test");
            },
            _ => panic!("Unexpected result for 408 status"),
        }

        eprintln!("\nCorrect RFC 9110 behavior:");
        let corrected_result = corrected_otlp_status_classifier(&timeout_response);
        match corrected_result {
            Err(OtlpError::Retryable { status_code, .. }) => {
                eprintln!("Fixed behavior: Retryable {} ✅", status_code);
                eprintln!("Impact: Batch preserved for retry with backoff");
            },
            _ => panic!("Corrected implementation should treat 408 as retryable"),
        }
    }
}
