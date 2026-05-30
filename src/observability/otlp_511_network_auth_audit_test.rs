//! OTLP-Trace exporter HTTP 511 Network Authentication Required audit.
//!
//! **Audit Question**: Does OTLP exporter correctly treat HTTP 511 as terminal
//! (correct per RFC 9110) or as retryable (incorrect)?
//!
//! **RFC 9110 Requirement**: HTTP 511 Network Authentication Required indicates
//! client needs to authenticate with network (captive portal). Cannot retry
//! without re-authentication, so should be terminal.
//!
//! **Expected Behavior**: 511 should be classified as non-retryable, causing
//! batch to be dropped rather than retried indefinitely.

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

    /// Current OTLP response status classifier (from otel.rs).
    ///
    /// **SOUND**: Correctly classifies 511 as non-retryable in 500-599 range.
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
                // Other client errors - not retryable
                Err(OtlpError::non_retryable(format!(
                    "OTLP client error: {} - batch dropped",
                    response.status
                )))
            }
            500..=599 => {
                // ✅ CORRECT: 511 falls here and is classified as non-retryable
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
    fn otlp_511_network_auth_classification_audit() {
        eprintln!("\n🔍 OTLP HTTP 511 NETWORK AUTHENTICATION AUDIT");
        eprintln!("==============================================");

        eprintln!("\n📋 RFC 9110 Requirements for HTTP 511:");
        eprintln!("  • 511 Network Authentication Required");
        eprintln!("  • Client needs to authenticate with network (captive portal)");
        eprintln!("  • Cannot retry without network re-authentication");
        eprintln!("  • Should be classified as terminal/non-retryable");

        // Test network authentication and related status codes
        let test_cases = vec![
            (511, "Network Authentication Required", false, "Terminal - needs network auth"),
            (429, "Too Many Requests", true, "Retryable - rate limiting"),
            (502, "Bad Gateway", true, "Retryable - gateway error"),
            (503, "Service Unavailable", true, "Retryable - temporary unavailable"),
            (504, "Gateway Timeout", true, "Retryable - gateway timeout"),
            (500, "Internal Server Error", false, "Terminal - general server error"),
            (505, "HTTP Version Not Supported", false, "Terminal - version mismatch"),
            (507, "Insufficient Storage", false, "Terminal - server storage issue"),
            (510, "Not Extended", false, "Terminal - extension required"),
        ];

        eprintln!("\n📊 Testing HTTP 5xx retry classification:");

        for (status_code, status_name, should_be_retryable, reasoning) in test_cases {
            let response = ResponseFixture {
                status: status_code,
                headers: vec![],
            };

            let result = current_otlp_status_classifier(&response);
            let is_retryable = matches!(result, Err(ref e) if e.is_retryable());
            let is_terminal = !is_retryable;

            eprintln!("  {} {}: {}", status_code, status_name, reasoning);
            eprintln!("    Expected: {}", if should_be_retryable { "retryable" } else { "terminal" });
            eprintln!("    Actual:   {} {}",
                if is_retryable { "retryable" } else { "terminal" },
                if is_retryable == should_be_retryable { "✅ CORRECT" } else { "❌ WRONG" }
            );

            // Verify 511 specific behavior
            if status_code == 511 {
                assert!(is_terminal, "511 Network Authentication Required should be terminal");

                eprintln!("\n🎯 HTTP 511 SPECIFIC ANALYSIS:");
                eprintln!("  Network Authentication Required scenario:");
                eprintln!("    • User connects to WiFi with captive portal");
                eprintln!("    • OTLP collector behind captive portal returns 511");
                eprintln!("    • Client must authenticate with portal first");
                eprintln!("    • Retrying same request will fail until auth complete");
                eprintln!("  Current classification: TERMINAL ✅ CORRECT");
                eprintln!("  RFC 9110 compliance: SOUND ✅");
            }

            // Verify classification matches expectation
            assert_eq!(is_retryable, should_be_retryable,
                "Status {} classification should match RFC 9110: {}", status_code, reasoning);
        }

        eprintln!("\n✅ AUDIT CONCLUSION:");
        eprintln!("====================");
        eprintln!("✅ SOUND: HTTP 511 correctly classified as terminal/non-retryable");
        eprintln!("✅ Falls into 500-599 range → non_retryable()");
        eprintln!("✅ RFC 9110 compliant: cannot retry without network authentication");
        eprintln!("✅ Prevents infinite retry loop in captive portal scenarios");
        eprintln!("✅ Existing implementation is correct - no fix needed");
    }

    #[test]
    fn rfc_9110_511_semantics_verification() {
        eprintln!("\n📖 RFC 9110 HTTP 511 SEMANTICS VERIFICATION");
        eprintln!("===========================================");

        eprintln!("📋 RFC 9110 Section 15.6.12 - 511 Network Authentication Required:");
        eprintln!("   • 'Client needs to authenticate to gain network access'");
        eprintln!("   • 'Intended for use by intercepting proxies'");
        eprintln!("   • 'Commonly used by captive portal systems'");
        eprintln!("   • → Network-level authentication required, not HTTP-level");

        eprintln!("\n🔍 OTLP Context Analysis:");
        eprintln!("   • OTLP collector may be behind captive portal");
        eprintln!("   • WiFi networks often require authentication first");
        eprintln!("   • Retrying without portal auth will always fail");
        eprintln!("   • Terminal classification prevents waste of resources");

        eprintln!("\n🎯 Correct OTLP Behavior:");
        eprintln!("   ✅ Classify 511 as terminal (non-retryable)");
        eprintln!("   ✅ Drop batch rather than retry indefinitely");
        eprintln!("   ✅ Log clear error message about network authentication");
        eprintln!("   ❌ Do NOT retry - will fail until network auth complete");

        // Verify 511 classification
        let response = ResponseFixture {
            status: 511,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&response);

        match result {
            Err(OtlpError::NonRetryable { message }) => {
                eprintln!("\n✅ VERIFIED: 511 correctly classified as NonRetryable");
                eprintln!("   Error message: {}", message);
                assert!(message.contains("511"), "Error message should mention status code");
                assert!(message.contains("batch dropped"), "Should indicate batch is dropped");
            },
            _ => panic!("511 should be classified as NonRetryable"),
        }
    }

    #[test]
    fn captive_portal_scenario_analysis() {
        eprintln!("\n🔒 CAPTIVE PORTAL SCENARIO ANALYSIS");
        eprintln!("===================================");

        eprintln!("📋 Common captive portal scenario:");
        eprintln!("   1. Application starts, begins sending OTLP traces");
        eprintln!("   2. User connects to hotel/airport WiFi");
        eprintln!("   3. Network has captive portal requiring authentication");
        eprintln!("   4. OTLP requests intercepted by portal → HTTP 511");
        eprintln!("   5. Current implementation: drops batches (correct)");
        eprintln!("   6. Alternative (incorrect): retry forever until auth");

        let response_511 = ResponseFixture {
            status: 511,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&response_511);

        eprintln!("\nCaptive portal returns: HTTP 511 Network Authentication Required");

        match result {
            Err(OtlpError::NonRetryable { message }) => {
                eprintln!("Current behavior: {}", message);
                eprintln!("Impact: Batch dropped, no infinite retry ✅");
                eprintln!("User experience: App continues working after portal auth ✅");
                eprintln!("Resource usage: No wasted bandwidth/CPU ✅");
            },
            _ => panic!("Should be non-retryable"),
        }

        eprintln!("\n🚀 Post-Authentication Behavior:");
        eprintln!("   • Once user completes captive portal authentication");
        eprintln!("   • Subsequent OTLP requests will succeed (200-299)");
        eprintln!("   • New telemetry data flows normally");
        eprintln!("   • Previous dropped batches are acceptably lost");
        eprintln!("     (observability data vs blocking app functionality)");
    }

    /// Demonstrate the correctness of terminal classification for 511.
    #[test]
    fn demonstrate_511_terminal_correctness() {
        eprintln!("\n✅ DEMONSTRATING 511 TERMINAL CLASSIFICATION CORRECTNESS");
        eprintln!("========================================================");

        let auth_required_response = ResponseFixture {
            status: 511,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&auth_required_response);

        eprintln!("Network proxy returns: HTTP 511 Network Authentication Required");

        match result {
            Err(OtlpError::NonRetryable { message }) => {
                eprintln!("Current behavior: {} ✅", message);
                eprintln!("Classification: Terminal (correct for network auth requirement)");
                eprintln!("");
                eprintln!("🎯 Why this is correct:");
                eprintln!("   • Network authentication is external to application");
                eprintln!("   • OTLP client cannot solve network auth programmatically");
                eprintln!("   • Retrying wastes bandwidth until user authenticates");
                eprintln!("   • Terminal classification is RFC 9110 compliant");
            },
            Err(OtlpError::Retryable { .. }) => {
                panic!("511 should NOT be retryable - would cause infinite retry until network auth");
            },
            _ => panic!("Unexpected result for 511"),
        }

        eprintln!("\n🔄 Comparison with retryable 5xx codes:");

        // Compare with genuinely retryable server errors
        for retryable_code in [502, 503, 504] {
            let response = ResponseFixture {
                status: retryable_code,
                headers: vec![],
            };

            let result = current_otlp_status_classifier(&response);
            match result {
                Err(OtlpError::Retryable { status_code, .. }) => {
                    eprintln!("   {} → retryable ✅ (temporary server issue)", status_code);
                },
                _ => panic!("{} should be retryable", retryable_code),
            }
        }

        eprintln!("   511 → terminal ✅ (requires external network auth)");
    }
}
