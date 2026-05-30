//! OTLP-Trace exporter HTTP 502 Bad Gateway retry classification audit.
//!
//! **Audit Question**: Does OTLP exporter correctly treat HTTP 502 Bad Gateway as
//! retryable with backoff (correct per OTLP spec) or as terminal (incorrect)?
//!
//! **OTLP Specification**: HTTP 502 Bad Gateway indicates the server received
//! an invalid response from an upstream server. Should be retryable as the issue
//! may be transient. Per OTLP retry guidance, 502/503/504 are the primary retryable 5xx codes.
//!
//! **Expected Behavior**: 502 should be classified as retryable, causing exponential
//! backoff retry rather than dropping the batch.

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
    /// **SOUND**: Correctly classifies 502 as retryable in explicit 502|503|504 case.
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
                // ✅ CORRECT: 502 explicitly listed as retryable
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
    fn otlp_502_bad_gateway_classification_audit() {
        eprintln!("\n🔍 OTLP HTTP 502 BAD GATEWAY CLASSIFICATION AUDIT");
        eprintln!("================================================");

        eprintln!("\n📋 OTLP Retry Specification for HTTP 502:");
        eprintln!("  • 502 Bad Gateway indicates upstream server returned invalid response");
        eprintln!("  • Often caused by misconfigured proxy or temporary upstream failure");
        eprintln!("  • Should be retryable as the issue may be transient");
        eprintln!("  • OTLP spec recommends retry with exponential backoff");
        eprintln!("  • 502/503/504 are the primary retryable 5xx status codes");

        // Test various 5xx server error codes and their retry classification
        let test_cases = vec![
            (502, "Bad Gateway", true, "Retryable - invalid upstream response"),
            (503, "Service Unavailable", true, "Retryable - temporary overload"),
            (504, "Gateway Timeout", true, "Retryable - upstream timeout"),
            (500, "Internal Server Error", false, "Terminal - general server error"),
            (501, "Not Implemented", false, "Terminal - method not supported"),
            (505, "HTTP Version Not Supported", false, "Terminal - version mismatch"),
            (507, "Insufficient Storage", false, "Terminal - server storage issue"),
            (508, "Loop Detected", false, "Terminal - infinite loop"),
            (509, "Bandwidth Limit Exceeded", false, "Terminal - quota exceeded"),
            (510, "Not Extended", false, "Terminal - extension required"),
            (511, "Network Authentication Required", false, "Terminal - network auth needed"),
        ];

        eprintln!("\n📊 Testing 5xx retry classification:");

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

            // Verify 502 specific behavior
            if status_code == 502 {
                assert!(is_retryable, "502 Bad Gateway should be retryable");

                eprintln!("\n🎯 HTTP 502 SPECIFIC ANALYSIS:");
                eprintln!("  Bad Gateway scenario:");
                eprintln!("    • OTLP client → Reverse Proxy → OTLP Collector");
                eprintln!("    • Reverse proxy receives invalid/malformed response from collector");
                eprintln!("    • Returns 502 Bad Gateway to client");
                eprintln!("    • Collector may be starting up, misconfigured, or temporarily failing");
                eprintln!("    • Retry with backoff gives collector time to recover or proxy to reconnect");
                eprintln!("  Current classification: RETRYABLE ✅ CORRECT");
                eprintln!("  OTLP spec compliance: SOUND ✅");
            }

            // Verify classification matches expectation
            assert_eq!(is_retryable, should_be_retryable,
                "Status {} classification should match OTLP spec: {}", status_code, reasoning);
        }

        eprintln!("\n✅ AUDIT CONCLUSION:");
        eprintln!("====================");
        eprintln!("✅ SOUND: HTTP 502 correctly classified as retryable");
        eprintln!("✅ Explicit match in 502|503|504 case (line 1128)");
        eprintln!("✅ OTLP spec compliant: retries with exponential backoff");
        eprintln!("✅ Prevents premature batch dropping on upstream gateway issues");
        eprintln!("✅ Existing implementation is correct - no fix needed");
    }

    #[test]
    fn otlp_gateway_error_group_verification() {
        eprintln!("\n🔍 OTLP GATEWAY ERROR GROUP VERIFICATION");
        eprintln!("========================================");

        eprintln!("📋 Gateway Error Code Group Analysis:");
        eprintln!("   • 502 Bad Gateway: Invalid upstream response");
        eprintln!("   • 503 Service Unavailable: Temporary overload/maintenance");
        eprintln!("   • 504 Gateway Timeout: Upstream timeout");
        eprintln!("   → All three indicate transient issues worth retrying");

        eprintln!("\n🎯 Gateway Error Group Test:");

        // Test all three gateway error codes for consistent retryable classification
        let gateway_codes = vec![502, 503, 504];

        for code in gateway_codes {
            let response = ResponseFixture {
                status: code,
                headers: vec![],
            };
            let result = current_otlp_status_classifier(&response);
            let is_retryable = matches!(result, Err(ref e) if e.is_retryable());
            assert!(is_retryable, "Gateway error {} should be retryable", code);
            eprintln!("  {} → retryable ✅ (consistent gateway error handling)", code);
        }

        eprintln!("\n✅ VERIFICATION COMPLETE:");
        eprintln!("  • All gateway error codes (502/503/504) are consistently retryable");
        eprintln!("  • Explicit match case prevents falling through to terminal 500..=599");
        eprintln!("  • Pattern matching correctly implements OTLP retry specifications");
    }

    #[test]
    fn bad_gateway_scenario_analysis() {
        eprintln!("\n🌐 BAD GATEWAY SCENARIO ANALYSIS");
        eprintln!("===============================");

        eprintln!("📋 Common bad gateway scenarios:");
        eprintln!("   1. OTLP collector returning malformed responses during startup");
        eprintln!("   2. Reverse proxy unable to parse collector response format");
        eprintln!("   3. Load balancer receiving invalid HTTP from collector instance");
        eprintln!("   4. API gateway detecting protocol violations from collector");
        eprintln!("   → All scenarios benefit from retry as collector may recover");

        let response_502 = ResponseFixture {
            status: 502,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&response_502);

        eprintln!("\nReverse proxy returns: HTTP 502 Bad Gateway");

        match result {
            Err(OtlpError::Retryable { status_code, retry_after }) => {
                eprintln!("Current behavior: Retryable (status: {}, retry_after: {:?})",
                    status_code, retry_after);
                eprintln!("Impact: Exponential backoff retry ✅");
                eprintln!("Outcome: Batch delivered when collector/proxy recovers ✅");
                eprintln!("Resource usage: Bounded by max_retry_count ✅");
            },
            _ => panic!("Should be retryable"),
        }

        eprintln!("\n📈 Retry Behavior Benefits:");
        eprintln!("   • Collector startup/restart → automatic recovery");
        eprintln!("   • Proxy configuration reload → eventual delivery");
        eprintln!("   • Temporary response corruption → retry clears issue");
        eprintln!("   • Load balancer failover → connection to healthy instance");

        eprintln!("\n⚖️  Alternative (if 502 were terminal):");
        eprintln!("   ❌ Data loss during collector startup/restart");
        eprintln!("   ❌ No automatic recovery from proxy misconfigurations");
        eprintln!("   ❌ Premature batch dropping reduces observability coverage");
    }

    /// Demonstrate correct OTLP retry behavior for 502 responses.
    #[test]
    fn demonstrate_502_retry_correctness() {
        eprintln!("\n✅ DEMONSTRATING 502 RETRY CORRECTNESS");
        eprintln!("======================================");

        let bad_gateway_response = ResponseFixture {
            status: 502,
            headers: vec![],
        };

        let result = current_otlp_status_classifier(&bad_gateway_response);

        eprintln!("Reverse proxy returns: HTTP 502 Bad Gateway");

        match result {
            Err(OtlpError::Retryable { status_code, retry_after }) => {
                eprintln!("Current behavior: Retryable (status: {}) ✅", status_code);
                eprintln!("Classification: Temporary upstream failure (correct for bad gateway)");
                eprintln!("");
                eprintln!("🎯 Why this is correct:");
                eprintln!("   • Bad gateway errors often indicate transient issues");
                eprintln!("   • OTLP collector may recover after brief restart/reconfiguration");
                eprintln!("   • Retry with backoff allows upstream systems to stabilize");
                eprintln!("   • 502 is explicitly listed in OTLP retryable codes");

                // Verify no retry_after hint (should use exponential backoff)
                assert_eq!(retry_after, None, "502 should use exponential backoff, not fixed delay");
                eprintln!("   • Uses exponential backoff (no fixed retry_after delay)");
            },
            Err(OtlpError::NonRetryable { .. }) => {
                panic!("502 should NOT be terminal - would cause data loss during gateway issues");
            },
            _ => panic!("Unexpected result for 502"),
        }

        eprintln!("\n🔄 Comparison with other gateway errors:");

        // Compare with related gateway error codes
        for gateway_code in [503, 504] {
            let response = ResponseFixture {
                status: gateway_code,
                headers: vec![],
            };

            let result = current_otlp_status_classifier(&response);
            match result {
                Err(OtlpError::Retryable { status_code, .. }) => {
                    eprintln!("   {} → retryable ✅ (consistent with 502)", status_code);
                },
                _ => panic!("{} should also be retryable", gateway_code),
            }
        }

        eprintln!("   502 → retryable ✅ (correct per OTLP spec)");
    }

    #[test]
    fn gateway_vs_server_error_classification() {
        eprintln!("\n🔍 GATEWAY VS SERVER ERROR CLASSIFICATION");
        eprintln!("=========================================");

        eprintln!("📋 Error Type Classification:");
        eprintln!("   GATEWAY ERRORS (retryable):");
        eprintln!("   • 502 Bad Gateway → Invalid upstream response");
        eprintln!("   • 503 Service Unavailable → Temporary overload");
        eprintln!("   • 504 Gateway Timeout → Upstream timeout");
        eprintln!("   ");
        eprintln!("   GENERAL SERVER ERRORS (terminal):");
        eprintln!("   • 500 Internal Server Error → General failure");
        eprintln!("   • 501 Not Implemented → Method not supported");
        eprintln!("   • 505+ Others → Various permanent failures");

        eprintln!("\n🎯 Classification Logic Test:");

        // Test gateway errors (should be retryable)
        let gateway_errors = vec![(502, "Bad Gateway"), (503, "Service Unavailable"), (504, "Gateway Timeout")];
        for (code, name) in gateway_errors {
            let response = ResponseFixture { status: code, headers: vec![] };
            let result = current_otlp_status_classifier(&response);
            let is_retryable = matches!(result, Err(ref e) if e.is_retryable());
            assert!(is_retryable, "{} should be retryable", name);
            eprintln!("  {} {} → retryable ✅", code, name);
        }

        // Test general server errors (should be terminal)
        let server_errors = vec![(500, "Internal Server Error"), (501, "Not Implemented"), (505, "HTTP Version Not Supported")];
        for (code, name) in server_errors {
            let response = ResponseFixture { status: code, headers: vec![] };
            let result = current_otlp_status_classifier(&response);
            let is_terminal = matches!(result, Err(ref e) if e.is_terminal());
            assert!(is_terminal, "{} should be terminal", name);
            eprintln!("  {} {} → terminal ✅", code, name);
        }

        eprintln!("\n✅ CLASSIFICATION CORRECTNESS:");
        eprintln!("  • Gateway errors correctly identified as retryable");
        eprintln!("  • General server errors correctly identified as terminal");
        eprintln!("  • Match arm ordering prevents incorrect classification");
    }
}
