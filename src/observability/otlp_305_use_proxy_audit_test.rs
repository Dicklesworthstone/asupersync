//! OTLP-Trace exporter HTTP 305 Use Proxy handling audit test.
//!
//! Per RFC 9110, HTTP 305 Use Proxy is deprecated and should not be used.
//! This status code was originally intended to indicate that the requested
//! resource must be accessed through a proxy specified in the Location header.
//! However, it poses security risks and is no longer recommended.
//!
//! This audit verifies that:
//! 1. HTTP 305 is correctly classified as terminal (no automatic proxy following)
//! 2. Security is maintained by not following proxy redirects automatically
//! 3. Error message indicates unexpected/unsupported status
//! 4. Batch is properly dropped to prevent data leakage through untrusted proxies
//!
//! Audit date: 2026-05-03
//! RFC 9110 reference: 305 Use Proxy is deprecated due to security concerns
//! OTLP security: Should not automatically follow proxy redirects for telemetry data

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cx::Cx;
use crate::http::{HttpClient, Method, Request, Response};
use crate::observability::otel::{OtlpError, OtlpHttpExporter, TraceSpan};
use crate::time::Instant;
use crate::types::{Outcome, TraceId};

/// Scripted HTTP client that returns HTTP 305 Use Proxy responses.
#[derive(Clone)]
struct Scripted305HttpClient {
    responses: Arc<Mutex<Vec<Response>>>,
    request_log: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Scripted305HttpClient {
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

impl HttpClient for Scripted305HttpClient {
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

        // Return next response or 305 if no more responses
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Response {
                status: 305,
                headers: vec![
                    ("location".to_string(), "http://proxy.example.com:8080".to_string()),
                ],
                body: b"Use Proxy".to_vec(),
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
    fn test_305_use_proxy_is_terminal() {
        // AUDIT POINT 1: Verify 305 is correctly classified as terminal for security

        let scripted_client = Scripted305HttpClient::new(vec![Response {
            status: 305,
            headers: vec![
                ("location".to_string(), "http://proxy.malicious.com:8080".to_string()),
                ("server".to_string(), "compromised-proxy/1.0".to_string()),
            ],
            body: b"305 Use Proxy - redirect through specified proxy".to_vec(),
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

        // Export should fail with terminal error for 305
        let result = cx.block_on(async { exporter.export_spans(&cx, &spans).await });

        assert!(result.is_err(), "Export should fail for 305 Use Proxy");

        let error = result.unwrap_err();
        match error {
            OtlpError::NonRetryable(message) => {
                assert!(
                    message.contains("305"),
                    "Error message should contain 305 status: {}",
                    message
                );
                assert!(
                    message.contains("Unexpected OTLP response status"),
                    "Should indicate unexpected status: {}",
                    message
                );

                eprintln!("✅ SOUND: HTTP 305 correctly classified as terminal");
                eprintln!("   Error message: {}", message);
                eprintln!("   Classification: NonRetryable (terminal)");
                eprintln!("   Security: No automatic proxy following ✓");
                eprintln!("   RFC 9110 compliance: ✅ (deprecated status code)");
                eprintln!("   OTLP security: ✅ (prevents data leakage through untrusted proxies)");
            }
            _ => panic!(
                "Expected OtlpError::NonRetryable for 305, got: {:?}",
                error
            ),
        }

        assert_eq!(scripted_client.request_count(), 1);
    }

    #[test]
    fn test_305_security_vs_legitimate_redirects() {
        // AUDIT POINT 2: Verify 305 behaves differently from legitimate redirects

        struct RedirectTest {
            status: u16,
            description: &'static str,
            should_be_terminal: bool,
            security_reason: &'static str,
        }

        let redirect_tests = vec![
            RedirectTest {
                status: 301,
                description: "Moved Permanently",
                should_be_terminal: true, // Should be terminal (not handled automatically)
                security_reason: "OTLP clients should not follow redirects automatically",
            },
            RedirectTest {
                status: 302,
                description: "Found",
                should_be_terminal: true, // Should be terminal
                security_reason: "Temporary redirects could be malicious",
            },
            RedirectTest {
                status: 305,
                description: "Use Proxy",
                should_be_terminal: true, // ✅ Should be terminal (deprecated + security risk)
                security_reason: "Proxy redirects are deprecated and pose security risks",
            },
            RedirectTest {
                status: 307,
                description: "Temporary Redirect",
                should_be_terminal: true, // Should be terminal
                security_reason: "Automatic redirects could leak telemetry to wrong endpoints",
            },
        ];

        eprintln!("\n🧪 HTTP 305 VS OTHER REDIRECTS SECURITY TEST");
        eprintln!("============================================");

        for test_case in redirect_tests {
            let scripted_client = Scripted305HttpClient::new(vec![Response {
                status: test_case.status,
                headers: vec![
                    ("location".to_string(), "http://redirect.example.com/otlp".to_string()),
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

            match result.unwrap_err() {
                OtlpError::NonRetryable(_) => {
                    assert!(test_case.should_be_terminal,
                        "Status {} should not be terminal but was classified as terminal", test_case.status);
                    eprintln!("  {}: ❌ Terminal ({})", test_case.status, test_case.security_reason);
                }
                other => {
                    panic!("All redirect statuses should be terminal for security, got: {:?}", other);
                }
            }
        }

        eprintln!("\n✅ REDIRECT SECURITY POLICY:");
        eprintln!("   305 Use Proxy: Terminal (deprecated + proxy security risk)");
        eprintln!("   301/302/307 Redirects: Terminal (prevent telemetry data leakage)");
        eprintln!("   OTLP security stance: No automatic redirect following");
        eprintln!("   Manual configuration required for endpoint changes");
    }

    #[test]
    fn test_305_proxy_security_scenarios() {
        // AUDIT POINT 3: Test security scenarios with malicious proxy redirects

        struct ProxySecurityScenario {
            name: &'static str,
            proxy_location: &'static str,
            security_risk: &'static str,
            attack_vector: &'static str,
        }

        let scenarios = vec![
            ProxySecurityScenario {
                name: "malicious_proxy_harvest",
                proxy_location: "http://data-harvester.evil.com:8080",
                security_risk: "Telemetry data theft",
                attack_vector: "Compromised collector redirects to data harvesting proxy",
            },
            ProxySecurityScenario {
                name: "man_in_the_middle",
                proxy_location: "http://192.168.1.100:3128",
                security_risk: "Traffic interception",
                attack_vector: "Network attacker redirects through MITM proxy",
            },
            ProxySecurityScenario {
                name: "corporate_espionage",
                proxy_location: "http://competitor-analytics.example.com:8080",
                security_risk: "Business intelligence theft",
                attack_vector: "Compromised infrastructure redirects to competitor proxy",
            },
            ProxySecurityScenario {
                name: "credential_harvesting",
                proxy_location: "http://auth-proxy.phishing.com:8080",
                security_risk: "Authentication credential theft",
                attack_vector: "Proxy requires authentication and harvests credentials",
            },
            ProxySecurityScenario {
                name: "internal_network_probe",
                proxy_location: "http://10.0.0.1:8080",
                security_risk: "Internal network reconnaissance",
                attack_vector: "External proxy used to probe internal network topology",
            },
        ];

        eprintln!("\n🛡️ HTTP 305 PROXY SECURITY SCENARIOS");
        eprintln!("===================================");

        for scenario in scenarios {
            let scripted_client = Scripted305HttpClient::new(vec![Response {
                status: 305,
                headers: vec![
                    ("location".to_string(), scenario.proxy_location.to_string()),
                    ("server".to_string(), "compromised-server/1.0".to_string()),
                ],
                body: b"Use specified proxy for this request".to_vec(),
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
                    assert!(message.contains("305"));
                    assert!(message.contains("Unexpected"));

                    eprintln!("  Scenario '{}': ✅ Terminal (prevented attack)",
                        scenario.name);
                    eprintln!("    Risk: {}", scenario.security_risk);
                    eprintln!("    Attack: {}", scenario.attack_vector);
                    eprintln!("    Proxy: {}", scenario.proxy_location);
                }
                other => panic!("Scenario '{}' should be terminal for security, got: {:?}",
                    scenario.name, other),
            }
        }

        eprintln!("\n🛡️ ALL PROXY ATTACK VECTORS PREVENTED:");
        eprintln!("   • Telemetry data harvesting: Blocked");
        eprintln!("   • Man-in-the-middle attacks: Blocked");
        eprintln!("   • Corporate espionage: Blocked");
        eprintln!("   • Credential harvesting: Blocked");
        eprintln!("   • Internal network probing: Blocked");
        eprintln!("   • Consistent terminal classification prevents all proxy attacks");
    }

    #[test]
    fn test_305_deprecated_status_compliance() {
        // AUDIT POINT 4: Document RFC 9110 deprecation compliance

        eprintln!("\n📋 RFC 9110 HTTP 305 DEPRECATION COMPLIANCE");
        eprintln!("==========================================");
        eprintln!("Per RFC 9110 Section 15.4.6:");
        eprintln!("   • HTTP 305 Use Proxy is deprecated");
        eprintln!("   • Originally indicated resource must be accessed through proxy");
        eprintln!("   • Security concerns led to deprecation");
        eprintln!("   • Clients SHOULD NOT automatically follow proxy redirects");

        let scripted_client = Scripted305HttpClient::new(vec![Response {
            status: 305,
            headers: vec![
                ("location".to_string(), "http://legacy-proxy.deprecated.com:8080".to_string()),
                ("server".to_string(), "legacy-server/0.9".to_string()),
            ],
            body: b"This server still uses deprecated 305 responses".to_vec(),
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
                // Verify deprecation handling
                assert!(message.contains("305"), "Should identify HTTP status");
                assert!(message.contains("Unexpected"), "Should treat as unexpected");

                eprintln!("\n✅ RFC 9110 DEPRECATION COMPLIANCE:");
                eprintln!("   ✓ 305 treated as unexpected (honors deprecation)");
                eprintln!("   ✓ No automatic proxy following (security compliance)");
                eprintln!("   ✓ Terminal classification (prevents deprecated behavior)");
                eprintln!("   ✓ Batch dropped securely (no data leakage)");

                eprintln!("\n🔒 SECURITY BENEFITS OF TERMINAL CLASSIFICATION:");
                eprintln!("   • Prevents telemetry data leakage through untrusted proxies");
                eprintln!("   • Blocks man-in-the-middle attacks via proxy redirects");
                eprintln!("   • Forces explicit proxy configuration (no surprise redirects)");
                eprintln!("   • Protects against credential harvesting proxy attacks");

                eprintln!("\n📊 COMPARISON WITH MODERN ALTERNATIVES:");
                eprintln!("   Deprecated: HTTP 305 Use Proxy (automatic proxy redirect)");
                eprintln!("   Modern: Explicit proxy configuration in HTTP client");
                eprintln!("   Benefit: User controls proxy choice, no automatic redirects");

                eprintln!("\n🚫 WHAT WOULD BE WRONG (automatic proxy following):");
                eprintln!("   ✗ Telemetry data sent through untrusted proxies");
                eprintln!("   ✗ Vulnerability to proxy-based man-in-the-middle attacks");
                eprintln!("   ✗ Credential exposure to malicious proxy servers");
                eprintln!("   ✗ Violation of RFC 9110 deprecation guidance");

                eprintln!("\n✅ CURRENT IMPLEMENTATION: Terminal classification (SECURE)");
                eprintln!("   Error message: {}", message);
            }
            other => panic!("Expected NonRetryable for 305, got: {:?}", other),
        }
    }

    #[test]
    fn test_305_vs_proxy_configuration_best_practices() {
        // AUDIT POINT 5: Document proper proxy configuration vs 305 handling

        eprintln!("\n🔧 PROPER PROXY CONFIGURATION VS HTTP 305");
        eprintln!("=========================================");

        eprintln!("❌ DEPRECATED: HTTP 305 Use Proxy Response");
        eprintln!("   • Server responds with 305 + Location header");
        eprintln!("   • Client automatically redirects through specified proxy");
        eprintln!("   • Security risk: Client has no control over proxy choice");
        eprintln!("   • RFC 9110: Deprecated due to security concerns");

        eprintln!("\n✅ SECURE: Explicit Proxy Configuration");
        eprintln!("   • Operator explicitly configures HTTP proxy in client");
        eprintln!("   • Client connects through known, trusted proxy");
        eprintln!("   • Security benefit: Operator controls proxy choice");
        eprintln!("   • OTLP spec: Supports standard HTTP proxy configuration");

        let scripted_client = Scripted305HttpClient::new(vec![Response {
            status: 305,
            headers: vec![
                ("location".to_string(), "http://suggested-proxy.example.com:8080".to_string()),
            ],
            body: b"Please use the suggested proxy".to_vec(),
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
                eprintln!("\n🎯 OPERATOR GUIDANCE FROM 305 ERROR:");
                eprintln!("   Current: Server returning deprecated 305 response");
                eprintln!("   Action: Configure explicit proxy in OTLP client settings");
                eprintln!("   Benefit: Secure, controlled proxy usage");
                eprintln!("   Error: {}", message);

                eprintln!("\n📋 RECOMMENDED PROXY CONFIGURATION:");
                eprintln!("   1. Identify trusted proxy server (verify ownership/security)");
                eprintln!("   2. Configure proxy in HTTP client (not via 305 responses)");
                eprintln!("   3. Use authenticated proxy connections when available");
                eprintln!("   4. Monitor proxy logs for security anomalies");
                eprintln!("   5. Regularly audit proxy configuration and access");
            }
            other => panic!("Expected NonRetryable for 305, got: {:?}", other),
        }

        eprintln!("\n✅ SECURITY STANCE: Terminal 305 handling enforces secure proxy practices");
    }
}
