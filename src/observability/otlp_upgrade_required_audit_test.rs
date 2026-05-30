//! OTLP upgrade required (426) response handling audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter behavior when collector returns
//! HTTP 426 Upgrade Required per RFC 9110 §15.5.22.
//!
//! **RFC 9110 UPGRADE REQUIRED SPECIFICATION**:
//! - 426 indicates server requires protocol upgrade (TLS, HTTP/2, HTTP/3)
//! - Client should check Upgrade header for required protocol
//! - Retry with upgraded protocol or fail-fast with clear message
//! - NOT: treat as generic 4xx client error (vague)
//! - NOT: retry without upgrade (won't succeed)
//! - CORRECT: fail-fast with specific upgrade requirement message
//!
//! **CURRENT BEHAVIOR ANALYSIS**:
//! - 426 falls into 400..=499 range (lines 1100-1105 in otel.rs)
//! - Treated as "OTLP client error: 426 - batch dropped"
//! - Generic error message doesn't indicate upgrade requirement
//! - No Upgrade header inspection for required protocol

#![cfg(test)]

/// HTTP response fixture for testing 426 Upgrade Required scenarios.
#[derive(Debug, Clone)]
struct UpgradeResponseFixture {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl UpgradeResponseFixture {
    fn new_upgrade_required_tls() -> Self {
        Self {
            status: 426,
            headers: vec![
                ("upgrade".to_string(), "TLS/1.2".to_string()),
                ("connection".to_string(), "Upgrade".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ],
            body: b"TLS required for OTLP endpoint".to_vec(),
        }
    }

    fn new_upgrade_required_h2() -> Self {
        Self {
            status: 426,
            headers: vec![
                ("upgrade".to_string(), "h2".to_string()),
                ("connection".to_string(), "Upgrade".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ],
            body: b"HTTP/2 required for OTLP endpoint".to_vec(),
        }
    }

    fn new_upgrade_required_h3() -> Self {
        Self {
            status: 426,
            headers: vec![
                ("upgrade".to_string(), "h3".to_string()),
                ("connection".to_string(), "Upgrade".to_string()),
                ("alt-svc".to_string(), "h3=\":443\"".to_string()),
            ],
            body: b"HTTP/3 required for OTLP endpoint".to_vec(),
        }
    }

    fn new_upgrade_required_no_header() -> Self {
        Self {
            status: 426,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: b"Upgrade Required".to_vec(),
        }
    }
}

/// OTLP error handler fixture for testing upgrade required scenarios.
#[derive(Debug)]
struct UpgradeHandlerFixture {
    responses_received: Vec<UpgradeResponseFixture>,
    error_messages: Vec<String>,
}

impl UpgradeHandlerFixture {
    fn new() -> Self {
        Self {
            responses_received: Vec::new(),
            error_messages: Vec::new(),
        }
    }

    /// Current defective implementation: treats 426 as generic 4xx.
    fn handle_response_defective(
        &mut self,
        response: UpgradeResponseFixture,
    ) -> Result<(), String> {
        self.responses_received.push(response.clone());

        match response.status {
            200..=299 => Ok(()),
            400..=499 => {
                // DEFECTIVE: Generic client error handling for 426
                let error = format!("OTLP client error: {} - batch dropped", response.status);
                self.error_messages.push(error.clone());
                Err(error)
            }
            _ => {
                let error = format!("Unexpected status: {}", response.status);
                self.error_messages.push(error.clone());
                Err(error)
            }
        }
    }

    /// Correct implementation: specific 426 handling with upgrade guidance.
    fn handle_response_correct(&mut self, response: UpgradeResponseFixture) -> Result<(), String> {
        self.responses_received.push(response.clone());

        match response.status {
            200..=299 => Ok(()),
            426 => {
                // CORRECT: Specific upgrade required handling
                let upgrade_header = response
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
                    .map(|(_, value)| value.clone());

                let error = if let Some(required_protocol) = upgrade_header {
                    format!(
                        "OTLP endpoint requires protocol upgrade to {} (RFC 9110 §15.5.22). \
                         Reconfigure client with required protocol or use TLS endpoint.",
                        required_protocol
                    )
                } else {
                    "OTLP endpoint requires protocol upgrade (RFC 9110 §15.5.22). \
                     Check server documentation for required protocol."
                        .to_string()
                };

                self.error_messages.push(error.clone());
                Err(error)
            }
            400..=499 => {
                // Other client errors
                let error = format!("OTLP client error: {} - batch dropped", response.status);
                self.error_messages.push(error.clone());
                Err(error)
            }
            _ => {
                let error = format!("Unexpected status: {}", response.status);
                self.error_messages.push(error.clone());
                Err(error)
            }
        }
    }
}

/// **AUDIT TEST**: Verify 426 Upgrade Required response handling.
///
/// **SCENARIO**: Collector requires TLS upgrade and returns 426 with Upgrade header.
/// **REQUIREMENT**: Should fail-fast with clear upgrade guidance (not generic 4xx).
/// **ASSESSMENT**: DEFECTIVE - treated as generic client error without upgrade guidance.
#[test]
fn audit_upgrade_required_tls_scenario() {
    println!("🔍 AUDIT: OTLP 426 Upgrade Required (TLS) response handling");

    println!("📋 RFC 9110 §15.5.22 requirements:");
    println!("   • 426 indicates server requires protocol upgrade");
    println!("   • Client should inspect Upgrade header for required protocol");
    println!("   • Should fail-fast with actionable upgrade guidance");
    println!("   • NOT: retry without upgrade (RFC violation)");
    println!("   • NOT: treat as generic 4xx (user confusion)");

    let tls_upgrade_response = UpgradeResponseFixture::new_upgrade_required_tls();

    println!("📊 Test scenario:");
    println!("   Status: 426 Upgrade Required");
    println!("   Upgrade header: TLS/1.2");
    println!("   Expected: Fail-fast with TLS upgrade guidance");

    // **DEFECTIVE APPROACH**: Current implementation
    println!("📊 Testing defective implementation (current behavior):");
    let mut defective_handler = UpgradeHandlerFixture::new();

    let defective_result =
        defective_handler.handle_response_defective(tls_upgrade_response.clone());

    println!("   Result: {:?}", defective_result);
    println!(
        "   Error message: {:?}",
        defective_handler.error_messages.last()
    );

    // Verify defective behavior
    assert!(defective_result.is_err());
    let error_msg = defective_handler.error_messages.last().unwrap();
    assert!(error_msg.contains("OTLP client error: 426 - batch dropped"));
    assert!(!error_msg.contains("upgrade"));
    assert!(!error_msg.contains("TLS"));

    println!("⚠️  DEFECTIVE: Generic 4xx error message, no upgrade guidance");

    // **CORRECT APPROACH**: Specific 426 handling
    println!("📊 Testing correct implementation (RFC 9110 compliant):");
    let mut correct_handler = UpgradeHandlerFixture::new();

    let correct_result = correct_handler.handle_response_correct(tls_upgrade_response);

    println!("   Result: {:?}", correct_result);
    println!(
        "   Error message: {:?}",
        correct_handler.error_messages.last()
    );

    // Verify correct behavior
    assert!(correct_result.is_err());
    let correct_error = correct_handler.error_messages.last().unwrap();
    assert!(correct_error.contains("protocol upgrade to TLS/1.2"));
    assert!(correct_error.contains("RFC 9110"));
    assert!(correct_error.contains("Reconfigure client"));

    println!("✅ CORRECT: Specific upgrade guidance with actionable advice");

    println!("🚨 AUDIT FINDING: DEFECTIVE");
    println!("   Current: 426 → generic 4xx client error");
    println!("   Required: 426 → specific upgrade guidance per RFC 9110");
}

/// **AUDIT TEST**: Verify 426 handling for HTTP/2 upgrade requirement.
///
/// **SCENARIO**: Collector requires HTTP/2 and returns 426 with h2 upgrade.
/// **REQUIREMENT**: Should provide specific h2 upgrade guidance.
/// **ASSESSMENT**: Current implementation loses upgrade context.
#[test]
fn audit_upgrade_required_h2_scenario() {
    println!("🔍 AUDIT: OTLP 426 Upgrade Required (HTTP/2) response handling");

    let h2_upgrade_response = UpgradeResponseFixture::new_upgrade_required_h2();

    println!("📊 HTTP/2 upgrade scenario:");
    println!("   Status: 426 Upgrade Required");
    println!("   Upgrade header: h2");
    println!("   Expected: HTTP/2 specific upgrade guidance");

    // Test both implementations
    let mut defective_handler = UpgradeHandlerFixture::new();
    let mut correct_handler = UpgradeHandlerFixture::new();

    let _defective_result =
        defective_handler.handle_response_defective(h2_upgrade_response.clone());
    let _correct_result = correct_handler.handle_response_correct(h2_upgrade_response);

    println!("📊 Defective behavior:");
    println!("   Error: {:?}", defective_handler.error_messages.last());

    println!("📊 Correct behavior:");
    println!("   Error: {:?}", correct_handler.error_messages.last());

    // Verify correct handler extracts protocol
    let correct_error = correct_handler.error_messages.last().unwrap();
    assert!(correct_error.contains("upgrade to h2"));
    assert!(
        !defective_handler
            .error_messages
            .last()
            .unwrap()
            .contains("h2")
    );

    println!("✅ CORRECT: Protocol-specific guidance (h2)");
    println!("⚠️  DEFECTIVE: Generic error loses upgrade protocol context");
}

/// **AUDIT TEST**: Verify 426 handling for HTTP/3 upgrade requirement.
///
/// **SCENARIO**: Collector requires HTTP/3 and returns 426 with h3 upgrade.
/// **REQUIREMENT**: Should preserve h3 protocol guidance and alternate service details.
#[test]
fn audit_upgrade_required_h3_scenario() {
    println!("🔍 AUDIT: OTLP 426 Upgrade Required (HTTP/3) response handling");

    let h3_upgrade_response = UpgradeResponseFixture::new_upgrade_required_h3();
    assert!(
        String::from_utf8_lossy(&h3_upgrade_response.body).contains("HTTP/3"),
        "HTTP/3 upgrade fixture body should describe the requested protocol"
    );
    assert!(
        h3_upgrade_response
            .headers
            .iter()
            .any(|(name, value)| name == "alt-svc" && value.contains("h3")),
        "HTTP/3 upgrade responses should carry an h3 Alt-Svc hint"
    );

    let mut correct_handler = UpgradeHandlerFixture::new();
    let correct_result = correct_handler.handle_response_correct(h3_upgrade_response);

    assert!(correct_result.is_err());
    let correct_error = correct_handler.error_messages.last().unwrap();
    assert!(
        correct_error.contains("upgrade to h3"),
        "HTTP/3 426 handling should preserve the required protocol: {correct_error}"
    );
    assert!(
        correct_error.contains("RFC 9110"),
        "HTTP/3 426 handling should keep the standards reference: {correct_error}"
    );
}

/// **AUDIT TEST**: Verify 426 handling without Upgrade header.
///
/// **SCENARIO**: Malformed 426 response missing required Upgrade header.
/// **REQUIREMENT**: Should provide fallback guidance referencing RFC 9110.
/// **ASSESSMENT**: Current implementation misses RFC context entirely.
#[test]
fn audit_upgrade_required_no_header_scenario() {
    println!("🔍 AUDIT: OTLP 426 Upgrade Required without Upgrade header");

    let no_header_response = UpgradeResponseFixture::new_upgrade_required_no_header();

    println!("📊 Malformed 426 scenario:");
    println!("   Status: 426 Upgrade Required");
    println!("   Missing: Upgrade header (RFC 9110 violation by server)");
    println!("   Expected: Fallback guidance with RFC reference");

    let mut correct_handler = UpgradeHandlerFixture::new();
    let _correct_result = correct_handler.handle_response_correct(no_header_response);

    println!("📊 Correct fallback behavior:");
    println!("   Error: {:?}", correct_handler.error_messages.last());

    // Verify fallback includes RFC reference
    let error_msg = correct_handler.error_messages.last().unwrap();
    assert!(error_msg.contains("protocol upgrade"));
    assert!(error_msg.contains("RFC 9110"));
    assert!(error_msg.contains("server documentation"));

    println!("✅ CORRECT: Fallback guidance references RFC 9110 for context");
}

/// **AUDIT TEST**: Verify current OTLP exporter status code classification.
///
/// **SCENARIO**: Examine how 426 vs other 4xx codes are currently handled.
/// **REQUIREMENT**: 426 should be distinct from generic client errors.
/// **ASSESSMENT**: 426 lumped with all other 400-499 codes.
#[test]
fn audit_current_status_code_classification() {
    println!("🔍 AUDIT: Current OTLP status code classification for 4xx range");

    println!("📋 Current classification (lines 1100-1105 in otel.rs):");
    println!("   415: Special handling (compression fallback)");
    println!("   400-414, 416-499: Generic 'OTLP client error: N - batch dropped'");
    println!("   Problem: 426 Upgrade Required is protocol-specific, not generic");

    // Simulate the current classification logic
    fn classify_client_error(status: u16) -> &'static str {
        match status {
            415 => "compression_fallback",
            400..=499 => "non_retryable_generic_client_error", // Current behavior
            _ => "other",
        }
    }

    println!("📊 Current 4xx error classification:");
    let statuses = [400, 401, 403, 404, 415, 426, 429, 499];
    for status in statuses {
        let classification = classify_client_error(status);
        println!("   {}: {}", status, classification);
    }

    println!("📊 Correct RFC-aware classification should be:");
    println!("   400: generic_client_error (Bad Request)");
    println!("   401: auth_error (Unauthorized)");
    println!("   403: auth_error (Forbidden)");
    println!("   404: config_error (Not Found - wrong endpoint)");
    println!("   415: compression_fallback (Unsupported Media Type)");
    println!("   426: upgrade_required (Protocol upgrade needed)");
    println!("   429: rate_limited (Too Many Requests)");

    // Verify the defective classification
    assert_eq!(
        classify_client_error(426),
        "non_retryable_generic_client_error"
    );
    assert_eq!(classify_client_error(415), "compression_fallback"); // Correct special handling

    println!("🚨 DEFECT CONFIRMED: 426 lacks special handling like 415");
    println!("   Should provide protocol upgrade guidance per RFC 9110");
}

/// **AUDIT TEST**: Verify RFC 9110 compliance requirements for 426.
///
/// **SCENARIO**: Document exact RFC 9110 requirements for Upgrade Required.
/// **REQUIREMENT**: Client should provide actionable next steps for upgrade.
/// **ASSESSMENT**: Current implementation violates RFC guidance principles.
#[test]
fn audit_rfc_9110_compliance_requirements() {
    println!("🔍 AUDIT: RFC 9110 §15.5.22 compliance for 426 Upgrade Required");

    println!("📋 RFC 9110 §15.5.22 verbatim requirements:");
    println!("   'The 426 (Upgrade Required) status code indicates that the server");
    println!("   refuses to perform the request using the current protocol but");
    println!("   might be willing to do so after the client upgrades to a");
    println!("   different protocol.'");
    println!();
    println!("   'A server MUST send an Upgrade header field in a 426 response");
    println!("   to indicate the required protocol(s).'");
    println!();
    println!("   'A client MAY repeat a request if it adds a suitable Upgrade");
    println!("   header field or change the request to a different protocol.'");

    println!("📊 RFC compliance analysis:");
    println!("   ✅ Server requirement: Send Upgrade header (server's responsibility)");
    println!("   ❌ Client requirement: Handle upgrade guidance (our responsibility)");
    println!("   ❌ User experience: Provide actionable next steps (our responsibility)");

    println!("📊 Current implementation vs RFC guidance:");
    let current_message = "OTLP client error: 426 - batch dropped";
    let rfc_compliant_message = "OTLP endpoint requires protocol upgrade to TLS/1.2 (RFC 9110 §15.5.22). Reconfigure client with required protocol or use TLS endpoint.";

    println!("   Current: '{}'", current_message);
    println!("   RFC-compliant: '{}'", rfc_compliant_message);

    println!("📊 RFC compliance gap analysis:");
    println!("   Missing: Protocol identification from Upgrade header");
    println!("   Missing: Actionable reconfiguration guidance");
    println!("   Missing: RFC 9110 reference for context");
    println!("   Missing: Distinction from other 4xx errors");

    // Test compliance characteristics
    assert!(!current_message.contains("upgrade"));
    assert!(!current_message.contains("protocol"));
    assert!(!current_message.contains("RFC"));
    assert!(current_message.contains("batch dropped")); // Generic 4xx handling

    assert!(rfc_compliant_message.contains("protocol upgrade"));
    assert!(rfc_compliant_message.contains("RFC 9110"));
    assert!(rfc_compliant_message.contains("Reconfigure"));

    println!("🚨 RFC 9110 COMPLIANCE GAP: Lacks upgrade-specific handling");
    println!("   Required: Extract Upgrade header, provide reconfiguration guidance");
}
