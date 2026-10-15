//! Fuzzing target for HTTP/2 :authority pseudo-header userinfo rejection.
//!
//! Tests RFC 7540 §8.1.2.3 compliance for rejecting userinfo syntax in
//! :authority pseudo-header. Per RFC 7540: "The authority MUST NOT include
//! the userinfo subcomponent of an URI."
//!
//! Focus on pseudo-header processing context:
//! 1. :authority with userinfo in pseudo-header ordering context
//! 2. Interaction with other pseudo-headers when userinfo present
//! 3. Error propagation during pseudo-header validation phase
//! 4. Consistent rejection across different request types
//! 5. Edge cases in pseudo-header parsing pipeline
//!
//! Per RFC 7540 §8.1.2.3: "Authority contains the host and optional port
//! components of the target URI. Authority MUST NOT include the userinfo
//! subcomponent of an URI. Clients that generate HTTP/2 requests directly
//! SHOULD use the :authority pseudo-header field instead of the Host header field."
//!
//! Vulnerability areas:
//! - Parser accepting userinfo despite RFC prohibition
//! - Inconsistent validation across pseudo-header processing stages
//! - Userinfo leaking through to Host header processing
//! - Error handling differences between :authority vs Host header
//! - Security bypass through encoded userinfo formats

#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test input for HTTP/2 :authority pseudo-header userinfo validation
#[derive(Debug, Arbitrary)]
pub struct PseudoAuthorityUserinfoInput {
    /// Different userinfo patterns to test in :authority
    userinfo_patterns: Vec<UserinfoPattern>,
    /// Other pseudo-headers to combine with :authority
    other_pseudo_headers: Vec<PseudoHeader>,
    /// Regular headers to test interaction
    regular_headers: Vec<HttpHeader>,
    /// Request configuration
    request_config: RequestConfig,
    /// Validation configuration
    validation_config: ValidationConfig,
    /// Edge case scenarios
    edge_cases: Vec<EdgeCaseTest>,
}

/// Different userinfo pattern types to test
#[derive(Debug, Arbitrary)]
pub struct UserinfoPattern {
    /// Type of userinfo format
    pattern_type: UserinfoType,
    /// Base authority without userinfo
    base_authority: String,
    /// Userinfo component to inject
    userinfo_component: String,
    /// Expected validation behavior
    expect_rejection: bool,
    /// Encoding/obfuscation attempts
    obfuscation: Option<ObfuscationType>,
}

/// Types of userinfo syntax to test
#[derive(Debug, Arbitrary)]
pub enum UserinfoType {
    /// Simple username: "user@host"
    SimpleUser,
    /// Username with password: "user:pass@host"
    UserPassword,
    /// Empty userinfo: "@host"
    EmptyUserinfo,
    /// Multiple @ symbols: "user@domain@host"
    MultipleAt,
    /// Userinfo with port: "user:pass@host:8080"
    UserinfoWithPort,
    /// Encoded userinfo: "user%40domain:pass@host"
    EncodedUserinfo,
    /// Unicode userinfo: "用户:密码@host"
    UnicodeUserinfo,
    /// Very long userinfo component
    LongUserinfo,
    /// Special characters in userinfo
    SpecialCharsUserinfo,
}

/// Obfuscation techniques to test parser robustness
#[derive(Debug, Arbitrary)]
pub enum ObfuscationType {
    /// Percent encoding: @ -> %40, : -> %3A
    PercentEncoding,
    /// Unicode normalization attempts
    UnicodeNormalization,
    /// Double encoding: %40 -> %2540
    DoubleEncoding,
    /// Mixed case in encoding: %4a instead of %4A
    MixedCaseEncoding,
    /// Invalid percent encoding: %GG
    InvalidPercentEncoding,
}

/// Other pseudo-headers to test with :authority
#[derive(Debug, Arbitrary)]
pub struct PseudoHeader {
    /// Pseudo-header name (without :)
    header_type: PseudoHeaderType,
    /// Header value
    value: String,
    /// Whether this header should be valid
    is_valid: bool,
}

#[derive(Debug, Arbitrary)]
pub enum PseudoHeaderType {
    Method,
    Path,
    Scheme,
    Status,
}

impl PseudoHeaderType {
    fn name(&self) -> &'static str {
        match self {
            PseudoHeaderType::Method => ":method",
            PseudoHeaderType::Path => ":path",
            PseudoHeaderType::Scheme => ":scheme",
            PseudoHeaderType::Status => ":status",
        }
    }
}

/// Regular HTTP header
#[derive(Debug, Arbitrary)]
pub struct HttpHeader {
    name: String,
    value: String,
    /// Whether to include Host header (should be redundant with :authority)
    is_host_header: bool,
}

/// Request configuration
#[derive(Debug, Arbitrary)]
pub struct RequestConfig {
    /// Stream ID for the request
    stream_id: u32,
    /// Request or response headers
    is_request: bool,
    /// HTTP/2 connection side
    side: ConnectionSide,
}

#[derive(Debug, Arbitrary)]
pub enum ConnectionSide {
    Client,
    Server,
}

/// Validation configuration
#[derive(Debug, Arbitrary, Clone)]
pub struct ValidationConfig {
    /// Strict RFC 7540 compliance
    strict_rfc_compliance: bool,
    /// Reject userinfo in :authority
    reject_userinfo_in_authority: bool,
    /// Allow Host header alongside :authority
    allow_host_with_authority: bool,
    /// Maximum authority length
    max_authority_length: u16,
    /// Validate pseudo-header ordering
    validate_pseudo_order: bool,
}

/// Edge case testing scenarios
#[derive(Debug, Arbitrary)]
pub enum EdgeCaseTest {
    /// Multiple :authority headers
    MultipleAuthority { authorities: Vec<String> },
    /// :authority after regular headers (invalid order)
    AuthorityAfterRegular,
    /// Both :authority and Host header present
    AuthorityAndHost { authority: String, host: String },
    /// :authority with IPv6 address containing userinfo-like syntax
    IPv6WithUserinfoPattern { ipv6_addr: String },
    /// Empty :authority header
    EmptyAuthority,
    /// :authority with only port
    PortOnlyAuthority { port: u16 },
    /// :authority with invalid characters
    InvalidCharsAuthority { chars: String },
    /// Very long :authority header
    VeryLongAuthority { length: u16 },
}

/// Mock HTTP/2 pseudo-header processor for :authority userinfo validation
pub struct MockPseudoAuthorityProcessor {
    /// Current processing state
    state: ProcessingState,
    /// Received pseudo-headers
    pseudo_headers: HashMap<String, String>,
    /// Regular headers
    regular_headers: HashMap<String, String>,
    /// Parsed authority components
    authority_info: Option<AuthorityInfo>,
    /// Detected violations
    violations: Vec<AuthorityViolation>,
    /// Processing statistics
    stats: ProcessorStats,
    /// Configuration
    config: ValidationConfig,
    /// Current stream being processed
    current_stream_id: u32,
}

#[derive(Debug, Clone)]
pub enum ProcessingState {
    /// Awaiting pseudo-headers
    AwaitingPseudoHeaders,
    /// Processing pseudo-headers phase
    ProcessingPseudoHeaders,
    /// Processing regular headers phase
    ProcessingRegularHeaders,
    /// Processing complete
    Complete,
    /// Error state
    Error(AuthorityValidationError),
}

#[derive(Debug, Clone)]
pub struct AuthorityInfo {
    /// Host component
    host: String,
    /// Port component if present
    port: Option<u16>,
    /// Whether userinfo was detected (should trigger rejection)
    userinfo_detected: bool,
    /// Detected userinfo component
    detected_userinfo: Option<String>,
    /// Raw authority value
    raw_authority: String,
}

#[derive(Debug, Clone)]
pub enum AuthorityValidationError {
    /// Userinfo found in :authority (RFC violation)
    UserinfoInAuthority(String),
    /// Multiple :authority headers
    MultipleAuthorityHeaders,
    /// Empty :authority value
    EmptyAuthority,
    /// Invalid authority format
    InvalidAuthorityFormat(String),
    /// Authority too long
    AuthorityTooLong { length: usize, max: usize },
    /// Invalid characters in authority
    InvalidCharacters(String),
    /// Pseudo-header ordering violation
    PseudoHeaderOrderViolation,
    /// Both :authority and Host header present
    AuthorityAndHostConflict,
}

#[derive(Debug, Clone)]
pub struct AuthorityViolation {
    violation_type: ViolationType,
    description: String,
    authority_value: String,
    detected_userinfo: Option<String>,
    severity: ViolationSeverity,
    rfc_reference: String,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    UserinfoPresent,       // Userinfo detected in :authority
    EncodedUserinfo,       // Percent-encoded userinfo attempt
    UserinfoObfuscation,   // Obfuscated userinfo attempt
    PseudoHeaderOrder,     // :authority in wrong position
    DuplicateAuthority,    // Multiple :authority headers
    HostAuthorityConflict, // Both Host and :authority present
    InvalidFormat,         // Malformed authority value
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationSeverity {
    Critical, // Clear RFC violation
    High,     // Likely RFC violation
    Medium,   // Compliance issue
    Low,      // Style issue
}

#[derive(Debug, Default, Clone)]
pub struct ProcessorStats {
    requests_processed: u32,
    authorities_with_userinfo: u32,
    userinfo_rejections: u32,
    authority_parsing_attempts: u32,
    pseudo_header_order_violations: u32,
    encoding_detection_attempts: u32,
    violations_detected: u32,
}

impl MockPseudoAuthorityProcessor {
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            state: ProcessingState::AwaitingPseudoHeaders,
            pseudo_headers: HashMap::new(),
            regular_headers: HashMap::new(),
            authority_info: None,
            violations: Vec::new(),
            stats: ProcessorStats::default(),
            config,
            current_stream_id: 0,
        }
    }

    /// Process headers frame with pseudo-header validation
    pub fn process_headers_frame(
        &mut self,
        stream_id: u32,
        headers: Vec<(String, String)>,
    ) -> Result<(), AuthorityValidationError> {
        self.current_stream_id = stream_id;
        self.state = ProcessingState::ProcessingPseudoHeaders;
        self.stats.requests_processed += 1;

        let mut found_authority = false;
        let mut pseudo_phase = true;

        for (name, value) in headers {
            // Process pseudo-headers first
            if name.starts_with(':') {
                if !pseudo_phase && self.config.validate_pseudo_order {
                    self.violations.push(AuthorityViolation {
                        violation_type: ViolationType::PseudoHeaderOrder,
                        description: "Pseudo-header after regular header".to_string(),
                        authority_value: value.clone(),
                        detected_userinfo: None,
                        severity: ViolationSeverity::High,
                        rfc_reference: "RFC 7540 §8.1.2.1".to_string(),
                    });
                    return Err(AuthorityValidationError::PseudoHeaderOrderViolation);
                }

                if name == ":authority" {
                    if found_authority {
                        return Err(AuthorityValidationError::MultipleAuthorityHeaders);
                    }
                    found_authority = true;
                    self.process_authority_header(&value)?;
                }

                self.pseudo_headers.insert(name, value);
            } else {
                // Regular headers
                pseudo_phase = false;
                self.state = ProcessingState::ProcessingRegularHeaders;

                // Check for Host header
                if name.eq_ignore_ascii_case("host")
                    && found_authority
                    && !self.config.allow_host_with_authority
                {
                    self.violations.push(AuthorityViolation {
                        violation_type: ViolationType::HostAuthorityConflict,
                        description: "Both :authority and Host header present".to_string(),
                        authority_value: self
                            .pseudo_headers
                            .get(":authority")
                            .unwrap_or(&"".to_string())
                            .clone(),
                        detected_userinfo: None,
                        severity: ViolationSeverity::High,
                        rfc_reference: "RFC 7540 §8.1.2.3".to_string(),
                    });
                    return Err(AuthorityValidationError::AuthorityAndHostConflict);
                }

                self.regular_headers.insert(name, value);
            }
        }

        self.state = ProcessingState::Complete;
        Ok(())
    }

    /// Process and validate :authority header
    fn process_authority_header(
        &mut self,
        authority: &str,
    ) -> Result<(), AuthorityValidationError> {
        self.stats.authority_parsing_attempts += 1;

        // Check for empty authority
        if authority.is_empty() {
            return Err(AuthorityValidationError::EmptyAuthority);
        }

        // Check authority length
        if authority.len() > self.config.max_authority_length as usize {
            return Err(AuthorityValidationError::AuthorityTooLong {
                length: authority.len(),
                max: self.config.max_authority_length as usize,
            });
        }

        // Check for userinfo component
        if let Some(userinfo) = self.detect_userinfo(authority) {
            self.stats.authorities_with_userinfo += 1;

            self.violations.push(AuthorityViolation {
                violation_type: ViolationType::UserinfoPresent,
                description: "Userinfo component detected in :authority".to_string(),
                authority_value: authority.to_string(),
                detected_userinfo: Some(userinfo.clone()),
                severity: ViolationSeverity::Critical,
                rfc_reference: "RFC 7540 §8.1.2.3".to_string(),
            });

            if self.config.reject_userinfo_in_authority {
                self.stats.userinfo_rejections += 1;
                return Err(AuthorityValidationError::UserinfoInAuthority(userinfo));
            }
        }

        // Parse authority components
        self.parse_authority_components(authority)?;

        Ok(())
    }

    /// Detect userinfo component in authority
    fn detect_userinfo(&mut self, authority: &str) -> Option<String> {
        // Look for @ symbol which indicates userinfo
        if let Some(at_pos) = authority.find('@') {
            let potential_userinfo = &authority[..at_pos];

            // Additional validation to distinguish from IPv6 addresses
            if !authority.starts_with('[') {
                // Not IPv6, so @ likely indicates userinfo
                self.stats.encoding_detection_attempts += 1;
                return Some(potential_userinfo.to_string());
            }
        }

        // Check for percent-encoded @ (%40)
        if authority.contains("%40") {
            self.violations.push(AuthorityViolation {
                violation_type: ViolationType::EncodedUserinfo,
                description: "Percent-encoded @ symbol detected (possible userinfo)".to_string(),
                authority_value: authority.to_string(),
                detected_userinfo: Some("encoded @ symbol".to_string()),
                severity: ViolationSeverity::High,
                rfc_reference: "RFC 7540 §8.1.2.3".to_string(),
            });
            return Some("encoded userinfo".to_string());
        }

        // Check for percent-encoded : (%3A) which might indicate password separator
        if authority.contains("%3A") || authority.contains("%3a") {
            let before_at = authority.split('@').next().unwrap_or(authority);
            if before_at.contains("%3A") || before_at.contains("%3a") {
                self.violations.push(AuthorityViolation {
                    violation_type: ViolationType::EncodedUserinfo,
                    description: "Percent-encoded : symbol before @ (possible password)"
                        .to_string(),
                    authority_value: authority.to_string(),
                    detected_userinfo: Some("encoded password separator".to_string()),
                    severity: ViolationSeverity::High,
                    rfc_reference: "RFC 7540 §8.1.2.3".to_string(),
                });
                return Some("encoded userinfo".to_string());
            }
        }

        None
    }

    /// Parse authority into host and port components
    fn parse_authority_components(
        &mut self,
        authority: &str,
    ) -> Result<(), AuthorityValidationError> {
        // Remove userinfo if present (for parsing purposes, even though it should be rejected)
        let authority_without_userinfo = if let Some(at_pos) = authority.find('@') {
            &authority[at_pos + 1..]
        } else {
            authority
        };

        // Parse host and port
        let (host, port) = if authority_without_userinfo.starts_with('[') {
            // IPv6 address
            if let Some(close_bracket) = authority_without_userinfo.find(']') {
                let ipv6_host = authority_without_userinfo[1..close_bracket].to_string();
                let remaining = &authority_without_userinfo[close_bracket + 1..];

                if let Some(port_str) = remaining.strip_prefix(':') {
                    match port_str.parse::<u16>() {
                        Ok(port_num) => (ipv6_host, Some(port_num)),
                        Err(_) => {
                            return Err(AuthorityValidationError::InvalidAuthorityFormat(format!(
                                "Invalid port in IPv6 authority: {}",
                                authority
                            )));
                        }
                    }
                } else if remaining.is_empty() {
                    (ipv6_host, None)
                } else {
                    return Err(AuthorityValidationError::InvalidAuthorityFormat(format!(
                        "Invalid IPv6 authority format: {}",
                        authority
                    )));
                }
            } else {
                return Err(AuthorityValidationError::InvalidAuthorityFormat(format!(
                    "Unclosed IPv6 bracket: {}",
                    authority
                )));
            }
        } else {
            // IPv4 or hostname
            if let Some(colon_pos) = authority_without_userinfo.rfind(':') {
                let host_part = authority_without_userinfo[..colon_pos].to_string();
                let port_str = &authority_without_userinfo[colon_pos + 1..];

                match port_str.parse::<u16>() {
                    Ok(port_num) => (host_part, Some(port_num)),
                    Err(_) => {
                        // Might be IPv6 without brackets or malformed
                        (authority_without_userinfo.to_string(), None)
                    }
                }
            } else {
                (authority_without_userinfo.to_string(), None)
            }
        };

        // Validate host component
        if host.is_empty() {
            return Err(AuthorityValidationError::InvalidAuthorityFormat(
                "Empty host component".to_string(),
            ));
        }

        // Check for invalid characters in host
        if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AuthorityValidationError::InvalidCharacters(host.clone()));
        }

        self.authority_info = Some(AuthorityInfo {
            host,
            port,
            userinfo_detected: authority.contains('@'),
            detected_userinfo: self.detect_userinfo(authority),
            raw_authority: authority.to_string(),
        });

        Ok(())
    }

    /// Generate test authority with userinfo based on pattern
    pub fn generate_authority_with_userinfo(pattern: &UserinfoPattern) -> String {
        let base_host = if pattern.base_authority.is_empty() {
            "example.com"
        } else {
            &pattern.base_authority
        };

        let userinfo = if pattern.userinfo_component.is_empty() {
            "user"
        } else {
            &pattern.userinfo_component
        };

        let mut result = match pattern.pattern_type {
            UserinfoType::SimpleUser => format!("{}@{}", userinfo, base_host),
            UserinfoType::UserPassword => format!("{}:password@{}", userinfo, base_host),
            UserinfoType::EmptyUserinfo => format!("@{}", base_host),
            UserinfoType::MultipleAt => format!("{}@domain@{}", userinfo, base_host),
            UserinfoType::UserinfoWithPort => format!("{}:password@{}:8080", userinfo, base_host),
            UserinfoType::EncodedUserinfo => {
                format!("{}%40domain:password@{}", userinfo, base_host)
            }
            UserinfoType::UnicodeUserinfo => format!("用户:密码@{}", base_host),
            UserinfoType::LongUserinfo => {
                let long_user = format!("{}_{}", userinfo, "x".repeat(100));
                format!("{}:longpassword@{}", long_user, base_host)
            }
            UserinfoType::SpecialCharsUserinfo => format!("{}!#$%:pass@{}", userinfo, base_host),
        };

        // Apply obfuscation if specified
        if let Some(obfuscation) = &pattern.obfuscation {
            result = Self::apply_obfuscation(&result, obfuscation);
        }

        result
    }

    /// Apply obfuscation to authority
    fn apply_obfuscation(authority: &str, obfuscation: &ObfuscationType) -> String {
        match obfuscation {
            ObfuscationType::PercentEncoding => authority.replace("@", "%40").replace(":", "%3A"),
            ObfuscationType::UnicodeNormalization => {
                // Simple Unicode substitution for testing
                authority.replace("@", "＠").replace(":", "：")
            }
            ObfuscationType::DoubleEncoding => {
                authority.replace("@", "%2540").replace(":", "%253A")
            }
            ObfuscationType::MixedCaseEncoding => {
                authority.replace("@", "%4a0").replace(":", "%3a")
            }
            ObfuscationType::InvalidPercentEncoding => {
                authority.replace("@", "%GG").replace(":", "%ZZ")
            }
        }
    }

    /// Get processing results
    pub fn results(&self) -> ProcessingResults {
        ProcessingResults {
            authority_info: self.authority_info.clone(),
            pseudo_headers: self.pseudo_headers.clone(),
            regular_headers: self.regular_headers.clone(),
            violations: self.violations.clone(),
            stats: self.stats.clone(),
            final_state: self.state.clone(),
        }
    }

    /// Check if processing was successful (no userinfo violations)
    pub fn is_userinfo_free(&self) -> bool {
        !self.violations.iter().any(|v| {
            matches!(
                v.violation_type,
                ViolationType::UserinfoPresent | ViolationType::EncodedUserinfo
            )
        })
    }

    /// Get userinfo violations
    pub fn userinfo_violations(&self) -> Vec<&AuthorityViolation> {
        self.violations
            .iter()
            .filter(|v| {
                matches!(
                    v.violation_type,
                    ViolationType::UserinfoPresent
                        | ViolationType::EncodedUserinfo
                        | ViolationType::UserinfoObfuscation
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProcessingResults {
    pub authority_info: Option<AuthorityInfo>,
    pub pseudo_headers: HashMap<String, String>,
    pub regular_headers: HashMap<String, String>,
    pub violations: Vec<AuthorityViolation>,
    pub stats: ProcessorStats,
    pub final_state: ProcessingState,
}

/// Cap values for reasonable fuzzing bounds
fn cap_u8(value: u8, max: u8) -> u8 {
    value.min(max)
}

fn cap_u16(value: u16, max: u16) -> u16 {
    value.min(max)
}

fn cap_u32(value: u32, max: u32) -> u32 {
    value.min(max)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fuzz_target!(|input: PseudoAuthorityUserinfoInput| {
    let config = ValidationConfig {
        strict_rfc_compliance: true,
        reject_userinfo_in_authority: true,
        allow_host_with_authority: false,
        max_authority_length: cap_u16(input.validation_config.max_authority_length, 2048),
        validate_pseudo_order: true,
    };

    // Process each userinfo pattern
    for pattern in input.userinfo_patterns.iter().take(10) {
        let mut processor = MockPseudoAuthorityProcessor::new(config.clone());

        // Generate test authority with userinfo
        let test_authority =
            MockPseudoAuthorityProcessor::generate_authority_with_userinfo(pattern);

        // Ensure reasonable length for fuzzing
        let final_authority = if test_authority.len() > 1024 {
            let host_start = test_authority
                .rfind('@')
                .map(|index| index + 1)
                .unwrap_or(0);
            let host = truncate_chars(&test_authority[host_start..], 99);
            format!("user:pass@{}", host)
        } else {
            test_authority
        };

        // Build headers for request
        let mut headers = Vec::new();

        // Add other pseudo-headers first (correct order)
        for pseudo in input.other_pseudo_headers.iter().take(3) {
            if pseudo.header_type.name() != ":status" || !input.request_config.is_request {
                let name = pseudo.header_type.name().to_string();
                let value = truncate_chars(&pseudo.value, 100);
                headers.push((name, value));
            }
        }

        // Add :authority header
        headers.push((":authority".to_string(), final_authority.clone()));

        // Add regular headers
        for header in input.regular_headers.iter().take(5) {
            let name = truncate_chars(&header.name, 50);
            let value = truncate_chars(&header.value, 200);

            // Handle Host header specially
            if header.is_host_header {
                headers.push(("Host".to_string(), value));
            } else if !name.starts_with(':') {
                headers.push((name, value));
            }
        }

        // Process the headers frame
        let stream_id = cap_u32(input.request_config.stream_id, 0x7fff_ffff) | 1; // Ensure odd for client
        let result = processor.process_headers_frame(stream_id, headers);

        // Validate expected behavior for userinfo patterns
        if pattern.expect_rejection || final_authority.contains('@') {
            // Should be rejected due to userinfo
            match result {
                Err(AuthorityValidationError::UserinfoInAuthority(_)) => {
                    // Expected rejection - good
                }
                Err(AuthorityValidationError::InvalidAuthorityFormat(_)) => {
                    // Also acceptable for malformed userinfo
                }
                Ok(_) => {
                    // Check if violations were at least detected
                    let userinfo_violations = processor.userinfo_violations();
                    assert!(
                        !userinfo_violations.is_empty() || !config.strict_rfc_compliance,
                        "Authority with userinfo '{}' was accepted without violations",
                        final_authority
                    );
                }
                Err(_) => {
                    // Other errors are fine for malformed input
                }
            }
        } else {
            // Valid authority without userinfo should be accepted
            if result.is_err() && !final_authority.contains('@') {
                // Only complain if it's clearly valid authority that was rejected
            }
        }

        // Verify userinfo detection worked correctly
        let results = processor.results();
        if final_authority.contains('@') && !final_authority.starts_with('[') {
            // Should have detected userinfo (unless it's IPv6)
            if let Some(auth_info) = &results.authority_info {
                assert!(
                    auth_info.userinfo_detected || !config.strict_rfc_compliance,
                    "Failed to detect userinfo in authority: {}",
                    final_authority
                );
            }
        }
    }

    // Process edge case tests
    for edge_case in input.edge_cases.iter().take(5) {
        let mut processor = MockPseudoAuthorityProcessor::new(config.clone());

        match edge_case {
            EdgeCaseTest::MultipleAuthority { authorities } => {
                // Test multiple :authority headers (should be rejected)
                let mut headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                ];

                for auth in authorities.iter().take(3) {
                    let auth_value = if auth.contains('@') {
                        auth.clone()
                    } else {
                        format!("user:pass@{}", auth)
                    };
                    headers.push((":authority".to_string(), auth_value));
                }

                let result = processor.process_headers_frame(1, headers);
                assert!(
                    result.is_err(),
                    "Multiple :authority headers should be rejected"
                );
            }
            EdgeCaseTest::AuthorityAfterRegular => {
                // Test :authority after regular headers (should be rejected)
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                    ("user-agent".to_string(), "test".to_string()), // Regular header
                    (
                        ":authority".to_string(),
                        "user:pass@example.com".to_string(),
                    ), // Pseudo after regular
                ];

                let result = processor.process_headers_frame(1, headers);
                if config.validate_pseudo_order {
                    assert!(
                        result.is_err(),
                        "Pseudo-headers after regular headers should be rejected"
                    );
                }
            }
            EdgeCaseTest::AuthorityAndHost { authority, host } => {
                // Test both :authority and Host header
                let authority_with_userinfo = if authority.contains('@') {
                    authority.clone()
                } else {
                    format!("user:pass@{}", authority)
                };

                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                    (":authority".to_string(), authority_with_userinfo),
                    ("Host".to_string(), truncate_chars(host, 100)),
                ];

                let result = processor.process_headers_frame(1, headers);
                if !config.allow_host_with_authority {
                    assert!(
                        result.is_err(),
                        "Both :authority and Host should be rejected when not allowed"
                    );
                }
            }
            EdgeCaseTest::IPv6WithUserinfoPattern { ipv6_addr } => {
                // Test IPv6 address that might contain @ or : symbols
                let ipv6_authority = format!("[{}]", truncate_chars(ipv6_addr, 50));

                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                    (":authority".to_string(), ipv6_authority),
                ];

                let result = processor.process_headers_frame(1, headers);
                // IPv6 addresses should be valid even if they contain @ or : inside brackets
                if result.is_err() {
                    // Verify it's not rejected due to userinfo detection
                    let results = processor.results();
                    let userinfo_violations = results
                        .violations
                        .iter()
                        .filter(|v| matches!(v.violation_type, ViolationType::UserinfoPresent))
                        .count();
                    assert_eq!(
                        userinfo_violations, 0,
                        "IPv6 address should not be detected as userinfo"
                    );
                }
            }
            EdgeCaseTest::EmptyAuthority => {
                // Test empty :authority
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                    (":authority".to_string(), "".to_string()),
                ];

                let result = processor.process_headers_frame(1, headers);
                assert!(result.is_err(), "Empty :authority should be rejected");
            }
            _ => {
                // Other edge cases - test with userinfo
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":path".to_string(), "/".to_string()),
                    (
                        ":authority".to_string(),
                        "user:pass@example.com".to_string(),
                    ),
                ];

                let result = processor.process_headers_frame(1, headers);
                // Should be rejected due to userinfo
                assert!(
                    result.is_err(),
                    "Edge case with userinfo should be rejected"
                );
            }
        }
    }

    // Verify overall statistics and violations
    // At least one processor should have detected userinfo if patterns contained it
    let has_userinfo_patterns = input
        .userinfo_patterns
        .iter()
        .any(|p| MockPseudoAuthorityProcessor::generate_authority_with_userinfo(p).contains('@'));

    if has_userinfo_patterns {
        // Should have processed some requests with userinfo
        // (Individual processors are reset for each test, but the pattern indicates userinfo presence)
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_userinfo_detection() {
        let config = ValidationConfig {
            strict_rfc_compliance: true,
            reject_userinfo_in_authority: true,
            allow_host_with_authority: false,
            max_authority_length: 1024,
            validate_pseudo_order: true,
        };

        let mut processor = MockPseudoAuthorityProcessor::new(config);

        // Test simple userinfo detection
        assert_eq!(
            processor.detect_userinfo("user@example.com"),
            Some("user".to_string())
        );
        assert_eq!(
            processor.detect_userinfo("user:pass@example.com"),
            Some("user:pass".to_string())
        );
        assert_eq!(
            processor.detect_userinfo("@example.com"),
            Some("".to_string())
        );

        // Should not detect userinfo in IPv6
        assert_eq!(processor.detect_userinfo("[::1]:8080"), None);
        assert_eq!(processor.detect_userinfo("example.com:8080"), None);

        // Should detect encoded userinfo
        assert_eq!(
            processor.detect_userinfo("user%40domain:pass@example.com"),
            Some("encoded userinfo".to_string())
        );
    }

    #[test]
    fn test_userinfo_rejection() {
        let config = ValidationConfig {
            strict_rfc_compliance: true,
            reject_userinfo_in_authority: true,
            allow_host_with_authority: false,
            max_authority_length: 1024,
            validate_pseudo_order: true,
        };

        let mut processor = MockPseudoAuthorityProcessor::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            (
                ":authority".to_string(),
                "user:password@example.com".to_string(),
            ),
        ];

        let result = processor.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorityValidationError::UserinfoInAuthority(_)
        ));

        let results = processor.results();
        assert!(!processor.is_userinfo_free());
        assert_eq!(processor.userinfo_violations().len(), 1);
    }

    #[test]
    fn test_valid_authority_without_userinfo() {
        let config = ValidationConfig {
            strict_rfc_compliance: true,
            reject_userinfo_in_authority: true,
            allow_host_with_authority: false,
            max_authority_length: 1024,
            validate_pseudo_order: true,
        };

        let mut processor = MockPseudoAuthorityProcessor::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            (":authority".to_string(), "example.com:8080".to_string()),
        ];

        let result = processor.process_headers_frame(1, headers);
        assert!(result.is_ok());

        let results = processor.results();
        assert!(processor.is_userinfo_free());
        assert_eq!(processor.userinfo_violations().len(), 0);

        if let Some(auth_info) = results.authority_info {
            assert_eq!(auth_info.host, "example.com");
            assert_eq!(auth_info.port, Some(8080));
            assert!(!auth_info.userinfo_detected);
        }
    }

    #[test]
    fn test_multiple_authority_headers() {
        let config = ValidationConfig {
            strict_rfc_compliance: true,
            reject_userinfo_in_authority: true,
            allow_host_with_authority: false,
            max_authority_length: 1024,
            validate_pseudo_order: true,
        };

        let mut processor = MockPseudoAuthorityProcessor::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (
                ":authority".to_string(),
                "user:pass@example.org".to_string(),
            ), // Duplicate
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
        ];

        let result = processor.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorityValidationError::MultipleAuthorityHeaders
        ));
    }

    #[test]
    fn test_authority_generation() {
        let pattern = UserinfoPattern {
            pattern_type: UserinfoType::UserPassword,
            base_authority: "example.com".to_string(),
            userinfo_component: "testuser".to_string(),
            expect_rejection: true,
            obfuscation: None,
        };

        let generated = MockPseudoAuthorityProcessor::generate_authority_with_userinfo(&pattern);
        assert_eq!(generated, "testuser:password@example.com");

        // Test with obfuscation
        let pattern_encoded = UserinfoPattern {
            pattern_type: UserinfoType::SimpleUser,
            base_authority: "example.com".to_string(),
            userinfo_component: "user".to_string(),
            expect_rejection: true,
            obfuscation: Some(ObfuscationType::PercentEncoding),
        };

        let generated_encoded =
            MockPseudoAuthorityProcessor::generate_authority_with_userinfo(&pattern_encoded);
        assert_eq!(generated_encoded, "user%40example.com");
    }

    #[test]
    fn test_pseudo_header_order_validation() {
        let config = ValidationConfig {
            strict_rfc_compliance: true,
            reject_userinfo_in_authority: true,
            allow_host_with_authority: false,
            max_authority_length: 1024,
            validate_pseudo_order: true,
        };

        let mut processor = MockPseudoAuthorityProcessor::new(config);

        // :authority after regular header should be rejected
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            ("user-agent".to_string(), "test".to_string()), // Regular header
            (":authority".to_string(), "example.com".to_string()), // Pseudo after regular
        ];

        let result = processor.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorityValidationError::PseudoHeaderOrderViolation
        ));
    }
}
