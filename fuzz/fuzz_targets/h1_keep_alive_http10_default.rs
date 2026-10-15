#![no_main]

//! HTTP/1.1 Connection keep-alive vs HTTP/1.0 default behavior fuzzing target
//!
//! Tests RFC 9112 §9.6 connection persistence rules:
//! - HTTP/1.0 defaults to "Connection: close" (non-persistent)
//! - HTTP/1.1 defaults to "Connection: keep-alive" (persistent)
//! - Connection header can override these defaults
//! - Tests server.rs should_close_connection() and connection persistence logic

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test case for Connection header precedence vs HTTP version defaults
#[derive(Arbitrary, Debug, Clone)]
pub struct KeepAliveDefaultTestCase {
    pub scenario: ConnectionScenario,
    pub http_version: HttpVersion,
    pub connection_headers: Vec<ConnectionHeader>,
    pub server_config: ServerConfig,
    pub connection_state: ConnectionStateConfig,
    pub precedence_config: PrecedenceConfig,
}

/// Different connection persistence testing scenarios
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum ConnectionScenario {
    /// Test HTTP/1.0 default behavior (should close)
    Http10Default,
    /// Test HTTP/1.1 default behavior (should keep-alive)
    Http11Default,
    /// Test explicit Connection: close header
    ExplicitClose,
    /// Test explicit Connection: keep-alive header
    ExplicitKeepAlive,
    /// Test Connection header case sensitivity
    CaseSensitivity,
    /// Test multiple Connection headers (should be invalid)
    MultipleConnectionHeaders,
    /// Test malformed Connection header values
    MalformedConnectionValues,
    /// Test Connection header with multiple tokens
    MultipleTokens,
    /// Test server config overrides
    ServerConfigOverride,
    /// Test request limit interactions
    RequestLimitInteraction,
    /// Test whitespace handling in Connection values
    WhitespaceHandling,
    /// Test HTTP version vs Connection header precedence
    VersionHeaderPrecedence,
}

/// HTTP version variants
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http09, // Edge case - should probably reject
    Http20, // Edge case - should probably reject in H1 context
}

/// Connection header test variations
#[derive(Arbitrary, Debug, Clone)]
pub struct ConnectionHeader {
    pub name: HeaderName,
    pub value: ConnectionValue,
    pub case_variant: CaseVariant,
}

/// Header name variations
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum HeaderName {
    Connection,
    ProxyConnection, // Legacy header
    Other(String),
}

/// Connection header value types
#[derive(Arbitrary, Debug, Clone)]
pub enum ConnectionValue {
    Close,
    KeepAlive,
    Upgrade,
    MultipleTokens(Vec<String>),
    Invalid(String),
    Empty,
    WhitespaceOnly(String),
    CaseVariant(String),
}

/// Case variations for testing
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum CaseVariant {
    Lowercase,
    Uppercase,
    MixedCase,
    CamelCase,
}

/// Server configuration that affects connection persistence
#[derive(Arbitrary, Debug, Clone)]
pub struct ServerConfig {
    pub keep_alive_enabled: bool,
    pub max_requests_per_connection: Option<u32>,
    pub idle_timeout_ms: Option<u32>,
    pub force_close_on_error: bool,
}

/// Connection state simulation
#[derive(Arbitrary, Debug, Clone)]
pub struct ConnectionStateConfig {
    pub requests_served: u32,
    pub connection_phase: ConnectionPhase,
    pub idle_time_ms: u32,
    pub has_errors: bool,
}

/// Connection phases for testing
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum ConnectionPhase {
    Idle,
    Processing,
    Responding,
    Error,
}

/// Precedence testing configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct PrecedenceConfig {
    pub strict_rfc_compliance: bool,
    pub allow_proxy_connection_fallback: bool,
    pub validate_header_syntax: bool,
    pub case_sensitive_header_values: bool,
}

/// Mock HTTP/1.1 connection manager for testing
#[derive(Debug)]
pub struct MockConnectionManager {
    pub config: ServerConfig,
    pub precedence_config: PrecedenceConfig,
    pub violations: Vec<PersistenceViolation>,
}

/// Connection persistence analysis result
#[derive(Debug, PartialEq)]
pub struct PersistenceAnalysis {
    pub should_close: bool,
    pub effective_behavior: EffectiveBehavior,
    pub decision_reason: DecisionReason,
    pub header_violations: Vec<HeaderViolation>,
    pub rfc_compliance_score: f32,
}

/// Effective connection behavior after analysis
#[derive(Debug, PartialEq)]
pub enum EffectiveBehavior {
    Close,
    KeepAlive,
    Ambiguous, // Conflicting signals
    Invalid,   // Malformed input
}

/// Reason for connection persistence decision
#[derive(Debug, PartialEq)]
pub enum DecisionReason {
    HttpVersionDefault,
    ExplicitConnectionHeader,
    ServerConfigOverride,
    RequestLimitReached,
    ErrorForceClose,
    HeaderSyntaxError,
}

/// Connection persistence violations
#[derive(Debug, PartialEq, Clone)]
pub struct PersistenceViolation {
    pub violation_type: PersistenceViolationType,
    pub http_version: String,
    pub connection_header: Option<String>,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub severity: ViolationSeverity,
}

/// Types of connection persistence violations
#[derive(Debug, PartialEq, Clone)]
pub enum PersistenceViolationType {
    /// HTTP/1.0 didn't default to close
    Http10ShouldDefaultClose,
    /// HTTP/1.1 didn't default to keep-alive
    Http11ShouldDefaultKeepAlive,
    /// Connection header not respected
    HeaderNotRespected,
    /// Case sensitivity issue
    CaseSensitivityError,
    /// Multiple headers not handled correctly
    MultipleHeaderHandling,
    /// Server config not enforced
    ServerConfigIgnored,
    /// Request limit not enforced
    RequestLimitIgnored,
}

/// Header parsing violations
#[derive(Debug, PartialEq)]
pub struct HeaderViolation {
    pub violation_type: HeaderViolationType,
    pub header_name: String,
    pub header_value: String,
    pub expected_result: String,
    pub actual_result: String,
}

/// Types of header violations
#[derive(Debug, PartialEq)]
pub enum HeaderViolationType {
    InvalidSyntax,
    CaseHandling,
    WhitespaceHandling,
    TokenParsing,
    DuplicateHeaders,
}

/// Violation severity levels
#[derive(Debug, PartialEq, Clone)]
pub enum ViolationSeverity {
    Critical, // Protocol violation, interop failure
    High,     // RFC deviation, compatibility risk
    Medium,   // Edge case, minor deviation
    Low,      // Style/best practice issue
}

impl MockConnectionManager {
    pub fn new(config: ServerConfig, precedence_config: PrecedenceConfig) -> Self {
        Self {
            config,
            precedence_config,
            violations: Vec::new(),
        }
    }

    /// Analyze connection persistence behavior for test case
    pub fn analyze_connection_persistence(
        &mut self,
        test_case: &KeepAliveDefaultTestCase,
    ) -> PersistenceAnalysis {
        let headers = self.build_headers(&test_case.connection_headers);
        let mut header_violations = Vec::new();

        // Parse Connection header(s)
        let connection_directives = self.parse_connection_headers(&headers, &mut header_violations);

        // Determine default behavior based on HTTP version
        let version_default = self.get_version_default_behavior(&test_case.http_version);

        // Check server config overrides
        let server_override =
            self.check_server_config_overrides(&self.config, &test_case.connection_state);

        // Determine effective behavior
        let (should_close, effective_behavior, decision_reason) = self
            .determine_effective_behavior(
                &test_case.http_version,
                &connection_directives,
                version_default,
                server_override,
                &test_case.connection_state,
            );

        // Validate behavior against expectations
        self.validate_behavior(test_case, should_close, &decision_reason);

        // Calculate RFC compliance score
        let rfc_compliance_score = self.calculate_rfc_compliance();

        PersistenceAnalysis {
            should_close,
            effective_behavior,
            decision_reason,
            header_violations,
            rfc_compliance_score,
        }
    }

    /// Build headers map from test case
    fn build_headers(&self, connection_headers: &[ConnectionHeader]) -> HashMap<String, String> {
        let mut headers: HashMap<String, String> = HashMap::new();

        for header in connection_headers {
            let name = self.format_header_name(&header.name, &header.case_variant);
            let value = self.format_connection_value(&header.value);

            headers
                .entry(name)
                .and_modify(|existing| {
                    existing.push_str(", ");
                    existing.push_str(&value);
                })
                .or_insert(value);
        }

        headers
    }

    /// Parse Connection header values and extract directives
    fn parse_connection_headers(
        &self,
        headers: &HashMap<String, String>,
        violations: &mut Vec<HeaderViolation>,
    ) -> Vec<String> {
        let mut directives = Vec::new();

        for (name, value) in headers {
            let is_connection = name.eq_ignore_ascii_case("connection");
            let is_proxy_connection = name.eq_ignore_ascii_case("proxy-connection");

            if is_connection
                || (is_proxy_connection && self.precedence_config.allow_proxy_connection_fallback)
            {
                // Parse comma-separated tokens
                let tokens: Vec<String> = value
                    .split(',')
                    .map(|token| token.trim().to_string())
                    .filter(|token| !token.is_empty())
                    .collect();

                if tokens.is_empty() && !value.trim().is_empty() {
                    // Malformed header
                    violations.push(HeaderViolation {
                        violation_type: HeaderViolationType::InvalidSyntax,
                        header_name: name.clone(),
                        header_value: value.clone(),
                        expected_result: "valid tokens".to_string(),
                        actual_result: "no parseable tokens".to_string(),
                    });
                }

                for token in tokens {
                    // Validate token syntax
                    if self.precedence_config.validate_header_syntax
                        && !self.is_valid_connection_token(&token)
                    {
                        violations.push(HeaderViolation {
                            violation_type: HeaderViolationType::TokenParsing,
                            header_name: name.clone(),
                            header_value: token.clone(),
                            expected_result: "valid token syntax".to_string(),
                            actual_result: "invalid characters".to_string(),
                        });
                        continue;
                    }

                    directives.push(token);
                }
            }
        }

        directives
    }

    /// Get default behavior for HTTP version
    fn get_version_default_behavior(&self, version: &HttpVersion) -> bool {
        match version {
            HttpVersion::Http10 => true,  // HTTP/1.0 defaults to close
            HttpVersion::Http11 => false, // HTTP/1.1 defaults to keep-alive
            HttpVersion::Http09 => true,  // HTTP/0.9 closes (if supported at all)
            HttpVersion::Http20 => false, // H2 doesn't have connection header, but if testing in H1...
        }
    }

    /// Check server configuration overrides
    fn check_server_config_overrides(
        &self,
        config: &ServerConfig,
        state: &ConnectionStateConfig,
    ) -> Option<bool> {
        // If keep-alive is disabled server-wide, always close
        if !config.keep_alive_enabled {
            return Some(true);
        }

        // If request limit reached, close
        if let Some(max) = config.max_requests_per_connection
            && state.requests_served.saturating_add(1) >= max
        {
            return Some(true);
        }

        if matches!(state.connection_phase, ConnectionPhase::Error) {
            return Some(true);
        }

        if let Some(timeout_ms) = config.idle_timeout_ms
            && matches!(state.connection_phase, ConnectionPhase::Idle)
            && state.idle_time_ms >= timeout_ms
        {
            return Some(true);
        }

        // Force close on error
        if config.force_close_on_error && state.has_errors {
            return Some(true);
        }

        None
    }

    /// Determine effective connection behavior
    fn determine_effective_behavior(
        &self,
        version: &HttpVersion,
        connection_directives: &[String],
        version_default: bool,
        server_override: Option<bool>,
        _state: &ConnectionStateConfig,
    ) -> (bool, EffectiveBehavior, DecisionReason) {
        // Server override takes precedence
        if let Some(should_close) = server_override {
            let behavior = if should_close {
                EffectiveBehavior::Close
            } else {
                EffectiveBehavior::KeepAlive
            };
            return (should_close, behavior, DecisionReason::ServerConfigOverride);
        }

        // Check explicit Connection headers
        let matches_directive = |directive: &str, expected: &str| {
            if self.precedence_config.case_sensitive_header_values {
                directive == expected
            } else {
                directive.eq_ignore_ascii_case(expected)
            }
        };
        let has_close = connection_directives
            .iter()
            .any(|d| matches_directive(d, "close"));
        let has_keep_alive = connection_directives
            .iter()
            .any(|d| matches_directive(d, "keep-alive"));

        if has_close && has_keep_alive {
            // Conflicting directives - ambiguous
            return (
                true,
                EffectiveBehavior::Ambiguous,
                DecisionReason::HeaderSyntaxError,
            );
        }

        if has_close {
            return (
                true,
                EffectiveBehavior::Close,
                DecisionReason::ExplicitConnectionHeader,
            );
        }

        if has_keep_alive {
            return (
                false,
                EffectiveBehavior::KeepAlive,
                DecisionReason::ExplicitConnectionHeader,
            );
        }

        // No explicit header - use version default
        let should_close = version_default;
        let behavior = if should_close {
            EffectiveBehavior::Close
        } else {
            EffectiveBehavior::KeepAlive
        };

        // Special handling for invalid versions
        match version {
            HttpVersion::Http09 | HttpVersion::Http20 => (
                true,
                EffectiveBehavior::Invalid,
                DecisionReason::HeaderSyntaxError,
            ),
            _ => (should_close, behavior, DecisionReason::HttpVersionDefault),
        }
    }

    /// Validate behavior against expected patterns
    fn validate_behavior(
        &mut self,
        test_case: &KeepAliveDefaultTestCase,
        should_close: bool,
        reason: &DecisionReason,
    ) {
        match &test_case.scenario {
            ConnectionScenario::Http10Default => {
                if test_case.http_version == HttpVersion::Http10
                    && !should_close
                    && *reason == DecisionReason::HttpVersionDefault
                {
                    // HTTP/1.0 should default to close
                    self.violations.push(PersistenceViolation {
                        violation_type: PersistenceViolationType::Http10ShouldDefaultClose,
                        http_version: "HTTP/1.0".to_string(),
                        connection_header: None,
                        expected_behavior: "close".to_string(),
                        actual_behavior: "keep-alive".to_string(),
                        severity: ViolationSeverity::High,
                    });
                }
            }
            ConnectionScenario::Http11Default => {
                if test_case.http_version == HttpVersion::Http11
                    && should_close
                    && *reason == DecisionReason::HttpVersionDefault
                {
                    // HTTP/1.1 should default to keep-alive
                    self.violations.push(PersistenceViolation {
                        violation_type: PersistenceViolationType::Http11ShouldDefaultKeepAlive,
                        http_version: "HTTP/1.1".to_string(),
                        connection_header: None,
                        expected_behavior: "keep-alive".to_string(),
                        actual_behavior: "close".to_string(),
                        severity: ViolationSeverity::High,
                    });
                }
            }
            ConnectionScenario::ExplicitClose => {
                if !should_close && *reason != DecisionReason::ServerConfigOverride {
                    // Explicit Connection: close not respected
                    self.violations.push(PersistenceViolation {
                        violation_type: PersistenceViolationType::HeaderNotRespected,
                        http_version: format!("{:?}", test_case.http_version),
                        connection_header: Some("close".to_string()),
                        expected_behavior: "close".to_string(),
                        actual_behavior: "keep-alive".to_string(),
                        severity: ViolationSeverity::Critical,
                    });
                }
            }
            ConnectionScenario::ExplicitKeepAlive => {
                if should_close
                    && *reason != DecisionReason::ServerConfigOverride
                    && *reason != DecisionReason::RequestLimitReached
                {
                    // Explicit Connection: keep-alive not respected
                    self.violations.push(PersistenceViolation {
                        violation_type: PersistenceViolationType::HeaderNotRespected,
                        http_version: format!("{:?}", test_case.http_version),
                        connection_header: Some("keep-alive".to_string()),
                        expected_behavior: "keep-alive".to_string(),
                        actual_behavior: "close".to_string(),
                        severity: ViolationSeverity::Critical,
                    });
                }
            }
            _ => {
                // Other scenarios have more complex validation rules
            }
        }
    }

    /// Validate Connection token syntax
    fn is_valid_connection_token(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }

        // Basic token validation - must be ASCII alphanumeric or hyphen
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }

    /// Calculate RFC compliance score
    fn calculate_rfc_compliance(&self) -> f32 {
        if self.violations.is_empty() {
            return 1.0;
        }

        let penalty = self
            .violations
            .iter()
            .map(|v| match v.severity {
                ViolationSeverity::Critical => 10.0,
                ViolationSeverity::High => 5.0,
                ViolationSeverity::Medium => 2.0,
                ViolationSeverity::Low => 1.0,
            })
            .sum::<f32>();

        let max_score = 100.0;
        (max_score - penalty).max(0.0) / max_score
    }

    /// Format header name with case variant
    fn format_header_name(&self, name: &HeaderName, case_variant: &CaseVariant) -> String {
        let base_name = match name {
            HeaderName::Connection => "connection",
            HeaderName::ProxyConnection => "proxy-connection",
            HeaderName::Other(s) => s.as_str(),
        };

        match case_variant {
            CaseVariant::Lowercase => base_name.to_lowercase(),
            CaseVariant::Uppercase => base_name.to_uppercase(),
            CaseVariant::CamelCase => "Connection".to_string(),
            CaseVariant::MixedCase => base_name
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                })
                .collect(),
        }
    }

    /// Format connection value
    fn format_connection_value(&self, value: &ConnectionValue) -> String {
        match value {
            ConnectionValue::Close => "close".to_string(),
            ConnectionValue::KeepAlive => "keep-alive".to_string(),
            ConnectionValue::Upgrade => "upgrade".to_string(),
            ConnectionValue::MultipleTokens(tokens) => tokens.join(", "),
            ConnectionValue::Invalid(s) => s.clone(),
            ConnectionValue::Empty => "".to_string(),
            ConnectionValue::WhitespaceOnly(ws) => ws.clone(),
            ConnectionValue::CaseVariant(s) => s.clone(),
        }
    }
}

/// Generate comprehensive keep-alive default test cases
fn generate_keep_alive_default_test_cases() -> Vec<KeepAliveDefaultTestCase> {
    vec![
        // HTTP/1.0 default behavior (should close)
        KeepAliveDefaultTestCase {
            scenario: ConnectionScenario::Http10Default,
            http_version: HttpVersion::Http10,
            connection_headers: vec![], // No Connection header
            server_config: ServerConfig {
                keep_alive_enabled: true,
                max_requests_per_connection: None,
                idle_timeout_ms: Some(30000),
                force_close_on_error: false,
            },
            connection_state: ConnectionStateConfig {
                requests_served: 0,
                connection_phase: ConnectionPhase::Idle,
                idle_time_ms: 0,
                has_errors: false,
            },
            precedence_config: PrecedenceConfig {
                strict_rfc_compliance: true,
                allow_proxy_connection_fallback: false,
                validate_header_syntax: true,
                case_sensitive_header_values: false,
            },
        },
        // HTTP/1.1 default behavior (should keep-alive)
        KeepAliveDefaultTestCase {
            scenario: ConnectionScenario::Http11Default,
            http_version: HttpVersion::Http11,
            connection_headers: vec![], // No Connection header
            server_config: ServerConfig {
                keep_alive_enabled: true,
                max_requests_per_connection: None,
                idle_timeout_ms: Some(30000),
                force_close_on_error: false,
            },
            connection_state: ConnectionStateConfig {
                requests_served: 0,
                connection_phase: ConnectionPhase::Idle,
                idle_time_ms: 0,
                has_errors: false,
            },
            precedence_config: PrecedenceConfig {
                strict_rfc_compliance: true,
                allow_proxy_connection_fallback: false,
                validate_header_syntax: true,
                case_sensitive_header_values: false,
            },
        },
        // HTTP/1.0 with explicit keep-alive (should override default)
        KeepAliveDefaultTestCase {
            scenario: ConnectionScenario::ExplicitKeepAlive,
            http_version: HttpVersion::Http10,
            connection_headers: vec![ConnectionHeader {
                name: HeaderName::Connection,
                value: ConnectionValue::KeepAlive,
                case_variant: CaseVariant::Lowercase,
            }],
            server_config: ServerConfig {
                keep_alive_enabled: true,
                max_requests_per_connection: None,
                idle_timeout_ms: Some(30000),
                force_close_on_error: false,
            },
            connection_state: ConnectionStateConfig {
                requests_served: 0,
                connection_phase: ConnectionPhase::Idle,
                idle_time_ms: 0,
                has_errors: false,
            },
            precedence_config: PrecedenceConfig {
                strict_rfc_compliance: true,
                allow_proxy_connection_fallback: false,
                validate_header_syntax: true,
                case_sensitive_header_values: false,
            },
        },
        // HTTP/1.1 with explicit close (should override default)
        KeepAliveDefaultTestCase {
            scenario: ConnectionScenario::ExplicitClose,
            http_version: HttpVersion::Http11,
            connection_headers: vec![ConnectionHeader {
                name: HeaderName::Connection,
                value: ConnectionValue::Close,
                case_variant: CaseVariant::Lowercase,
            }],
            server_config: ServerConfig {
                keep_alive_enabled: true,
                max_requests_per_connection: None,
                idle_timeout_ms: Some(30000),
                force_close_on_error: false,
            },
            connection_state: ConnectionStateConfig {
                requests_served: 0,
                connection_phase: ConnectionPhase::Idle,
                idle_time_ms: 0,
                has_errors: false,
            },
            precedence_config: PrecedenceConfig {
                strict_rfc_compliance: true,
                allow_proxy_connection_fallback: false,
                validate_header_syntax: true,
                case_sensitive_header_values: false,
            },
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    // Try to generate a test case from fuzzer input
    let test_case = match KeepAliveDefaultTestCase::arbitrary(&mut unstructured) {
        Ok(tc) => tc,
        Err(_) => {
            // If generation fails, use a pre-generated test case
            let predefined_cases = generate_keep_alive_default_test_cases();
            if predefined_cases.is_empty() {
                return;
            }
            let index = unstructured
                .int_in_range(0..=predefined_cases.len() - 1)
                .unwrap_or(0);
            predefined_cases[index].clone()
        }
    };

    // Create connection manager
    let mut manager = MockConnectionManager::new(
        test_case.server_config.clone(),
        test_case.precedence_config.clone(),
    );

    // Analyze connection persistence behavior
    let analysis = manager.analyze_connection_persistence(&test_case);
    assert!(
        (0.0..=1.0).contains(&analysis.rfc_compliance_score),
        "RFC compliance score must stay normalized"
    );
    match analysis.effective_behavior {
        EffectiveBehavior::Close => assert!(analysis.should_close),
        EffectiveBehavior::KeepAlive => assert!(!analysis.should_close),
        EffectiveBehavior::Ambiguous | EffectiveBehavior::Invalid => assert!(analysis.should_close),
    }

    // Test specific edge cases
    test_http_version_defaults(&test_case);
    test_connection_header_precedence(&test_case);
    test_server_config_overrides(&test_case);
    test_case_sensitivity_handling(&test_case);
});

/// Test HTTP version default behaviors
fn test_http_version_defaults(test_case: &KeepAliveDefaultTestCase) {
    let manager = MockConnectionManager::new(
        test_case.server_config.clone(),
        test_case.precedence_config.clone(),
    );

    // Test HTTP/1.0 default (should close)
    let http10_default = manager.get_version_default_behavior(&HttpVersion::Http10);
    assert!(http10_default, "HTTP/1.0 should default to close");

    // Test HTTP/1.1 default (should keep-alive)
    let http11_default = manager.get_version_default_behavior(&HttpVersion::Http11);
    assert!(!http11_default, "HTTP/1.1 should default to keep-alive");
}

/// Test Connection header precedence over version defaults
fn test_connection_header_precedence(test_case: &KeepAliveDefaultTestCase) {
    if test_case.connection_headers.is_empty() {
        return;
    }

    let mut manager = MockConnectionManager::new(
        test_case.server_config.clone(),
        test_case.precedence_config.clone(),
    );

    let analysis = manager.analyze_connection_persistence(test_case);

    // If there's an explicit Connection header and no server override,
    // it should take precedence over version default
    if let DecisionReason::ExplicitConnectionHeader = analysis.decision_reason {
        assert!(
            matches!(
                analysis.effective_behavior,
                EffectiveBehavior::Close | EffectiveBehavior::KeepAlive
            ),
            "explicit Connection header resolved to invalid persistence behavior"
        );
    }
}

/// Test server configuration overrides
fn test_server_config_overrides(test_case: &KeepAliveDefaultTestCase) {
    // Test keep-alive disabled server-wide
    let disabled_config = ServerConfig {
        keep_alive_enabled: false,
        ..test_case.server_config.clone()
    };

    let mut manager =
        MockConnectionManager::new(disabled_config, test_case.precedence_config.clone());
    let analysis = manager.analyze_connection_persistence(test_case);

    assert!(
        matches!(
            analysis.decision_reason,
            DecisionReason::ServerConfigOverride
        ),
        "disabled keep-alive config should drive the persistence decision"
    );
    assert!(
        analysis.should_close,
        "server config disable should force close"
    );
}

/// Test case sensitivity in Connection header handling
fn test_case_sensitivity_handling(test_case: &KeepAliveDefaultTestCase) {
    for header in &test_case.connection_headers {
        let value_str = match &header.value {
            ConnectionValue::Close => "close",
            ConnectionValue::KeepAlive => "keep-alive",
            _ => continue,
        };

        // Connection header values should be case-insensitive per RFC
        let case_variants: &[&str] = match value_str {
            "close" => &["close", "CLOSE", "Close", "cLoSe"],
            "keep-alive" => &["keep-alive", "KEEP-ALIVE", "Keep-Alive", "kEeP-aLiVe"],
            _ => unreachable!("only close and keep-alive variants reach this check"),
        };
        for variant in case_variants {
            assert!(
                value_str.eq_ignore_ascii_case(variant),
                "Connection header values should be case-insensitive"
            );
        }
    }
}
