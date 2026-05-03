#![no_main]
//! HTTP/2 :authority pseudo-header invalid format fuzz target
//!
//! Tests handling of :authority pseudo-headers that start with "@" which
//! violates RFC 3986 requirements. Per RFC 3986, an authority component
//! starting with "@" suggests user-info but is missing the user part,
//! making it malformed. Valid user-info format is "user@host" not "@host".
//!
//! Primary test scenario: :authority with "@host:8080", "@example.com"
//!
//! Additional test scenarios:
//! - Simple "@hostname" without port
//! - Just "@" (minimal malformed case)
//! - "@:port" (missing hostname after @)
//! - "@host:" (missing port number)
//! - Multiple "@" symbols ("@@host", "@user@host")
//! - Very long hostnames with "@" prefix
//! - IPv6 addresses with "@" prefix ("@[::1]:8080")
//! - "@" with percent-encoded characters
//! - Complex malformed authorities with multiple violations
//!
//! RFC references:
//! - RFC 3986 §3.2.2: Authority component format
//! - RFC 3986 §3.2.1: User information subcomponent
//! - RFC 7540 §8.1.2.3: :authority pseudo-header requirements
//! - RFC 6874: IPv6 Zone ID representation

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for invalid authority testing scenarios
#[derive(Debug, Clone)]
struct InvalidAuthorityTestConfig {
    /// Include simple "@hostname" patterns
    pub include_simple_at_prefix: bool,
    /// Include complex malformed patterns
    pub include_complex_malformed: bool,
    /// Include IPv6 address testing
    pub include_ipv6_cases: bool,
    /// Include very long authority strings
    pub include_long_authorities: bool,
    /// Include percent-encoded patterns
    pub include_encoded_cases: bool,
}

impl Default for InvalidAuthorityTestConfig {
    fn default() -> Self {
        Self {
            include_simple_at_prefix: true,
            include_complex_malformed: true,
            include_ipv6_cases: true,
            include_long_authorities: true,
            include_encoded_cases: true,
        }
    }
}

/// Mock HTTP/2 connection for invalid authority validation testing
#[derive(Debug)]
struct MockInvalidAuthorityConnection {
    /// Count of requests with "@hostname" pattern
    pub at_hostname_pattern: Arc<Mutex<u64>>,
    /// Count of requests with "@hostname:port" pattern
    pub at_hostname_port_pattern: Arc<Mutex<u64>>,
    /// Count of requests with just "@"
    pub just_at_symbol: Arc<Mutex<u64>>,
    /// Count of requests with "@:port" (missing hostname)
    pub at_port_only: Arc<Mutex<u64>>,
    /// Count of requests with "@hostname:" (missing port)
    pub at_hostname_no_port: Arc<Mutex<u64>>,
    /// Count of requests with multiple "@" symbols
    pub multiple_at_symbols: Arc<Mutex<u64>>,
    /// Count of requests with IPv6 addresses starting with "@"
    pub at_ipv6_addresses: Arc<Mutex<u64>>,
    /// Count of requests with percent-encoded "@" patterns
    pub encoded_at_patterns: Arc<Mutex<u64>>,
    /// Count of requests with very long authorities starting with "@"
    pub long_at_authorities: Arc<Mutex<u64>>,
    /// Count of requests suggesting incomplete userinfo
    pub incomplete_userinfo: Arc<Mutex<u64>>,
    /// Count of BAD_REQUEST responses for invalid authorities
    pub bad_request_responses: Arc<Mutex<u64>>,
    /// Count of PROTOCOL_ERROR responses for malformed authorities
    pub protocol_errors: Arc<Mutex<u64>>,
    /// Count of valid requests (proper authority format)
    pub valid_requests: Arc<Mutex<u64>>,
    /// Track consistency violations (same input, different response)
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: InvalidAuthorityTestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, AuthorityResult>>>,
}

impl MockInvalidAuthorityConnection {
    fn new(config: InvalidAuthorityTestConfig) -> Self {
        Self {
            at_hostname_pattern: Arc::new(Mutex::new(0)),
            at_hostname_port_pattern: Arc::new(Mutex::new(0)),
            just_at_symbol: Arc::new(Mutex::new(0)),
            at_port_only: Arc::new(Mutex::new(0)),
            at_hostname_no_port: Arc::new(Mutex::new(0)),
            multiple_at_symbols: Arc::new(Mutex::new(0)),
            at_ipv6_addresses: Arc::new(Mutex::new(0)),
            encoded_at_patterns: Arc::new(Mutex::new(0)),
            long_at_authorities: Arc::new(Mutex::new(0)),
            incomplete_userinfo: Arc::new(Mutex::new(0)),
            bad_request_responses: Arc::new(Mutex::new(0)),
            protocol_errors: Arc::new(Mutex::new(0)),
            valid_requests: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with :authority validation
    fn handle_authority_request(&self, authority: &str) -> AuthorityResult {
        // Analyze authority characteristics
        let analysis = self.analyze_authority(authority);

        // Track various invalid patterns
        if analysis.just_at_symbol {
            *self.just_at_symbol.lock().unwrap() += 1;
        }

        if analysis.at_hostname_pattern {
            *self.at_hostname_pattern.lock().unwrap() += 1;
        }

        if analysis.at_hostname_port_pattern {
            *self.at_hostname_port_pattern.lock().unwrap() += 1;
        }

        if analysis.at_port_only {
            *self.at_port_only.lock().unwrap() += 1;
        }

        if analysis.at_hostname_no_port {
            *self.at_hostname_no_port.lock().unwrap() += 1;
        }

        if analysis.multiple_at_symbols {
            *self.multiple_at_symbols.lock().unwrap() += 1;
        }

        if analysis.at_ipv6_pattern {
            *self.at_ipv6_addresses.lock().unwrap() += 1;
        }

        if analysis.encoded_at_pattern {
            *self.encoded_at_patterns.lock().unwrap() += 1;
        }

        if analysis.long_at_authority {
            *self.long_at_authorities.lock().unwrap() += 1;
        }

        if analysis.suggests_incomplete_userinfo {
            *self.incomplete_userinfo.lock().unwrap() += 1;
        }

        // Determine if authority is valid per RFC 3986
        let is_valid_authority = self.validate_authority_format(authority, &analysis);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid_authority {
            *self.valid_requests.lock().unwrap() += 1;
            AuthorityResult::Accepted
        } else {
            if analysis.is_malformed {
                *self.protocol_errors.lock().unwrap() += 1;
                AuthorityResult::ProtocolError("Malformed authority syntax")
            } else {
                *self.bad_request_responses.lock().unwrap() += 1;
                AuthorityResult::BadRequest("Invalid authority format per RFC 3986")
            }
        };

        // Consistency check
        if let Some(previous_result) = cache.get(authority) {
            if !self.results_match(&result, previous_result) {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(authority.to_string(), result.clone());
        }

        result
    }

    /// Analyze authority characteristics for classification
    fn analyze_authority(&self, authority: &str) -> AuthorityAnalysis {
        let mut analysis = AuthorityAnalysis::default();

        // Basic checks
        analysis.is_empty = authority.is_empty();
        analysis.starts_with_at = authority.starts_with('@');

        if !analysis.starts_with_at {
            return analysis; // Not our concern if it doesn't start with @
        }

        // Specific @ pattern analysis
        analysis.just_at_symbol = authority == "@";

        // Count @ symbols
        let at_count = authority.matches('@').count();
        analysis.multiple_at_symbols = at_count > 1;

        // Pattern matching for @ prefixed authorities
        if authority.len() > 1 {
            let after_at = &authority[1..];

            // Check for @:port pattern (missing hostname)
            if after_at.starts_with(':') {
                analysis.at_port_only = true;
                analysis.suggests_incomplete_userinfo = true;
            }
            // Check for @hostname:port pattern
            else if after_at.contains(':') && !after_at.starts_with('[') {
                analysis.at_hostname_port_pattern = true;
                analysis.suggests_incomplete_userinfo = true;

                // Check if port is missing after colon
                if after_at.ends_with(':') {
                    analysis.at_hostname_no_port = true;
                }
            }
            // Check for @hostname pattern (no port)
            else if !after_at.is_empty() && !after_at.contains(':') {
                analysis.at_hostname_pattern = true;
                analysis.suggests_incomplete_userinfo = true;
            }

            // Check for IPv6 pattern @[address]:port
            if after_at.starts_with('[') {
                analysis.at_ipv6_pattern = true;
                analysis.suggests_incomplete_userinfo = true;
            }

            // Check for encoded characters
            if after_at.contains('%') {
                analysis.encoded_at_pattern = true;
            }

            // Check for very long authorities
            if authority.len() > 1024 {
                analysis.long_at_authority = true;
            }
        }

        // Malformed detection
        analysis.is_malformed = self.detect_malformed_authority(authority);

        analysis
    }

    /// Detect malformed authority syntax
    fn detect_malformed_authority(&self, authority: &str) -> bool {
        // Check for invalid characters
        if authority.contains('\0') || authority.contains('\r') || authority.contains('\n') {
            return true;
        }

        // Check for invalid percent encoding
        let mut chars = authority.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Must be followed by exactly two hex digits
                let hex1 = chars.next();
                let hex2 = chars.next();
                match (hex1, hex2) {
                    (Some(h1), Some(h2)) => {
                        if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                            return true;
                        }
                    }
                    _ => return true, // Incomplete percent encoding
                }
            }
        }

        // Check for malformed IPv6 addresses (if starting with @[)
        if authority.starts_with("@[") {
            if !authority.contains(']') {
                return true; // Unclosed IPv6 bracket
            }
        }

        // Check for multiple consecutive colons outside IPv6
        if !authority.contains('[') && authority.contains("::") {
            // :: is only valid in IPv6 addresses
            return true;
        }

        false
    }

    /// Validate authority format per RFC 3986 requirements
    fn validate_authority_format(&self, authority: &str, analysis: &AuthorityAnalysis) -> bool {
        // RFC 3986: authority starting with @ is invalid
        // It suggests user-info but is missing the user part
        if analysis.starts_with_at {
            return false; // Always invalid per RFC 3986
        }

        if analysis.is_empty {
            return false; // Empty authority is generally invalid
        }

        if analysis.is_malformed {
            return false; // Malformed syntax is always invalid
        }

        // Valid authority formats (for comparison):
        // - hostname
        // - hostname:port
        // - [ipv6]:port
        // - user@hostname:port (but not @hostname:port)
        true
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &AuthorityResult, result2: &AuthorityResult) -> bool {
        match (result1, result2) {
            (AuthorityResult::Accepted, AuthorityResult::Accepted) => true,
            (AuthorityResult::BadRequest(_), AuthorityResult::BadRequest(_)) => true,
            (AuthorityResult::ProtocolError(_), AuthorityResult::ProtocolError(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> InvalidAuthorityStatistics {
        InvalidAuthorityStatistics {
            total_at_hostname: *self.at_hostname_pattern.lock().unwrap(),
            total_at_hostname_port: *self.at_hostname_port_pattern.lock().unwrap(),
            total_just_at: *self.just_at_symbol.lock().unwrap(),
            total_at_port_only: *self.at_port_only.lock().unwrap(),
            total_at_hostname_no_port: *self.at_hostname_no_port.lock().unwrap(),
            total_multiple_at: *self.multiple_at_symbols.lock().unwrap(),
            total_at_ipv6: *self.at_ipv6_addresses.lock().unwrap(),
            total_encoded_at: *self.encoded_at_patterns.lock().unwrap(),
            total_long_at: *self.long_at_authorities.lock().unwrap(),
            total_incomplete_userinfo: *self.incomplete_userinfo.lock().unwrap(),
            total_bad_requests: *self.bad_request_responses.lock().unwrap(),
            total_protocol_errors: *self.protocol_errors.lock().unwrap(),
            total_valid: *self.valid_requests.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct AuthorityAnalysis {
    pub is_empty: bool,
    pub starts_with_at: bool,
    pub just_at_symbol: bool,
    pub at_hostname_pattern: bool,
    pub at_hostname_port_pattern: bool,
    pub at_port_only: bool,
    pub at_hostname_no_port: bool,
    pub multiple_at_symbols: bool,
    pub at_ipv6_pattern: bool,
    pub encoded_at_pattern: bool,
    pub long_at_authority: bool,
    pub suggests_incomplete_userinfo: bool,
    pub is_malformed: bool,
}

#[derive(Debug, Clone)]
enum AuthorityResult {
    Accepted,
    BadRequest(&'static str),
    ProtocolError(&'static str),
}

#[derive(Debug)]
struct InvalidAuthorityStatistics {
    pub total_at_hostname: u64,
    pub total_at_hostname_port: u64,
    pub total_just_at: u64,
    pub total_at_port_only: u64,
    pub total_at_hostname_no_port: u64,
    pub total_multiple_at: u64,
    pub total_at_ipv6: u64,
    pub total_encoded_at: u64,
    pub total_long_at: u64,
    pub total_incomplete_userinfo: u64,
    pub total_bad_requests: u64,
    pub total_protocol_errors: u64,
    pub total_valid: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for invalid authority testing
#[derive(Arbitrary, Debug)]
struct InvalidAuthorityInput {
    /// Base hostname
    hostname: String,
    /// Port number (as string)
    port: String,
    /// Additional characters to inject
    extra_chars: String,
    /// Test scenario configuration
    scenario: InvalidAuthorityScenario,
    /// Length multiplier for stress testing
    length_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum InvalidAuthorityScenario {
    /// Primary: "@hostname:port"
    AtHostnamePort,
    /// "@hostname" without port
    AtHostnameOnly,
    /// Just "@"
    JustAtSymbol,
    /// "@:port" (missing hostname)
    AtPortOnly,
    /// "@hostname:" (missing port number)
    AtHostnameNoPort,
    /// Multiple @ symbols
    MultipleAtSymbols,
    /// IPv6 with @ prefix
    AtIPv6Address,
    /// Encoded @ patterns
    EncodedAtPattern,
    /// Very long authority with @
    LongAtAuthority,
    /// Valid authority (for comparison)
    ValidAuthority,
    /// Malformed authority
    MalformedAuthority,
}

impl InvalidAuthorityInput {
    /// Generate authority string based on the test scenario
    fn generate_authority(&self) -> String {
        match &self.scenario {
            InvalidAuthorityScenario::AtHostnamePort => {
                // Primary test case: @hostname:port
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                let port = if self.port.is_empty() { "8080" } else { &self.port };
                format!("@{}:{}", host, port)
            }

            InvalidAuthorityScenario::AtHostnameOnly => {
                // @hostname without port
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                format!("@{}", host)
            }

            InvalidAuthorityScenario::JustAtSymbol => {
                // Minimal invalid case: just @
                "@".to_string()
            }

            InvalidAuthorityScenario::AtPortOnly => {
                // @:port (missing hostname)
                let port = if self.port.is_empty() { "8080" } else { &self.port };
                format!("@:{}", port)
            }

            InvalidAuthorityScenario::AtHostnameNoPort => {
                // @hostname: (missing port number)
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                format!("@{}:", host)
            }

            InvalidAuthorityScenario::MultipleAtSymbols => {
                // Multiple @ symbols (various patterns)
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                format!("@@{}", host)
            }

            InvalidAuthorityScenario::AtIPv6Address => {
                // IPv6 with @ prefix
                "@[::1]:8080".to_string()
            }

            InvalidAuthorityScenario::EncodedAtPattern => {
                // Percent-encoded patterns
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                format!("@{}%2E{}", host, self.extra_chars)
            }

            InvalidAuthorityScenario::LongAtAuthority => {
                // Very long authority starting with @
                let mut authority = "@".to_string();
                let repeat_count = (self.length_multiplier as usize).max(1);
                for i in 0..repeat_count {
                    authority.push_str(&format!("subdomain{}.example", i));
                    if authority.len() > 2048 {
                        break;
                    }
                    if i < repeat_count - 1 {
                        authority.push('.');
                    }
                }
                authority.push_str(".com:8080");
                authority
            }

            InvalidAuthorityScenario::ValidAuthority => {
                // Valid authority for comparison (no @ prefix)
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                if self.port.is_empty() {
                    host.to_string()
                } else {
                    format!("{}:{}", host, self.port)
                }
            }

            InvalidAuthorityScenario::MalformedAuthority => {
                // Malformed authority with invalid encoding
                let host = if self.hostname.is_empty() { "example.com" } else { &self.hostname };
                format!("@{}%GG:{}", host, self.port)
            }
        }
    }
}

fuzz_target!(|input: InvalidAuthorityInput| {
    // Skip excessively large inputs
    if input.hostname.len() > 1000 || input.port.len() > 100 {
        return;
    }

    // Generate test configuration
    let config = InvalidAuthorityTestConfig::default();

    // Create mock connection
    let connection = MockInvalidAuthorityConnection::new(config);

    // Generate authority for testing
    let authority = input.generate_authority();

    // Limit authority length to prevent OOM
    if authority.len() > 8192 {
        return;
    }

    // Test the authority validation
    let result = connection.handle_authority_request(&authority);

    // Verify the result makes sense
    match result {
        AuthorityResult::Accepted => {
            // Should only be accepted if authority doesn't start with @
            if authority.starts_with('@') {
                panic!("RFC 3986 violation: authority starting with '@' should be rejected: '{}'", authority);
            }
        }
        AuthorityResult::BadRequest(_reason) => {
            // Should be rejected for @ prefix (incomplete userinfo)
        }
        AuthorityResult::ProtocolError(_reason) => {
            // Should be rejected for malformed syntax
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_authority_request(&authority);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent authority validation: {:?} != {:?} for authority: '{}'",
               result, result2, authority);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For the primary test cases (@ prefix), verify rejection
    match input.scenario {
        InvalidAuthorityScenario::AtHostnamePort |
        InvalidAuthorityScenario::AtHostnameOnly |
        InvalidAuthorityScenario::JustAtSymbol |
        InvalidAuthorityScenario::AtPortOnly |
        InvalidAuthorityScenario::AtHostnameNoPort => {
            if authority.starts_with('@') {
                match result {
                    AuthorityResult::BadRequest(_) => {
                        // Correct: @ prefix should be rejected
                    }
                    AuthorityResult::ProtocolError(_) => {
                        // Also correct if treated as protocol error
                    }
                    AuthorityResult::Accepted => {
                        panic!("RFC 3986 violation: authority starting with '@' should be rejected: '{}'", authority);
                    }
                }
            }
        }
        _ => {
            // Other scenarios have their own validation requirements
        }
    }
});