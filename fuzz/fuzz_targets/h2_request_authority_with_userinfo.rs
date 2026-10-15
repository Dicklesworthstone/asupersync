#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :authority pseudo-header user-info rejection fuzz target.
///
/// Tests RFC 7540 §8.1.2.3 compliance for :authority pseudo-header containing
/// user-info syntax (e.g., "user:pass@host:port"). Per the specification:
/// "The authority MUST NOT include the userinfo subcomponent of an URI."
///
/// Critical test scenarios:
/// - Various user-info patterns: user@host, user:pass@host, @host
/// - Edge cases: multiple @ symbols, encoded characters, IPv6 with @
/// - Error detection and proper rejection messages
/// - Valid authorities that contain @ but aren't user-info

#[derive(Arbitrary, Debug, Clone)]
struct AuthorityUserInfoInput {
    /// Authority value with potential user-info
    authority: String,

    /// User-info test patterns
    userinfo_patterns: Vec<UserInfoPattern>,

    /// HTTP/2 request context
    request_context: RequestContext,

    /// Parser configuration
    parser_config: AuthorityParserConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum UserInfoPattern {
    /// Simple user@host format
    SimpleUser { username: String, hostname: String },

    /// User with password user:pass@host
    UserPassword {
        username: String,
        password: String,
        hostname: String,
        port: Option<u16>,
    },

    /// Empty user info @host
    EmptyUser { hostname: String },

    /// Complex user info with special characters
    ComplexUser {
        username: String,
        password: String,
        hostname: String,
        encoded_chars: bool,
    },

    /// Multiple @ symbols (malformed)
    MultipleAt { parts: Vec<String> },

    /// Edge cases that might be confused with user-info
    EdgeCase {
        edge_type: EdgeCaseType,
        value: String,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseType {
    /// IPv6 address with @ in data
    IPv6WithAt,
    /// Domain with @ in subdomain (invalid but test anyway)
    DomainWithAt,
    /// Encoded @ character
    EncodedAt,
    /// @ at start or end
    AtPosition,
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestContext {
    /// HTTP method
    method: String,

    /// Request path
    path: String,

    /// Scheme
    scheme: String,

    /// Additional headers for context
    other_headers: Vec<(String, String)>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            scheme: "https".to_string(),
            other_headers: Vec::new(),
        }
    }
}

fn normalize_request_context(context: &mut RequestContext) {
    const MAX_METHOD_LEN: usize = 32;
    const MAX_PATH_LEN: usize = 256;
    const MAX_SCHEME_LEN: usize = 16;
    const MAX_HEADER_COUNT: usize = 16;
    const MAX_HEADER_NAME_LEN: usize = 64;
    const MAX_HEADER_VALUE_LEN: usize = 256;

    if context.method.len() > MAX_METHOD_LEN {
        context.method.truncate(MAX_METHOD_LEN);
    }
    if context.path.len() > MAX_PATH_LEN {
        context.path.truncate(MAX_PATH_LEN);
    }
    if context.scheme.len() > MAX_SCHEME_LEN {
        context.scheme.truncate(MAX_SCHEME_LEN);
    }

    if context.other_headers.len() > MAX_HEADER_COUNT {
        context.other_headers.truncate(MAX_HEADER_COUNT);
    }
    for (name, value) in &mut context.other_headers {
        if name.len() > MAX_HEADER_NAME_LEN {
            name.truncate(MAX_HEADER_NAME_LEN);
        }
        if value.len() > MAX_HEADER_VALUE_LEN {
            value.truncate(MAX_HEADER_VALUE_LEN);
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct AuthorityParserConfig {
    /// Whether to enforce strict RFC 7540 compliance
    strict_rfc_compliance: bool,

    /// Whether to detect encoded user-info
    detect_encoded_userinfo: bool,

    /// Whether to allow IPv6 literals
    allow_ipv6_literals: bool,

    /// Whether to validate hostname format
    validate_hostname_format: bool,
}

impl Default for AuthorityParserConfig {
    fn default() -> Self {
        Self {
            strict_rfc_compliance: true,
            detect_encoded_userinfo: true,
            allow_ipv6_literals: true,
            validate_hostname_format: true,
        }
    }
}

/// Mock HTTP/2 :authority parser for user-info testing
struct MockAuthorityParser {
    config: AuthorityParserConfig,
    rejection_stats: RejectionStats,
}

impl MockAuthorityParser {
    fn new(config: AuthorityParserConfig) -> Self {
        Self {
            config,
            rejection_stats: RejectionStats::default(),
        }
    }

    /// Parse :authority pseudo-header and validate per RFC 7540 §8.1.2.3
    fn parse_authority(
        &mut self,
        authority: &str,
        context: &RequestContext,
    ) -> AuthorityParseResult {
        self.rejection_stats.total_parses += 1;

        if authority.is_empty() {
            self.rejection_stats.other_rejections += 1;
            return AuthorityParseResult::Invalid("Empty authority header".to_string());
        }

        // RFC 7540 §8.1.2.3: Check for user-info
        if let Some(userinfo_violation) = self.detect_userinfo(authority) {
            self.rejection_stats.userinfo_rejections += 1;
            return AuthorityParseResult::UserInfoViolation {
                authority: authority.to_string(),
                violation_type: userinfo_violation.violation_type,
                detected_userinfo: userinfo_violation.userinfo,
            };
        }

        // Parse authority components
        let result = self.parse_authority_components(authority, context);
        if matches!(&result, AuthorityParseResult::Invalid(_)) {
            self.rejection_stats.other_rejections += 1;
        }
        result
    }

    fn detect_userinfo(&self, authority: &str) -> Option<UserInfoViolation> {
        // RFC 7540 §8.1.2.3: "The authority MUST NOT include the userinfo subcomponent"
        // userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
        // authority = [ userinfo "@" ] host [ ":" port ]

        // Look for @ symbol indicating potential user-info
        if let Some(at_pos) = authority.find('@') {
            // Check if this looks like user-info@host format
            let potential_userinfo = &authority[..at_pos];
            let host_part = &authority[at_pos + 1..];

            if self.is_userinfo_pattern(potential_userinfo, host_part) {
                return Some(UserInfoViolation {
                    violation_type: self.classify_userinfo_violation(potential_userinfo),
                    userinfo: potential_userinfo.to_string(),
                });
            }
        }

        // Check for encoded @ symbols if enabled
        if self.config.detect_encoded_userinfo
            && let Some(encoded_violation) = self.detect_encoded_userinfo(authority)
        {
            return Some(encoded_violation);
        }

        None
    }

    fn is_userinfo_pattern(&self, potential_userinfo: &str, host_part: &str) -> bool {
        // Empty potential userinfo with non-empty host suggests @host format (invalid)
        if potential_userinfo.is_empty() {
            return !host_part.is_empty();
        }

        // Check if host_part looks like a valid hostname/IP
        if !self.looks_like_host(host_part) {
            return false;
        }

        // Check if potential_userinfo contains user-info characters
        // RFC 3986: userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
        for ch in potential_userinfo.chars() {
            if ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '-' | '.'
                        | '_'
                        | '~'
                        | ':'
                        | '!'
                        | '$'
                        | '&'
                        | '\''
                        | '('
                        | ')'
                        | '*'
                        | '+'
                        | ','
                        | ';'
                        | '='
                )
            {
                // Valid userinfo character
                continue;
            } else if ch == '%' {
                // Percent-encoded character (simplified check)
                continue;
            } else {
                // Invalid userinfo character - might not be userinfo
                return false;
            }
        }

        true
    }

    fn looks_like_host(&self, host_part: &str) -> bool {
        if host_part.is_empty() {
            return false;
        }

        // Check for IPv6 literal format
        if host_part.starts_with('[') && host_part.ends_with(']') {
            return self.config.allow_ipv6_literals;
        }

        // Check for hostname or IPv4
        // Simplified validation - looks for basic hostname patterns
        let host_without_port = host_part.split(':').next().unwrap_or(host_part);

        // Basic hostname validation
        !host_without_port.is_empty()
            && host_without_port
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }

    fn classify_userinfo_violation(&self, userinfo: &str) -> UserInfoViolationType {
        if userinfo.is_empty() {
            UserInfoViolationType::EmptyUser
        } else if userinfo.contains(':') {
            UserInfoViolationType::UserPassword
        } else {
            UserInfoViolationType::SimpleUser
        }
    }

    fn detect_encoded_userinfo(&self, authority: &str) -> Option<UserInfoViolation> {
        // Check for percent-encoded @ symbol (%40)
        if let Some(encoded_at_pos) = authority.find("%40") {
            let potential_userinfo = &authority[..encoded_at_pos];
            let host_part = &authority[encoded_at_pos + 3..];

            if self.is_userinfo_pattern(potential_userinfo, host_part) {
                return Some(UserInfoViolation {
                    violation_type: UserInfoViolationType::EncodedAt,
                    userinfo: potential_userinfo.to_string(),
                });
            }
        }

        // Check for other encoded forms
        if authority.contains("%3A") {
            // Encoded :
            // Might be encoded user:pass format
            if authority.contains("@") || authority.contains("%40") {
                return Some(UserInfoViolation {
                    violation_type: UserInfoViolationType::EncodedChars,
                    userinfo: "encoded_userinfo".to_string(),
                });
            }
        }

        None
    }

    fn parse_authority_components(
        &mut self,
        authority: &str,
        context: &RequestContext,
    ) -> AuthorityParseResult {
        // Parse without user-info (already validated absent)
        let (host, port) = if let Some(colon_pos) = authority.rfind(':') {
            let host_part = &authority[..colon_pos];
            let port_str = &authority[colon_pos + 1..];

            // Check if this is actually a port or part of IPv6
            if host_part.contains('[') && authority.ends_with(']') {
                // IPv6 without port
                (authority, None)
            } else {
                match port_str.parse::<u16>() {
                    Ok(port) => (host_part, Some(port)),
                    Err(_) => (authority, None), // Not a port, treat as hostname
                }
            }
        } else {
            (authority, None)
        };

        // Validate host component
        if let Err(msg) = self.validate_host_component(host) {
            return AuthorityParseResult::Invalid(msg);
        }

        // Validate port if present
        if let Some(port) = port
            && let Err(msg) = self.validate_port(port, &context.scheme)
        {
            return AuthorityParseResult::Invalid(msg);
        }

        AuthorityParseResult::Valid {
            host: host.to_string(),
            port,
            scheme_compatible: self.is_scheme_compatible(host, port, &context.scheme),
        }
    }

    fn validate_host_component(&self, host: &str) -> Result<(), String> {
        if host.is_empty() {
            return Err("Empty host component".to_string());
        }

        // IPv6 literal validation
        if host.starts_with('[') && host.ends_with(']') {
            if !self.config.allow_ipv6_literals {
                return Err("IPv6 literals not allowed".to_string());
            }

            let ipv6_part = &host[1..host.len() - 1];
            if ipv6_part.is_empty() {
                return Err("Empty IPv6 address".to_string());
            }

            // Basic IPv6 format check
            if !ipv6_part.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                return Err("Invalid IPv6 address format".to_string());
            }

            return Ok(());
        }

        // Regular hostname validation
        if self.config.validate_hostname_format {
            if host.starts_with('-') || host.ends_with('-') {
                return Err("Hostname cannot start or end with hyphen".to_string());
            }

            if host.contains("..") {
                return Err("Hostname cannot contain consecutive dots".to_string());
            }

            // Check for invalid characters
            for ch in host.chars() {
                if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' {
                    return Err(format!("Invalid character in hostname: '{}'", ch));
                }
            }
        }

        Ok(())
    }

    fn validate_port(&self, port: u16, scheme: &str) -> Result<(), String> {
        if port == 0 {
            return Err("Port cannot be zero".to_string());
        }

        // Check scheme-specific port validity
        match scheme {
            "http" => {
                // HTTP default port is 80
                Ok(())
            }
            "https" => {
                // HTTPS default port is 443
                Ok(())
            }
            _ => {
                // Other schemes
                Ok(())
            }
        }
    }

    fn is_scheme_compatible(&self, host: &str, port: Option<u16>, scheme: &str) -> bool {
        let is_local_development_host = host.eq_ignore_ascii_case("localhost")
            || host.starts_with("127.")
            || host == "[::1]"
            || host == "::1";

        match scheme {
            "https" => {
                // HTTPS should use secure port or default 443
                port.is_none_or(|p| p == 443 || p >= 1024 || is_local_development_host)
            }
            "http" => {
                // HTTP typically uses port 80 or high ports
                port.is_none_or(|p| p == 80 || p >= 1024 || is_local_development_host)
            }
            _ => true, // Unknown schemes are compatible
        }
    }

    fn get_rejection_stats(&self) -> RejectionStats {
        self.rejection_stats.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct RejectionStats {
    total_parses: u32,
    userinfo_rejections: u32,
    other_rejections: u32,
}

#[derive(Debug)]
struct UserInfoViolation {
    violation_type: UserInfoViolationType,
    userinfo: String,
}

#[derive(Debug, PartialEq)]
enum UserInfoViolationType {
    SimpleUser,   // user@host
    UserPassword, // user:pass@host
    EmptyUser,    // @host
    EncodedAt,    // user%40host
    EncodedChars, // user%3Apass@host
}

#[derive(Debug, PartialEq)]
enum AuthorityParseResult {
    /// Valid authority without user-info
    Valid {
        host: String,
        port: Option<u16>,
        scheme_compatible: bool,
    },

    /// RFC 7540 §8.1.2.3 violation - contains user-info
    UserInfoViolation {
        authority: String,
        violation_type: UserInfoViolationType,
        detected_userinfo: String,
    },

    /// Invalid authority format
    Invalid(String),
}

fuzz_target!(|input: AuthorityUserInfoInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.userinfo_patterns.len() > 10 {
        input.userinfo_patterns.truncate(10); // Limit for performance
    }
    normalize_request_context(&mut input.request_context);

    let mut parser = MockAuthorityParser::new(input.parser_config.clone());

    // Test basic authority from input
    let basic_result = parser.parse_authority(&input.authority, &input.request_context);

    // Validate basic result
    match basic_result {
        AuthorityParseResult::UserInfoViolation {
            ref violation_type,
            ref detected_userinfo,
            ..
        } => {
            // Verify user-info was properly detected
            assert!(
                !detected_userinfo.is_empty()
                    || violation_type == &UserInfoViolationType::EmptyUser,
                "User-info violation should have detected userinfo or be empty user type"
            );

            match violation_type {
                UserInfoViolationType::SimpleUser => {
                    assert!(
                        !detected_userinfo.contains(':'),
                        "Simple user should not contain password separator"
                    );
                }
                UserInfoViolationType::UserPassword => {
                    assert!(
                        detected_userinfo.contains(':'),
                        "User password type should contain password separator"
                    );
                }
                UserInfoViolationType::EmptyUser => {
                    assert!(
                        detected_userinfo.is_empty(),
                        "Empty user type should have empty userinfo"
                    );
                }
                _ => {
                    // Other types are acceptable
                }
            }
        }

        AuthorityParseResult::Valid {
            ref host,
            port,
            scheme_compatible,
        } => {
            // Valid authority should not contain @ symbols in problematic positions
            if input.authority.contains('@') {
                // If @ is present but result is valid, verify it's not user-info pattern
                // (e.g., might be IPv6 or other edge case)
                if parser.config.strict_rfc_compliance {
                    panic!(
                        "Authority with @ should be rejected under strict RFC compliance: {}",
                        input.authority
                    );
                }
            }

            assert!(
                !host.is_empty(),
                "Valid authority should have non-empty host"
            );

            if let Some(p) = port {
                assert!(p > 0, "Valid port should be non-zero");
            }

            if scheme_compatible {
                assert!(
                    input.request_context.scheme.len() <= 16,
                    "Normalized scheme should remain bounded"
                );
            }
        }

        AuthorityParseResult::Invalid(_) => {
            // Invalid results are acceptable for malformed input
        }
    }

    // Test specific user-info patterns
    for pattern in &input.userinfo_patterns {
        let test_authority = build_authority_from_pattern(pattern);
        let pattern_result = parser.parse_authority(&test_authority, &input.request_context);

        match pattern_result {
            AuthorityParseResult::UserInfoViolation { violation_type, .. } => {
                // Verify the violation type matches the pattern
                match (pattern, violation_type) {
                    (UserInfoPattern::SimpleUser { .. }, UserInfoViolationType::SimpleUser) => {
                        // Correct detection
                    }
                    (UserInfoPattern::UserPassword { .. }, UserInfoViolationType::UserPassword) => {
                        // Correct detection
                    }
                    (UserInfoPattern::EmptyUser { .. }, UserInfoViolationType::EmptyUser) => {
                        // Correct detection
                    }
                    _ => {
                        // Other combinations might be acceptable depending on detection logic
                    }
                }
            }

            AuthorityParseResult::Valid { .. } => {
                // Should not be valid for obvious user-info patterns
                match pattern {
                    UserInfoPattern::SimpleUser { .. }
                    | UserInfoPattern::UserPassword { .. }
                    | UserInfoPattern::EmptyUser { .. }
                        if parser.config.strict_rfc_compliance =>
                    {
                        panic!("User-info pattern should be rejected: {:?}", pattern);
                    }
                    _ => {
                        // Edge cases might be valid
                    }
                }
            }

            AuthorityParseResult::Invalid(_) => {
                // Invalid results are acceptable
            }
        }
    }

    // Test edge cases that should NOT be rejected as user-info
    let valid_authorities = vec![
        "[2001:db8::1]:8080".to_string(), // IPv6 with port
        "example.com:443".to_string(),    // Simple host:port
        "sub.domain.com".to_string(),     // Subdomain
        "192.168.1.1:8080".to_string(),   // IPv4 with port
    ];

    for valid_auth in valid_authorities {
        let valid_result = parser.parse_authority(&valid_auth, &input.request_context);
        match valid_result {
            AuthorityParseResult::Valid { .. } => {
                // Expected for valid authorities
            }
            AuthorityParseResult::UserInfoViolation { .. } => {
                panic!(
                    "Valid authority should not be rejected as user-info: {}",
                    valid_auth
                );
            }
            AuthorityParseResult::Invalid(_) => {
                // Acceptable if validation is strict
            }
        }
    }

    // Test obvious user-info violations
    let userinfo_violations = vec![
        "user@example.com".to_string(),
        "user:pass@example.com".to_string(),
        "@example.com".to_string(),
        "admin:secret@host:8080".to_string(),
    ];

    for violation_auth in userinfo_violations {
        let violation_result = parser.parse_authority(&violation_auth, &input.request_context);
        match violation_result {
            AuthorityParseResult::UserInfoViolation { .. } => {
                // Expected for obvious violations
            }
            AuthorityParseResult::Valid { .. } => {
                if parser.config.strict_rfc_compliance {
                    panic!(
                        "Obvious user-info violation should be rejected: {}",
                        violation_auth
                    );
                }
            }
            AuthorityParseResult::Invalid(_) => {
                // Acceptable alternative rejection
            }
        }
    }

    // Verify statistics consistency
    let stats = parser.get_rejection_stats();
    assert!(stats.total_parses > 0, "Should have processed some parses");
    let accounted_rejections = stats.userinfo_rejections + stats.other_rejections;
    assert!(
        accounted_rejections <= stats.total_parses,
        "Rejection counts should not exceed total parses"
    );

    // Verify no panics occurred during user-info detection
    // (Implicit - if we reach here without panicking, the test passed)
});

fn build_authority_from_pattern(pattern: &UserInfoPattern) -> String {
    match pattern {
        UserInfoPattern::SimpleUser { username, hostname } => {
            format!("{}@{}", username, hostname)
        }

        UserInfoPattern::UserPassword {
            username,
            password,
            hostname,
            port,
        } => {
            let auth = format!("{}:{}@{}", username, password, hostname);
            if let Some(p) = port {
                format!("{}:{}", auth, p)
            } else {
                auth
            }
        }

        UserInfoPattern::EmptyUser { hostname } => {
            format!("@{}", hostname)
        }

        UserInfoPattern::ComplexUser {
            username,
            password,
            hostname,
            encoded_chars,
        } => {
            if *encoded_chars {
                format!("{}%3A{}%40{}", username, password, hostname)
            } else {
                format!("{}:{}@{}", username, password, hostname)
            }
        }

        UserInfoPattern::MultipleAt { parts } => parts.join("@"),

        UserInfoPattern::EdgeCase { edge_type, value } => match edge_type {
            EdgeCaseType::IPv6WithAt => format!("[{}]", value),
            EdgeCaseType::DomainWithAt => value.clone(),
            EdgeCaseType::EncodedAt => value.replace("@", "%40"),
            EdgeCaseType::AtPosition => value.clone(),
        },
    }
}
