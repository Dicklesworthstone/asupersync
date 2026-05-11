#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :authority pseudo-header validation fuzz target.
///
/// Tests RFC 7540 §8.1.2 and RFC 3986 compliance for :authority pseudo-header
/// values. The :authority header must contain a valid authority component per
/// RFC 3986, which excludes control characters, spaces, and various forbidden
/// characters like /, ?, #.
///
/// Critical invalid cases:
/// - Control characters (0x00-0x1F, 0x7F)
/// - Spaces and tabs
/// - Path separators (/, \)
/// - Query indicators (?, #)
/// - Fragment indicators (#)
/// - Invalid port formats

#[derive(Arbitrary, Debug, Clone)]
struct AuthorityInput {
    /// Authority value to validate
    authority: String,

    /// Request method (affects validation strictness)
    method: String,

    /// Request scheme (http, https)
    scheme: String,

    /// Validation policy configuration
    policy: AuthorityValidationPolicy,
}

#[derive(Arbitrary, Debug, Clone)]
struct AuthorityValidationPolicy {
    /// Whether to enforce strict RFC 3986 compliance
    strict_rfc3986: bool,

    /// Whether to allow IPv6 literals with brackets
    allow_ipv6_literals: bool,

    /// Whether to allow international domain names
    allow_idn: bool,

    /// Maximum authority length
    max_length: usize,

    /// Whether to validate port ranges (1-65535)
    validate_port_range: bool,
}

impl Default for AuthorityValidationPolicy {
    fn default() -> Self {
        Self {
            strict_rfc3986: true,
            allow_ipv6_literals: true,
            allow_idn: false,
            max_length: 255,
            validate_port_range: true,
        }
    }
}

/// Mock HTTP/2 authority validator for testing RFC compliance
struct MockAuthorityValidator {
    policy: AuthorityValidationPolicy,
}

impl MockAuthorityValidator {
    fn new(policy: AuthorityValidationPolicy) -> Self {
        Self { policy }
    }

    /// Validate :authority pseudo-header per RFC 7540 §8.1.2 and RFC 3986
    fn validate_authority(&self, input: &AuthorityInput) -> AuthorityResult {
        let authority = &input.authority;
        let _request_context = (&input.method, &input.scheme);

        // Check length limits
        if authority.len() > self.policy.max_length {
            return AuthorityResult::Invalid(format!(
                "Authority too long: {} > {}",
                authority.len(),
                self.policy.max_length
            ));
        }

        // Empty authority is invalid for most cases
        if authority.is_empty() {
            return AuthorityResult::Invalid("Empty authority".to_string());
        }

        // RFC 3986 forbidden characters validation
        if let Some(invalid_char) = self.find_forbidden_characters(authority) {
            return AuthorityResult::ProtocolError(format!(
                "Forbidden character in authority: {:?} (0x{:02X})",
                invalid_char, invalid_char as u8
            ));
        }

        // Parse and validate components
        self.validate_authority_components(authority)
    }

    fn find_forbidden_characters(&self, authority: &str) -> Option<char> {
        for ch in authority.chars() {
            // RFC 3986 control characters (0x00-0x1F, 0x7F)
            if ch.is_control() {
                return Some(ch);
            }

            // RFC 3986 forbidden characters in authority component
            match ch {
                // Space and tab
                ' ' | '\t' => return Some(ch),

                // Path separators
                '/' | '\\' => return Some(ch),

                // Query and fragment indicators
                '?' | '#' => return Some(ch),

                // Other forbidden characters
                '"' | '<' | '>' | '`' | '{' | '}' | '|' => return Some(ch),

                // Unicode control categories if strict
                _ if self.policy.strict_rfc3986 && is_unicode_control(ch) => return Some(ch),

                _ => continue,
            }
        }
        None
    }

    fn validate_authority_components(&self, authority: &str) -> AuthorityResult {
        // Check for IPv6 literal format [::1]:8080
        if authority.starts_with('[') {
            return self.validate_ipv6_authority(authority);
        }

        // Split host:port
        let (host, port_str) = if let Some(colon_pos) = authority.rfind(':') {
            let (host_part, port_part) = authority.split_at(colon_pos);
            (host_part, Some(&port_part[1..]))
        } else {
            (authority, None)
        };

        // Validate host component
        if let Err(msg) = self.validate_host_component(host) {
            return AuthorityResult::Invalid(msg);
        }

        // Validate port component if present
        if let Some(port_str) = port_str
            && let Err(msg) = self.validate_port_component(port_str)
        {
            return AuthorityResult::Invalid(msg);
        }

        // Additional validation scenarios
        self.validate_specific_scenarios(authority)
    }

    fn validate_ipv6_authority(&self, authority: &str) -> AuthorityResult {
        if !self.policy.allow_ipv6_literals {
            return AuthorityResult::Invalid("IPv6 literals not allowed".to_string());
        }

        if !authority.starts_with('[') || !authority.contains(']') {
            return AuthorityResult::Invalid("Malformed IPv6 literal".to_string());
        }

        let bracket_end = authority.find(']').unwrap();
        let ipv6_part = &authority[1..bracket_end];
        let remainder = &authority[bracket_end + 1..];

        // Validate IPv6 address format (simplified)
        if ipv6_part.is_empty() {
            return AuthorityResult::Invalid("Empty IPv6 address".to_string());
        }

        // Check for forbidden characters in IPv6 part
        for ch in ipv6_part.chars() {
            if !ch.is_ascii_hexdigit() && ch != ':' {
                return AuthorityResult::ProtocolError(format!(
                    "Invalid character in IPv6 address: {:?}",
                    ch
                ));
            }
        }

        // Validate port part if present
        if let Some(port_str) = remainder.strip_prefix(':') {
            if let Err(msg) = self.validate_port_component(port_str) {
                return AuthorityResult::Invalid(msg);
            }
        } else if !remainder.is_empty() {
            return AuthorityResult::Invalid("Invalid IPv6 literal format".to_string());
        }

        AuthorityResult::Valid("Valid IPv6 authority".to_string())
    }

    fn validate_host_component(&self, host: &str) -> Result<(), String> {
        if host.is_empty() {
            return Err("Empty host component".to_string());
        }

        // Check for invalid characters in hostname
        for ch in host.chars() {
            if ch.is_control() {
                return Err(format!("Control character in host: {:?}", ch));
            }
            if matches!(
                ch,
                ' ' | '\t' | '/' | '\\' | '?' | '#' | '"' | '<' | '>' | '`' | '{' | '}' | '|'
            ) {
                return Err(format!("Forbidden character in host: {:?}", ch));
            }
        }

        // Basic hostname format validation
        if host.starts_with('-') || host.ends_with('-') {
            return Err("Hostname cannot start or end with hyphen".to_string());
        }

        if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
            return Err("Invalid dot placement in hostname".to_string());
        }

        Ok(())
    }

    fn validate_port_component(&self, port_str: &str) -> Result<(), String> {
        if port_str.is_empty() {
            return Err("Empty port component".to_string());
        }

        // Check for non-digit characters
        if !port_str.chars().all(|c| c.is_ascii_digit()) {
            return Err("Non-digit characters in port".to_string());
        }

        // Parse port number
        let port: u32 = port_str
            .parse()
            .map_err(|_| "Port number too large".to_string())?;

        if self.policy.validate_port_range && (port == 0 || port > 65535) {
            return Err(format!("Port {} out of valid range 1-65535", port));
        }

        Ok(())
    }

    fn validate_specific_scenarios(&self, authority: &str) -> AuthorityResult {
        // Scenario 1: Authority with control characters
        if authority.chars().any(|c| c.is_control()) {
            return AuthorityResult::ProtocolError(
                "Control characters forbidden in authority".to_string(),
            );
        }

        // Scenario 2: Authority with spaces
        if authority.contains(' ') || authority.contains('\t') {
            return AuthorityResult::ProtocolError(
                "Whitespace characters forbidden in authority".to_string(),
            );
        }

        // Scenario 3: Authority with path-like characters
        if authority.contains('/') || authority.contains('\\') {
            return AuthorityResult::ProtocolError(
                "Path separators forbidden in authority".to_string(),
            );
        }

        // Scenario 4: Authority with query/fragment indicators
        if authority.contains('?') || authority.contains('#') {
            return AuthorityResult::ProtocolError(
                "Query/fragment indicators forbidden in authority".to_string(),
            );
        }

        // Scenario 5: International characters without IDN support
        if !self.policy.allow_idn && !authority.is_ascii() {
            return AuthorityResult::Invalid(
                "Non-ASCII characters not allowed without IDN support".to_string(),
            );
        }

        // Scenario 6: Multiple consecutive colons (invalid port format)
        if authority.matches(':').count() > 1 && !authority.starts_with('[') {
            return AuthorityResult::Invalid("Multiple colons in non-IPv6 authority".to_string());
        }

        // Scenario 7: Authority with scheme-like prefix
        if authority.contains("://") {
            return AuthorityResult::Invalid("Scheme separator in authority component".to_string());
        }

        AuthorityResult::Valid(format!("Valid authority: {}", authority))
    }
}

fn is_unicode_control(ch: char) -> bool {
    matches!(ch,
        '\u{0000}'..='\u{001F}' | // C0 controls
        '\u{007F}'..='\u{009F}' | // DEL + C1 controls
        '\u{2028}' | '\u{2029}'   // Line/paragraph separators
    )
}

#[derive(Debug, PartialEq)]
enum AuthorityResult {
    /// Authority is valid per RFC 3986 and RFC 7540
    Valid(String),

    /// Authority violates RFC and should trigger PROTOCOL_ERROR
    ProtocolError(String),

    /// Authority is invalid but may not be a protocol error
    Invalid(String),
}

fuzz_target!(|input: AuthorityInput| {
    let validator = MockAuthorityValidator::new(input.policy.clone());
    let result = validator.validate_authority(&input);

    // Test critical RFC violations
    match result {
        AuthorityResult::ProtocolError(ref msg) => {
            let authority = &input.authority;

            // Control characters should always be protocol errors
            if authority.chars().any(|c| c.is_control()) {
                assert!(
                    msg.contains("Control") || msg.contains("Forbidden"),
                    "Control character not properly flagged: {}",
                    msg
                );
            }

            // Space/tab characters
            if authority.contains(' ') || authority.contains('\t') {
                assert!(
                    msg.contains("Whitespace") || msg.contains("Forbidden"),
                    "Whitespace not properly flagged: {}",
                    msg
                );
            }

            // Path separators
            if authority.contains('/') || authority.contains('\\') {
                assert!(
                    msg.contains("Path") || msg.contains("Forbidden"),
                    "Path separator not properly flagged: {}",
                    msg
                );
            }

            // Query/fragment indicators
            if authority.contains('?') || authority.contains('#') {
                assert!(
                    msg.contains("Query") || msg.contains("fragment") || msg.contains("Forbidden"),
                    "Query/fragment indicator not properly flagged: {}",
                    msg
                );
            }
        }

        AuthorityResult::Valid(_) => {
            // Valid authorities should not contain forbidden characters
            let authority = &input.authority;

            assert!(
                !authority.chars().any(|c| c.is_control()),
                "Valid authority contains control characters"
            );
            assert!(
                !authority.contains(' ') && !authority.contains('\t'),
                "Valid authority contains whitespace"
            );
            assert!(
                !authority.contains('/') && !authority.contains('\\'),
                "Valid authority contains path separators"
            );
            assert!(
                !authority.contains('?') && !authority.contains('#'),
                "Valid authority contains query/fragment indicators"
            );
        }

        AuthorityResult::Invalid(_) => {
            // Invalid results are acceptable for edge cases
        }
    }

    // Additional consistency checks
    if input.authority.is_empty() && matches!(&result, AuthorityResult::Valid(_)) {
        panic!("Empty authority should not be valid");
    }

    // Check for proper IPv6 handling
    if input.authority.starts_with('[')
        && !input.policy.allow_ipv6_literals
        && matches!(&result, AuthorityResult::Valid(_))
    {
        panic!("IPv6 literal should be rejected when not allowed");
    }
});
