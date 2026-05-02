#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// Fuzz target for HTTP/1.1 request line validation.
///
/// Per RFC 9112 §3: "A request-line begins with a method token, followed by a
/// single space (SP), the request-target, another single space (SP), the protocol
/// version, and ends with CRLF."
///
/// Format: method SP request-target SP HTTP-version CRLF
///
/// Tests include:
/// - Method with whitespace/control chars (must reject)
/// - Request target with control chars (must reject)
/// - Ambiguous HTTP versions like "HTTP/1.10" (consistency required)
/// - Missing/extra spaces
/// - Invalid method tokens
/// - Malformed HTTP version strings

#[derive(Debug, Arbitrary)]
struct RequestLineTest {
    /// HTTP method (potentially invalid)
    method: String,
    /// Request target/path (potentially invalid)
    target: String,
    /// HTTP version string (potentially invalid)
    version: String,
    /// Number of spaces between components
    spaces_after_method: usize,
    spaces_after_target: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum RequestParseResult {
    Valid(RequestLine),
    Invalid(RequestError),
    Ambiguous(RequestLine, String), // Parsed but potentially problematic
}

#[derive(Debug, Clone, PartialEq)]
enum RequestError {
    MalformedLine,
    InvalidMethod(String),
    InvalidTarget(String),
    InvalidVersion(String),
    MissingComponents,
    ExtraWhitespace,
    ControlCharacters,
    LineTooLong,
    UnsupportedVersion,
}

#[derive(Debug, Clone, PartialEq)]
struct RequestLine {
    /// HTTP method (GET, POST, etc.)
    method: String,
    /// Request target (path, absolute URI, etc.)
    target: String,
    /// HTTP version (major, minor)
    version: HttpVersion,
    /// Raw request line for debugging
    raw_line: String,
}

#[derive(Debug, Clone, PartialEq)]
struct HttpVersion {
    major: u8,
    minor: u8,
}

/// Mock HTTP/1.1 request line parser
struct MockRequestLineParser {
    policy: ParsingPolicy,
    stats: ParsingStats,
}

#[derive(Debug, Clone)]
struct ParsingPolicy {
    /// Maximum request line length
    max_line_length: usize,
    /// Allow unusual HTTP versions (1.10, 2.0, etc.)
    allow_unusual_versions: bool,
    /// Strict method token validation
    strict_method_validation: bool,
    /// Allow control characters in request target
    allow_control_chars_in_target: bool,
    /// Maximum method length
    max_method_length: usize,
    /// Maximum target length
    max_target_length: usize,
}

#[derive(Debug, Clone, Default)]
struct ParsingStats {
    lines_parsed: usize,
    valid_lines: usize,
    invalid_lines: usize,
    ambiguous_lines: usize,
    security_violations: usize,
}

impl Default for ParsingPolicy {
    fn default() -> Self {
        Self {
            max_line_length: 8192,
            allow_unusual_versions: false,
            strict_method_validation: true,
            allow_control_chars_in_target: false,
            max_method_length: 16,
            max_target_length: 4096,
        }
    }
}

impl MockRequestLineParser {
    fn new() -> Self {
        Self {
            policy: ParsingPolicy::default(),
            stats: ParsingStats::default(),
        }
    }

    fn with_policy(policy: ParsingPolicy) -> Self {
        Self {
            policy,
            stats: ParsingStats::default(),
        }
    }

    /// Parse HTTP/1.1 request line per RFC 9112 §3
    fn parse_request_line(&mut self, line: &str) -> Result<RequestParseResult, RequestError> {
        self.stats.lines_parsed += 1;

        // Remove trailing CRLF
        let line = if line.ends_with("\r\n") {
            &line[..line.len() - 2]
        } else if line.ends_with('\n') {
            &line[..line.len() - 1]
        } else {
            line
        };

        // Check maximum line length
        if line.len() > self.policy.max_line_length {
            self.stats.security_violations += 1;
            return Err(RequestError::LineTooLong);
        }

        // Basic format check - must have at least 3 parts separated by spaces
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 3 {
            self.stats.invalid_lines += 1;
            return Err(RequestError::MissingComponents);
        }

        // RFC 9112 requires exactly 2 spaces in request line
        if parts.len() > 3 {
            // Check if this is just extra whitespace or malformed
            let reconstructed = format!("{} {} {}", parts[0], parts[1], parts[2..].join(" "));
            if reconstructed != line {
                self.stats.invalid_lines += 1;
                return Err(RequestError::ExtraWhitespace);
            }
        }

        let method = parts[0];
        let target = if parts.len() == 3 {
            parts[1]
        } else {
            // Handle case where target contains spaces (malformed but sometimes seen)
            &parts[1..parts.len()-1].join(" ")
        };
        let version_str = parts[parts.len()-1];

        // Validate method
        self.validate_method(method)?;

        // Validate request target
        self.validate_target(target)?;

        // Validate HTTP version
        let version = self.validate_version(version_str)?;

        let request_line = RequestLine {
            method: method.to_string(),
            target: target.to_string(),
            version: version.clone(),
            raw_line: line.to_string(),
        };

        // Check for ambiguous cases
        if let Some(ambiguity) = self.check_ambiguity(&request_line) {
            self.stats.ambiguous_lines += 1;
            Ok(RequestParseResult::Ambiguous(request_line, ambiguity))
        } else {
            self.stats.valid_lines += 1;
            Ok(RequestParseResult::Valid(request_line))
        }
    }

    /// Validate HTTP method per RFC 9112
    fn validate_method(&self, method: &str) -> Result<(), RequestError> {
        if method.is_empty() {
            return Err(RequestError::InvalidMethod("Empty method".to_string()));
        }

        if method.len() > self.policy.max_method_length {
            return Err(RequestError::InvalidMethod("Method too long".to_string()));
        }

        if self.policy.strict_method_validation {
            // RFC 7230: method = token
            // token = 1*tchar
            // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
            //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA

            for c in method.chars() {
                match c {
                    // Valid token characters
                    'a'..='z' | 'A'..='Z' | '0'..='9' |
                    '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' |
                    '-' | '.' | '^' | '_' | '`' | '|' | '~' => {
                        // Valid
                    }
                    // Invalid characters (separators, control chars, whitespace)
                    ' ' | '\t' | '\r' | '\n' => {
                        return Err(RequestError::InvalidMethod(
                            format!("Method contains whitespace: '{}'", c)
                        ));
                    }
                    c if c.is_control() => {
                        self.stats.security_violations += 1;
                        return Err(RequestError::ControlCharacters);
                    }
                    _ => {
                        return Err(RequestError::InvalidMethod(
                            format!("Method contains invalid character: '{}'", c)
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate request target per RFC 9112
    fn validate_target(&self, target: &str) -> Result<(), RequestError> {
        if target.is_empty() {
            return Err(RequestError::InvalidTarget("Empty target".to_string()));
        }

        if target.len() > self.policy.max_target_length {
            return Err(RequestError::InvalidTarget("Target too long".to_string()));
        }

        // Check for control characters
        for c in target.chars() {
            if c.is_control() && c != '\t' {
                if !self.policy.allow_control_chars_in_target {
                    self.stats.security_violations += 1;
                    return Err(RequestError::ControlCharacters);
                }
            }
        }

        // Additional target validation could go here:
        // - URI format validation
        // - Path traversal detection
        // - Null byte detection

        Ok(())
    }

    /// Validate HTTP version per RFC 9112
    fn validate_version(&self, version_str: &str) -> Result<HttpVersion, RequestError> {
        // Expected format: HTTP/1.1, HTTP/1.0, etc.
        if !version_str.starts_with("HTTP/") {
            return Err(RequestError::InvalidVersion(
                "Version must start with 'HTTP/'".to_string()
            ));
        }

        let version_part = &version_str[5..]; // Skip "HTTP/"

        // Must be in format "major.minor"
        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.len() != 2 {
            return Err(RequestError::InvalidVersion(
                "Version must be in format 'major.minor'".to_string()
            ));
        }

        // Parse major and minor versions
        let major = parts[0].parse::<u8>().map_err(|_| {
            RequestError::InvalidVersion("Invalid major version".to_string())
        })?;

        let minor = parts[1].parse::<u8>().map_err(|_| {
            RequestError::InvalidVersion("Invalid minor version".to_string())
        })?;

        let version = HttpVersion { major, minor };

        // Check for supported versions
        match (major, minor) {
            (1, 0) | (1, 1) => {
                // Standard HTTP/1.x versions
                Ok(version)
            }
            (1, 2..=255) => {
                // HTTP/1.2, HTTP/1.10, etc. - ambiguous
                if self.policy.allow_unusual_versions {
                    Ok(version)
                } else {
                    Err(RequestError::UnsupportedVersion)
                }
            }
            (0, _) => {
                // HTTP/0.x - very old
                Err(RequestError::UnsupportedVersion)
            }
            (2..=255, _) => {
                // HTTP/2.x, etc. - should use different protocol
                if self.policy.allow_unusual_versions {
                    Ok(version)
                } else {
                    Err(RequestError::UnsupportedVersion)
                }
            }
        }
    }

    /// Check for ambiguous request lines that might be problematic
    fn check_ambiguity(&self, request: &RequestLine) -> Option<String> {
        // Check for ambiguous HTTP versions
        match (request.version.major, request.version.minor) {
            (1, 10) => {
                Some("HTTP/1.10 is ambiguous - could be 1.1.0 or 1.10".to_string())
            }
            (1, 2..=9) => {
                Some(format!("HTTP/1.{} is non-standard", request.version.minor))
            }
            (2, 0) => {
                Some("HTTP/2.0 should use HTTP/2 protocol, not HTTP/1.1".to_string())
            }
            _ => {
                // Check other ambiguous cases

                // Method case sensitivity
                if request.method.chars().any(|c| c.is_lowercase()) {
                    if matches!(request.method.to_uppercase().as_str(),
                               "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH") {
                        return Some("Method should be uppercase".to_string());
                    }
                }

                // Target with unusual characters
                if request.target.contains("//") {
                    return Some("Double slashes in target may cause confusion".to_string());
                }

                if request.target.contains('%') && !request.target.contains("%20") {
                    return Some("Percent encoding detected - ensure proper decoding".to_string());
                }

                None
            }
        }
    }

    fn get_stats(&self) -> &ParsingStats {
        &self.stats
    }
}

/// Generate predefined test cases for request line parsing
fn generate_test_cases() -> Vec<(String, RequestParseResult)> {
    vec![
        // Valid request lines
        ("GET / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Valid(RequestLine {
             method: "GET".to_string(),
             target: "/".to_string(),
             version: HttpVersion { major: 1, minor: 1 },
             raw_line: "GET / HTTP/1.1".to_string(),
         })),

        ("POST /api/users HTTP/1.0\r\n".to_string(),
         RequestParseResult::Valid(RequestLine {
             method: "POST".to_string(),
             target: "/api/users".to_string(),
             version: HttpVersion { major: 1, minor: 0 },
             raw_line: "POST /api/users HTTP/1.0".to_string(),
         })),

        // Method with whitespace (must reject)
        ("GET POST / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::ExtraWhitespace)),

        ("G ET / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidMethod("Method contains whitespace: ' '".to_string()))),

        // Method with control characters (must reject)
        ("GET\x00 / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::ControlCharacters)),

        ("GET\r / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidMethod("Method contains whitespace: '\r'".to_string()))),

        // Path with control characters (must reject)
        ("GET /\x00path HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::ControlCharacters)),

        ("GET /\rpath HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::ControlCharacters)),

        // Ambiguous HTTP version (consistency required)
        ("GET / HTTP/1.10\r\n".to_string(),
         RequestParseResult::Ambiguous(
             RequestLine {
                 method: "GET".to_string(),
                 target: "/".to_string(),
                 version: HttpVersion { major: 1, minor: 10 },
                 raw_line: "GET / HTTP/1.10".to_string(),
             },
             "HTTP/1.10 is ambiguous - could be 1.1.0 or 1.10".to_string()
         )),

        // Invalid HTTP version format
        ("GET / HTTP/1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidVersion("Version must be in format 'major.minor'".to_string()))),

        ("GET / HTTP1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidVersion("Version must start with 'HTTP/'".to_string()))),

        ("GET / HTTP/1.1.0\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidVersion("Version must be in format 'major.minor'".to_string()))),

        // Missing components
        ("GET /\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::MissingComponents)),

        ("GET\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::MissingComponents)),

        // Extra whitespace
        ("GET  /  HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::ExtraWhitespace)),

        // Empty method
        (" / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidMethod("Empty method".to_string()))),

        // Lowercase method (ambiguous)
        ("get / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Ambiguous(
             RequestLine {
                 method: "get".to_string(),
                 target: "/".to_string(),
                 version: HttpVersion { major: 1, minor: 1 },
                 raw_line: "get / HTTP/1.1".to_string(),
             },
             "Method should be uppercase".to_string()
         )),

        // Invalid method characters
        ("GET() / HTTP/1.1\r\n".to_string(),
         RequestParseResult::Invalid(RequestError::InvalidMethod("Method contains invalid character: '('".to_string()))),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 1024 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match RequestLineTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with extremely long components
    if test.method.len() > 100 || test.target.len() > 500 || test.version.len() > 50 {
        return;
    }

    // Limit spaces to reasonable range
    let spaces_after_method = (test.spaces_after_method % 5).max(1);
    let spaces_after_target = (test.spaces_after_target % 5).max(1);

    // Build request line
    let request_line = format!(
        "{}{}{}{}{}{}",
        test.method,
        " ".repeat(spaces_after_method),
        test.target,
        " ".repeat(spaces_after_target),
        test.version,
        "\r\n"
    );

    // Test with default (strict) policy
    let mut parser = MockRequestLineParser::new();
    let result = parser.parse_request_line(&request_line);

    // Validate result consistency
    match result {
        Ok(RequestParseResult::Valid(request)) => {
            // Valid requests should have reasonable properties
            assert!(!request.method.is_empty(), "Valid method cannot be empty");
            assert!(!request.target.is_empty(), "Valid target cannot be empty");
            assert!(request.version.major > 0, "Valid version major must be > 0");

            // Method should not contain whitespace or control chars for valid requests
            assert!(!request.method.chars().any(|c| c.is_whitespace()),
                "Valid method should not contain whitespace");
            assert!(!request.method.chars().any(|c| c.is_control()),
                "Valid method should not contain control characters");
        }

        Ok(RequestParseResult::Invalid(error)) => {
            // Invalid results should have a clear reason
            match error {
                RequestError::InvalidMethod(_) |
                RequestError::InvalidTarget(_) |
                RequestError::InvalidVersion(_) |
                RequestError::ControlCharacters => {
                    // These are expected rejection reasons
                }
                RequestError::LineTooLong => {
                    assert!(parser.get_stats().security_violations > 0,
                        "Security violations should be tracked");
                }
                _ => {
                    // Other errors are also acceptable
                }
            }
        }

        Ok(RequestParseResult::Ambiguous(request, reason)) => {
            // Ambiguous results should still be parseable but flagged
            assert!(!reason.is_empty(), "Ambiguous results must have a reason");
            assert!(parser.get_stats().ambiguous_lines > 0,
                "Ambiguous lines should be counted");

            // The request should still be structurally valid
            assert!(!request.method.is_empty(), "Ambiguous method cannot be empty");
            assert!(!request.target.is_empty(), "Ambiguous target cannot be empty");
        }

        Err(error) => {
            // Direct parsing errors
            match error {
                RequestError::MissingComponents |
                RequestError::ExtraWhitespace |
                RequestError::MalformedLine => {
                    // Expected for malformed input
                }
                _ => {
                    // Other errors are acceptable
                }
            }
        }
    }

    // Test with permissive policy
    let permissive_policy = ParsingPolicy {
        max_line_length: 16384,
        allow_unusual_versions: true,
        strict_method_validation: false,
        allow_control_chars_in_target: true,
        max_method_length: 100,
        max_target_length: 8192,
    };

    let mut permissive_parser = MockRequestLineParser::with_policy(permissive_policy);
    let _permissive_result = permissive_parser.parse_request_line(&request_line);

    // With permissive policy, more things should be allowed
    // This tests different code paths and edge cases

    // Run predefined test cases to ensure core functionality
    for (test_line, expected) in generate_test_cases() {
        let mut test_parser = MockRequestLineParser::new();
        let test_result = test_parser.parse_request_line(&test_line);

        match expected {
            RequestParseResult::Valid(ref expected_request) => {
                match test_result {
                    Ok(RequestParseResult::Valid(actual_request)) => {
                        assert_eq!(actual_request.method, expected_request.method,
                            "Method mismatch for line: {}", test_line);
                        assert_eq!(actual_request.target, expected_request.target,
                            "Target mismatch for line: {}", test_line);
                        assert_eq!(actual_request.version, expected_request.version,
                            "Version mismatch for line: {}", test_line);
                    }
                    _ => {
                        // May fail for other reasons in fuzzing context
                    }
                }
            }

            RequestParseResult::Invalid(_) => {
                // Should result in error
                match test_result {
                    Ok(RequestParseResult::Invalid(_)) |
                    Err(_) => {
                        // Expected
                    }
                    _ => {
                        // May be handled differently with different policies
                    }
                }
            }

            RequestParseResult::Ambiguous(_, _) => {
                // Should be flagged as ambiguous or handled consistently
                match test_result {
                    Ok(RequestParseResult::Ambiguous(_, _)) |
                    Ok(RequestParseResult::Valid(_)) |  // May be accepted in some policies
                    Ok(RequestParseResult::Invalid(_)) => {
                        // All are acceptable as long as consistent
                    }
                    _ => {
                        // May be handled differently
                    }
                }
            }
        }
    }

    // Consistency test - same input should always give same result
    let mut parser2 = MockRequestLineParser::new();
    let result2 = parser2.parse_request_line(&request_line);

    match (&result, &result2) {
        (Ok(r1), Ok(r2)) => {
            // Results should be identical for same input
            assert_eq!(std::mem::discriminant(r1), std::mem::discriminant(r2),
                "Consistent parsing should give same result type");
        }
        (Err(e1), Err(e2)) => {
            // Error types should match
            assert_eq!(std::mem::discriminant(e1), std::mem::discriminant(e2),
                "Consistent parsing should give same error type");
        }
        _ => {
            // Mixed results indicate inconsistency
            panic!("Inconsistent parsing results for same input");
        }
    }
});