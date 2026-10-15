//! Fuzzing target for HTTP/2 :path pseudo-header with query-only values.
//!
//! Tests RFC 9110 compliance for invalid :path formats that contain only
//! query strings without a proper path component. Per RFC 9110 §4.2.3,
//! the path component MUST start with "/" for absolute-path form.
//!
//! Key test scenarios:
//! 1. :path value contains only query string (e.g., "?foo=bar")
//! 2. :path value starts with query without leading "/" (e.g., "?query")
//! 3. :path value with malformed query-only formats
//! 4. :path value with fragments and query but no path
//! 5. Edge cases with empty/whitespace before query
//!
//! Per RFC 9110 §4.2.3: "A path component that contains only a query
//! component is indicated by starting with a '?' character."
//! However, in HTTP/2 context per RFC 9113 §8.3.1, :path MUST be an
//! absolute-path which starts with "/".
//!
//! Vulnerability areas:
//! - Parser accepting invalid query-only paths
//! - Path normalization bypassing validation
//! - Query-only paths causing routing confusion
//! - Inconsistent validation between HTTP/1.1 and HTTP/2 modes
//! - Edge cases in URI parsing leading to security bypass

#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test input for HTTP/2 :path pseudo-header query-only validation
#[derive(Debug, Arbitrary)]
pub struct PathQueryOnlyInput {
    /// Different query-only path formats to test
    query_only_paths: Vec<QueryOnlyPath>,
    /// Additional headers to include with request
    additional_headers: Vec<HttpHeader>,
    /// Request configuration options
    request_config: RequestConfig,
    /// Edge case testing scenarios
    edge_cases: Vec<EdgeCaseTest>,
    /// Parser behavior validation options
    validation_config: ValidationConfig,
}

/// Query-only path test cases
#[derive(Debug, Arbitrary)]
pub struct QueryOnlyPath {
    /// The path value to test (should be invalid)
    path_value: String,
    /// Whether to expect this to be rejected
    expect_rejection: bool,
    /// Type of query-only format
    format_type: QueryOnlyFormat,
    /// Additional malformation attempts
    malformation_type: Option<MalformationType>,
}

/// Types of query-only path formats
#[derive(Debug, Arbitrary)]
pub enum QueryOnlyFormat {
    /// Simple query only: "?foo=bar"
    SimpleQuery,
    /// Query with multiple parameters: "?a=1&b=2&c=3"
    MultipleParams,
    /// Query with encoded characters: "?name=%20value"
    EncodedQuery,
    /// Query with empty value: "?key="
    EmptyValue,
    /// Query with no value: "?flag"
    NoValue,
    /// Query with special characters: "?weird=!@#$%"
    SpecialChars,
    /// Query with Unicode: "?message=こんにちは"
    Unicode,
    /// Very long query: "?data=" + long string
    LongQuery,
    /// Nested query structures: "?q=a%3Db%26c%3Dd"
    NestedQuery,
}

/// Malformation types for testing edge cases
#[derive(Debug, Arbitrary)]
pub enum MalformationType {
    /// Double question marks: "??foo=bar"
    DoubleQuestionMark,
    /// Question mark at end: "?foo=bar?"
    TrailingQuestionMark,
    /// Whitespace before query: " ?foo=bar"
    LeadingWhitespace,
    /// Control characters in query: "?\x00foo=bar"
    ControlCharacters,
    /// Invalid percent encoding: "?foo=%ZZ"
    InvalidPercentEncoding,
    /// Fragment with query: "?foo=bar#fragment"
    FragmentIncluded,
    /// Semicolon instead of ampersand: "?a=1;b=2"
    SemicolonSeparator,
    /// Mixed separators: "?a=1&b=2;c=3"
    MixedSeparators,
}

/// HTTP header for testing
#[derive(Debug, Arbitrary)]
pub struct HttpHeader {
    name: String,
    value: String,
    is_pseudo_header: bool,
}

/// Request configuration
#[derive(Debug, Arbitrary)]
pub struct RequestConfig {
    /// HTTP method for the request
    method: String,
    /// Scheme for the request
    scheme: String,
    /// Authority for the request
    authority: String,
    /// Stream ID for the request
    stream_id: u32,
    /// Whether to include END_STREAM flag
    end_stream: bool,
    /// Whether to include END_HEADERS flag
    end_headers: bool,
}

/// Validation configuration
#[derive(Debug, Arbitrary, Clone)]
pub struct ValidationConfig {
    /// Enforce RFC 9110 absolute-path requirement
    enforce_absolute_path: bool,
    /// Reject query-only paths
    reject_query_only: bool,
    /// Maximum path length
    max_path_length: u16,
    /// Allow empty paths
    allow_empty_paths: bool,
    /// Strict RFC compliance mode
    strict_mode: bool,
}

/// Edge case testing scenarios
#[derive(Debug, Arbitrary)]
pub enum EdgeCaseTest {
    /// Multiple :path headers in same request
    MultiplePseudoPaths { count: u8, paths: Vec<String> },
    /// :path header after regular headers (invalid order)
    PathAfterRegularHeaders,
    /// Mixed case :path header name
    MixedCasePseudoHeader { name: String },
    /// :path with different values in CONTINUATION
    PathInContinuation { initial: String, continued: String },
    /// Empty :path header value
    EmptyPathValue,
    /// :path header with null bytes
    PathWithNullBytes,
    /// Very long :path header value
    VeryLongPath { length: u16 },
    /// :path with binary data
    PathWithBinaryData { data: Vec<u8> },
}

/// Mock HTTP/2 request parser for :path validation
pub struct MockH2PathQueryOnlyParser {
    /// Current parsing state
    state: ParsingState,
    /// Received pseudo-headers
    pseudo_headers: HashMap<String, String>,
    /// Regular headers
    regular_headers: HashMap<String, String>,
    /// Detected violations
    violations: Vec<PathValidationViolation>,
    /// Parser statistics
    stats: ParserStats,
    /// Configuration
    config: ValidationConfig,
    /// Current stream ID being processed
    current_stream_id: u32,
}

#[derive(Debug, Clone)]
pub enum ParsingState {
    /// Expecting pseudo-headers
    PseudoHeaders,
    /// Expecting regular headers
    RegularHeaders,
    /// Headers complete
    Complete,
    /// Error state
    Error(PathValidationError),
}

#[derive(Debug, Clone)]
pub enum PathValidationError {
    /// Query-only path without leading slash
    QueryOnlyPath(String),
    /// Missing required :path header
    MissingPathHeader,
    /// Empty :path header value
    EmptyPathValue,
    /// Invalid path format
    InvalidPathFormat(String),
    /// Control characters in path
    ControlCharactersInPath(String),
    /// Path too long
    PathTooLong { length: usize, max: usize },
    /// Multiple :path headers
    MultiplePathHeaders,
    /// :path after regular headers
    PseudoHeaderAfterRegular,
    /// Invalid percent encoding
    InvalidPercentEncoding(String),
    /// Fragment in path (not allowed in HTTP/2)
    FragmentInPath(String),
}

#[derive(Debug, Clone)]
pub struct PathValidationViolation {
    violation_type: ViolationType,
    path_value: String,
    description: String,
    severity: ViolationSeverity,
    rfc_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    QueryOnlyPath,
    InvalidPathFormat,
    RFCViolation,
    SecurityRisk,
    ParserInconsistency,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationSeverity {
    Critical, // Security vulnerability
    High,     // RFC violation
    Medium,   // Compliance issue
    Low,      // Style issue
}

#[derive(Debug, Default, Clone)]
pub struct ParserStats {
    requests_processed: u32,
    query_only_paths_detected: u32,
    invalid_paths_rejected: u32,
    valid_paths_accepted: u32,
    pseudo_headers_processed: u32,
    violations_detected: u32,
}

impl MockH2PathQueryOnlyParser {
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            state: ParsingState::PseudoHeaders,
            pseudo_headers: HashMap::new(),
            regular_headers: HashMap::new(),
            violations: Vec::new(),
            stats: ParserStats::default(),
            config,
            current_stream_id: 0,
        }
    }

    /// Process a HEADERS frame with pseudo-headers
    pub fn process_headers_frame(
        &mut self,
        stream_id: u32,
        headers: Vec<(String, String)>,
    ) -> Result<(), PathValidationError> {
        self.current_stream_id = stream_id;
        self.stats.requests_processed += 1;

        let mut found_path = false;
        let mut pseudo_header_phase = true;

        for (name, value) in headers {
            // Check pseudo-header ordering
            if name.starts_with(':') {
                if !pseudo_header_phase {
                    return Err(PathValidationError::PseudoHeaderAfterRegular);
                }

                // Check for :path header
                if name == ":path" {
                    if found_path {
                        return Err(PathValidationError::MultiplePathHeaders);
                    }
                    found_path = true;
                    self.validate_path_value(&value)?;
                    self.pseudo_headers.insert(name, value);
                } else {
                    self.pseudo_headers.insert(name, value);
                }
                self.stats.pseudo_headers_processed += 1;
            } else {
                // Regular header
                pseudo_header_phase = false;
                self.regular_headers.insert(name, value);
            }
        }

        // Check if :path header was present
        if !found_path {
            return Err(PathValidationError::MissingPathHeader);
        }

        self.state = ParsingState::Complete;
        Ok(())
    }

    /// Validate :path header value
    fn validate_path_value(&mut self, path: &str) -> Result<(), PathValidationError> {
        // Check for empty path
        if path.is_empty() && !self.config.allow_empty_paths {
            return Err(PathValidationError::EmptyPathValue);
        }

        // Check path length
        if path.len() > self.config.max_path_length as usize {
            return Err(PathValidationError::PathTooLong {
                length: path.len(),
                max: self.config.max_path_length as usize,
            });
        }

        // Check for control characters
        if path.chars().any(|c| c.is_control()) {
            return Err(PathValidationError::ControlCharactersInPath(
                path.to_string(),
            ));
        }

        // Main validation: Check if path starts with query only (RFC violation)
        if self.is_query_only_path(path) {
            self.violations.push(PathValidationViolation {
                violation_type: ViolationType::QueryOnlyPath,
                path_value: path.to_string(),
                description: "Path contains only query string without leading '/'".to_string(),
                severity: ViolationSeverity::High,
                rfc_reference: "RFC 9110 §4.2.3, RFC 9113 §8.3.1".to_string(),
            });

            self.stats.query_only_paths_detected += 1;

            if self.config.reject_query_only {
                return Err(PathValidationError::QueryOnlyPath(path.to_string()));
            }
        }

        // Check for fragments (not allowed in HTTP/2)
        if path.contains('#') {
            return Err(PathValidationError::FragmentInPath(path.to_string()));
        }

        // Validate percent encoding
        if path.contains('%') && self.validate_percent_encoding(path).is_err() {
            return Err(PathValidationError::InvalidPercentEncoding(
                path.to_string(),
            ));
        }

        // RFC 9113 §8.3.1: :path MUST be absolute-path for http/https
        if self.config.enforce_absolute_path && !path.starts_with('/') && !path.is_empty() {
            // This is the main check - path must start with '/'
            if path.starts_with('?') {
                // Specifically a query-only path
                self.violations.push(PathValidationViolation {
                    violation_type: ViolationType::RFCViolation,
                    path_value: path.to_string(),
                    description: "RFC 9113 violation: :path must start with '/' (absolute-path)"
                        .to_string(),
                    severity: ViolationSeverity::High,
                    rfc_reference: "RFC 9113 §8.3.1".to_string(),
                });

                if self.config.strict_mode {
                    self.stats.invalid_paths_rejected += 1;
                    return Err(PathValidationError::InvalidPathFormat(format!(
                        "Path must start with '/', got query-only path: {}",
                        path
                    )));
                }
            } else {
                // Other invalid path format
                return Err(PathValidationError::InvalidPathFormat(format!(
                    "Path must start with '/', got: {}",
                    path
                )));
            }
        }

        self.stats.valid_paths_accepted += 1;
        Ok(())
    }

    /// Check if path is query-only format
    fn is_query_only_path(&self, path: &str) -> bool {
        // Query-only paths start with '?' and have no preceding '/'
        path.starts_with('?') && !path.starts_with("/?")
    }

    /// Validate percent encoding in path
    fn validate_percent_encoding(&self, path: &str) -> Result<(), ()> {
        let mut chars = path.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                // Need exactly 2 hex digits after %
                let hex1 = chars.next().ok_or(())?;
                let hex2 = chars.next().ok_or(())?;

                if !hex1.is_ascii_hexdigit() || !hex2.is_ascii_hexdigit() {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    /// Generate test path based on format type
    fn generate_test_path(format_type: &QueryOnlyFormat, base_value: &str) -> String {
        match format_type {
            QueryOnlyFormat::SimpleQuery => {
                if base_value.is_empty() {
                    "?foo=bar".to_string()
                } else {
                    format!("?{}", base_value)
                }
            }
            QueryOnlyFormat::MultipleParams => "?a=1&b=2&c=3".to_string(),
            QueryOnlyFormat::EncodedQuery => "?name=%20value&data=%21%40%23".to_string(),
            QueryOnlyFormat::EmptyValue => "?key=".to_string(),
            QueryOnlyFormat::NoValue => "?flag".to_string(),
            QueryOnlyFormat::SpecialChars => "?weird=!@#$%^&*()".to_string(),
            QueryOnlyFormat::Unicode => {
                "?message=%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF".to_string()
            }
            QueryOnlyFormat::LongQuery => {
                let long_value = "x".repeat(1000);
                format!("?data={}", long_value)
            }
            QueryOnlyFormat::NestedQuery => "?q=a%3Db%26c%3Dd&nested=%3Ffoo%3Dbar".to_string(),
        }
    }

    /// Apply malformation to path
    fn apply_malformation(path: &str, malformation: &MalformationType) -> String {
        match malformation {
            MalformationType::DoubleQuestionMark => path.replacen("?", "??", 1),
            MalformationType::TrailingQuestionMark => format!("{}?", path),
            MalformationType::LeadingWhitespace => format!(" {}", path),
            MalformationType::ControlCharacters => {
                let remainder = path.strip_prefix('?').unwrap_or(path);
                format!("?\x00{}", remainder)
            }
            MalformationType::InvalidPercentEncoding => path.replace("=", "=%ZZ"),
            MalformationType::FragmentIncluded => format!("{}#fragment", path),
            MalformationType::SemicolonSeparator => path.replace("&", ";"),
            MalformationType::MixedSeparators => path.replacen("&", ";", 1),
        }
    }

    /// Get parsing results
    pub fn results(&self) -> ParsingResults {
        ParsingResults {
            pseudo_headers: self.pseudo_headers.clone(),
            regular_headers: self.regular_headers.clone(),
            violations: self.violations.clone(),
            stats: self.stats.clone(),
            final_state: self.state.clone(),
        }
    }

    /// Check if parsing completed successfully
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ParsingState::Complete)
    }

    /// Get violations by type
    pub fn violations_by_type(
        &self,
        violation_type: ViolationType,
    ) -> Vec<&PathValidationViolation> {
        self.violations
            .iter()
            .filter(|v| v.violation_type == violation_type)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ParsingResults {
    pub pseudo_headers: HashMap<String, String>,
    pub regular_headers: HashMap<String, String>,
    pub violations: Vec<PathValidationViolation>,
    pub stats: ParserStats,
    pub final_state: ParsingState,
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

fuzz_target!(|input: PathQueryOnlyInput| {
    let config = ValidationConfig {
        enforce_absolute_path: true,
        reject_query_only: true,
        max_path_length: cap_u16(input.validation_config.max_path_length, 8192),
        allow_empty_paths: false,
        strict_mode: true,
    };

    let mut parser = MockH2PathQueryOnlyParser::new(config.clone());
    let mut processed_query_cases = 0u32;
    let mut query_issue_observed = false;
    let mut observed_violations = Vec::new();

    // Process each query-only path test case
    for query_path in input.query_only_paths.iter().take(10) {
        let mut test_path = MockH2PathQueryOnlyParser::generate_test_path(
            &query_path.format_type,
            &query_path.path_value,
        );

        // Apply malformation if specified
        if let Some(malformation) = &query_path.malformation_type {
            test_path = MockH2PathQueryOnlyParser::apply_malformation(&test_path, malformation);
        }

        // Ensure path length is reasonable for fuzzing
        if test_path.len() > 2048 {
            let remainder = test_path.strip_prefix('?').unwrap_or(&test_path);
            test_path = format!("?{}", truncate_chars(remainder, 1023));
        }

        // Build headers for request
        let mut headers = vec![
            (
                ":method".to_string(),
                truncate_chars(&input.request_config.method, 10),
            ),
            (":path".to_string(), test_path.clone()),
            (
                ":scheme".to_string(),
                truncate_chars(&input.request_config.scheme, 10),
            ),
            (
                ":authority".to_string(),
                truncate_chars(&input.request_config.authority, 100),
            ),
        ];

        // Add additional headers
        for header in input.additional_headers.iter().take(5) {
            if !header.is_pseudo_header && !header.name.starts_with(':') {
                let name = truncate_chars(&header.name, 50);
                let value = truncate_chars(&header.value, 200);
                headers.push((name, value));
            }
        }

        // Process the headers frame
        let stream_id = cap_u32(input.request_config.stream_id, 0x7fff_ffff) | 1; // Ensure odd for client-initiated
        let result = parser.process_headers_frame(stream_id, headers);
        processed_query_cases += 1;

        // Validate expected behavior
        if query_path.expect_rejection || test_path.starts_with('?') {
            // Should be rejected for query-only paths
            match result {
                Err(PathValidationError::QueryOnlyPath(_)) => {
                    // Expected rejection - good
                    query_issue_observed = true;
                }
                Err(PathValidationError::InvalidPathFormat(_)) => {
                    // Also acceptable rejection reason
                    query_issue_observed = true;
                }
                Ok(_) => {
                    // This might be a problem - query-only path was accepted
                    // But check if violations were at least detected
                    let query_violations = parser.violations_by_type(ViolationType::QueryOnlyPath);
                    if !query_violations.is_empty() {
                        query_issue_observed = true;
                    }
                    assert!(
                        !query_violations.is_empty() || !config.strict_mode,
                        "Query-only path '{}' was accepted without violations",
                        test_path
                    );
                }
                Err(_) => {
                    // Other errors are fine too (malformation, etc.)
                    query_issue_observed = true;
                }
            }
        } else {
            // Valid path should be accepted
            if result.is_err() && !test_path.starts_with('?') {
                // Only complain if it's a valid path that was rejected
                // (malformed paths can legitimately be rejected)
            }
        }

        observed_violations.extend(parser.results().violations);

        // Reset parser for next test
        parser = MockH2PathQueryOnlyParser::new(config.clone());
    }

    // Process edge case tests
    for edge_case in input.edge_cases.iter().take(5) {
        let mut parser = MockH2PathQueryOnlyParser::new(config.clone());

        match edge_case {
            EdgeCaseTest::MultiplePseudoPaths { count, paths } => {
                // Test multiple :path headers (should be rejected)
                let mut headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":authority".to_string(), "example.com".to_string()),
                ];

                for (i, path) in paths.iter().take(cap_u8(*count, 5) as usize).enumerate() {
                    let path_value = if path.starts_with('?') {
                        path.clone()
                    } else {
                        format!("?test{}", i)
                    };
                    headers.push((":path".to_string(), path_value));
                }

                let result = parser.process_headers_frame(1, headers);
                assert!(result.is_err(), "Multiple :path headers should be rejected");
            }
            EdgeCaseTest::PathAfterRegularHeaders => {
                // Test :path after regular headers (should be rejected)
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":authority".to_string(), "example.com".to_string()),
                    ("user-agent".to_string(), "test".to_string()), // Regular header
                    (":path".to_string(), "?invalid".to_string()),  // Pseudo after regular
                ];

                let result = parser.process_headers_frame(1, headers);
                assert!(
                    result.is_err(),
                    "Pseudo-headers after regular headers should be rejected"
                );
            }
            EdgeCaseTest::EmptyPathValue => {
                // Test empty :path value
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":path".to_string(), "".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":authority".to_string(), "example.com".to_string()),
                ];

                let result = parser.process_headers_frame(1, headers);
                if !config.allow_empty_paths {
                    assert!(
                        result.is_err(),
                        "Empty :path should be rejected when not allowed"
                    );
                }
            }
            EdgeCaseTest::VeryLongPath { length } => {
                // Test very long query-only path
                let long_value = "x".repeat(cap_u16(*length, 4096) as usize);
                let long_path = format!("?data={}", long_value);

                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":path".to_string(), long_path),
                    (":scheme".to_string(), "https".to_string()),
                    (":authority".to_string(), "example.com".to_string()),
                ];

                let result = parser.process_headers_frame(1, headers);
                if long_value.len() + 6 > config.max_path_length as usize {
                    assert!(result.is_err(), "Oversized path should be rejected");
                }
            }
            _ => {
                // Other edge cases - basic validation
                let headers = vec![
                    (":method".to_string(), "GET".to_string()),
                    (":path".to_string(), "?edge_case".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":authority".to_string(), "example.com".to_string()),
                ];

                let result = parser.process_headers_frame(1, headers);
                // Edge cases with query-only paths should be rejected
                assert!(
                    result.is_err(),
                    "Query-only path edge case should be rejected"
                );
            }
        }
    }

    // Verify overall statistics
    // Check that query-only paths were properly detected
    if !input.query_only_paths.is_empty() {
        assert!(
            processed_query_cases > 0,
            "Should have processed some requests"
        );

        // Should have detected some violations unless all paths were valid
        let has_query_only = input.query_only_paths.iter().any(|p| {
            MockH2PathQueryOnlyParser::generate_test_path(&p.format_type, &p.path_value)
                .starts_with('?')
        });

        if has_query_only && config.reject_query_only {
            // Either rejections or violations should be detected
            assert!(
                query_issue_observed || !observed_violations.is_empty(),
                "Query-only paths should result in rejections or violations"
            );
        }
    }

    // Verify violation severity classification
    for violation in &observed_violations {
        match violation.violation_type {
            ViolationType::QueryOnlyPath => {
                assert_eq!(
                    violation.severity,
                    ViolationSeverity::High,
                    "Query-only path violations should be high severity"
                );
            }
            ViolationType::RFCViolation => {
                assert_eq!(
                    violation.severity,
                    ViolationSeverity::High,
                    "RFC violations should be high severity"
                );
            }
            _ => {}
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_only_path_detection() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let mut parser = MockH2PathQueryOnlyParser::new(config);

        // Test query-only path detection
        assert!(parser.is_query_only_path("?foo=bar"));
        assert!(parser.is_query_only_path("?"));
        assert!(parser.is_query_only_path("?key=value&other=data"));

        // These should NOT be detected as query-only
        assert!(!parser.is_query_only_path("/?foo=bar")); // Valid path with query
        assert!(!parser.is_query_only_path("/path")); // Valid path without query
        assert!(!parser.is_query_only_path("/")); // Valid root path
        assert!(!parser.is_query_only_path("")); // Empty path
    }

    #[test]
    fn test_query_only_path_rejection() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let mut parser = MockH2PathQueryOnlyParser::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "?foo=bar".to_string()), // Query-only path
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let result = parser.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PathValidationError::QueryOnlyPath(_)
        ));
    }

    #[test]
    fn test_valid_path_with_query() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let mut parser = MockH2PathQueryOnlyParser::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/search?q=test".to_string()), // Valid path with query
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let result = parser.process_headers_frame(1, headers);
        assert!(result.is_ok(), "Valid path with query should be accepted");
    }

    #[test]
    fn test_multiple_path_headers() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let mut parser = MockH2PathQueryOnlyParser::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/first".to_string()),
            (":path".to_string(), "?second".to_string()), // Duplicate :path
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let result = parser.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PathValidationError::MultiplePathHeaders
        ));
    }

    #[test]
    fn test_pseudo_header_after_regular() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let mut parser = MockH2PathQueryOnlyParser::new(config);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            ("user-agent".to_string(), "test".to_string()), // Regular header
            (":path".to_string(), "?invalid".to_string()),  // Pseudo after regular
        ];

        let result = parser.process_headers_frame(1, headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PathValidationError::PseudoHeaderAfterRegular
        ));
    }

    #[test]
    fn test_path_generation() {
        // Test different query format generation
        assert_eq!(
            MockH2PathQueryOnlyParser::generate_test_path(&QueryOnlyFormat::SimpleQuery, ""),
            "?foo=bar"
        );

        assert_eq!(
            MockH2PathQueryOnlyParser::generate_test_path(&QueryOnlyFormat::MultipleParams, ""),
            "?a=1&b=2&c=3"
        );

        assert_eq!(
            MockH2PathQueryOnlyParser::generate_test_path(&QueryOnlyFormat::EmptyValue, ""),
            "?key="
        );
    }

    #[test]
    fn test_malformation_application() {
        let original = "?foo=bar";

        assert_eq!(
            MockH2PathQueryOnlyParser::apply_malformation(
                original,
                &MalformationType::DoubleQuestionMark
            ),
            "??foo=bar"
        );

        assert_eq!(
            MockH2PathQueryOnlyParser::apply_malformation(
                original,
                &MalformationType::TrailingQuestionMark
            ),
            "?foo=bar?"
        );

        assert_eq!(
            MockH2PathQueryOnlyParser::apply_malformation(
                original,
                &MalformationType::LeadingWhitespace
            ),
            " ?foo=bar"
        );
    }

    #[test]
    fn test_percent_encoding_validation() {
        let config = ValidationConfig {
            enforce_absolute_path: true,
            reject_query_only: true,
            max_path_length: 1024,
            allow_empty_paths: false,
            strict_mode: true,
        };

        let parser = MockH2PathQueryOnlyParser::new(config);

        assert!(parser.validate_percent_encoding("?foo=%20bar").is_ok());
        assert!(parser.validate_percent_encoding("?foo=%2F%3F").is_ok());
        assert!(parser.validate_percent_encoding("?foo=%ZZ").is_err());
        assert!(parser.validate_percent_encoding("?foo=%2").is_err());
        assert!(parser.validate_percent_encoding("?foo=%").is_err());
    }
}
