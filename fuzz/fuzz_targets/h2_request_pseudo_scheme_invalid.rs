#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 :scheme pseudo-header validation fuzz target.
///
/// Tests RFC 7540 compliance for :scheme pseudo-header validation against
/// invalid and non-standard scheme values. Per RFC 7540 §8.1.2.3:
/// "The scheme and path pseudo-header fields MUST NOT be empty for http or
/// https URIs; URIs that do not contain a path component MUST include a
/// value of '/' for the path pseudo-header field."
///
/// Per RFC 7230 §2.7.3 and RFC 3986 §3.1: scheme names consist of letters,
/// digits, plus ("+"), period ("."), and hyphen ("-") characters. They are
/// case-insensitive but canonically lowercase.
///
/// Critical test scenarios:
/// - Valid schemes: "http", "https"
/// - Invalid schemes: "ws", "ftp", "file", "mailto"
/// - Malformed schemes: "http://", "https:", "HTTP", "Http"
/// - Edge cases: empty scheme, scheme with special chars, very long schemes
/// - Security concerns: schemes that could bypass validation

#[derive(Arbitrary, Debug, Clone)]
struct SchemeValidationInput {
    /// Test cases for various scheme values
    scheme_tests: Vec<SchemeTestCase>,

    /// Request configuration
    request_config: RequestConfig,

    /// Validation configuration
    validation_config: ValidationConfig,

    /// Edge case scenarios
    edge_cases: Vec<EdgeCaseTest>,

    /// Performance test scenarios
    performance_tests: Vec<PerformanceTest>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SchemeTestCase {
    /// The :scheme value to test
    scheme_value: String,

    /// Expected validation result
    expected_result: ExpectedSchemeResult,

    /// Additional pseudo-headers to include
    other_pseudo_headers: Vec<PseudoHeader>,

    /// Regular headers
    regular_headers: Vec<(String, String)>,

    /// Stream ID for this test
    stream_id: u32,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ExpectedSchemeResult {
    /// Scheme should be accepted (valid)
    Accept,

    /// Scheme should be rejected (invalid)
    Reject,

    /// Implementation-defined behavior
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
enum PseudoHeader {
    Method(String),
    Authority(String),
    Path(String),
}

impl PseudoHeader {
    fn name(&self) -> &str {
        match self {
            PseudoHeader::Method(_) => ":method",
            PseudoHeader::Authority(_) => ":authority",
            PseudoHeader::Path(_) => ":path",
        }
    }

    fn value(&self) -> &str {
        match self {
            PseudoHeader::Method(v) => v,
            PseudoHeader::Authority(v) => v,
            PseudoHeader::Path(v) => v,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestConfig {
    /// Whether to set END_HEADERS flag
    end_headers: bool,

    /// Whether to set END_STREAM flag
    end_stream: bool,

    /// Connection side (client/server)
    is_client: bool,

    /// Include Host header for comparison
    include_host_header: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct ValidationConfig {
    /// Strict RFC 7540 compliance
    strict_rfc_compliance: bool,

    /// Allow non-standard schemes
    allow_non_standard_schemes: bool,

    /// Case-sensitive scheme validation
    case_sensitive: bool,

    /// Maximum scheme length
    max_scheme_length: u8,

    /// Validate scheme format per RFC 3986
    validate_scheme_format: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseTest {
    /// Empty scheme value
    EmptyScheme,

    /// Scheme with uppercase characters
    UppercaseScheme { scheme: String },

    /// Scheme with trailing colon
    SchemeWithColon { scheme: String },

    /// Scheme with authority-like syntax
    SchemeWithAuthority { scheme: String },

    /// Very long scheme value
    VeryLongScheme { length: u8 },

    /// Scheme with special characters
    SchemeWithSpecialChars { chars: String },

    /// Multiple :scheme headers
    MultipleSchemes { schemes: Vec<String> },

    /// Scheme with null bytes
    SchemeWithNullBytes,

    /// Scheme with Unicode characters
    UnicodeScheme { scheme: String },

    /// Scheme that looks like URL
    UrlLikeScheme { scheme: String },
}

#[derive(Arbitrary, Debug, Clone)]
enum PerformanceTest {
    /// Many scheme validation calls
    ManyValidations { count: u8 },

    /// Scheme with repeated patterns
    RepeatedPattern { pattern: String, count: u8 },

    /// Borderline valid/invalid schemes
    BorderlineSchemes { schemes: Vec<String> },
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict_rfc_compliance: true,
            allow_non_standard_schemes: false, // Only http/https by default
            case_sensitive: false, // Schemes are case-insensitive per RFC
            max_scheme_length: 32, // Reasonable limit
            validate_scheme_format: true,
        }
    }
}

/// Mock HTTP/2 connection for testing :scheme validation
struct MockSchemeValidationConnection {
    /// Stream states
    streams: HashMap<u32, StreamState>,

    /// Connection-level errors
    connection_error: Option<ConnectionError>,

    /// Scheme validation results
    validation_results: Vec<SchemeValidationResult>,

    /// Detected violations
    violations: Vec<SchemeViolation>,

    /// Configuration
    config: ValidationConfig,

    /// Statistics
    stats: SchemeValidationStats,
}

#[derive(Debug, Clone)]
struct StreamState {
    headers_received: bool,
    scheme_validated: bool,
    scheme_value: Option<String>,
    violation_detected: bool,
    error_code: Option<u32>,
}

#[derive(Debug, Clone)]
enum ConnectionError {
    ProtocolError(String),
    InternalError(String),
}

#[derive(Debug, Clone)]
struct SchemeValidationResult {
    stream_id: u32,
    scheme: String,
    valid: bool,
    violation_type: Option<SchemeViolationType>,
    normalized_scheme: Option<String>,
}

#[derive(Debug, Clone)]
struct SchemeViolation {
    stream_id: u32,
    scheme: String,
    violation_type: SchemeViolationType,
    position: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
enum SchemeViolationType {
    EmptyScheme,                    // Empty string
    InvalidScheme(String),          // Non-http/https scheme
    MalformedScheme(String),        // Contains invalid characters
    SchemeWithColon,                // "http:" instead of "http"
    SchemeWithAuthority,            // "http://example.com"
    CaseMismatch(String),           // "HTTP" instead of "http"
    SchemeTooLong,                  // Exceeds length limit
    InvalidCharacters(Vec<char>),   // Contains non-allowed characters
    NullBytes,                      // Contains null bytes
    UnicodeCharacters,              // Contains Unicode
    MultipleSchemes,                // Multiple :scheme headers
}

#[derive(Debug, Clone, Default)]
struct SchemeValidationStats {
    valid_schemes: u32,
    invalid_schemes: u32,
    http_schemes: u32,
    https_schemes: u32,
    non_standard_schemes: u32,
    malformed_schemes: u32,
    case_mismatches: u32,
    empty_schemes: u32,
    long_schemes: u32,
}

impl MockSchemeValidationConnection {
    fn new(config: ValidationConfig) -> Self {
        Self {
            streams: HashMap::new(),
            connection_error: None,
            validation_results: Vec::new(),
            violations: Vec::new(),
            config,
            stats: SchemeValidationStats::default(),
        }
    }

    /// Process HEADERS frame with :scheme validation
    fn process_headers_frame(&mut self, stream_id: u32, scheme: &str,
                           other_headers: &[(String, String)]) -> ProcessingResult {
        // Stream ID validation
        if stream_id == 0 || stream_id % 2 == 0 {
            self.connection_error = Some(ConnectionError::ProtocolError(
                "Invalid stream ID for client-initiated request".to_string()
            ));
            return ProcessingResult::ConnectionError;
        }

        // Validate the :scheme pseudo-header
        let validation_result = self.validate_scheme(stream_id, scheme);

        // Update stream state
        let stream_state = self.streams.entry(stream_id).or_insert(StreamState {
            headers_received: false,
            scheme_validated: false,
            scheme_value: None,
            violation_detected: false,
            error_code: None,
        });

        stream_state.headers_received = true;
        stream_state.scheme_value = Some(scheme.to_string());

        match validation_result {
            SchemeValidationResult { valid: true, .. } => {
                stream_state.scheme_validated = true;
                self.stats.valid_schemes += 1;

                // Update scheme-specific stats
                match scheme.to_lowercase().as_str() {
                    "http" => self.stats.http_schemes += 1,
                    "https" => self.stats.https_schemes += 1,
                    _ => self.stats.non_standard_schemes += 1,
                }

                ProcessingResult::Success
            }

            SchemeValidationResult { valid: false, violation_type: Some(ref vtype), .. } => {
                stream_state.violation_detected = true;
                self.stats.invalid_schemes += 1;

                // Update specific violation counters
                match vtype {
                    SchemeViolationType::EmptyScheme => {
                        self.stats.empty_schemes += 1;
                    }
                    SchemeViolationType::InvalidScheme(_) => {
                        self.stats.non_standard_schemes += 1;
                    }
                    SchemeViolationType::CaseMismatch(_) => {
                        self.stats.case_mismatches += 1;
                    }
                    SchemeViolationType::SchemeTooLong => {
                        self.stats.long_schemes += 1;
                    }
                    _ => {
                        self.stats.malformed_schemes += 1;
                    }
                }

                // Generate appropriate error
                stream_state.error_code = Some(0x1); // PROTOCOL_ERROR
                ProcessingResult::StreamError(0x1)
            }

            _ => ProcessingResult::ValidationError,
        }
    }

    /// Validate :scheme pseudo-header per RFC 7540 and RFC 3986
    fn validate_scheme(&mut self, stream_id: u32, scheme: &str) -> SchemeValidationResult {
        let mut violations = Vec::new();

        // Empty scheme check
        if scheme.is_empty() {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::EmptyScheme,
                position: None,
            };

            if self.config.strict_rfc_compliance {
                self.violations.push(violation);
                return SchemeValidationResult {
                    stream_id,
                    scheme: scheme.to_string(),
                    valid: false,
                    violation_type: Some(SchemeViolationType::EmptyScheme),
                    normalized_scheme: None,
                };
            }
        }

        // Length check
        if scheme.len() > self.config.max_scheme_length as usize {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::SchemeTooLong,
                position: None,
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::SchemeTooLong),
                normalized_scheme: None,
            };
        }

        // Null byte check
        if scheme.contains('\0') {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::NullBytes,
                position: scheme.find('\0'),
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::NullBytes),
                normalized_scheme: None,
            };
        }

        // Unicode character check
        if !scheme.is_ascii() {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::UnicodeCharacters,
                position: None,
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::UnicodeCharacters),
                normalized_scheme: None,
            };
        }

        // Character format validation per RFC 3986
        if self.config.validate_scheme_format {
            let invalid_chars: Vec<char> = scheme
                .chars()
                .filter(|&c| !self.is_valid_scheme_char(c))
                .collect();

            if !invalid_chars.is_empty() {
                let violation = SchemeViolation {
                    stream_id,
                    scheme: scheme.to_string(),
                    violation_type: SchemeViolationType::InvalidCharacters(invalid_chars.clone()),
                    position: scheme.find(invalid_chars[0]),
                };

                self.violations.push(violation);
                return SchemeValidationResult {
                    stream_id,
                    scheme: scheme.to_string(),
                    valid: false,
                    violation_type: Some(SchemeViolationType::InvalidCharacters(invalid_chars)),
                    normalized_scheme: None,
                };
            }
        }

        // Check for trailing colon (common mistake)
        if scheme.ends_with(':') {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::SchemeWithColon,
                position: Some(scheme.len() - 1),
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::SchemeWithColon),
                normalized_scheme: Some(scheme.trim_end_matches(':').to_string()),
            };
        }

        // Check for authority syntax (common mistake)
        if scheme.contains("://") {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::SchemeWithAuthority,
                position: scheme.find("://"),
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::SchemeWithAuthority),
                normalized_scheme: scheme.split("://").next().map(String::from),
            };
        }

        // Normalize scheme to lowercase for comparison
        let normalized_scheme = scheme.to_lowercase();

        // Case sensitivity check
        if self.config.case_sensitive && scheme != normalized_scheme {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::CaseMismatch(normalized_scheme.clone()),
                position: None,
            };

            if self.config.strict_rfc_compliance {
                self.violations.push(violation);
                return SchemeValidationResult {
                    stream_id,
                    scheme: scheme.to_string(),
                    valid: false,
                    violation_type: Some(SchemeViolationType::CaseMismatch(normalized_scheme.clone())),
                    normalized_scheme: Some(normalized_scheme),
                };
            }
        }

        // Validate against allowed schemes
        let is_standard_scheme = matches!(normalized_scheme.as_str(), "http" | "https");

        if !is_standard_scheme && !self.config.allow_non_standard_schemes {
            let violation = SchemeViolation {
                stream_id,
                scheme: scheme.to_string(),
                violation_type: SchemeViolationType::InvalidScheme(normalized_scheme.clone()),
                position: None,
            };

            self.violations.push(violation);
            return SchemeValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: false,
                violation_type: Some(SchemeViolationType::InvalidScheme(normalized_scheme.clone())),
                normalized_scheme: Some(normalized_scheme),
            };
        }

        // Valid scheme
        SchemeValidationResult {
            stream_id,
            scheme: scheme.to_string(),
            valid: true,
            violation_type: None,
            normalized_scheme: Some(normalized_scheme),
        }
    }

    /// Check if character is valid in scheme per RFC 3986
    fn is_valid_scheme_char(&self, ch: char) -> bool {
        // RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        match ch {
            'A'..='Z' | 'a'..='z' => true,      // ALPHA
            '0'..='9' => true,                   // DIGIT
            '+' | '-' | '.' => true,             // Special allowed chars
            _ => false,
        }
    }

    fn get_status(&self) -> ConnectionStatus {
        ConnectionStatus {
            connection_error: self.connection_error.clone(),
            stream_count: self.streams.len(),
            validation_results: self.validation_results.clone(),
            violations: self.violations.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ProcessingResult {
    Success,
    StreamError(u32),
    ConnectionError,
    ValidationError,
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    connection_error: Option<ConnectionError>,
    stream_count: usize,
    validation_results: Vec<SchemeValidationResult>,
    violations: Vec<SchemeViolation>,
    stats: SchemeValidationStats,
}

/// Generate predefined test schemes for validation
fn generate_test_schemes() -> Vec<(&'static str, ExpectedSchemeResult)> {
    vec![
        // Valid standard schemes
        ("http", ExpectedSchemeResult::Accept),
        ("https", ExpectedSchemeResult::Accept),
        ("HTTP", ExpectedSchemeResult::Accept), // Should normalize to lowercase
        ("HTTPS", ExpectedSchemeResult::Accept),
        ("Http", ExpectedSchemeResult::Accept),
        ("Https", ExpectedSchemeResult::Accept),

        // Invalid non-standard schemes
        ("ws", ExpectedSchemeResult::Reject),
        ("wss", ExpectedSchemeResult::Reject),
        ("ftp", ExpectedSchemeResult::Reject),
        ("ftps", ExpectedSchemeResult::Reject),
        ("file", ExpectedSchemeResult::Reject),
        ("mailto", ExpectedSchemeResult::Reject),
        ("data", ExpectedSchemeResult::Reject),
        ("javascript", ExpectedSchemeResult::Reject),
        ("custom", ExpectedSchemeResult::Reject),

        // Malformed schemes
        ("http:", ExpectedSchemeResult::Reject),      // With colon
        ("https:", ExpectedSchemeResult::Reject),
        ("http://", ExpectedSchemeResult::Reject),    // With authority
        ("https://", ExpectedSchemeResult::Reject),
        ("http://example.com", ExpectedSchemeResult::Reject),
        ("https://example.com", ExpectedSchemeResult::Reject),

        // Empty and edge cases
        ("", ExpectedSchemeResult::Reject),           // Empty
        (" http", ExpectedSchemeResult::Reject),      // Leading space
        ("http ", ExpectedSchemeResult::Reject),      // Trailing space
        ("ht tp", ExpectedSchemeResult::Reject),      // Space inside
        ("http\n", ExpectedSchemeResult::Reject),     // Control character
        ("http\0", ExpectedSchemeResult::Reject),     // Null byte

        // Invalid characters
        ("http$", ExpectedSchemeResult::Reject),      // Invalid character
        ("http@", ExpectedSchemeResult::Reject),
        ("http%", ExpectedSchemeResult::Reject),
        ("http&", ExpectedSchemeResult::Reject),
        ("http*", ExpectedSchemeResult::Reject),
        ("http(", ExpectedSchemeResult::Reject),
        ("http)", ExpectedSchemeResult::Reject),

        // Unicode and encoding
        ("hттр", ExpectedSchemeResult::Reject),       // Cyrillic chars
        ("ｈttp", ExpectedSchemeResult::Reject),       // Fullwidth chars
        ("http\u{200B}", ExpectedSchemeResult::Reject), // Zero-width space
        ("http%20", ExpectedSchemeResult::Reject),    // URL-encoded space

        // Very long schemes
        ("httpverylongschemenamethatexceedslimits", ExpectedSchemeResult::Reject),
    ]
}

fuzz_target!(|input: SchemeValidationInput| {
    // Limit input size for performance
    let mut input = input;
    if input.scheme_tests.len() > 20 {
        input.scheme_tests.truncate(20);
    }

    let mut connection = MockSchemeValidationConnection::new(input.validation_config.clone());

    // Test predefined schemes
    let test_schemes = generate_test_schemes();
    for (scheme, expected_result) in test_schemes {
        let result = connection.process_headers_frame(
            1, // Use stream ID 1 for basic tests
            scheme,
            &[] // No additional headers for basic tests
        );

        match expected_result {
            ExpectedSchemeResult::Accept => {
                assert!(matches!(result, ProcessingResult::Success),
                    "Valid scheme '{}' should be accepted", scheme);
            }

            ExpectedSchemeResult::Reject => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Invalid scheme '{}' should be rejected", scheme);
            }

            ExpectedSchemeResult::ImplementationDefined => {
                // Either accept or reject is fine
            }
        }
    }

    // Test fuzzed input cases
    for (idx, test_case) in input.scheme_tests.iter().enumerate() {
        let stream_id = if test_case.stream_id == 0 || test_case.stream_id % 2 == 0 {
            (idx as u32 * 2) + 3 // Ensure odd stream ID, start from 3
        } else {
            test_case.stream_id
        };

        let result = connection.process_headers_frame(
            stream_id,
            &test_case.scheme_value,
            &test_case.regular_headers
        );

        // Verify result matches expectation
        match test_case.expected_result {
            ExpectedSchemeResult::Accept => {
                if is_valid_scheme(&test_case.scheme_value) {
                    assert_eq!(result, ProcessingResult::Success,
                        "Expected valid scheme to be accepted: '{}'", test_case.scheme_value);
                }
            }

            ExpectedSchemeResult::Reject => {
                if !is_valid_scheme(&test_case.scheme_value) {
                    assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                        "Expected invalid scheme to be rejected: '{}'", test_case.scheme_value);
                }
            }

            ExpectedSchemeResult::ImplementationDefined => {
                // Either result is acceptable
            }
        }
    }

    // Test edge cases
    for edge_case in &input.edge_cases {
        match edge_case {
            EdgeCaseTest::EmptyScheme => {
                let result = connection.process_headers_frame(101, "", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Empty scheme should be rejected");
            }

            EdgeCaseTest::SchemeWithColon { scheme } => {
                let scheme_with_colon = format!("{}:", scheme);
                let result = connection.process_headers_frame(103, &scheme_with_colon, &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Scheme with colon '{}' should be rejected", scheme_with_colon);
            }

            EdgeCaseTest::SchemeWithAuthority { scheme } => {
                let scheme_with_auth = format!("{}://example.com", scheme);
                let result = connection.process_headers_frame(105, &scheme_with_auth, &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Scheme with authority '{}' should be rejected", scheme_with_auth);
            }

            EdgeCaseTest::VeryLongScheme { length } => {
                let long_scheme = "x".repeat(*length as usize);
                let result = connection.process_headers_frame(107, &long_scheme, &[]);
                if *length > connection.config.max_scheme_length {
                    assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                        "Long scheme should be rejected");
                }
            }

            EdgeCaseTest::SchemeWithNullBytes => {
                let result = connection.process_headers_frame(109, "http\0", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Scheme with null bytes should be rejected");
            }

            EdgeCaseTest::UnicodeScheme { scheme } => {
                let result = connection.process_headers_frame(111, scheme, &[]);
                if !scheme.is_ascii() {
                    assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                        "Unicode scheme '{}' should be rejected", scheme);
                }
            }

            _ => {
                // Other edge cases can be tested similarly
            }
        }
    }

    // Verify statistics consistency
    let status = connection.get_status();
    assert_eq!(
        status.stats.valid_schemes + status.stats.invalid_schemes,
        status.validation_results.len() as u32,
        "Statistics should match validation results count"
    );

    // Test that standard schemes are always accepted
    for standard_scheme in &["http", "https"] {
        let result = connection.process_headers_frame(301, standard_scheme, &[]);
        assert_eq!(result, ProcessingResult::Success,
            "Standard scheme '{}' should always be accepted", standard_scheme);
    }

    // Test that clearly invalid schemes are always rejected
    for invalid_scheme in &["javascript", "data", "file", "ftp"] {
        if !connection.config.allow_non_standard_schemes {
            let result = connection.process_headers_frame(401, invalid_scheme, &[]);
            assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                "Invalid scheme '{}' should be rejected", invalid_scheme);
        }
    }
});

/// Helper to check if a scheme is valid for HTTP/2
fn is_valid_scheme(scheme: &str) -> bool {
    matches!(scheme.to_lowercase().as_str(), "http" | "https") &&
    !scheme.is_empty() &&
    scheme.is_ascii() &&
    !scheme.contains('\0') &&
    !scheme.contains("://") &&
    !scheme.ends_with(':') &&
    scheme.chars().all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '-' | '.'))
}