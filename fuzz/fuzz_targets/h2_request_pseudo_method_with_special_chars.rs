#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 :method pseudo-header with control characters and whitespace fuzz target.
///
/// Tests RFC 9110 compliance for :method pseudo-header validation against
/// control characters, whitespace, and CRLF sequences. Per RFC 9110 §9.1:
/// "The method token is case-sensitive and MUST NOT include any characters
/// outside the token production rule."
///
/// Per RFC 9110 token definition (§5.6.2):
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
///
/// Critical violations to test:
/// - Control characters (0x00-0x1F, 0x7F): "\r", "\n", "\t"
/// - Whitespace inside method: "GE T", "POST ", " GET"
/// - Mixed violations: "PO\tST", "GET\r\nBAD"
/// - Boundary cases: empty method, only whitespace
/// - Valid methods for comparison: "GET", "POST", "OPTIONS"

#[derive(Arbitrary, Debug, Clone)]
struct SpecialCharsMethodInput {
    /// Test scenarios to validate
    test_cases: Vec<MethodTestCase>,

    /// Additional request configuration
    request_config: RequestConfig,

    /// Stream and connection settings
    connection_config: ConnectionConfig,

    /// Edge case variations
    edge_cases: Vec<EdgeCaseTest>,
}

#[derive(Arbitrary, Debug, Clone)]
struct MethodTestCase {
    /// The :method value to test (potentially invalid)
    method_value: String,

    /// Type of violation expected
    expected_violation: ExpectedViolation,

    /// Additional pseudo-headers
    additional_headers: Vec<PseudoHeader>,

    /// Regular headers
    regular_headers: Vec<(String, String)>,

    /// Stream ID for this test
    stream_id: u32,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ExpectedViolation {
    /// Method should be accepted (valid)
    None,

    /// Contains control characters (0x00-0x1F, 0x7F)
    ControlCharacters,

    /// Contains whitespace (space, tab)
    Whitespace,

    /// Contains CRLF sequences
    CRLF,

    /// Empty method
    EmptyMethod,

    /// Only whitespace
    OnlyWhitespace,

    /// Mixed violations
    Mixed,
}

#[derive(Arbitrary, Debug, Clone)]
enum PseudoHeader {
    Authority(String),
    Path(String),
    Scheme(String),
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestConfig {
    /// Whether to set END_HEADERS flag
    end_headers: bool,

    /// Whether to set END_STREAM flag
    end_stream: bool,

    /// Include CONTINUATION frames
    use_continuation: bool,

    /// Fragment headers across frames
    fragment_headers: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    /// Strict RFC validation mode
    strict_validation: bool,

    /// Track all violations
    track_violations: bool,

    /// Maximum method length allowed
    max_method_length: u8,

    /// Generate PROTOCOL_ERROR for violations
    error_on_violation: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseTest {
    /// Test method with null bytes
    NullByteMethod,

    /// Test method with high ASCII characters
    HighAsciiMethod,

    /// Test method with Unicode characters
    UnicodeMethod,

    /// Test very long method with special chars
    LongMethodWithSpecialChars,

    /// Test methods that look like valid but have hidden chars
    HiddenCharMethod,

    /// Test case-sensitive variations with special chars
    CaseSensitiveSpecialChars,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            strict_validation: true,
            track_violations: true,
            max_method_length: 64, // RFC doesn't specify, but reasonable limit
            error_on_violation: true,
        }
    }
}

/// Mock HTTP/2 connection for testing :method validation with special characters
struct MockMethodSpecialCharsConnection {
    /// Stream states
    streams: HashMap<u32, StreamState>,

    /// Connection-level errors
    connection_error: Option<ConnectionError>,

    /// Method validation results
    validation_results: Vec<MethodValidationResult>,

    /// Detected violations
    violations: Vec<MethodViolation>,

    /// Configuration
    config: ConnectionConfig,

    /// Statistics
    stats: ValidationStats,
}

#[derive(Debug, Clone)]
struct StreamState {
    headers_received: bool,
    method_validated: bool,
    method_value: Option<String>,
    violation_detected: bool,
    error_code: Option<u32>,
}

#[derive(Debug, Clone)]
enum ConnectionError {
    ProtocolError(String),
    InternalError(String),
}

#[derive(Debug, Clone)]
struct MethodValidationResult {
    stream_id: u32,
    method: String,
    valid: bool,
    violation_type: Option<ViolationType>,
    error_details: Option<String>,
}

#[derive(Debug, Clone)]
struct MethodViolation {
    stream_id: u32,
    method: String,
    violation_type: ViolationType,
    detected_chars: Vec<char>,
    position: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
enum ViolationType {
    ControlCharacter(char),   // Specific control character found
    WhitespaceInside(char),   // Space/tab inside method
    CRLFSequence,             // \r\n sequence
    EmptyMethod,              // Empty string
    OnlyWhitespace,           // Only whitespace characters
    InvalidCharacter(char),   // Other invalid characters
    MethodTooLong,            // Exceeds length limit
}

#[derive(Debug, Clone, Default)]
struct ValidationStats {
    valid_methods: u32,
    invalid_methods: u32,
    control_char_violations: u32,
    whitespace_violations: u32,
    crlf_violations: u32,
    empty_method_violations: u32,
    mixed_violations: u32,
}

impl MockMethodSpecialCharsConnection {
    fn new(config: ConnectionConfig) -> Self {
        Self {
            streams: HashMap::new(),
            connection_error: None,
            validation_results: Vec::new(),
            violations: Vec::new(),
            config,
            stats: ValidationStats::default(),
        }
    }

    /// Process HEADERS frame with :method validation
    fn process_headers_frame(&mut self, stream_id: u32, method: &str,
                           other_headers: &[(String, String)]) -> ProcessingResult {
        // Stream ID validation
        if stream_id == 0 || stream_id % 2 == 0 {
            self.connection_error = Some(ConnectionError::ProtocolError(
                "Invalid stream ID for client-initiated request".to_string()
            ));
            return ProcessingResult::ConnectionError;
        }

        // Validate the :method pseudo-header
        let validation_result = self.validate_method(stream_id, method);

        // Update stream state
        let stream_state = self.streams.entry(stream_id).or_insert(StreamState {
            headers_received: false,
            method_validated: false,
            method_value: None,
            violation_detected: false,
            error_code: None,
        });

        stream_state.headers_received = true;
        stream_state.method_value = Some(method.to_string());

        match validation_result {
            MethodValidationResult { valid: true, .. } => {
                stream_state.method_validated = true;
                self.stats.valid_methods += 1;
                ProcessingResult::Success
            }

            MethodValidationResult { valid: false, violation_type: Some(ref vtype), .. } => {
                stream_state.violation_detected = true;
                self.stats.invalid_methods += 1;

                // Update specific violation counters
                match vtype {
                    ViolationType::ControlCharacter(_) => {
                        self.stats.control_char_violations += 1;
                    }
                    ViolationType::WhitespaceInside(_) => {
                        self.stats.whitespace_violations += 1;
                    }
                    ViolationType::CRLFSequence => {
                        self.stats.crlf_violations += 1;
                    }
                    ViolationType::EmptyMethod => {
                        self.stats.empty_method_violations += 1;
                    }
                    ViolationType::OnlyWhitespace => {
                        self.stats.whitespace_violations += 1;
                    }
                    _ => {
                        self.stats.mixed_violations += 1;
                    }
                }

                if self.config.error_on_violation {
                    // Per RFC 9110 + RFC 7540, invalid :method should cause stream error
                    stream_state.error_code = Some(0x1); // PROTOCOL_ERROR
                    ProcessingResult::StreamError(0x1)
                } else {
                    ProcessingResult::ValidationError
                }
            }

            _ => {
                ProcessingResult::ValidationError
            }
        }
    }

    /// Validate :method pseudo-header against RFC 9110 rules
    fn validate_method(&mut self, stream_id: u32, method: &str) -> MethodValidationResult {
        let mut violations = Vec::new();
        let mut detected_chars = Vec::new();

        // Empty method check
        if method.is_empty() {
            let violation = MethodViolation {
                stream_id,
                method: method.to_string(),
                violation_type: ViolationType::EmptyMethod,
                detected_chars: vec![],
                position: None,
            };

            if self.config.track_violations {
                self.violations.push(violation);
            }

            return MethodValidationResult {
                stream_id,
                method: method.to_string(),
                valid: false,
                violation_type: Some(ViolationType::EmptyMethod),
                error_details: Some("Method cannot be empty".to_string()),
            };
        }

        // Only whitespace check
        if method.trim().is_empty() {
            let violation = MethodViolation {
                stream_id,
                method: method.to_string(),
                violation_type: ViolationType::OnlyWhitespace,
                detected_chars: method.chars().collect(),
                position: None,
            };

            if self.config.track_violations {
                self.violations.push(violation);
            }

            return MethodValidationResult {
                stream_id,
                method: method.to_string(),
                valid: false,
                violation_type: Some(ViolationType::OnlyWhitespace),
                error_details: Some("Method cannot be only whitespace".to_string()),
            };
        }

        // Length check
        if method.len() > self.config.max_method_length as usize {
            return MethodValidationResult {
                stream_id,
                method: method.to_string(),
                valid: false,
                violation_type: Some(ViolationType::MethodTooLong),
                error_details: Some(format!("Method too long: {} > {}",
                    method.len(), self.config.max_method_length)),
            };
        }

        // Character validation
        for (pos, ch) in method.char_indices() {
            let violation_type = if ch.is_control() {
                // Control characters (0x00-0x1F, 0x7F)
                Some(ViolationType::ControlCharacter(ch))
            } else if ch == ' ' || ch == '\t' {
                // Whitespace inside method
                Some(ViolationType::WhitespaceInside(ch))
            } else if !self.is_valid_method_char(ch) {
                // Other invalid characters
                Some(ViolationType::InvalidCharacter(ch))
            } else {
                None
            };

            if let Some(vtype) = violation_type {
                detected_chars.push(ch);

                let violation = MethodViolation {
                    stream_id,
                    method: method.to_string(),
                    violation_type: vtype.clone(),
                    detected_chars: vec![ch],
                    position: Some(pos),
                };

                violations.push(violation);
            }
        }

        // Check for CRLF sequences
        if method.contains("\r\n") {
            let violation = MethodViolation {
                stream_id,
                method: method.to_string(),
                violation_type: ViolationType::CRLFSequence,
                detected_chars: vec!['\r', '\n'],
                position: method.find("\r\n"),
            };

            violations.push(violation);
        }

        // Store violations if tracking enabled
        if self.config.track_violations {
            self.violations.extend(violations.clone());
        }

        // Determine validation result
        if violations.is_empty() {
            MethodValidationResult {
                stream_id,
                method: method.to_string(),
                valid: true,
                violation_type: None,
                error_details: None,
            }
        } else {
            let primary_violation = violations.into_iter().next().unwrap();

            MethodValidationResult {
                stream_id,
                method: method.to_string(),
                valid: false,
                violation_type: Some(primary_violation.violation_type),
                error_details: Some(format!("Invalid character '{}' at position {:?}",
                    primary_violation.detected_chars.get(0).unwrap_or(&'?'),
                    primary_violation.position)),
            }
        }
    }

    /// Check if character is valid in HTTP method per RFC 9110
    fn is_valid_method_char(&self, ch: char) -> bool {
        // RFC 9110 tchar definition:
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA

        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' => true,
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' |
            '^' | '_' | '`' | '|' | '~' => true,
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
    validation_results: Vec<MethodValidationResult>,
    violations: Vec<MethodViolation>,
    stats: ValidationStats,
}

/// Generate test methods with various special character violations
fn generate_test_methods() -> Vec<(&'static str, ExpectedViolation)> {
    vec![
        // Control characters
        ("GET\r", ExpectedViolation::ControlCharacters),
        ("PO\nST", ExpectedViolation::ControlCharacters),
        ("PUT\t", ExpectedViolation::ControlCharacters),
        ("DELETE\x00", ExpectedViolation::ControlCharacters),
        ("HEAD\x1F", ExpectedViolation::ControlCharacters),
        ("OPTIONS\x7F", ExpectedViolation::ControlCharacters),

        // Whitespace violations
        ("GE T", ExpectedViolation::Whitespace),
        ("POST ", ExpectedViolation::Whitespace),
        (" GET", ExpectedViolation::Whitespace),
        ("P UT", ExpectedViolation::Whitespace),
        ("DE\tLETE", ExpectedViolation::Whitespace),

        // CRLF sequences
        ("GET\r\n", ExpectedViolation::CRLF),
        ("POST\r\nBAD", ExpectedViolation::CRLF),
        ("\r\nGET", ExpectedViolation::CRLF),

        // Empty and whitespace-only
        ("", ExpectedViolation::EmptyMethod),
        (" ", ExpectedViolation::OnlyWhitespace),
        ("  ", ExpectedViolation::OnlyWhitespace),
        ("\t", ExpectedViolation::OnlyWhitespace),
        (" \t ", ExpectedViolation::OnlyWhitespace),

        // Mixed violations
        ("GET\r\n ", ExpectedViolation::Mixed),
        (" POST\t", ExpectedViolation::Mixed),
        ("PU\x00T ", ExpectedViolation::Mixed),

        // Valid methods (should pass)
        ("GET", ExpectedViolation::None),
        ("POST", ExpectedViolation::None),
        ("PUT", ExpectedViolation::None),
        ("DELETE", ExpectedViolation::None),
        ("HEAD", ExpectedViolation::None),
        ("OPTIONS", ExpectedViolation::None),
        ("TRACE", ExpectedViolation::None),
        ("CONNECT", ExpectedViolation::None),
        ("PATCH", ExpectedViolation::None),
        ("CUSTOM-METHOD", ExpectedViolation::None),
    ]
}

fuzz_target!(|input: SpecialCharsMethodInput| {
    // Limit input size for performance
    let mut input = input;
    if input.test_cases.len() > 20 {
        input.test_cases.truncate(20);
    }

    let mut connection = MockMethodSpecialCharsConnection::new(input.connection_config.clone());

    // Test predefined violation cases
    let test_methods = generate_test_methods();
    for (method, expected_violation) in test_methods {
        let result = connection.process_headers_frame(
            1, // Use stream ID 1 for basic tests
            method,
            &[] // No additional headers for basic tests
        );

        match expected_violation {
            ExpectedViolation::None => {
                assert_eq!(result, ProcessingResult::Success,
                    "Valid method '{}' should be accepted", method);
            }

            ExpectedViolation::ControlCharacters => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with control characters '{}' should be rejected", method);
            }

            ExpectedViolation::Whitespace => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with whitespace '{}' should be rejected", method);
            }

            ExpectedViolation::CRLF => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with CRLF '{}' should be rejected", method);
            }

            ExpectedViolation::EmptyMethod | ExpectedViolation::OnlyWhitespace => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Empty/whitespace-only method '{}' should be rejected", method);
            }

            ExpectedViolation::Mixed => {
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with mixed violations '{}' should be rejected", method);
            }
        }
    }

    // Test fuzzed input cases
    for (idx, test_case) in input.test_cases.iter().enumerate() {
        let stream_id = if test_case.stream_id == 0 || test_case.stream_id % 2 == 0 {
            (idx as u32 * 2) + 1 // Ensure odd stream ID
        } else {
            test_case.stream_id
        };

        let result = connection.process_headers_frame(
            stream_id,
            &test_case.method_value,
            &test_case.regular_headers
        );

        // Verify result matches expectation
        match test_case.expected_violation {
            ExpectedViolation::None => {
                if connection.is_valid_method(&test_case.method_value) {
                    assert_eq!(result, ProcessingResult::Success,
                        "Expected valid method to be accepted: '{}'", test_case.method_value);
                }
            }

            _ => {
                if !connection.is_valid_method(&test_case.method_value) {
                    assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                        "Expected invalid method to be rejected: '{}'", test_case.method_value);
                }
            }
        }
    }

    // Test edge cases
    for edge_case in &input.edge_cases {
        match edge_case {
            EdgeCaseTest::NullByteMethod => {
                let result = connection.process_headers_frame(101, "GET\0", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with null byte should be rejected");
            }

            EdgeCaseTest::HighAsciiMethod => {
                let result = connection.process_headers_frame(103, "GET\u{80}", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with high ASCII should be rejected");
            }

            EdgeCaseTest::UnicodeMethod => {
                let result = connection.process_headers_frame(105, "GÉT", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with Unicode should be rejected");
            }

            EdgeCaseTest::LongMethodWithSpecialChars => {
                let long_method = format!("GET{}", " ".repeat(100));
                let result = connection.process_headers_frame(107, &long_method, &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Long method with special chars should be rejected");
            }

            EdgeCaseTest::HiddenCharMethod => {
                // Test methods that look valid but have hidden control characters
                let result = connection.process_headers_frame(109, "GET\u{200B}", &[]);
                assert!(matches!(result, ProcessingResult::StreamError(_) | ProcessingResult::ValidationError),
                    "Method with hidden characters should be rejected");
            }

            _ => {
                // Other edge cases can be implemented similarly
            }
        }
    }

    // Verify statistics consistency
    let status = connection.get_status();
    if connection.config.track_violations {
        assert_eq!(
            status.stats.valid_methods + status.stats.invalid_methods,
            status.validation_results.len() as u32,
            "Statistics should match validation results count"
        );

        // Verify violation categorization is consistent
        let total_violations = status.stats.control_char_violations +
                             status.stats.whitespace_violations +
                             status.stats.crlf_violations +
                             status.stats.empty_method_violations +
                             status.stats.mixed_violations;

        assert!(total_violations <= status.stats.invalid_methods,
            "Violation categories should not exceed total invalid methods");
    }

    // Test that valid common methods are always accepted
    for valid_method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"] {
        let result = connection.process_headers_frame(201, valid_method, &[]);
        assert_eq!(result, ProcessingResult::Success,
            "Standard HTTP method '{}' should always be accepted", valid_method);
    }
});

impl MockMethodSpecialCharsConnection {
    /// Helper to check if a method is valid according to RFC 9110
    fn is_valid_method(&self, method: &str) -> bool {
        !method.is_empty() &&
        !method.trim().is_empty() &&
        method.len() <= self.config.max_method_length as usize &&
        !method.contains("\r\n") &&
        method.chars().all(|c| !c.is_control() && c != ' ' && c != '\t' && self.is_valid_method_char(c))
    }
}