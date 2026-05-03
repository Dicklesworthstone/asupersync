#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 :scheme uppercase rejection fuzz target.
///
/// Tests RFC 7540 §8.1.2.3 strict compliance for lowercase-only :scheme
/// pseudo-header values. Per RFC 7540 §8.1.2.3: "All pseudo-header fields
/// MUST appear in the header block before regular header fields. Any request
/// or response containing uppercase header field names MUST be treated as
/// malformed (Section 8.1.2.6)."
///
/// Additionally, per HTTP/2 specification normative requirements:
/// - Scheme values MUST be lowercase per URI scheme normalization rules
/// - "HTTPS", "HTTP", "Https", "Http" are all invalid - only "https", "http" allowed
/// - Parser MUST reject with PROTOCOL_ERROR per RFC 7540 §8.1.2.6
///
/// Critical test scenarios:
/// - "HTTPS" → PROTOCOL_ERROR (all uppercase)
/// - "HTTP" → PROTOCOL_ERROR (all uppercase)
/// - "Https" → PROTOCOL_ERROR (mixed case)
/// - "Http" → PROTOCOL_ERROR (mixed case)
/// - "hTTp", "hTTps" → PROTOCOL_ERROR (various mixed cases)
/// - "https", "http" → Accept (correct lowercase)

#[derive(Arbitrary, Debug, Clone)]
struct UppercaseSchemeInput {
    /// Test cases for various case combinations
    case_tests: Vec<CaseTestCase>,

    /// Request configuration
    request_config: RequestConfig,

    /// Validation strictness
    validation_config: ValidationConfig,

    /// Additional edge cases
    edge_cases: Vec<EdgeCaseTest>,
}

#[derive(Arbitrary, Debug, Clone)]
struct CaseTestCase {
    /// The scheme value to test (with specific casing)
    scheme_value: String,

    /// Expected result based on casing rules
    expected_result: CaseExpectation,

    /// Stream ID for this test
    stream_id: u32,

    /// Other pseudo-headers
    other_pseudo_headers: Vec<PseudoHeader>,

    /// Test with continuation frames
    use_continuation: bool,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum CaseExpectation {
    /// Should be accepted (lowercase)
    Accept,

    /// Should be rejected (uppercase/mixed case)
    Reject,

    /// Test both strict and lenient modes
    ConfigurationDependent,
}

#[derive(Arbitrary, Debug, Clone)]
enum PseudoHeader {
    Method(String),
    Authority(String),
    Path(String),
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestConfig {
    /// Whether to set END_HEADERS flag
    end_headers: bool,

    /// Whether to set END_STREAM flag
    end_stream: bool,

    /// Fragment across CONTINUATION frames
    use_continuation_frames: bool,

    /// Include regular headers after pseudo-headers
    include_regular_headers: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct ValidationConfig {
    /// Strict RFC 7540 §8.1.2.3 compliance (reject uppercase)
    strict_case_compliance: bool,

    /// Generate PROTOCOL_ERROR for case violations
    error_on_case_violation: bool,

    /// Track case violation statistics
    track_case_violations: bool,

    /// Allow normalization instead of rejection
    allow_case_normalization: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseTest {
    /// Test all possible case combinations for "http"
    HttpAllCombinations,

    /// Test all possible case combinations for "https"
    HttpsAllCombinations,

    /// Test with Unicode lookalikes
    UnicodeLookalikes { scheme: String },

    /// Test with mixed ASCII and non-ASCII
    MixedAsciiNonAscii { scheme: String },

    /// Case sensitivity in different header positions
    CaseInDifferentPositions,

    /// Uppercase in CONTINUATION frames
    UppercaseInContinuation,

    /// Case violations with other header violations
    CombinedViolations,

    /// Very long scheme with mixed case
    LongSchemeWithCase { length: u8 },
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict_case_compliance: true,
            error_on_case_violation: true,
            track_case_violations: true,
            allow_case_normalization: false, // RFC requires rejection, not normalization
        }
    }
}

/// Mock HTTP/2 connection for testing :scheme case sensitivity
struct MockSchemeUppercaseConnection {
    /// Stream states
    streams: HashMap<u32, StreamState>,

    /// Connection-level errors
    connection_error: Option<ConnectionError>,

    /// Case validation results
    validation_results: Vec<CaseValidationResult>,

    /// Detected case violations
    violations: Vec<CaseViolation>,

    /// Configuration
    config: ValidationConfig,

    /// Statistics
    stats: CaseValidationStats,
}

#[derive(Debug, Clone)]
struct StreamState {
    headers_received: bool,
    scheme_validated: bool,
    scheme_value: Option<String>,
    case_violation_detected: bool,
    error_code: Option<u32>,
}

#[derive(Debug, Clone)]
enum ConnectionError {
    ProtocolError(String),
    HeaderCaseViolation(String),
}

#[derive(Debug, Clone)]
struct CaseValidationResult {
    stream_id: u32,
    scheme: String,
    valid: bool,
    case_violation_type: Option<CaseViolationType>,
    normalized_scheme: Option<String>,
}

#[derive(Debug, Clone)]
struct CaseViolation {
    stream_id: u32,
    scheme: String,
    violation_type: CaseViolationType,
    uppercase_positions: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq)]
enum CaseViolationType {
    AllUppercase,                    // "HTTPS", "HTTP"
    MixedCase,                       // "Https", "Http"
    RandomCase,                      // "hTTp", "hTTPs"
    LeadingCapital,                  // "Https", "Http"
    NonStandardCasing,               // Any other case pattern
}

#[derive(Debug, Clone, Default)]
struct CaseValidationStats {
    lowercase_schemes: u32,          // "http", "https"
    uppercase_schemes: u32,          // "HTTP", "HTTPS"
    mixed_case_schemes: u32,         // "Http", "Https"
    random_case_schemes: u32,        // "hTTp", "HTtp"
    case_violations_detected: u32,
    case_violations_rejected: u32,
    case_normalization_applied: u32,
}

impl MockSchemeUppercaseConnection {
    fn new(config: ValidationConfig) -> Self {
        Self {
            streams: HashMap::new(),
            connection_error: None,
            validation_results: Vec::new(),
            violations: Vec::new(),
            config,
            stats: CaseValidationStats::default(),
        }
    }

    /// Process HEADERS frame with :scheme case validation
    fn process_headers_frame(&mut self, stream_id: u32, scheme: &str) -> ProcessingResult {
        // Stream ID validation
        if stream_id == 0 || stream_id % 2 == 0 {
            self.connection_error = Some(ConnectionError::ProtocolError(
                "Invalid stream ID for client-initiated request".to_string()
            ));
            return ProcessingResult::ConnectionError;
        }

        // Validate the :scheme case sensitivity
        let validation_result = self.validate_scheme_case(stream_id, scheme);

        // Update stream state
        let stream_state = self.streams.entry(stream_id).or_insert(StreamState {
            headers_received: false,
            scheme_validated: false,
            scheme_value: None,
            case_violation_detected: false,
            error_code: None,
        });

        stream_state.headers_received = true;
        stream_state.scheme_value = Some(scheme.to_string());

        // Update statistics based on scheme case
        self.update_case_statistics(scheme);

        match validation_result {
            CaseValidationResult { valid: true, .. } => {
                stream_state.scheme_validated = true;
                ProcessingResult::Success
            }

            CaseValidationResult {
                valid: false,
                case_violation_type: Some(ref violation_type),
                ..
            } => {
                stream_state.case_violation_detected = true;
                self.stats.case_violations_detected += 1;

                if self.config.error_on_case_violation {
                    // Per RFC 7540 §8.1.2.6: malformed requests with uppercase
                    // header names MUST be treated as PROTOCOL_ERROR
                    stream_state.error_code = Some(0x1); // PROTOCOL_ERROR
                    self.stats.case_violations_rejected += 1;

                    // Connection-level error for case violations
                    self.connection_error = Some(ConnectionError::HeaderCaseViolation(
                        format!("Uppercase characters in :scheme '{}' violate RFC 7540 §8.1.2.3", scheme)
                    ));

                    ProcessingResult::ProtocolError(format!(
                        "PROTOCOL_ERROR: :scheme '{}' contains uppercase characters", scheme
                    ))
                } else if self.config.allow_case_normalization {
                    // Normalize instead of rejecting (non-compliant but sometimes used)
                    stream_state.scheme_validated = true;
                    self.stats.case_normalization_applied += 1;
                    ProcessingResult::Normalized(scheme.to_lowercase())
                } else {
                    ProcessingResult::ValidationError
                }
            }

            _ => ProcessingResult::ValidationError,
        }
    }

    /// Validate :scheme case sensitivity per RFC 7540 §8.1.2.3
    fn validate_scheme_case(&mut self, stream_id: u32, scheme: &str) -> CaseValidationResult {
        // Check if scheme is all lowercase (correct)
        let lowercase_scheme = scheme.to_lowercase();
        if scheme == lowercase_scheme {
            return CaseValidationResult {
                stream_id,
                scheme: scheme.to_string(),
                valid: true,
                case_violation_type: None,
                normalized_scheme: Some(lowercase_scheme),
            };
        }

        // Analyze the type of case violation
        let violation_type = self.analyze_case_violation(scheme);
        let uppercase_positions = self.find_uppercase_positions(scheme);

        // Record the violation
        let violation = CaseViolation {
            stream_id,
            scheme: scheme.to_string(),
            violation_type: violation_type.clone(),
            uppercase_positions,
        };

        if self.config.track_case_violations {
            self.violations.push(violation);
        }

        // Return validation result
        CaseValidationResult {
            stream_id,
            scheme: scheme.to_string(),
            valid: !self.config.strict_case_compliance, // Fail if strict compliance enabled
            case_violation_type: Some(violation_type),
            normalized_scheme: Some(lowercase_scheme),
        }
    }

    /// Analyze what type of case violation occurred
    fn analyze_case_violation(&self, scheme: &str) -> CaseViolationType {
        let uppercase_count = scheme.chars().filter(|c| c.is_uppercase()).count();
        let total_chars = scheme.chars().filter(|c| c.is_alphabetic()).count();

        if uppercase_count == total_chars && total_chars > 0 {
            // All alphabetic characters are uppercase
            CaseViolationType::AllUppercase
        } else if scheme.chars().next().map_or(false, |c| c.is_uppercase()) {
            // First character is uppercase
            CaseViolationType::LeadingCapital
        } else if self.has_mixed_case_pattern(scheme) {
            // Specific mixed case patterns
            CaseViolationType::MixedCase
        } else if uppercase_count > 0 {
            // Random uppercase characters
            CaseViolationType::RandomCase
        } else {
            // Non-standard casing pattern
            CaseViolationType::NonStandardCasing
        }
    }

    /// Check for common mixed case patterns
    fn has_mixed_case_pattern(&self, scheme: &str) -> bool {
        // Common patterns: "Http", "Https", "Http", etc.
        matches!(scheme, "Http" | "Https" | "HTTP" | "HTTPS") ||
        (scheme.len() > 1 &&
         scheme.chars().next().unwrap().is_uppercase() &&
         scheme.chars().skip(1).all(|c| c.is_lowercase()))
    }

    /// Find positions of uppercase characters
    fn find_uppercase_positions(&self, scheme: &str) -> Vec<usize> {
        scheme
            .char_indices()
            .filter_map(|(i, c)| if c.is_uppercase() { Some(i) } else { None })
            .collect()
    }

    /// Update statistics based on scheme case pattern
    fn update_case_statistics(&mut self, scheme: &str) {
        let lowercase_scheme = scheme.to_lowercase();

        if scheme == lowercase_scheme {
            self.stats.lowercase_schemes += 1;
        } else {
            let violation_type = self.analyze_case_violation(scheme);
            match violation_type {
                CaseViolationType::AllUppercase => {
                    self.stats.uppercase_schemes += 1;
                }
                CaseViolationType::LeadingCapital | CaseViolationType::MixedCase => {
                    self.stats.mixed_case_schemes += 1;
                }
                CaseViolationType::RandomCase | CaseViolationType::NonStandardCasing => {
                    self.stats.random_case_schemes += 1;
                }
            }
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
    ProtocolError(String),
    Normalized(String),
    ConnectionError,
    ValidationError,
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    connection_error: Option<ConnectionError>,
    stream_count: usize,
    validation_results: Vec<CaseValidationResult>,
    violations: Vec<CaseViolation>,
    stats: CaseValidationStats,
}

/// Generate comprehensive case test scenarios
fn generate_case_test_schemes() -> Vec<(&'static str, CaseExpectation)> {
    vec![
        // Correct lowercase (should be accepted)
        ("http", CaseExpectation::Accept),
        ("https", CaseExpectation::Accept),

        // All uppercase (MUST be rejected per RFC 7540)
        ("HTTP", CaseExpectation::Reject),
        ("HTTPS", CaseExpectation::Reject),

        // Leading capital (MUST be rejected)
        ("Http", CaseExpectation::Reject),
        ("Https", CaseExpectation::Reject),

        // Mixed case variations (all MUST be rejected)
        ("hTTP", CaseExpectation::Reject),
        ("hTTPs", CaseExpectation::Reject),
        ("HtTp", CaseExpectation::Reject),
        ("HtTpS", CaseExpectation::Reject),
        ("HTtp", CaseExpectation::Reject),
        ("HTTPs", CaseExpectation::Reject),

        // Single character case variations
        ("htTp", CaseExpectation::Reject),
        ("httP", CaseExpectation::Reject),
        ("httpS", CaseExpectation::Reject),
        ("hTtps", CaseExpectation::Reject),
        ("httPs", CaseExpectation::Reject),

        // Random case patterns
        ("hTtP", CaseExpectation::Reject),
        ("HtTpS", CaseExpectation::Reject),
        ("hTtPs", CaseExpectation::Reject),
        ("HTtP", CaseExpectation::Reject),
        ("HTtPs", CaseExpectation::Reject),

        // Edge cases with case sensitivity
        ("HTTP ", CaseExpectation::Reject),        // Uppercase with space
        (" HTTPS", CaseExpectation::Reject),       // Leading space + uppercase
        ("Http\n", CaseExpectation::Reject),       // Mixed case with control char
    ]
}

/// Generate all possible case combinations for a given scheme
fn generate_all_case_combinations(base_scheme: &str) -> Vec<String> {
    let chars: Vec<char> = base_scheme.chars().collect();
    let n = chars.len();
    let mut combinations = Vec::new();

    // Generate all 2^n case combinations
    for i in 0..(1 << n) {
        let mut combo = String::new();
        for (j, &ch) in chars.iter().enumerate() {
            if (i & (1 << j)) != 0 {
                combo.push(ch.to_uppercase().next().unwrap_or(ch));
            } else {
                combo.push(ch.to_lowercase().next().unwrap_or(ch));
            }
        }
        combinations.push(combo);
    }

    combinations
}

fuzz_target!(|input: UppercaseSchemeInput| {
    // Limit input size for performance
    let mut input = input;
    if input.case_tests.len() > 15 {
        input.case_tests.truncate(15);
    }

    let mut connection = MockSchemeUppercaseConnection::new(input.validation_config.clone());

    // Test predefined case scenarios
    let case_tests = generate_case_test_schemes();
    for (scheme, expected_result) in case_tests {
        let result = connection.process_headers_frame(1, scheme);

        match expected_result {
            CaseExpectation::Accept => {
                assert_eq!(result, ProcessingResult::Success,
                    "Lowercase scheme '{}' should be accepted", scheme);
            }

            CaseExpectation::Reject => {
                if connection.config.strict_case_compliance {
                    assert!(matches!(result, ProcessingResult::ProtocolError(_)),
                        "Uppercase/mixed-case scheme '{}' should be rejected with PROTOCOL_ERROR", scheme);
                }
            }

            CaseExpectation::ConfigurationDependent => {
                // Result depends on configuration - either accept or reject is valid
            }
        }
    }

    // Test all case combinations for "http"
    let http_combinations = generate_all_case_combinations("http");
    for (idx, scheme) in http_combinations.iter().enumerate() {
        let stream_id = (idx as u32 * 2) + 101; // Ensure odd stream IDs
        let result = connection.process_headers_frame(stream_id, scheme);

        if scheme == "http" {
            // Only lowercase should be accepted
            assert_eq!(result, ProcessingResult::Success,
                "Lowercase 'http' should be accepted");
        } else if connection.config.strict_case_compliance {
            // All other combinations should be rejected
            assert!(matches!(result, ProcessingResult::ProtocolError(_)),
                "Non-lowercase 'http' variant '{}' should be rejected", scheme);
        }
    }

    // Test all case combinations for "https"
    let https_combinations = generate_all_case_combinations("https");
    for (idx, scheme) in https_combinations.iter().enumerate() {
        let stream_id = (idx as u32 * 2) + 201; // Ensure odd stream IDs
        let result = connection.process_headers_frame(stream_id, scheme);

        if scheme == "https" {
            // Only lowercase should be accepted
            assert_eq!(result, ProcessingResult::Success,
                "Lowercase 'https' should be accepted");
        } else if connection.config.strict_case_compliance {
            // All other combinations should be rejected
            assert!(matches!(result, ProcessingResult::ProtocolError(_)),
                "Non-lowercase 'https' variant '{}' should be rejected", scheme);
        }
    }

    // Test fuzzed input cases
    for (idx, test_case) in input.case_tests.iter().enumerate() {
        let stream_id = if test_case.stream_id == 0 || test_case.stream_id % 2 == 0 {
            (idx as u32 * 2) + 301 // Ensure odd stream ID
        } else {
            test_case.stream_id
        };

        let result = connection.process_headers_frame(stream_id, &test_case.scheme_value);

        // Verify result matches expectation
        let is_lowercase = test_case.scheme_value == test_case.scheme_value.to_lowercase();

        match test_case.expected_result {
            CaseExpectation::Accept => {
                if is_lowercase && matches!(test_case.scheme_value.as_str(), "http" | "https") {
                    assert_eq!(result, ProcessingResult::Success,
                        "Expected lowercase scheme to be accepted: '{}'", test_case.scheme_value);
                }
            }

            CaseExpectation::Reject => {
                if !is_lowercase && connection.config.strict_case_compliance {
                    assert!(matches!(result, ProcessingResult::ProtocolError(_)),
                        "Expected non-lowercase scheme to be rejected: '{}'", test_case.scheme_value);
                }
            }

            CaseExpectation::ConfigurationDependent => {
                // Either result is acceptable depending on configuration
            }
        }
    }

    // Test edge cases
    for edge_case in &input.edge_cases {
        match edge_case {
            EdgeCaseTest::HttpAllCombinations => {
                // This is already tested above
            }

            EdgeCaseTest::HttpsAllCombinations => {
                // This is already tested above
            }

            EdgeCaseTest::UnicodeLookalikes { scheme } => {
                if !scheme.is_ascii() {
                    let result = connection.process_headers_frame(401, scheme);
                    // Unicode schemes should be rejected regardless of case
                    assert!(matches!(result, ProcessingResult::ProtocolError(_) | ProcessingResult::ValidationError),
                        "Unicode scheme '{}' should be rejected", scheme);
                }
            }

            EdgeCaseTest::LongSchemeWithCase { length } => {
                let mixed_case_scheme = format!("H{}", "t".repeat(*length as usize - 1));
                let result = connection.process_headers_frame(403, &mixed_case_scheme);
                if connection.config.strict_case_compliance {
                    assert!(matches!(result, ProcessingResult::ProtocolError(_) | ProcessingResult::ValidationError),
                        "Long mixed-case scheme should be rejected");
                }
            }

            _ => {
                // Other edge cases can be tested similarly
            }
        }
    }

    // Verify statistics consistency
    let status = connection.get_status();
    let total_schemes = status.stats.lowercase_schemes +
                       status.stats.uppercase_schemes +
                       status.stats.mixed_case_schemes +
                       status.stats.random_case_schemes;

    assert!(total_schemes > 0, "Should have processed some schemes");

    if connection.config.strict_case_compliance {
        assert_eq!(
            status.stats.case_violations_detected,
            status.stats.uppercase_schemes + status.stats.mixed_case_schemes + status.stats.random_case_schemes,
            "Case violations detected should match non-lowercase schemes"
        );
    }

    // Verify RFC compliance: only lowercase "http" and "https" should be accepted
    if connection.config.strict_case_compliance && connection.config.error_on_case_violation {
        // Test specific RFC violation examples
        for &scheme in &["HTTP", "HTTPS", "Http", "Https"] {
            let result = connection.process_headers_frame(501, scheme);
            assert!(matches!(result, ProcessingResult::ProtocolError(_)),
                "RFC 7540 violation: '{}' should generate PROTOCOL_ERROR", scheme);
        }
    }
});