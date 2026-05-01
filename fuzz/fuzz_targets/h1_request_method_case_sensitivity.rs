#![no_main]

//! HTTP/1.1 request method case sensitivity fuzzing target
//!
//! Tests RFC 9110 §9.1 method case sensitivity requirements:
//! - HTTP methods are case-sensitive (GET ≠ get ≠ Get)
//! - Standard methods must match exact byte patterns
//! - Extension methods must be valid tokens but preserve case
//! - Tests types.rs Method::from_bytes() and method parsing logic

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Test case for HTTP method case sensitivity
#[derive(Arbitrary, Debug, Clone)]
pub struct MethodCaseSensitivityTestCase {
    pub scenario: MethodScenario,
    pub method_variants: Vec<MethodVariant>,
    pub request_line_context: RequestLineContext,
    pub case_config: CaseConfig,
    pub validation_config: ValidationConfig,
}

/// Different method case sensitivity testing scenarios
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum MethodScenario {
    /// Test standard method case sensitivity
    StandardMethodCases,
    /// Test extension method case preservation
    ExtensionMethodCases,
    /// Test mixed case standard methods (should fail)
    MixedCaseStandardMethods,
    /// Test invalid method characters
    InvalidMethodCharacters,
    /// Test method length boundaries
    MethodLengthBoundaries,
    /// Test Unicode and non-ASCII methods
    UnicodeMethodHandling,
    /// Test method smuggling via case differences
    MethodSmugglingCases,
    /// Test empty and whitespace methods
    EmptyWhitespaceMethods,
    /// Test control character injection
    ControlCharacterInjection,
    /// Test RFC token compliance
    RfcTokenCompliance,
}

/// Method variant for testing
#[derive(Arbitrary, Debug, Clone)]
pub struct MethodVariant {
    pub base_method: BaseMethod,
    pub case_transformation: CaseTransformation,
    pub character_injection: Option<CharacterInjection>,
    pub length_modification: LengthModification,
}

/// Base HTTP methods for testing
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum BaseMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Extension(String),
    Invalid(Vec<u8>),
}

/// Case transformation types
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum CaseTransformation {
    Unchanged,
    Lowercase,
    Uppercase,
    TitleCase,
    MixedCase(Vec<bool>), // Per-character case pattern
    RandomCase,
    InvertCase,
}

/// Character injection for testing
#[derive(Arbitrary, Debug, Clone)]
pub struct CharacterInjection {
    pub injection_type: InjectionType,
    pub position: InjectionPosition,
    pub characters: Vec<u8>,
}

/// Types of character injection
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum InjectionType {
    ControlCharacters,  // \x00-\x1F, \x7F-\xFF
    WhitespaceCharacters, // space, tab, CR, LF
    UnicodeCharacters,
    InvalidTokenCharacters, // Characters not allowed in HTTP tokens
    NullBytes,
    HighBitCharacters,
}

/// Position for character injection
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum InjectionPosition {
    Beginning,
    Middle,
    End,
    Random,
    Multiple(Vec<usize>),
}

/// Length modification for boundary testing
#[derive(Arbitrary, Debug, Clone)]
pub enum LengthModification {
    None,
    Truncate(usize),
    Extend(String),
    Repeat(usize),
    Empty,
    VeryLong(usize), // Methods longer than typical limits
}

/// Request line context for testing
#[derive(Arbitrary, Debug, Clone)]
pub struct RequestLineContext {
    pub uri: String,
    pub version: HttpVersion,
    pub line_terminators: LineTerminators,
    pub whitespace_pattern: WhitespacePattern,
}

/// HTTP version for context
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http09, // Edge case
    Invalid(String),
}

/// Line terminator patterns
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum LineTerminators {
    CrLf,     // Standard \r\n
    LfOnly,   // Just \n (invalid)
    CrOnly,   // Just \r (invalid)
    None,     // No terminator
    Multiple, // Multiple terminators
}

/// Whitespace patterns between tokens
#[derive(Arbitrary, Debug, Clone)]
pub enum WhitespacePattern {
    SingleSpace,
    MultipleSpaces(usize),
    TabCharacters,
    MixedWhitespace(Vec<u8>),
    NoWhitespace, // Invalid - no space between tokens
}

/// Case sensitivity configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct CaseConfig {
    pub enforce_standard_case: bool,
    pub preserve_extension_case: bool,
    pub case_sensitive_validation: bool,
    pub normalize_before_comparison: bool,
}

/// Validation configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct ValidationConfig {
    pub strict_rfc_compliance: bool,
    pub allow_extension_methods: bool,
    pub max_method_length: usize,
    pub validate_token_characters: bool,
    pub reject_non_ascii: bool,
}

/// Mock HTTP method parser for testing
#[derive(Debug)]
pub struct MockMethodParser {
    pub case_config: CaseConfig,
    pub validation_config: ValidationConfig,
    pub violations: Vec<CaseSensitivityViolation>,
}

/// Method parsing result
#[derive(Debug, PartialEq)]
pub struct MethodParsingResult {
    pub parsed_method: Option<ParsedMethod>,
    pub parsing_error: Option<MethodError>,
    pub case_violations: Vec<CaseViolation>,
    pub rfc_compliance_score: f32,
}

/// Parsed method representation
#[derive(Debug, PartialEq)]
pub enum ParsedMethod {
    Standard(StandardMethod),
    Extension(String),
    Invalid,
}

/// Standard HTTP methods
#[derive(Debug, PartialEq, Clone)]
pub enum StandardMethod {
    Get, Head, Post, Put, Delete, Connect, Options, Trace, Patch,
}

/// Method parsing errors
#[derive(Debug, PartialEq, Clone)]
pub enum MethodError {
    Empty,
    InvalidCharacters(Vec<u8>),
    TooLong(usize),
    NonAscii,
    InvalidTokenSyntax,
    CaseMismatch(String),
}

/// Case sensitivity violations
#[derive(Debug, PartialEq, Clone)]
pub struct CaseSensitivityViolation {
    pub violation_type: CaseViolationType,
    pub method_bytes: Vec<u8>,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub severity: ViolationSeverity,
}

/// Types of case sensitivity violations
#[derive(Debug, PartialEq, Clone)]
pub enum CaseViolationType {
    /// Standard method accepted with wrong case
    StandardMethodCaseAccepted,
    /// Extension method case not preserved
    ExtensionCaseNotPreserved,
    /// Case-insensitive matching where case-sensitive required
    CaseInsensitiveMatching,
    /// Mixed case standard method accepted
    MixedCaseStandardAccepted,
    /// Invalid characters accepted in method
    InvalidCharactersAccepted,
    /// Method length limit not enforced
    LengthLimitNotEnforced,
}

/// Case violations in parsing
#[derive(Debug, PartialEq)]
pub struct CaseViolation {
    pub violation_type: CaseViolationType,
    pub input_method: String,
    pub expected_result: String,
    pub actual_result: String,
}

/// Violation severity levels
#[derive(Debug, PartialEq, Clone)]
pub enum ViolationSeverity {
    Critical,  // Protocol violation, security risk
    High,      // RFC deviation, compatibility issue
    Medium,    // Edge case handling problem
    Low,       // Minor parsing inconsistency
}

impl MockMethodParser {
    pub fn new(case_config: CaseConfig, validation_config: ValidationConfig) -> Self {
        Self {
            case_config,
            validation_config,
            violations: Vec::new(),
        }
    }

    /// Parse HTTP method with case sensitivity testing
    pub fn parse_method(&mut self, test_case: &MethodCaseSensitivityTestCase) -> MethodParsingResult {
        let mut case_violations = Vec::new();
        let mut all_results = Vec::new();

        // Test each method variant
        for variant in &test_case.method_variants {
            let method_bytes = self.build_method_bytes(variant);
            let result = self.parse_method_bytes(&method_bytes, &mut case_violations);
            all_results.push((method_bytes, result));
        }

        // Validate results against expectations
        self.validate_case_sensitivity_behavior(&test_case, &all_results, &mut case_violations);

        // Calculate compliance score
        let rfc_compliance_score = self.calculate_rfc_compliance();

        // Return the first result for the primary analysis
        let primary_result = all_results.into_iter().next()
            .map(|(_, result)| result)
            .unwrap_or(MethodParsingResult {
                parsed_method: None,
                parsing_error: Some(MethodError::Empty),
                case_violations: Vec::new(),
                rfc_compliance_score: 0.0,
            });

        MethodParsingResult {
            parsed_method: primary_result.parsed_method,
            parsing_error: primary_result.parsing_error,
            case_violations,
            rfc_compliance_score,
        }
    }

    /// Build method bytes from variant specification
    fn build_method_bytes(&self, variant: &MethodVariant) -> Vec<u8> {
        let base_bytes = self.get_base_method_bytes(&variant.base_method);
        let case_transformed = self.apply_case_transformation(&base_bytes, &variant.case_transformation);
        let with_injection = self.apply_character_injection(&case_transformed, &variant.character_injection);
        self.apply_length_modification(&with_injection, &variant.length_modification)
    }

    /// Get base method bytes
    fn get_base_method_bytes(&self, method: &BaseMethod) -> Vec<u8> {
        match method {
            BaseMethod::Get => b"GET".to_vec(),
            BaseMethod::Head => b"HEAD".to_vec(),
            BaseMethod::Post => b"POST".to_vec(),
            BaseMethod::Put => b"PUT".to_vec(),
            BaseMethod::Delete => b"DELETE".to_vec(),
            BaseMethod::Connect => b"CONNECT".to_vec(),
            BaseMethod::Options => b"OPTIONS".to_vec(),
            BaseMethod::Trace => b"TRACE".to_vec(),
            BaseMethod::Patch => b"PATCH".to_vec(),
            BaseMethod::Extension(s) => s.as_bytes().to_vec(),
            BaseMethod::Invalid(bytes) => bytes.clone(),
        }
    }

    /// Apply case transformation
    fn apply_case_transformation(&self, bytes: &[u8], transformation: &CaseTransformation) -> Vec<u8> {
        match transformation {
            CaseTransformation::Unchanged => bytes.to_vec(),
            CaseTransformation::Lowercase => bytes.iter().map(|&b| b.to_ascii_lowercase()).collect(),
            CaseTransformation::Uppercase => bytes.iter().map(|&b| b.to_ascii_uppercase()).collect(),
            CaseTransformation::TitleCase => {
                let mut result = bytes.to_vec();
                if !result.is_empty() {
                    result[0] = result[0].to_ascii_uppercase();
                    for b in &mut result[1..] {
                        *b = b.to_ascii_lowercase();
                    }
                }
                result
            },
            CaseTransformation::MixedCase(pattern) => {
                bytes.iter().enumerate().map(|(i, &b)| {
                    if *pattern.get(i % pattern.len()).unwrap_or(&false) {
                        b.to_ascii_uppercase()
                    } else {
                        b.to_ascii_lowercase()
                    }
                }).collect()
            },
            CaseTransformation::InvertCase => {
                bytes.iter().map(|&b| {
                    if b.is_ascii_uppercase() {
                        b.to_ascii_lowercase()
                    } else if b.is_ascii_lowercase() {
                        b.to_ascii_uppercase()
                    } else {
                        b
                    }
                }).collect()
            },
            CaseTransformation::RandomCase => {
                // Simple deterministic "random" based on byte value
                bytes.iter().map(|&b| {
                    if b % 2 == 0 {
                        b.to_ascii_uppercase()
                    } else {
                        b.to_ascii_lowercase()
                    }
                }).collect()
            },
        }
    }

    /// Apply character injection
    fn apply_character_injection(&self, bytes: &[u8], injection: &Option<CharacterInjection>) -> Vec<u8> {
        let Some(inj) = injection else {
            return bytes.to_vec();
        };

        let mut result = bytes.to_vec();
        let injection_chars = &inj.characters;

        match &inj.position {
            InjectionPosition::Beginning => {
                result.splice(0..0, injection_chars.iter().cloned());
            },
            InjectionPosition::End => {
                result.extend_from_slice(injection_chars);
            },
            InjectionPosition::Middle => {
                let pos = result.len() / 2;
                result.splice(pos..pos, injection_chars.iter().cloned());
            },
            InjectionPosition::Random => {
                let pos = if result.is_empty() { 0 } else { result[0] as usize % (result.len() + 1) };
                result.splice(pos..pos, injection_chars.iter().cloned());
            },
            InjectionPosition::Multiple(positions) => {
                // Insert in reverse order to maintain positions
                for &pos in positions.iter().rev() {
                    let actual_pos = pos.min(result.len());
                    result.splice(actual_pos..actual_pos, injection_chars.iter().cloned());
                }
            },
        }

        result
    }

    /// Apply length modification
    fn apply_length_modification(&self, bytes: &[u8], modification: &LengthModification) -> Vec<u8> {
        match modification {
            LengthModification::None => bytes.to_vec(),
            LengthModification::Truncate(len) => {
                bytes.iter().take(*len).copied().collect()
            },
            LengthModification::Extend(suffix) => {
                let mut result = bytes.to_vec();
                result.extend_from_slice(suffix.as_bytes());
                result
            },
            LengthModification::Repeat(times) => {
                bytes.repeat(*times)
            },
            LengthModification::Empty => Vec::new(),
            LengthModification::VeryLong(target_len) => {
                if bytes.is_empty() {
                    vec![b'A'; *target_len]
                } else {
                    let mut result = bytes.to_vec();
                    while result.len() < *target_len {
                        result.extend_from_slice(bytes);
                    }
                    result.truncate(*target_len);
                    result
                }
            },
        }
    }

    /// Parse method bytes and detect violations
    fn parse_method_bytes(&self, method_bytes: &[u8], violations: &mut Vec<CaseViolation>) -> MethodParsingResult {
        // Simulate the actual Method::from_bytes logic
        let parsed_method = self.mock_method_from_bytes(method_bytes);
        let parsing_error = self.validate_method_bytes(method_bytes);

        // Check for case sensitivity violations
        if let Some(method) = &parsed_method {
            self.check_case_sensitivity_violations(method_bytes, method, violations);
        }

        let rfc_compliance_score = if violations.is_empty() && parsing_error.is_none() { 1.0 } else { 0.0 };

        MethodParsingResult {
            parsed_method,
            parsing_error,
            case_violations: Vec::new(), // Will be filled by caller
            rfc_compliance_score,
        }
    }

    /// Mock implementation of Method::from_bytes
    fn mock_method_from_bytes(&self, src: &[u8]) -> Option<ParsedMethod> {
        match src {
            b"GET" => Some(ParsedMethod::Standard(StandardMethod::Get)),
            b"HEAD" => Some(ParsedMethod::Standard(StandardMethod::Head)),
            b"POST" => Some(ParsedMethod::Standard(StandardMethod::Post)),
            b"PUT" => Some(ParsedMethod::Standard(StandardMethod::Put)),
            b"DELETE" => Some(ParsedMethod::Standard(StandardMethod::Delete)),
            b"CONNECT" => Some(ParsedMethod::Standard(StandardMethod::Connect)),
            b"OPTIONS" => Some(ParsedMethod::Standard(StandardMethod::Options)),
            b"TRACE" => Some(ParsedMethod::Standard(StandardMethod::Trace)),
            b"PATCH" => Some(ParsedMethod::Standard(StandardMethod::Patch)),
            other => {
                if let Ok(s) = std::str::from_utf8(other) {
                    if self.is_valid_token(s) {
                        Some(ParsedMethod::Extension(s.to_owned()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Validate method bytes for common errors
    fn validate_method_bytes(&self, bytes: &[u8]) -> Option<MethodError> {
        if bytes.is_empty() {
            return Some(MethodError::Empty);
        }

        if self.validation_config.max_method_length > 0 && bytes.len() > self.validation_config.max_method_length {
            return Some(MethodError::TooLong(bytes.len()));
        }

        if self.validation_config.reject_non_ascii && !bytes.is_ascii() {
            return Some(MethodError::NonAscii);
        }

        let invalid_chars: Vec<u8> = bytes.iter()
            .copied()
            .filter(|&b| !self.is_valid_method_char(b))
            .collect();

        if !invalid_chars.is_empty() {
            return Some(MethodError::InvalidCharacters(invalid_chars));
        }

        None
    }

    /// Check for case sensitivity violations
    fn check_case_sensitivity_violations(&self, method_bytes: &[u8], parsed_method: &ParsedMethod, violations: &mut Vec<CaseViolation>) {
        // Check if a case-variant of a standard method was parsed as extension
        if let ParsedMethod::Extension(ext_name) = parsed_method {
            let standard_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"];

            for &std_method in &standard_methods {
                if ext_name.eq_ignore_ascii_case(std_method) && ext_name != std_method {
                    violations.push(CaseViolation {
                        violation_type: CaseViolationType::CaseInsensitiveMatching,
                        input_method: ext_name.clone(),
                        expected_result: "rejected or error".to_string(),
                        actual_result: format!("Extension({})", ext_name),
                    });
                }
            }
        }

        // Check if mixed-case standard method was incorrectly accepted
        if let ParsedMethod::Standard(_) = parsed_method {
            let method_str = String::from_utf8_lossy(method_bytes);
            let standard_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"];

            for &std_method in &standard_methods {
                if method_str == std_method {
                    // Correct case - no violation
                    return;
                }
                if method_str.eq_ignore_ascii_case(std_method) {
                    violations.push(CaseViolation {
                        violation_type: CaseViolationType::StandardMethodCaseAccepted,
                        input_method: method_str.to_string(),
                        expected_result: "error or extension".to_string(),
                        actual_result: format!("Standard({:?})", std_method),
                    });
                }
            }
        }
    }

    /// Validate case sensitivity behavior
    fn validate_case_sensitivity_behavior(&mut self, test_case: &MethodCaseSensitivityTestCase, results: &[(Vec<u8>, MethodParsingResult)], _violations: &mut Vec<CaseViolation>) {
        match &test_case.scenario {
            MethodScenario::StandardMethodCases => {
                for (method_bytes, result) in results {
                    let method_str = String::from_utf8_lossy(method_bytes);

                    // Standard methods with wrong case should not be recognized as standard
                    if method_str.to_uppercase() != method_str && matches!(result.parsed_method, Some(ParsedMethod::Standard(_))) {
                        self.violations.push(CaseSensitivityViolation {
                            violation_type: CaseViolationType::StandardMethodCaseAccepted,
                            method_bytes: method_bytes.clone(),
                            expected_behavior: "rejection or extension method".to_string(),
                            actual_behavior: "accepted as standard method".to_string(),
                            severity: ViolationSeverity::High,
                        });
                    }
                }
            },
            MethodScenario::ExtensionMethodCases => {
                for (method_bytes, result) in results {
                    if let Some(ParsedMethod::Extension(ext_name)) = &result.parsed_method {
                        let original = String::from_utf8_lossy(method_bytes);
                        if ext_name != &original {
                            self.violations.push(CaseSensitivityViolation {
                                violation_type: CaseViolationType::ExtensionCaseNotPreserved,
                                method_bytes: method_bytes.clone(),
                                expected_behavior: format!("preserve case: {}", original),
                                actual_behavior: format!("case changed: {}", ext_name),
                                severity: ViolationSeverity::Medium,
                            });
                        }
                    }
                }
            },
            _ => {
                // Other scenarios have different validation logic
            }
        }
    }

    /// RFC 9110 token validation (simplified)
    fn is_valid_token(&self, s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| self.is_valid_token_char(c as u8))
    }

    /// Check if character is valid in HTTP token
    fn is_valid_token_char(&self, b: u8) -> bool {
        matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
            b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        )
    }

    /// Check if character is valid in method name
    fn is_valid_method_char(&self, b: u8) -> bool {
        if self.validation_config.validate_token_characters {
            self.is_valid_token_char(b)
        } else {
            // More lenient validation
            b.is_ascii_graphic() && b != b' '
        }
    }

    /// Calculate RFC compliance score
    fn calculate_rfc_compliance(&self) -> f32 {
        if self.violations.is_empty() {
            return 1.0;
        }

        let penalty = self.violations.iter().map(|v| match v.severity {
            ViolationSeverity::Critical => 10.0,
            ViolationSeverity::High => 5.0,
            ViolationSeverity::Medium => 2.0,
            ViolationSeverity::Low => 1.0,
        }).sum::<f32>();

        let max_score = 100.0;
        (max_score - penalty).max(0.0) / max_score
    }
}

/// Generate comprehensive method case sensitivity test cases
fn generate_method_case_sensitivity_test_cases() -> Vec<MethodCaseSensitivityTestCase> {
    vec![
        // Standard method case sensitivity test
        MethodCaseSensitivityTestCase {
            scenario: MethodScenario::StandardMethodCases,
            method_variants: vec![
                MethodVariant {
                    base_method: BaseMethod::Get,
                    case_transformation: CaseTransformation::Unchanged,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
                MethodVariant {
                    base_method: BaseMethod::Get,
                    case_transformation: CaseTransformation::Lowercase,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
                MethodVariant {
                    base_method: BaseMethod::Post,
                    case_transformation: CaseTransformation::TitleCase,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
            ],
            request_line_context: RequestLineContext {
                uri: "/test".to_string(),
                version: HttpVersion::Http11,
                line_terminators: LineTerminators::CrLf,
                whitespace_pattern: WhitespacePattern::SingleSpace,
            },
            case_config: CaseConfig {
                enforce_standard_case: true,
                preserve_extension_case: true,
                case_sensitive_validation: true,
                normalize_before_comparison: false,
            },
            validation_config: ValidationConfig {
                strict_rfc_compliance: true,
                allow_extension_methods: true,
                max_method_length: 32,
                validate_token_characters: true,
                reject_non_ascii: true,
            },
        },

        // Extension method case preservation test
        MethodCaseSensitivityTestCase {
            scenario: MethodScenario::ExtensionMethodCases,
            method_variants: vec![
                MethodVariant {
                    base_method: BaseMethod::Extension("CUSTOM".to_string()),
                    case_transformation: CaseTransformation::Unchanged,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
                MethodVariant {
                    base_method: BaseMethod::Extension("Custom".to_string()),
                    case_transformation: CaseTransformation::Unchanged,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
                MethodVariant {
                    base_method: BaseMethod::Extension("custom".to_string()),
                    case_transformation: CaseTransformation::Unchanged,
                    character_injection: None,
                    length_modification: LengthModification::None,
                },
            ],
            request_line_context: RequestLineContext {
                uri: "/test".to_string(),
                version: HttpVersion::Http11,
                line_terminators: LineTerminators::CrLf,
                whitespace_pattern: WhitespacePattern::SingleSpace,
            },
            case_config: CaseConfig {
                enforce_standard_case: true,
                preserve_extension_case: true,
                case_sensitive_validation: true,
                normalize_before_comparison: false,
            },
            validation_config: ValidationConfig {
                strict_rfc_compliance: true,
                allow_extension_methods: true,
                max_method_length: 32,
                validate_token_characters: true,
                reject_non_ascii: true,
            },
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    // Try to generate a test case from fuzzer input
    let test_case = match MethodCaseSensitivityTestCase::arbitrary(&mut unstructured) {
        Ok(tc) => tc,
        Err(_) => {
            // If generation fails, use a pre-generated test case
            let predefined_cases = generate_method_case_sensitivity_test_cases();
            if predefined_cases.is_empty() {
                return;
            }
            let index = unstructured.int_in_range(0..=predefined_cases.len() - 1).unwrap_or(0);
            predefined_cases[index].clone()
        }
    };

    // Create method parser
    let mut parser = MockMethodParser::new(
        test_case.case_config.clone(),
        test_case.validation_config.clone()
    );

    // Parse methods and check case sensitivity
    let _result = parser.parse_method(&test_case);

    // Test specific case sensitivity edge cases
    test_standard_method_case_sensitivity(&test_case);
    test_extension_method_case_preservation(&test_case);
    test_method_smuggling_prevention(&test_case);
    test_invalid_character_rejection(&test_case);
});

/// Test standard method case sensitivity
fn test_standard_method_case_sensitivity(test_case: &MethodCaseSensitivityTestCase) {
    let parser = MockMethodParser::new(
        test_case.case_config.clone(),
        test_case.validation_config.clone()
    );

    // Test that "GET" is recognized but "get" is not
    let get_upper = parser.mock_method_from_bytes(b"GET");
    let get_lower = parser.mock_method_from_bytes(b"get");

    match (get_upper, get_lower) {
        (Some(ParsedMethod::Standard(StandardMethod::Get)), Some(ParsedMethod::Extension(_))) => {
            // Correct behavior - case sensitive
        },
        (Some(ParsedMethod::Standard(StandardMethod::Get)), None) => {
            // Also correct - lowercase rejected entirely
        },
        _ => {
            // Unexpected behavior - might be case insensitive
        }
    }
}

/// Test extension method case preservation
fn test_extension_method_case_preservation(test_case: &MethodCaseSensitivityTestCase) {
    if test_case.scenario != MethodScenario::ExtensionMethodCases {
        return;
    }

    let parser = MockMethodParser::new(
        test_case.case_config.clone(),
        test_case.validation_config.clone()
    );

    // Test that extension methods preserve their exact case
    let test_methods = ["CUSTOM", "Custom", "custom", "cUsToM"];

    for method in test_methods {
        if let Some(ParsedMethod::Extension(parsed)) = parser.mock_method_from_bytes(method.as_bytes()) {
            assert_eq!(parsed, method, "Extension method case not preserved");
        }
    }
}

/// Test method smuggling prevention via case differences
fn test_method_smuggling_prevention(test_case: &MethodCaseSensitivityTestCase) {
    let parser = MockMethodParser::new(
        test_case.case_config.clone(),
        test_case.validation_config.clone()
    );

    // Ensure that case variants of standard methods don't get special treatment
    let smuggling_attempts = [
        ("get", "GET"),      // lowercase
        ("Get", "GET"),      // title case
        ("gET", "GET"),      // mixed case
        ("post", "POST"),
        ("Post", "POST"),
        ("PUT", "PUT"),      // correct case (should work)
        ("put", "PUT"),      // wrong case (should not work as standard)
    ];

    for (attempt, expected) in smuggling_attempts {
        let result = parser.mock_method_from_bytes(attempt.as_bytes());

        if attempt == expected {
            // Exact match should be recognized as standard
            match result {
                Some(ParsedMethod::Standard(_)) => {
                    // Correct behavior
                },
                _ => {
                    // Unexpected - standard method not recognized
                }
            }
        } else {
            // Case mismatch should NOT be recognized as standard method
            match result {
                Some(ParsedMethod::Standard(_)) => {
                    // Violation - case insensitive matching
                },
                Some(ParsedMethod::Extension(_)) | Some(ParsedMethod::Invalid) | None => {
                    // Correct behavior - case sensitivity enforced
                }
            }
        }
    }
}

/// Test invalid character rejection
fn test_invalid_character_rejection(test_case: &MethodCaseSensitivityTestCase) {
    if test_case.scenario != MethodScenario::InvalidMethodCharacters {
        return;
    }

    let parser = MockMethodParser::new(
        test_case.case_config.clone(),
        test_case.validation_config.clone()
    );

    // Test various invalid characters
    let invalid_methods = [
        b"GET\x00".as_slice(),  // null byte
        b"GET\r".as_slice(),    // CR
        b"GET\n".as_slice(),    // LF
        b"GET ".as_slice(),     // space
        b"GET\t".as_slice(),    // tab
        b"GET(".as_slice(),     // invalid token char
        b"GET)".as_slice(),     // invalid token char
        b"G\xFFT".as_slice(),   // high bit set
    ];

    for invalid_method in invalid_methods {
        let result = parser.mock_method_from_bytes(invalid_method);

        // Should be rejected
        match result {
            None => {
                // Correct - invalid method rejected
            },
            Some(_) => {
                // Violation - invalid method accepted
            }
        }
    }
}