#![no_main]
#![allow(dead_code)]
#![allow(clippy::enum_variant_names)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :method pseudo-header case sensitivity test input
#[derive(Arbitrary, Debug)]
struct H2MethodCaseInput {
    /// Method case variation strategy
    method_strategy: MethodCaseStrategy,
    /// Additional pseudo-headers to include
    additional_pseudo_headers: Vec<PseudoHeader>,
    /// Regular headers to include
    regular_headers: Vec<RegularHeader>,
    /// Test scenario configuration
    test_scenario: TestScenario,
}

#[derive(Arbitrary, Debug)]
enum MethodCaseStrategy {
    /// Standard HTTP methods with case variations
    StandardMethod {
        method: StandardMethod,
        case_pattern: CasePattern,
    },
    /// Custom method names with case variations
    CustomMethod {
        base_name: String,
        case_pattern: CasePattern,
    },
    /// Multiple methods in same request (invalid but test parsing)
    MultipleMethod {
        methods: Vec<(StandardMethod, CasePattern)>,
    },
    /// Edge case method values
    EdgeCaseMethod {
        edge_type: MethodEdgeType,
        case_pattern: CasePattern,
    },
    /// Case variation within single method
    MixedCaseMethod {
        method: StandardMethod,
        mixed_pattern: MixedCasePattern,
    },
}

#[derive(Arbitrary, Debug)]
enum StandardMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
}

#[derive(Arbitrary, Debug)]
enum CasePattern {
    /// All lowercase
    Lowercase,
    /// All uppercase
    Uppercase,
    /// First letter uppercase, rest lowercase
    Titlecase,
    /// Random mixed case
    RandomMixed,
    /// Alternating case
    Alternating,
}

#[derive(Arbitrary, Debug)]
enum MethodEdgeType {
    /// Very short method
    Short(String),
    /// Very long method
    Long(u8), // Length multiplier
    /// Method with special characters
    WithSpecialChars,
    /// Method with numbers
    WithNumbers,
    /// Empty method (invalid)
    Empty,
    /// Whitespace in method (invalid)
    WithWhitespace,
}

#[derive(Arbitrary, Debug)]
enum MixedCasePattern {
    /// Different case per character
    PerCharacter(Vec<bool>), // true = uppercase, false = lowercase
    /// Case changes at specific positions
    AtPositions(Vec<usize>),
    /// Vowels vs consonants different case
    VowelConsonant,
    /// First/last different from middle
    FirstLastMiddle,
}

#[derive(Arbitrary, Debug)]
struct PseudoHeader {
    /// Pseudo-header type
    header_type: PseudoHeaderType,
    /// Value
    value: String,
    /// Whether to test case sensitivity for the name
    test_name_case: bool,
}

#[derive(Arbitrary, Debug)]
enum PseudoHeaderType {
    Authority,
    Path,
    Scheme,
    Status, // Only valid in responses
}

#[derive(Arbitrary, Debug)]
struct RegularHeader {
    /// Header name
    name: String,
    /// Header value
    value: String,
    /// Case pattern for name (should be forced to lowercase)
    name_case: CasePattern,
    /// Whether value case should be preserved
    preserve_value_case: bool,
}

#[derive(Arbitrary, Debug)]
struct TestScenario {
    /// Request vs response context
    context: RequestContext,
    /// Validation strictness
    validation_mode: ValidationMode,
    /// Case sensitivity enforcement
    case_enforcement: CaseEnforcement,
    /// Error handling approach
    error_handling: ErrorHandling,
}

#[derive(Arbitrary, Clone, Debug)]
enum RequestContext {
    /// HTTP/2 request
    Request,
    /// HTTP/2 response (methods not allowed)
    Response,
    /// CONNECT method context
    ConnectMethod,
    /// OPTIONS * context
    OptionsAsterisk,
}

#[derive(Arbitrary, Clone, Debug)]
enum ValidationMode {
    /// Strict RFC compliance
    StrictRFC,
    /// Lenient case handling
    Lenient,
    /// Security-focused validation
    Security,
}

#[derive(Arbitrary, Clone, Debug)]
enum CaseEnforcement {
    /// Enforce case sensitivity for method values
    Strict,
    /// Case insensitive method comparison
    Insensitive,
    /// Preserve original case but allow comparison
    PreserveOriginal,
}

#[derive(Arbitrary, Clone, Debug)]
enum ErrorHandling {
    /// Fail on case violations
    FailOnViolation,
    /// Normalize and continue
    NormalizeAndContinue,
    /// Preserve and validate later
    PreserveAndValidate,
}

/// Mock HTTP/2 header parser with case sensitivity handling
struct MockH2HeaderParser {
    validation_mode: ValidationMode,
    case_enforcement: CaseEnforcement,
    parsing_context: ParsingContext,
    case_preservation_state: CasePreservationState,
}

#[derive(Debug)]
struct ParsingContext {
    request_context: RequestContext,
    headers_processed: u32,
    pseudo_headers_found: Vec<String>,
    case_violations_detected: u32,
}

#[derive(Debug)]
struct CasePreservationState {
    original_method_case: Option<String>,
    normalized_method: Option<String>,
    header_name_transformations: Vec<(String, String)>, // (original, normalized)
    value_case_preserved: bool,
}

#[derive(Debug, Clone)]
struct ParsedHeaders {
    method: Option<MethodValue>,
    pseudo_headers: Vec<(String, String)>,
    regular_headers: Vec<(String, String)>,
    case_analysis: CaseAnalysis,
    validation_result: HeaderValidationResult,
}

#[derive(Debug, Clone)]
struct MethodValue {
    original_case: String,
    normalized: String,
    is_standard: bool,
    case_preserved: bool,
}

#[derive(Debug, Clone)]
struct CaseAnalysis {
    method_case_changes: Vec<CaseChange>,
    header_name_lowercased: Vec<String>,
    value_case_preserved: bool,
    case_violations: Vec<CaseViolation>,
}

#[derive(Debug, Clone)]
struct CaseChange {
    original: String,
    transformed: String,
    change_type: CaseChangeType,
}

#[derive(Debug, Clone, PartialEq)]
enum CaseChangeType {
    MethodValuePreserved,
    HeaderNameLowercased,
    ValueCasePreserved,
    CaseViolation,
}

#[derive(Debug, Clone)]
struct CaseViolation {
    violation_type: ViolationType,
    header_name: String,
    expected: String,
    actual: String,
}

#[derive(Debug, Clone, PartialEq)]
enum ViolationType {
    PseudoHeaderNameNotLowercase,
    RegularHeaderNameNotLowercase,
    MethodValueChanged,
    ValueCaseNotPreserved,
}

#[derive(Debug, Clone, PartialEq)]
enum HeaderValidationResult {
    Valid,
    CaseViolation(ViolationType),
    InvalidMethod(String),
    MissingRequiredPseudo,
    InvalidPseudoOrder,
    ParseError(String),
}

#[derive(Debug, PartialEq)]
enum HeaderParsingError {
    /// Method value case was not preserved
    MethodCaseNotPreserved { original: String, modified: String },
    /// Header name was not lowercased
    HeaderNameNotLowercased { header: String, value: String },
    /// Invalid method format
    InvalidMethodFormat(String),
    /// Pseudo-headers after regular headers
    PseudoHeaderOrder,
    /// Multiple :method pseudo-headers
    DuplicateMethod(String),
    /// Method value contains invalid characters
    InvalidMethodCharacters {
        method: String,
        invalid_chars: String,
    },
    /// Empty method value
    EmptyMethod,
    /// Method case handling inconsistency
    InconsistentCaseHandling(String),
}

// Standard HTTP methods (case-sensitive per RFC 9110)
const STANDARD_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

// Valid method characters per RFC 9110 (tchar)
const VALID_METHOD_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&-+.^_`|~";

impl MockH2HeaderParser {
    fn new(
        validation_mode: ValidationMode,
        case_enforcement: CaseEnforcement,
        context: RequestContext,
    ) -> Self {
        Self {
            validation_mode,
            case_enforcement,
            parsing_context: ParsingContext {
                request_context: context,
                headers_processed: 0,
                pseudo_headers_found: Vec::new(),
                case_violations_detected: 0,
            },
            case_preservation_state: CasePreservationState {
                original_method_case: None,
                normalized_method: None,
                header_name_transformations: Vec::new(),
                value_case_preserved: true,
            },
        }
    }

    fn parse_headers(
        &mut self,
        headers: &[(&str, &str)],
    ) -> Result<ParsedHeaders, HeaderParsingError> {
        let mut method_value = None;
        let mut pseudo_headers = Vec::new();
        let mut regular_headers = Vec::new();
        let mut case_analysis = CaseAnalysis {
            method_case_changes: Vec::new(),
            header_name_lowercased: Vec::new(),
            value_case_preserved: true,
            case_violations: Vec::new(),
        };

        let mut pseudo_header_phase = true;

        for (name, value) in headers {
            self.parsing_context.headers_processed += 1;

            // Check if this is a pseudo-header
            if name.starts_with(':') {
                if !pseudo_header_phase {
                    return Err(HeaderParsingError::PseudoHeaderOrder);
                }

                // Pseudo-header names must be lowercase (RFC 7540 §8.1.2.1)
                let normalized_name = name.to_lowercase();
                if *name != normalized_name {
                    case_analysis.case_violations.push(CaseViolation {
                        violation_type: ViolationType::PseudoHeaderNameNotLowercase,
                        header_name: name.to_string(),
                        expected: normalized_name.clone(),
                        actual: name.to_string(),
                    });
                }

                match normalized_name.as_str() {
                    ":method" => {
                        if method_value.is_some() {
                            return Err(HeaderParsingError::DuplicateMethod(value.to_string()));
                        }

                        // Parse and validate method value
                        let parsed_method = self.parse_method_value(value)?;
                        method_value = Some(parsed_method.clone());

                        // Record case preservation
                        self.case_preservation_state.original_method_case = Some(value.to_string());
                        self.case_preservation_state.normalized_method =
                            Some(parsed_method.normalized.clone());

                        // Method values should preserve case (RFC 7540 §8.1.2.1)
                        if parsed_method.original_case != *value {
                            case_analysis.case_violations.push(CaseViolation {
                                violation_type: ViolationType::MethodValueChanged,
                                header_name: ":method".to_string(),
                                expected: value.to_string(),
                                actual: parsed_method.original_case.clone(),
                            });
                        }

                        case_analysis.method_case_changes.push(CaseChange {
                            original: value.to_string(),
                            transformed: parsed_method.original_case.clone(),
                            change_type: CaseChangeType::MethodValuePreserved,
                        });
                    }
                    _ => {
                        // Other pseudo-headers
                        pseudo_headers.push((normalized_name.clone(), value.to_string()));
                    }
                }

                self.parsing_context
                    .pseudo_headers_found
                    .push(normalized_name);
            } else {
                // Regular header
                pseudo_header_phase = false;

                // Regular header names must be lowercase in HTTP/2 (RFC 7540 §8.1.2.1)
                let normalized_name = name.to_lowercase();
                if *name != normalized_name {
                    case_analysis.case_violations.push(CaseViolation {
                        violation_type: ViolationType::RegularHeaderNameNotLowercase,
                        header_name: name.to_string(),
                        expected: normalized_name.clone(),
                        actual: name.to_string(),
                    });
                }

                case_analysis
                    .header_name_lowercased
                    .push(normalized_name.clone());
                self.case_preservation_state
                    .header_name_transformations
                    .push((name.to_string(), normalized_name.clone()));

                // Header values should preserve case
                regular_headers.push((normalized_name.clone(), value.to_string()));

                case_analysis.method_case_changes.push(CaseChange {
                    original: name.to_string(),
                    transformed: normalized_name,
                    change_type: CaseChangeType::HeaderNameLowercased,
                });
            }
        }

        // Validate method presence for requests
        if matches!(
            self.parsing_context.request_context,
            RequestContext::Request
        ) && method_value.is_none()
        {
            return Err(HeaderParsingError::InvalidMethodFormat(
                "Missing :method pseudo-header".to_string(),
            ));
        }

        // Determine validation result
        let validation_result = if !case_analysis.case_violations.is_empty() {
            let first_violation = &case_analysis.case_violations[0];
            HeaderValidationResult::CaseViolation(first_violation.violation_type.clone())
        } else {
            HeaderValidationResult::Valid
        };

        Ok(ParsedHeaders {
            method: method_value,
            pseudo_headers,
            regular_headers,
            case_analysis,
            validation_result,
        })
    }

    fn parse_method_value(&self, method: &str) -> Result<MethodValue, HeaderParsingError> {
        // Validate method is not empty
        if method.is_empty() {
            return Err(HeaderParsingError::EmptyMethod);
        }

        // Validate method characters (RFC 9110 tchar)
        let invalid_chars: String = method
            .chars()
            .filter(|&c| !VALID_METHOD_CHARS.contains(c))
            .collect();

        if !invalid_chars.is_empty() {
            return Err(HeaderParsingError::InvalidMethodCharacters {
                method: method.to_string(),
                invalid_chars,
            });
        }

        // Check if it's a standard method
        let normalized_uppercase = method.to_uppercase();
        let is_standard = STANDARD_METHODS.contains(&normalized_uppercase.as_str());

        // Determine if case was preserved properly
        let case_preserved = match self.case_enforcement {
            CaseEnforcement::Strict => {
                // For standard methods, case should match exactly
                if is_standard {
                    STANDARD_METHODS.contains(&method)
                } else {
                    true // Custom methods can have any case
                }
            }
            CaseEnforcement::Insensitive => true, // Case doesn't matter
            CaseEnforcement::PreserveOriginal => true, // Always preserve original
        };

        Ok(MethodValue {
            original_case: method.to_string(),
            normalized: normalized_uppercase,
            is_standard,
            case_preserved,
        })
    }

    fn generate_method_with_case(method: &StandardMethod, pattern: &CasePattern) -> String {
        let base_method = match method {
            StandardMethod::Get => "GET",
            StandardMethod::Post => "POST",
            StandardMethod::Put => "PUT",
            StandardMethod::Delete => "DELETE",
            StandardMethod::Head => "HEAD",
            StandardMethod::Options => "OPTIONS",
            StandardMethod::Patch => "PATCH",
            StandardMethod::Connect => "CONNECT",
            StandardMethod::Trace => "TRACE",
        };

        Self::apply_case_pattern(base_method, pattern)
    }

    fn apply_case_pattern(text: &str, pattern: &CasePattern) -> String {
        match pattern {
            CasePattern::Lowercase => text.to_lowercase(),
            CasePattern::Uppercase => text.to_uppercase(),
            CasePattern::Titlecase => {
                let mut result = String::new();
                let mut first = true;
                for c in text.chars() {
                    if first {
                        result.push(c.to_uppercase().next().unwrap_or(c));
                        first = false;
                    } else {
                        result.push(c.to_lowercase().next().unwrap_or(c));
                    }
                }
                result
            }
            CasePattern::RandomMixed => {
                // Deterministic "random" based on character position
                text.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 3 == 0 {
                            c.to_uppercase().next().unwrap_or(c)
                        } else {
                            c.to_lowercase().next().unwrap_or(c)
                        }
                    })
                    .collect()
            }
            CasePattern::Alternating => text
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                })
                .collect(),
        }
    }

    fn apply_mixed_case_pattern(text: &str, pattern: &MixedCasePattern) -> String {
        match pattern {
            MixedCasePattern::PerCharacter(case_flags) => text
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    let uppercase = case_flags.get(i).unwrap_or(&false);
                    if *uppercase {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                })
                .collect(),
            MixedCasePattern::AtPositions(positions) => text
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if positions.contains(&i) {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                })
                .collect(),
            MixedCasePattern::VowelConsonant => text
                .chars()
                .map(|c| {
                    if "aeiouAEIOU".contains(c) {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                })
                .collect(),
            MixedCasePattern::FirstLastMiddle => {
                let chars: Vec<char> = text.chars().collect();
                if chars.len() <= 2 {
                    text.to_uppercase()
                } else {
                    let mut result = String::new();
                    for (i, &c) in chars.iter().enumerate() {
                        if i == 0 || i == chars.len() - 1 {
                            result.push(c.to_uppercase().next().unwrap_or(c));
                        } else {
                            result.push(c.to_lowercase().next().unwrap_or(c));
                        }
                    }
                    result
                }
            }
        }
    }

    fn build_header_list(input: &H2MethodCaseInput) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        // Add method header based on strategy
        match &input.method_strategy {
            MethodCaseStrategy::StandardMethod {
                method,
                case_pattern,
            } => {
                let method_value = Self::generate_method_with_case(method, case_pattern);
                headers.push((":method".to_string(), method_value));
            }
            MethodCaseStrategy::CustomMethod {
                base_name,
                case_pattern,
            } => {
                let method_value = Self::apply_case_pattern(base_name, case_pattern);
                headers.push((":method".to_string(), method_value));
            }
            MethodCaseStrategy::MultipleMethod { methods } => {
                // Multiple :method headers (invalid but test parsing)
                for (method, case_pattern) in methods {
                    let method_value = Self::generate_method_with_case(method, case_pattern);
                    headers.push((":method".to_string(), method_value));
                }
            }
            MethodCaseStrategy::EdgeCaseMethod {
                edge_type,
                case_pattern,
            } => {
                let base_method = match edge_type {
                    MethodEdgeType::Short(s) => s.clone(),
                    MethodEdgeType::Long(multiplier) => "CUSTOM".repeat(*multiplier as usize),
                    MethodEdgeType::WithSpecialChars => "GET-SPECIAL".to_string(),
                    MethodEdgeType::WithNumbers => "GET2".to_string(),
                    MethodEdgeType::Empty => "".to_string(),
                    MethodEdgeType::WithWhitespace => "GET POST".to_string(),
                };
                let method_value = Self::apply_case_pattern(&base_method, case_pattern);
                headers.push((":method".to_string(), method_value));
            }
            MethodCaseStrategy::MixedCaseMethod {
                method,
                mixed_pattern,
            } => {
                let base_method = Self::generate_method_with_case(method, &CasePattern::Uppercase);
                let method_value = Self::apply_mixed_case_pattern(&base_method, mixed_pattern);
                headers.push((":method".to_string(), method_value));
            }
        }

        // Add other pseudo-headers
        for pseudo in &input.additional_pseudo_headers {
            let name = match &pseudo.header_type {
                PseudoHeaderType::Authority => ":authority",
                PseudoHeaderType::Path => ":path",
                PseudoHeaderType::Scheme => ":scheme",
                PseudoHeaderType::Status => ":status",
            };

            let header_name = if pseudo.test_name_case {
                Self::apply_case_pattern(name, &CasePattern::RandomMixed)
            } else {
                name.to_string()
            };

            headers.push((header_name, pseudo.value.clone()));
        }

        // Add regular headers
        for regular in &input.regular_headers {
            let header_name = Self::apply_case_pattern(&regular.name, &regular.name_case);
            headers.push((header_name, regular.value.clone()));
        }

        headers
    }
}

fuzz_target!(|input: H2MethodCaseInput| {
    // Skip overly complex inputs that would timeout
    if input.additional_pseudo_headers.len() > 10 || input.regular_headers.len() > 20 {
        return;
    }

    // Generate header list based on input strategy
    let header_list = MockH2HeaderParser::build_header_list(&input);

    // Skip excessively large header lists
    if header_list.len() > 50 {
        return;
    }

    let mut parser = MockH2HeaderParser::new(
        input.test_scenario.validation_mode.clone(),
        input.test_scenario.case_enforcement.clone(),
        input.test_scenario.context.clone(),
    );

    // Convert to slice of tuples for parsing
    let header_refs: Vec<(&str, &str)> = header_list
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();

    let parse_result = parser.parse_headers(&header_refs);

    // Test case sensitivity behavior based on method strategy
    match input.method_strategy {
        MethodCaseStrategy::StandardMethod {
            ref method,
            ref case_pattern,
        } => {
            let expected_method =
                MockH2HeaderParser::generate_method_with_case(method, case_pattern);

            match &parse_result {
                Ok(parsed) => {
                    if let Some(method_value) = &parsed.method {
                        // RFC 7540 §8.1.2.1: pseudo-header values preserve case
                        assert_eq!(
                            method_value.original_case, expected_method,
                            "Method value case should be preserved: expected '{}', got '{}'",
                            expected_method, method_value.original_case
                        );

                        // For standard methods, verify normalization
                        if method_value.is_standard {
                            let expected_normalized = expected_method.to_uppercase();
                            assert_eq!(
                                method_value.normalized, expected_normalized,
                                "Standard method should normalize to uppercase: expected '{}', got '{}'",
                                expected_normalized, method_value.normalized
                            );
                        }
                    } else {
                        panic!("Method should be present in parsed headers");
                    }
                }
                Err(HeaderParsingError::MethodCaseNotPreserved { original, modified }) => {
                    panic!(
                        "Method case should be preserved but was changed: '{}' → '{}'",
                        original, modified
                    );
                }
                Err(error) => {
                    // Other errors may be valid depending on input
                    match error {
                        HeaderParsingError::InvalidMethodCharacters { .. }
                        | HeaderParsingError::EmptyMethod => {
                            // Expected for edge case methods
                        }
                        _ => {
                            // Unexpected error for standard methods
                            if !matches!(
                                input.method_strategy,
                                MethodCaseStrategy::EdgeCaseMethod { .. }
                                    | MethodCaseStrategy::MultipleMethod { .. }
                            ) {
                                panic!("Unexpected error for standard method: {:?}", error);
                            }
                        }
                    }
                }
            }
        }
        MethodCaseStrategy::EdgeCaseMethod { ref edge_type, .. } => {
            // Edge case methods may be rejected
            match edge_type {
                MethodEdgeType::Empty => {
                    match &parse_result {
                        Err(HeaderParsingError::EmptyMethod) => {
                            // Expected: empty method should be rejected
                        }
                        _ => {
                            panic!("Empty method should be rejected");
                        }
                    }
                }
                MethodEdgeType::WithWhitespace => {
                    match &parse_result {
                        Err(HeaderParsingError::InvalidMethodCharacters { .. }) => {
                            // Expected: whitespace in method should be rejected
                        }
                        _ => {
                            panic!("Method with whitespace should be rejected");
                        }
                    }
                }
                _ => {
                    // Other edge cases may be accepted or rejected
                    match &parse_result {
                        Ok(parsed) => {
                            if let Some(method_value) = &parsed.method {
                                assert!(
                                    !method_value.original_case.is_empty(),
                                    "Parsed method should not be empty"
                                );
                            }
                        }
                        Err(_) => {
                            // Rejection is also acceptable for edge cases
                        }
                    }
                }
            }
        }
        MethodCaseStrategy::MultipleMethod { .. } => {
            // Multiple :method headers should be rejected
            match &parse_result {
                Err(HeaderParsingError::DuplicateMethod(_)) => {
                    // Expected: duplicate method headers should be rejected
                }
                _ => {
                    panic!("Multiple :method headers should be rejected");
                }
            }
        }
        _ => {
            // Other strategies: verify basic case preservation
            match &parse_result {
                Ok(parsed) => {
                    if let Some(method_value) = &parsed.method {
                        assert!(
                            !method_value.original_case.is_empty(),
                            "Method value should not be empty"
                        );
                    }
                }
                Err(_) => {
                    // Errors may be acceptable for custom/complex patterns
                }
            }
        }
    }

    // Test case sensitivity invariants
    test_case_sensitivity_invariants(&input, &parse_result);
});

fn test_case_sensitivity_invariants(
    input: &H2MethodCaseInput,
    result: &Result<ParsedHeaders, HeaderParsingError>,
) {
    match result {
        Ok(parsed) => {
            // Invariant: Method case should always be preserved
            if let Some(method_value) = &parsed.method {
                assert!(
                    !method_value.original_case.is_empty(),
                    "Method value should not be empty"
                );

                // For standard methods, verify they can be normalized
                if method_value.is_standard {
                    let uppercase_version = method_value.original_case.to_uppercase();
                    assert!(
                        STANDARD_METHODS.contains(&uppercase_version.as_str()),
                        "Standard method should normalize to known method: {}",
                        uppercase_version
                    );
                }
            }

            // Invariant: Header names should be lowercased (HTTP/2 requirement)
            for (name, _) in &parsed.regular_headers {
                let lowercase_name = name.to_lowercase();
                assert_eq!(
                    *name, lowercase_name,
                    "Regular header names should be lowercase: expected '{}', got '{}'",
                    lowercase_name, name
                );
            }

            // Invariant: Case violations should be properly detected
            for violation in &parsed.case_analysis.case_violations {
                match violation.violation_type {
                    ViolationType::PseudoHeaderNameNotLowercase => {
                        assert!(
                            violation.header_name.starts_with(':'),
                            "Pseudo-header case violation should be for pseudo-header"
                        );
                        assert_ne!(
                            violation.expected, violation.actual,
                            "Case violation should show different expected vs actual"
                        );
                    }
                    ViolationType::RegularHeaderNameNotLowercase => {
                        assert!(
                            !violation.header_name.starts_with(':'),
                            "Regular header case violation should be for regular header"
                        );
                    }
                    ViolationType::MethodValueChanged => {
                        assert_eq!(
                            violation.header_name, ":method",
                            "Method value violation should be for :method header"
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(error) => {
            // Verify error conditions are appropriate
            match error {
                HeaderParsingError::EmptyMethod => {
                    // Should only occur for empty method strategies
                    let has_empty_method = matches!(
                        input.method_strategy,
                        MethodCaseStrategy::EdgeCaseMethod {
                            edge_type: MethodEdgeType::Empty,
                            ..
                        }
                    );
                    assert!(
                        has_empty_method,
                        "Empty method error should only occur for empty method strategy"
                    );
                }
                HeaderParsingError::InvalidMethodCharacters {
                    method,
                    invalid_chars,
                } => {
                    assert!(
                        !invalid_chars.is_empty(),
                        "Invalid characters error should specify which characters are invalid"
                    );
                    assert!(
                        !method.is_empty(),
                        "Method with invalid characters should not be empty"
                    );
                }
                HeaderParsingError::DuplicateMethod(_) => {
                    // Should only occur for multiple method strategies
                    let has_multiple_methods = matches!(
                        input.method_strategy,
                        MethodCaseStrategy::MultipleMethod { .. }
                    );
                    assert!(
                        has_multiple_methods,
                        "Duplicate method error should only occur for multiple method strategy"
                    );
                }
                HeaderParsingError::MethodCaseNotPreserved { original, modified } => {
                    assert_ne!(
                        *original, *modified,
                        "Case preservation error should show different original vs modified"
                    );
                }
                _ => {
                    // Other errors may be valid depending on input
                }
            }
        }
    }

    // Invariant: Standard methods in different cases should still be recognizable
    if let MethodCaseStrategy::StandardMethod {
        method,
        case_pattern,
    } = &input.method_strategy
    {
        let expected_base = match method {
            StandardMethod::Get => "GET",
            StandardMethod::Post => "POST",
            StandardMethod::Put => "PUT",
            _ => return, // Skip for simplicity
        };

        let case_modified = MockH2HeaderParser::apply_case_pattern(expected_base, case_pattern);
        let normalized = case_modified.to_uppercase();

        assert_eq!(
            normalized, expected_base,
            "Standard method should normalize back to expected base: '{}' → '{}' → '{}'",
            expected_base, case_modified, normalized
        );
    }

    // Invariant: Valid method characters should not be rejected
    for header in &MockH2HeaderParser::build_header_list(input) {
        if header.0 == ":method" {
            let method_value = &header.1;
            if !method_value.is_empty() {
                let all_valid = method_value.chars().all(|c| VALID_METHOD_CHARS.contains(c));
                if all_valid && let Err(HeaderParsingError::InvalidMethodCharacters { .. }) = result
                {
                    panic!(
                        "Valid method characters should not be rejected: '{}'",
                        method_value
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_case_preservation() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        // Test lowercase method
        let headers = vec![(":method", "get"), (":path", "/")];

        let result = parser.parse_headers(&headers).unwrap();
        let method = result.method.unwrap();

        assert_eq!(method.original_case, "get");
        assert_eq!(method.normalized, "GET");
        assert!(method.is_standard);
    }

    #[test]
    fn test_mixed_case_method() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        let headers = vec![(":method", "PoSt"), (":path", "/api")];

        let result = parser.parse_headers(&headers).unwrap();
        let method = result.method.unwrap();

        assert_eq!(method.original_case, "PoSt");
        assert_eq!(method.normalized, "POST");
        assert!(method.is_standard);
    }

    #[test]
    fn test_custom_method_case() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        let headers = vec![(":method", "CustomMethod"), (":path", "/api")];

        let result = parser.parse_headers(&headers).unwrap();
        let method = result.method.unwrap();

        assert_eq!(method.original_case, "CustomMethod");
        assert_eq!(method.normalized, "CUSTOMMETHOD");
        assert!(!method.is_standard);
    }

    #[test]
    fn test_header_name_lowercasing() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        let headers = vec![
            (":method", "GET"),
            ("Content-Type", "application/json"),
            ("USER-AGENT", "test-client"),
        ];

        let result = parser.parse_headers(&headers).unwrap();

        // Regular headers should be lowercased
        assert_eq!(result.regular_headers.len(), 2);
        assert_eq!(result.regular_headers[0].0, "content-type");
        assert_eq!(result.regular_headers[1].0, "user-agent");

        // Values should be preserved
        assert_eq!(result.regular_headers[0].1, "application/json");
        assert_eq!(result.regular_headers[1].1, "test-client");
    }

    #[test]
    fn test_invalid_method_characters() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::Strict,
            RequestContext::Request,
        );

        let headers = vec![
            (":method", "GET POST"), // Space is invalid
            (":path", "/"),
        ];

        let result = parser.parse_headers(&headers);
        assert!(matches!(
            result,
            Err(HeaderParsingError::InvalidMethodCharacters { .. })
        ));
    }

    #[test]
    fn test_empty_method() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::Strict,
            RequestContext::Request,
        );

        let headers = vec![(":method", ""), (":path", "/")];

        let result = parser.parse_headers(&headers);
        assert!(matches!(result, Err(HeaderParsingError::EmptyMethod)));
    }

    #[test]
    fn test_duplicate_method() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        let headers = vec![(":method", "GET"), (":method", "POST"), (":path", "/")];

        let result = parser.parse_headers(&headers);
        assert!(matches!(
            result,
            Err(HeaderParsingError::DuplicateMethod(_))
        ));
    }

    #[test]
    fn test_pseudo_header_order() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        let headers = vec![
            (":method", "GET"),
            ("content-type", "text/plain"),
            (":path", "/"), // Pseudo-header after regular header
        ];

        let result = parser.parse_headers(&headers);
        assert!(matches!(result, Err(HeaderParsingError::PseudoHeaderOrder)));
    }

    #[test]
    fn test_case_pattern_application() {
        // Test lowercase pattern
        let result = MockH2HeaderParser::apply_case_pattern("GET", &CasePattern::Lowercase);
        assert_eq!(result, "get");

        // Test uppercase pattern
        let result = MockH2HeaderParser::apply_case_pattern("get", &CasePattern::Uppercase);
        assert_eq!(result, "GET");

        // Test titlecase pattern
        let result = MockH2HeaderParser::apply_case_pattern("POST", &CasePattern::Titlecase);
        assert_eq!(result, "Post");

        // Test alternating pattern
        let result = MockH2HeaderParser::apply_case_pattern("PATCH", &CasePattern::Alternating);
        assert_eq!(result, "PaTcH");
    }

    #[test]
    fn test_mixed_case_patterns() {
        // Test per-character pattern
        let pattern = MixedCasePattern::PerCharacter(vec![true, false, true, false]);
        let result = MockH2HeaderParser::apply_mixed_case_pattern("test", &pattern);
        assert_eq!(result, "TeSt");

        // Test vowel-consonant pattern
        let pattern = MixedCasePattern::VowelConsonant;
        let result = MockH2HeaderParser::apply_mixed_case_pattern("hello", &pattern);
        assert_eq!(result, "hEllO");

        // Test first-last-middle pattern
        let pattern = MixedCasePattern::FirstLastMiddle;
        let result = MockH2HeaderParser::apply_mixed_case_pattern("method", &pattern);
        assert_eq!(result, "MethoD");
    }

    #[test]
    fn test_standard_method_recognition() {
        let mut parser = MockH2HeaderParser::new(
            ValidationMode::StrictRFC,
            CaseEnforcement::PreserveOriginal,
            RequestContext::Request,
        );

        // Test various case variations of standard methods
        let test_cases = vec![
            ("GET", true),
            ("get", true),
            ("Get", true),
            ("gEt", true),
            ("POST", true),
            ("post", true),
            ("CUSTOM", false),
            ("custom", false),
        ];

        for (method_str, should_be_standard) in test_cases {
            let method_value = parser.parse_method_value(method_str).unwrap();
            assert_eq!(
                method_value.is_standard, should_be_standard,
                "Method '{}' standard detection failed",
                method_str
            );
            assert_eq!(method_value.original_case, method_str);
        }
    }
}
