#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :path pseudo-header with fragment characters test input
#[derive(Arbitrary, Debug)]
struct H2PathFragmentInput {
    /// Path construction strategy
    path_strategy: PathFragmentStrategy,
    /// Additional request components
    request_context: RequestContext,
    /// Fragment validation mode
    validation_mode: ValidationMode,
    /// Encoding variations to test
    encoding_variants: Vec<EncodingVariant>,
}

#[derive(Arbitrary, Debug)]
enum PathFragmentStrategy {
    /// Path with fragment at the end
    TrailingFragment { base_path: String, fragment: String },
    /// Path with fragment in the middle
    MiddleFragment {
        prefix: String,
        fragment: String,
        suffix: String,
    },
    /// Multiple fragments in one path
    MultipleFragments {
        base_path: String,
        fragments: Vec<String>,
    },
    /// Empty fragment
    EmptyFragment { path: String },
    /// Fragment with query parameters
    QueryAndFragment {
        path: String,
        query: String,
        fragment: String,
    },
    /// URL-encoded fragment
    EncodedFragment {
        base_path: String,
        fragment: String,
        encoding_type: FragmentEncoding,
    },
    /// Edge cases with special characters
    SpecialCharFragment {
        base_path: String,
        special_chars: SpecialCharSet,
    },
    /// Nested fragments (invalid)
    NestedFragments {
        base_path: String,
        nesting_pattern: NestingPattern,
    },
}

#[derive(Arbitrary, Debug)]
enum FragmentEncoding {
    /// Standard URL encoding %23
    UrlEncoded,
    /// Double encoding %2523
    DoubleEncoded,
    /// Unicode normalization
    Unicode,
    /// Mixed encoding
    Mixed,
}

#[derive(Arbitrary, Debug)]
enum SpecialCharSet {
    /// Control characters in fragment
    Control,
    /// Unicode characters
    Unicode,
    /// Percent-encoded sequences
    PercentEncoded,
    /// Mixed special characters
    Mixed(Vec<char>),
}

#[derive(Arbitrary, Debug)]
enum NestingPattern {
    /// Multiple # characters
    MultipleHashes,
    /// Fragment within fragment
    FragmentInFragment,
    /// Escaped nested structure
    EscapedNesting,
}

#[derive(Arbitrary, Debug)]
struct RequestContext {
    /// HTTP method
    method: HttpMethod,
    /// Scheme
    scheme: String,
    /// Authority
    authority: String,
    /// Additional headers
    headers: Vec<(String, String)>,
    /// Request validation strictness
    strictness: ValidationStrictness,
}

#[derive(Arbitrary, Debug)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Custom(String),
}

#[derive(Arbitrary, Clone, Debug)]
enum ValidationStrictness {
    /// RFC strict compliance
    Strict,
    /// Lenient parsing
    Lenient,
    /// Security-focused validation
    Security,
}

#[derive(Arbitrary, Clone, Debug)]
struct ValidationMode {
    /// Check for fragment presence
    check_fragments: bool,
    /// Validate URI structure
    validate_uri_structure: bool,
    /// Check encoding compliance
    check_encoding: bool,
    /// Fragment position validation
    fragment_position_check: bool,
}

#[derive(Arbitrary, Debug)]
struct EncodingVariant {
    /// Type of encoding to test
    encoding: EncodingType,
    /// Target for encoding
    target: EncodingTarget,
}

#[derive(Arbitrary, Debug)]
enum EncodingType {
    /// No encoding
    None,
    /// Standard percent encoding
    PercentEncoding,
    /// Double percent encoding
    DoubleEncoding,
    /// UTF-8 encoding
    Utf8,
    /// Custom encoding scheme
    Custom(String),
}

#[derive(Arbitrary, Debug)]
enum EncodingTarget {
    /// Encode the fragment separator
    FragmentSeparator,
    /// Encode the fragment content
    FragmentContent,
    /// Encode the entire path
    EntirePath,
    /// Selective encoding
    Selective(Vec<char>),
}

/// Mock HTTP/2 path parser with fragment validation per RFC 7540
struct MockH2PathParser {
    validation_mode: ValidationMode,
    strictness: ValidationStrictness,
    fragment_detection_patterns: Vec<FragmentPattern>,
}

#[derive(Debug)]
struct FragmentPattern {
    pattern: String,
    encoded_variants: Vec<String>,
    description: String,
}

#[derive(Debug, Clone)]
struct ParsedPath {
    raw_path: String,
    normalized_path: String,
    query_part: Option<String>,
    fragment_part: Option<String>,
    validation_result: PathValidation,
    encoding_issues: Vec<EncodingIssue>,
}

#[derive(Debug, Clone, PartialEq)]
enum PathValidation {
    Valid,
    ContainsFragment,
    InvalidEncoding,
    MalformedStructure,
    SecurityViolation,
    NonCompliantCharacters,
}

#[derive(Debug, Clone)]
struct EncodingIssue {
    issue_type: EncodingIssueType,
    position: usize,
    details: String,
}

#[derive(Debug, Clone, PartialEq)]
enum EncodingIssueType {
    InvalidPercentEncoding,
    DoubleEncoding,
    FragmentInPath,
    SuspiciousPattern,
    SecurityRisk,
}

#[derive(Debug, PartialEq)]
enum PathValidationError {
    /// Path contains fragment (RFC 7540 §8.1.2.3 violation)
    ContainsFragment { fragment: String, position: usize },
    /// Invalid percent encoding
    InvalidEncoding { sequence: String, position: usize },
    /// Malformed path structure
    MalformedPath(String),
    /// Security-sensitive pattern detected
    SecurityViolation(String),
    /// Non-ASCII characters in invalid context
    InvalidCharacters(String),
    /// Path too long
    PathTooLong { length: usize, limit: usize },
    /// Empty path when required
    EmptyPath,
}

// RFC 7540 constraints
const MAX_PATH_LENGTH: usize = 8192; // Reasonable limit
const FRAGMENT_SEPARATOR: char = '#'; // RFC 3986 fragment separator
const QUERY_SEPARATOR: char = '?'; // RFC 3986 query separator

impl MockH2PathParser {
    fn new(validation_mode: ValidationMode, strictness: ValidationStrictness) -> Self {
        let fragment_patterns = vec![
            FragmentPattern {
                pattern: "#".to_string(),
                encoded_variants: vec!["%23".to_string(), "%2523".to_string()],
                description: "Standard fragment separator".to_string(),
            },
            FragmentPattern {
                pattern: "#fragment".to_string(),
                encoded_variants: vec!["%23fragment".to_string(), "%2523fragment".to_string()],
                description: "Fragment with content".to_string(),
            },
            FragmentPattern {
                pattern: "##".to_string(),
                encoded_variants: vec!["%23%23".to_string(), "%2523%2523".to_string()],
                description: "Double fragment separator".to_string(),
            },
        ];

        Self {
            validation_mode,
            strictness,
            fragment_detection_patterns: fragment_patterns,
        }
    }

    fn parse_path(&self, path: &str) -> Result<ParsedPath, PathValidationError> {
        // Basic length check
        if path.len() > MAX_PATH_LENGTH {
            return Err(PathValidationError::PathTooLong {
                length: path.len(),
                limit: MAX_PATH_LENGTH,
            });
        }

        // Handle empty path
        if path.is_empty() {
            return Err(PathValidationError::EmptyPath);
        }

        // Parse path components
        let (path_part, query_part, fragment_part) = self.parse_path_components(path)?;

        // RFC 7540 §8.1.2.3: :path MUST NOT contain fragment
        if self.validation_mode.check_fragments
            && let Some(fragment) = &fragment_part
        {
            let fragment_position = path.find(FRAGMENT_SEPARATOR).unwrap_or(path.len());
            return Err(PathValidationError::ContainsFragment {
                fragment: fragment.clone(),
                position: fragment_position,
            });
        }

        // Check for encoded fragments that might bypass simple detection
        let encoding_issues = self.detect_encoding_issues(path)?;

        // Determine overall validation result
        let validation_result =
            self.determine_validation_result(path, &fragment_part, &encoding_issues);

        // Normalize the path (remove fragments if in lenient mode)
        let normalized_path = match self.strictness {
            ValidationStrictness::Strict => {
                if let Some(fragment) = &fragment_part {
                    return Err(PathValidationError::ContainsFragment {
                        fragment: fragment.clone(),
                        position: path.find(FRAGMENT_SEPARATOR).unwrap_or(0),
                    });
                }
                path_part
            }
            ValidationStrictness::Lenient => path_part, // Strip fragment but continue
            ValidationStrictness::Security => {
                if fragment_part.is_some() || !encoding_issues.is_empty() {
                    return Err(PathValidationError::SecurityViolation(
                        "Fragment or suspicious encoding detected".to_string(),
                    ));
                }
                path_part
            }
        };

        Ok(ParsedPath {
            raw_path: path.to_string(),
            normalized_path,
            query_part,
            fragment_part,
            validation_result,
            encoding_issues,
        })
    }

    fn parse_path_components(
        &self,
        path: &str,
    ) -> Result<(String, Option<String>, Option<String>), PathValidationError> {
        // Find fragment separator first (rightmost # to handle multiple fragments)
        let fragment_pos = path.rfind(FRAGMENT_SEPARATOR);

        let (path_without_fragment, fragment_part) = match fragment_pos {
            Some(pos) => {
                let fragment = if pos + 1 < path.len() {
                    Some(path[pos + 1..].to_string())
                } else {
                    Some(String::new()) // Empty fragment
                };
                (&path[..pos], fragment)
            }
            None => (path, None),
        };

        // Find query separator in the remaining path
        let query_pos = path_without_fragment.rfind(QUERY_SEPARATOR);

        let (path_part, query_part) = match query_pos {
            Some(pos) => {
                let query = if pos + 1 < path_without_fragment.len() {
                    Some(path_without_fragment[pos + 1..].to_string())
                } else {
                    Some(String::new()) // Empty query
                };
                (&path_without_fragment[..pos], query)
            }
            None => (path_without_fragment, None),
        };

        Ok((path_part.to_string(), query_part, fragment_part))
    }

    fn detect_encoding_issues(
        &self,
        path: &str,
    ) -> Result<Vec<EncodingIssue>, PathValidationError> {
        let mut issues = Vec::new();

        // Check for encoded fragment separators
        if let Some(pos) = path.find("%23") {
            issues.push(EncodingIssue {
                issue_type: EncodingIssueType::FragmentInPath,
                position: pos,
                details: "URL-encoded fragment separator found".to_string(),
            });
        }

        // Check for double encoding
        if let Some(pos) = path.find("%2523") {
            issues.push(EncodingIssue {
                issue_type: EncodingIssueType::DoubleEncoding,
                position: pos,
                details: "Double-encoded fragment separator found".to_string(),
            });
        }

        // Check for other suspicious patterns
        for pattern in &self.fragment_detection_patterns {
            for variant in &pattern.encoded_variants {
                if let Some(pos) = path.find(variant) {
                    issues.push(EncodingIssue {
                        issue_type: EncodingIssueType::SuspiciousPattern,
                        position: pos,
                        details: format!("Suspicious pattern found: {}", variant),
                    });
                }
            }
        }

        // Validate percent encoding sequences
        let mut i = 0;
        let chars: Vec<char> = path.chars().collect();
        while i < chars.len() {
            if chars[i] == '%' {
                if i + 2 >= chars.len() {
                    issues.push(EncodingIssue {
                        issue_type: EncodingIssueType::InvalidPercentEncoding,
                        position: i,
                        details: "Incomplete percent encoding sequence".to_string(),
                    });
                } else {
                    let hex_chars = &chars[i + 1..i + 3];
                    if !hex_chars.iter().all(|c| c.is_ascii_hexdigit()) {
                        issues.push(EncodingIssue {
                            issue_type: EncodingIssueType::InvalidPercentEncoding,
                            position: i,
                            details: format!(
                                "Invalid hex digits: {}{}",
                                hex_chars[0], hex_chars[1]
                            ),
                        });
                    }
                }
                i += 3;
            } else {
                i += 1;
            }
        }

        Ok(issues)
    }

    fn determine_validation_result(
        &self,
        path: &str,
        fragment_part: &Option<String>,
        encoding_issues: &[EncodingIssue],
    ) -> PathValidation {
        // Check for fragment presence
        if fragment_part.is_some() {
            return PathValidation::ContainsFragment;
        }

        // Check for fragment-related encoding issues
        for issue in encoding_issues {
            match issue.issue_type {
                EncodingIssueType::FragmentInPath => return PathValidation::ContainsFragment,
                EncodingIssueType::InvalidPercentEncoding => {
                    return PathValidation::InvalidEncoding;
                }
                EncodingIssueType::SecurityRisk => return PathValidation::SecurityViolation,
                _ => {}
            }
        }

        // Check for malformed structure
        if path.contains("##") || path.ends_with('#') && path != "#" {
            return PathValidation::MalformedStructure;
        }

        // Check for non-compliant characters
        if path.chars().any(|c| c.is_control() && c != '\t') {
            return PathValidation::NonCompliantCharacters;
        }

        PathValidation::Valid
    }

    fn generate_fragment_path(strategy: &PathFragmentStrategy) -> String {
        match strategy {
            PathFragmentStrategy::TrailingFragment {
                base_path,
                fragment,
            } => {
                format!("{}#{}", base_path, fragment)
            }
            PathFragmentStrategy::MiddleFragment {
                prefix,
                fragment,
                suffix,
            } => {
                format!("{}#{}#{}", prefix, fragment, suffix)
            }
            PathFragmentStrategy::MultipleFragments {
                base_path,
                fragments,
            } => {
                let mut result = base_path.clone();
                for fragment in fragments {
                    result.push('#');
                    result.push_str(fragment);
                }
                result
            }
            PathFragmentStrategy::EmptyFragment { path } => {
                format!("{}#", path)
            }
            PathFragmentStrategy::QueryAndFragment {
                path,
                query,
                fragment,
            } => {
                format!("{}?{}#{}", path, query, fragment)
            }
            PathFragmentStrategy::EncodedFragment {
                base_path,
                fragment,
                encoding_type,
            } => {
                match encoding_type {
                    FragmentEncoding::UrlEncoded => {
                        format!("{}%23{}", base_path, fragment)
                    }
                    FragmentEncoding::DoubleEncoded => {
                        format!("{}%2523{}", base_path, fragment)
                    }
                    FragmentEncoding::Unicode => {
                        format!("{}#{}", base_path, fragment) // Simplified
                    }
                    FragmentEncoding::Mixed => {
                        format!(
                            "{}%23{}#{}",
                            base_path,
                            &fragment[..fragment.len() / 2],
                            &fragment[fragment.len() / 2..]
                        )
                    }
                }
            }
            PathFragmentStrategy::SpecialCharFragment {
                base_path,
                special_chars,
            } => match special_chars {
                SpecialCharSet::Control => format!("{}#\x00\x01\x02", base_path),
                SpecialCharSet::Unicode => format!("{}#🔥💯", base_path),
                SpecialCharSet::PercentEncoded => format!("{}#%20%21%22", base_path),
                SpecialCharSet::Mixed(chars) => {
                    let special_string: String = chars.iter().collect();
                    format!("{}#{}", base_path, special_string)
                }
            },
            PathFragmentStrategy::NestedFragments {
                base_path,
                nesting_pattern,
            } => match nesting_pattern {
                NestingPattern::MultipleHashes => format!("{}###fragment", base_path),
                NestingPattern::FragmentInFragment => format!("{}#outer#inner", base_path),
                NestingPattern::EscapedNesting => format!("{}#%23inner", base_path),
            },
        }
    }
}

fuzz_target!(|input: H2PathFragmentInput| {
    // Generate path based on strategy
    let test_path = MockH2PathParser::generate_fragment_path(&input.path_strategy);

    // Skip excessively long paths that would timeout
    if test_path.len() > MAX_PATH_LENGTH * 2 {
        return;
    }

    let parser = MockH2PathParser::new(
        input.validation_mode.clone(),
        input.request_context.strictness.clone(),
    );

    let parse_result = parser.parse_path(&test_path);

    // Apply test assertions based on path strategy
    match input.path_strategy {
        PathFragmentStrategy::TrailingFragment { .. }
        | PathFragmentStrategy::MiddleFragment { .. }
        | PathFragmentStrategy::MultipleFragments { .. }
        | PathFragmentStrategy::EmptyFragment { .. }
        | PathFragmentStrategy::QueryAndFragment { .. } => {
            // These strategies create paths with literal # characters
            match &parse_result {
                Ok(parsed) => {
                    // Should not be valid in strict mode
                    if matches!(
                        input.request_context.strictness,
                        ValidationStrictness::Strict
                    ) {
                        panic!(
                            "Path with fragment should be rejected in strict mode: {}",
                            test_path
                        );
                    }
                    // In lenient mode, fragment should be detected but possibly allowed
                    assert!(
                        parsed.validation_result == PathValidation::ContainsFragment
                            || parsed.fragment_part.is_some(),
                        "Fragment should be detected in path: {}",
                        test_path
                    );
                }
                Err(PathValidationError::ContainsFragment { .. }) => {
                    // Expected: fragment correctly rejected
                }
                Err(error) => {
                    // Other errors may be acceptable depending on path content
                    match error {
                        PathValidationError::MalformedPath(_)
                        | PathValidationError::InvalidCharacters(_) => {
                            // Acceptable for malformed fragment paths
                        }
                        _ => {
                            panic!("Unexpected error for fragment path: {:?}", error);
                        }
                    }
                }
            }
        }
        PathFragmentStrategy::EncodedFragment { .. } => {
            // Encoded fragments should be detected based on validation mode
            match &parse_result {
                Ok(parsed) => {
                    if input.validation_mode.check_encoding {
                        assert!(
                            !parsed.encoding_issues.is_empty()
                                || parsed.validation_result != PathValidation::Valid,
                            "Encoded fragment should be detected: {}",
                            test_path
                        );
                    }
                }
                Err(PathValidationError::ContainsFragment { .. })
                | Err(PathValidationError::InvalidEncoding { .. })
                | Err(PathValidationError::SecurityViolation(_)) => {
                    // Expected: encoded fragment detected and rejected
                }
                Err(_) => {
                    // Other validation errors may occur
                }
            }
        }
        PathFragmentStrategy::SpecialCharFragment { .. }
        | PathFragmentStrategy::NestedFragments { .. } => {
            // Special character and nested fragments should be handled carefully
            match &parse_result {
                Ok(_) => {
                    // May be allowed in very lenient modes
                    if matches!(
                        input.request_context.strictness,
                        ValidationStrictness::Security
                    ) {
                        panic!(
                            "Security-sensitive fragment pattern should be rejected: {}",
                            test_path
                        );
                    }
                }
                Err(_) => {
                    // Rejection is expected for most special patterns
                }
            }
        }
    }

    // Test fragment detection invariants
    test_fragment_detection_invariants(&input, &parse_result, &test_path);
});

fn test_fragment_detection_invariants(
    input: &H2PathFragmentInput,
    result: &Result<ParsedPath, PathValidationError>,
    test_path: &str,
) {
    // Invariant: Paths with literal # should be detected as containing fragments
    if test_path.contains('#') {
        match result {
            Ok(parsed) => {
                // Fragment should be detected unless in very lenient mode
                if input.validation_mode.check_fragments {
                    assert!(
                        parsed.fragment_part.is_some()
                            || parsed.validation_result == PathValidation::ContainsFragment
                            || !parsed.encoding_issues.is_empty(),
                        "Literal # in path should be detected as fragment: {}",
                        test_path
                    );
                }
            }
            Err(PathValidationError::ContainsFragment { .. }) => {
                // Expected: fragment correctly detected and rejected
            }
            Err(_) => {
                // Other errors acceptable for malformed paths
            }
        }
    }

    // Invariant: RFC 7540 strict compliance should reject all fragments
    if matches!(
        input.request_context.strictness,
        ValidationStrictness::Strict
    ) && input.validation_mode.check_fragments
        && (test_path.contains('#') || test_path.contains("%23"))
    {
        match result {
            Ok(_) => {
                panic!("Strict mode should reject fragment paths: {}", test_path);
            }
            Err(_) => {
                // Expected: strict rejection
            }
        }
    }

    // Invariant: Security mode should be most restrictive
    if matches!(
        input.request_context.strictness,
        ValidationStrictness::Security
    ) && (test_path.contains('#') || test_path.contains("%23") || test_path.contains("%2523"))
    {
        match result {
            Ok(_) => {
                panic!(
                    "Security mode should reject suspicious fragment patterns: {}",
                    test_path
                );
            }
            Err(PathValidationError::SecurityViolation(_))
            | Err(PathValidationError::ContainsFragment { .. }) => {
                // Expected: security rejection
            }
            Err(_) => {
                // Other rejections also acceptable in security mode
            }
        }
    }

    // Invariant: URL-encoded fragments should be detected when encoding check is enabled
    if input.validation_mode.check_encoding && test_path.contains("%23") {
        match result {
            Ok(parsed) => {
                assert!(
                    parsed.encoding_issues.iter().any(|issue| matches!(
                        issue.issue_type,
                        EncodingIssueType::FragmentInPath | EncodingIssueType::SuspiciousPattern
                    )),
                    "URL-encoded fragment should be detected: {}",
                    test_path
                );
            }
            Err(_) => {
                // Rejection is also acceptable for encoded fragments
            }
        }
    }

    // Invariant: Empty fragments should be handled consistently
    if test_path.ends_with('#') {
        match result {
            Ok(parsed) => {
                assert!(
                    parsed.fragment_part == Some(String::new())
                        || parsed.validation_result == PathValidation::ContainsFragment,
                    "Empty fragment should be detected: {}",
                    test_path
                );
            }
            Err(PathValidationError::ContainsFragment { fragment, .. }) => {
                assert!(
                    fragment.is_empty(),
                    "Empty fragment should be properly identified"
                );
            }
            Err(_) => {
                // Other errors acceptable for malformed paths
            }
        }
    }

    // Invariant: Paths without fragments should be valid (unless other issues)
    if !test_path.contains('#') && !test_path.contains("%23") {
        match result {
            Ok(parsed) => {
                assert!(
                    parsed.fragment_part.is_none(),
                    "Path without fragments should not have fragment part: {}",
                    test_path
                );
                if parsed.encoding_issues.is_empty() {
                    assert!(
                        matches!(parsed.validation_result, PathValidation::Valid),
                        "Clean path should be valid: {}",
                        test_path
                    );
                }
            }
            Err(PathValidationError::ContainsFragment { .. }) => {
                panic!(
                    "Path without fragments should not fail fragment validation: {}",
                    test_path
                );
            }
            Err(_) => {
                // Other validation errors may occur (length, encoding, etc.)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_without_fragment_valid() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Strict,
        );

        let result = parser.parse_path("/api/v1/users");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.normalized_path, "/api/v1/users");
        assert_eq!(parsed.fragment_part, None);
        assert_eq!(parsed.validation_result, PathValidation::Valid);
    }

    #[test]
    fn test_path_with_fragment_rejected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Strict,
        );

        let result = parser.parse_path("/api/v1/users#section1");
        assert!(matches!(
            result,
            Err(PathValidationError::ContainsFragment { .. })
        ));
    }

    #[test]
    fn test_encoded_fragment_detected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Security,
        );

        let result = parser.parse_path("/api/v1/users%23fragment");
        match result {
            Err(PathValidationError::ContainsFragment { .. })
            | Err(PathValidationError::SecurityViolation(_)) => {
                // Expected: encoded fragment detected
            }
            Ok(parsed) => {
                assert!(
                    !parsed.encoding_issues.is_empty(),
                    "Encoded fragment should be detected"
                );
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_query_with_fragment_rejected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Strict,
        );

        let result = parser.parse_path("/search?q=test#results");
        assert!(matches!(
            result,
            Err(PathValidationError::ContainsFragment { .. })
        ));
    }

    #[test]
    fn test_empty_fragment_rejected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Strict,
        );

        let result = parser.parse_path("/api/endpoint#");
        assert!(matches!(
            result,
            Err(PathValidationError::ContainsFragment { .. })
        ));
    }

    #[test]
    fn test_multiple_fragments_rejected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Strict,
        );

        let result = parser.parse_path("/api#fragment1#fragment2");
        assert!(matches!(
            result,
            Err(PathValidationError::ContainsFragment { .. })
        ));
    }

    #[test]
    fn test_lenient_mode_strips_fragment() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: false,
                fragment_position_check: true,
            },
            ValidationStrictness::Lenient,
        );

        let result = parser.parse_path("/api/v1/users#section1");
        match result {
            Ok(parsed) => {
                assert_eq!(parsed.normalized_path, "/api/v1/users");
                assert_eq!(parsed.fragment_part, Some("section1".to_string()));
            }
            Err(_) => {
                // Also acceptable in lenient mode
            }
        }
    }

    #[test]
    fn test_double_encoded_fragment_detected() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Security,
        );

        let result = parser.parse_path("/api%2523fragment");
        match result {
            Ok(parsed) => {
                assert!(
                    parsed
                        .encoding_issues
                        .iter()
                        .any(|issue| matches!(issue.issue_type, EncodingIssueType::DoubleEncoding))
                );
            }
            Err(_) => {
                // Rejection also acceptable
            }
        }
    }

    #[test]
    fn test_path_component_parsing() {
        let parser = MockH2PathParser::new(
            ValidationMode {
                check_fragments: true,
                validate_uri_structure: true,
                check_encoding: true,
                fragment_position_check: true,
            },
            ValidationStrictness::Lenient,
        );

        let result = parser.parse_path_components("/path?query=value#fragment");
        assert!(result.is_ok());

        let (path, query, fragment) = result.unwrap();
        assert_eq!(path, "/path");
        assert_eq!(query, Some("query=value".to_string()));
        assert_eq!(fragment, Some("fragment".to_string()));
    }

    #[test]
    fn test_fragment_generation_strategies() {
        // Test each generation strategy produces expected patterns
        let trailing =
            MockH2PathParser::generate_fragment_path(&PathFragmentStrategy::TrailingFragment {
                base_path: "/api".to_string(),
                fragment: "section".to_string(),
            });
        assert_eq!(trailing, "/api#section");

        let encoded =
            MockH2PathParser::generate_fragment_path(&PathFragmentStrategy::EncodedFragment {
                base_path: "/api".to_string(),
                fragment: "section".to_string(),
                encoding_type: FragmentEncoding::UrlEncoded,
            });
        assert_eq!(encoded, "/api%23section");

        let query_and_fragment =
            MockH2PathParser::generate_fragment_path(&PathFragmentStrategy::QueryAndFragment {
                path: "/search".to_string(),
                query: "q=test".to_string(),
                fragment: "results".to_string(),
            });
        assert_eq!(query_and_fragment, "/search?q=test#results");
    }
}
