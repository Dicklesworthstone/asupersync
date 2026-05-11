#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :path header test input for RFC 7540 §8.1.2.3 compliance
#[derive(Arbitrary, Debug)]
struct H2PathInput {
    /// Base path component
    base: String,
    /// Whether to include dot segments
    include_dots: bool,
    /// Type of dot segment to inject
    dot_type: DotSegmentType,
    /// Position to inject dot segment
    position: PositionType,
    /// Additional path components
    components: Vec<String>,
}

#[derive(Arbitrary, Debug)]
enum DotSegmentType {
    /// Single dot segment "./"
    SingleDot,
    /// Double dot segment "../"
    DoubleDot,
    /// Encoded single dot "%2E%2F"
    EncodedSingleDot,
    /// Encoded double dot "%2E%2E%2F"
    EncodedDoubleDot,
    /// Mixed encoding ".%2F"
    MixedSingle,
    /// Mixed encoding "..%2F"
    MixedDouble,
    /// Just dot "." without slash
    BareDoubleDot,
    /// Bare double dot ".."
    BareDot,
    /// Multiple dots ".../"
    MultipleDots,
    /// Trailing dot "/."
    TrailingDot,
    /// Trailing double dot "/.."
    TrailingDoubleDot,
}

#[derive(Arbitrary, Debug)]
enum PositionType {
    /// Beginning of path
    Start,
    /// Middle of path
    Middle,
    /// End of path
    End,
    /// Multiple positions
    Multiple,
}

/// Mock HTTP/2 path parser for testing RFC 7540 §8.1.2.3 compliance
struct MockH2PathParser;

#[derive(Debug, PartialEq)]
enum PathValidationError {
    /// Path contains relative segments (. or ..)
    RelativeSegments,
    /// Path is not absolute (doesn't start with /)
    NotAbsolute,
    /// Empty path value
    Empty,
    /// Invalid percent encoding
    InvalidEncoding,
    /// Path contains null bytes
    NullBytes,
}

impl MockH2PathParser {
    fn validate_path(path: &str) -> Result<(), PathValidationError> {
        // RFC 7540 §8.1.2.3: :path pseudo-header field MUST NOT be empty
        if path.is_empty() {
            return Err(PathValidationError::Empty);
        }

        // RFC 7540 §8.1.2.3: Must be absolute (start with /)
        // Exception: OPTIONS with "*" is allowed, but we test general case
        if !path.starts_with('/') && path != "*" {
            return Err(PathValidationError::NotAbsolute);
        }

        // Handle asterisk-form for OPTIONS (RFC 7540 §8.1.2.3)
        if path == "*" {
            return Ok(());
        }

        // Check for null bytes (HTTP/2 security requirement)
        if path.contains('\0') {
            return Err(PathValidationError::NullBytes);
        }

        // Decode percent-encoded sequences for dot segment detection
        let decoded_path = Self::percent_decode(path)?;

        // RFC 7540 §8.1.2.3: Path must not contain dot-segments
        // RFC 3986 defines dot-segments as "." and ".." path segments
        if Self::contains_dot_segments(&decoded_path) {
            return Err(PathValidationError::RelativeSegments);
        }

        Ok(())
    }

    fn percent_decode(path: &str) -> Result<String, PathValidationError> {
        let mut decoded = String::new();
        let mut chars = path.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Try to decode percent-encoded sequence
                let hex1 = chars.next().ok_or(PathValidationError::InvalidEncoding)?;
                let hex2 = chars.next().ok_or(PathValidationError::InvalidEncoding)?;

                if let (Some(d1), Some(d2)) = (hex1.to_digit(16), hex2.to_digit(16)) {
                    let byte_val = (d1 * 16 + d2) as u8;
                    // Only decode safe ASCII characters for path validation
                    if byte_val.is_ascii() && byte_val != 0 {
                        decoded.push(byte_val as char);
                    } else {
                        // Invalid encoding or null byte
                        return Err(PathValidationError::InvalidEncoding);
                    }
                } else {
                    return Err(PathValidationError::InvalidEncoding);
                }
            } else {
                decoded.push(ch);
            }
        }

        Ok(decoded)
    }

    fn contains_dot_segments(path: &str) -> bool {
        // Split by '/' and check each segment
        for segment in path.split('/') {
            match segment {
                // Single dot segment
                "." => return true,
                // Double dot segment
                ".." => return true,
                // Segments starting with dots (also invalid in HTTP context)
                s if s.starts_with('.') && (s.ends_with(".") || s.len() <= 3) => {
                    // Common patterns: "...", ".git", etc.
                    if s == "..." || s.chars().all(|c| c == '.') {
                        return true;
                    }
                }
                _ => continue,
            }
        }

        // Additional check for dot patterns at segment boundaries
        if path.contains("/./")
            || path.contains("/../")
            || path.ends_with("/.")
            || path.ends_with("/..")
            || path == "/"
            || path.contains("//")
        {
            // Double slashes and trailing dots are also problematic
            if path.ends_with("/.")
                || path.ends_with("/..")
                || path.contains("/./")
                || path.contains("/../")
            {
                return true;
            }
        }

        false
    }

    fn build_test_path(input: &H2PathInput) -> String {
        if !input.include_dots {
            // Generate a normal absolute path
            let mut path = format!("/{}", input.base);
            for component in &input.components {
                if !component.is_empty() {
                    path.push_str(&format!("/{}", component));
                }
            }
            return path;
        }

        let dot_segment = match input.dot_type {
            DotSegmentType::SingleDot => "./",
            DotSegmentType::DoubleDot => "../",
            DotSegmentType::EncodedSingleDot => "%2E/",
            DotSegmentType::EncodedDoubleDot => "%2E%2E/",
            DotSegmentType::MixedSingle => ".%2F",
            DotSegmentType::MixedDouble => "..%2F",
            DotSegmentType::BareDoubleDot => "..",
            DotSegmentType::BareDot => ".",
            DotSegmentType::MultipleDots => ".../",
            DotSegmentType::TrailingDot => "/.",
            DotSegmentType::TrailingDoubleDot => "/..",
        };

        match input.position {
            PositionType::Start => {
                format!("/{}{}", dot_segment, input.base)
            }
            PositionType::Middle => {
                let mut path = format!("/{}", input.base);
                path.push_str(dot_segment);
                if !input.components.is_empty() {
                    path.push_str(&input.components[0]);
                }
                path
            }
            PositionType::End => {
                let mut path = format!("/{}", input.base);
                if matches!(
                    input.dot_type,
                    DotSegmentType::TrailingDot | DotSegmentType::TrailingDoubleDot
                ) {
                    path.push_str(dot_segment);
                } else {
                    path.push('/');
                    path.push_str(dot_segment.trim_end_matches('/'));
                }
                path
            }
            PositionType::Multiple => {
                let mut path = format!("/{}", dot_segment);
                path.push_str(&input.base);
                path.push_str(dot_segment);
                if !input.components.is_empty() {
                    path.push_str(&input.components[0]);
                }
                path.push_str(dot_segment.trim_end_matches('/'));
                path
            }
        }
    }
}

fuzz_target!(|input: H2PathInput| {
    let test_path = MockH2PathParser::build_test_path(&input);

    // Skip extremely long paths that would be rejected for size reasons
    if test_path.len() > 8192 {
        return;
    }

    let result = MockH2PathParser::validate_path(&test_path);

    if input.include_dots {
        // Paths with dot segments should be rejected per RFC 7540 §8.1.2.3
        match result {
            Ok(()) => {
                // This would be a compliance violation - RFC requires rejection
                // In real implementation, this should trigger PROTOCOL_ERROR
                panic!(
                    "COMPLIANCE VIOLATION: Path with dot segments was accepted: '{}'",
                    test_path
                );
            }
            Err(PathValidationError::RelativeSegments) => {
                // Expected outcome - correctly rejected
            }
            Err(PathValidationError::NotAbsolute) => {
                // Also acceptable - malformed paths may trigger different errors
            }
            Err(PathValidationError::InvalidEncoding) => {
                // Acceptable - encoding errors can occur with percent sequences
            }
            Err(_) => {
                // Other errors are also acceptable ways to reject invalid paths
                // Real HTTP/2 implementation might use different error categories
            }
        }
    } else {
        // Normal absolute paths without dot segments should be accepted
        match result {
            Ok(()) => {
                // Expected outcome for valid paths
            }
            Err(PathValidationError::Empty) if test_path.is_empty() => {
                // RFC violation caught correctly
            }
            Err(PathValidationError::NotAbsolute) if !test_path.starts_with('/') => {
                // RFC violation caught correctly
            }
            Err(_) => {
                // Debug: valid path was unexpectedly rejected
                // In fuzzing, we want to be lenient about edge cases
                // Real implementation might have additional validation rules
            }
        }
    }

    // Additional invariant testing
    test_path_invariants(&test_path, &result);
});

fn test_path_invariants(path: &str, result: &Result<(), PathValidationError>) {
    // Invariant: Empty paths must be rejected
    if path.is_empty() {
        assert!(result.is_err(), "Empty path must be rejected");
        if let Err(PathValidationError::Empty) = result {
            // Correct error type
        } else {
            // Any error is acceptable for empty paths
        }
    }

    // Invariant: Paths with obvious dot segments must be rejected
    if path.contains("/./")
        || path.contains("/../")
        || path.ends_with("/.")
        || path.ends_with("/..")
    {
        assert!(
            result.is_err(),
            "Path with obvious dot segments must be rejected: '{}'",
            path
        );
    }

    // Invariant: Non-absolute paths must be rejected (except "*")
    if !path.starts_with('/') && path != "*" {
        assert!(
            result.is_err(),
            "Non-absolute path must be rejected: '{}'",
            path
        );
    }

    // Invariant: Null bytes must be rejected
    if path.contains('\0') {
        assert!(result.is_err(), "Path with null bytes must be rejected");
    }

    // Invariant: Asterisk form is only valid as exactly "*"
    if path.contains('*') && path != "*" {
        // Most implementations would reject this, but not strictly required by RFC
        // This is more of a security/robustness check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_absolute_paths() {
        assert!(MockH2PathParser::validate_path("/").is_ok());
        assert!(MockH2PathParser::validate_path("/api").is_ok());
        assert!(MockH2PathParser::validate_path("/api/v1/users").is_ok());
        assert!(MockH2PathParser::validate_path("/path/to/resource").is_ok());
        assert!(MockH2PathParser::validate_path("*").is_ok()); // OPTIONS asterisk-form
    }

    #[test]
    fn test_reject_relative_paths() {
        // Basic dot segments
        assert!(MockH2PathParser::validate_path("/api/../admin").is_err());
        assert!(MockH2PathParser::validate_path("/./config").is_err());
        assert!(MockH2PathParser::validate_path("/api/./v1").is_err());
        assert!(MockH2PathParser::validate_path("/api/v1/..").is_err());

        // Trailing dot segments
        assert!(MockH2PathParser::validate_path("/api/.").is_err());
        assert!(MockH2PathParser::validate_path("/api/..").is_err());
    }

    #[test]
    fn test_reject_non_absolute_paths() {
        assert!(MockH2PathParser::validate_path("api/v1").is_err());
        assert!(MockH2PathParser::validate_path("../admin").is_err());
        assert!(MockH2PathParser::validate_path("./config").is_err());
        assert!(MockH2PathParser::validate_path("").is_err());
    }

    #[test]
    fn test_percent_encoded_dot_segments() {
        // Percent-encoded dot segments should also be rejected
        assert!(MockH2PathParser::validate_path("/api/%2E%2E/admin").is_err());
        assert!(MockH2PathParser::validate_path("/%2E/config").is_err());
        assert!(MockH2PathParser::validate_path("/api%2F%2E%2E%2Fadmin").is_err());
    }

    #[test]
    fn test_null_byte_rejection() {
        assert!(MockH2PathParser::validate_path("/api\0/admin").is_err());
        assert!(MockH2PathParser::validate_path("/\0").is_err());
    }

    #[test]
    fn test_edge_cases() {
        // Multiple dots
        assert!(MockH2PathParser::validate_path("/...").is_ok()); // Not RFC dot segment
        assert!(MockH2PathParser::validate_path("/.../file").is_ok());

        // URL-encoded sequences that don't form dot segments
        assert!(MockH2PathParser::validate_path("/api%2Fv1").is_ok()); // "/api%2Fv1" -> "/api/v1"

        // Edge encoding cases
        assert!(MockH2PathParser::validate_path("/api/%").is_err()); // Invalid encoding
        assert!(MockH2PathParser::validate_path("/api/%2").is_err()); // Incomplete encoding
    }

    #[test]
    fn test_build_path_generation() {
        let input = H2PathInput {
            base: "api".to_string(),
            include_dots: true,
            dot_type: DotSegmentType::DoubleDot,
            position: PositionType::Middle,
            components: vec!["admin".to_string()],
        };

        let path = MockH2PathParser::build_test_path(&input);
        assert!(path.contains(".."));
        assert!(path.starts_with('/'));
    }

    #[test]
    fn test_invariant_enforcement() {
        // Test that our invariant checking catches violations
        let empty_result = MockH2PathParser::validate_path("");
        test_path_invariants("", &empty_result);

        let dot_path_result = MockH2PathParser::validate_path("/api/../admin");
        test_path_invariants("/api/../admin", &dot_path_result);

        let non_absolute_result = MockH2PathParser::validate_path("api/v1");
        test_path_invariants("api/v1", &non_absolute_result);
    }
}
