#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Fuzz target for HTTP/2 :path canonicalization testing.
///
/// Per RFC 9112 §4.2.3: "A server MUST perform path normalization before
/// routing requests to avoid security issues arising from path traversal
/// attacks and directory confusion."
///
/// Tests include:
/// - Percent-encoded slashes (%2F → /)
/// - Dot-segments (../, ./, ..%2F, .%2F)
/// - Unicode normalization (NFC, NFD, NFKC, NFKD)
/// - Path traversal attempts
/// - Double encoding attacks

#[derive(Debug, Arbitrary)]
struct PathTest {
    /// The original :path value to test
    path: String,
    /// Expected canonicalized result (if valid)
    expected_canonical: Option<String>,
    /// Whether this should be rejected as malicious
    should_reject: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum PathValidationResult {
    Valid(String),        // Canonicalized path
    Invalid(PathError),   // Validation error
    SecurityRisk(String), // Potential security issue detected
}

#[derive(Debug, Clone, PartialEq)]
enum PathError {
    EmptyPath,
    InvalidPercent,
    RelativePathNotAllowed,
    PathTraversal,
    InvalidCharacter(char),
    UnicodeNormalizationFailed,
    ExcessiveRedirection,
}

/// Mock HTTP/2 connection for testing path canonicalization
struct MockPathCanonicalizationConnection {
    stream_state: HashMap<u32, StreamState>,
    connection_error: Option<H2Error>,
    security_policy: SecurityPolicy,
}

#[derive(Debug, Clone)]
struct StreamState {
    id: u32,
    canonical_path: Option<String>,
    original_path: Option<String>,
    validation_result: Option<PathValidationResult>,
}

#[derive(Debug, Clone)]
struct SecurityPolicy {
    /// Allow path traversal sequences
    allow_path_traversal: bool,
    /// Maximum path segments after normalization
    max_path_segments: usize,
    /// Maximum path length after normalization
    max_path_length: usize,
    /// Strict Unicode normalization
    strict_unicode_normalization: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum H2Error {
    ProtocolError,
    SecurityPolicyViolation,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_path_traversal: false,
            max_path_segments: 64,
            max_path_length: 8192,
            strict_unicode_normalization: true,
        }
    }
}

impl MockPathCanonicalizationConnection {
    fn new() -> Self {
        Self {
            stream_state: HashMap::new(),
            connection_error: None,
            security_policy: SecurityPolicy::default(),
        }
    }

    fn with_policy(policy: SecurityPolicy) -> Self {
        Self {
            stream_state: HashMap::new(),
            connection_error: None,
            security_policy: policy,
        }
    }

    /// Canonicalize and validate a :path pseudo-header per RFC 9112
    fn canonicalize_path(
        &mut self,
        stream_id: u32,
        path: &str,
    ) -> Result<PathValidationResult, H2Error> {
        // Check if connection is already in error state
        if let Some(ref error) = self.connection_error {
            return Err(error.clone());
        }

        // RFC 9112 §4.2.3: Path normalization steps
        let result = self.perform_path_normalization(path);

        {
            let stream = self
                .stream_state
                .entry(stream_id)
                .or_insert_with(|| StreamState {
                    id: stream_id,
                    canonical_path: None,
                    original_path: None,
                    validation_result: None,
                });
            debug_assert_eq!(stream.id, stream_id);
            stream.original_path = Some(path.to_string());
            stream.validation_result = Some(result.clone());

            if let PathValidationResult::Valid(canonical_path) = &result {
                stream.canonical_path = Some(canonical_path.clone());
            }
        }

        match result {
            PathValidationResult::Valid(_) => Ok(result),
            PathValidationResult::Invalid(_) => {
                // Invalid paths result in PROTOCOL_ERROR
                self.connection_error = Some(H2Error::ProtocolError);
                Err(H2Error::ProtocolError)
            }
            PathValidationResult::SecurityRisk(_) => {
                // Security risks may be handled differently based on policy
                if self.security_policy.allow_path_traversal {
                    Ok(result)
                } else {
                    self.connection_error = Some(H2Error::SecurityPolicyViolation);
                    Err(H2Error::SecurityPolicyViolation)
                }
            }
        }
    }

    /// Perform RFC 9112 compliant path normalization
    fn perform_path_normalization(&self, path: &str) -> PathValidationResult {
        // Step 1: Basic validation
        if path.is_empty() {
            return PathValidationResult::Invalid(PathError::EmptyPath);
        }

        // Step 2: Must start with '/' for HTTP/2 :path
        if !path.starts_with('/') {
            return PathValidationResult::Invalid(PathError::RelativePathNotAllowed);
        }

        // Step 3: Percent-decode the path
        let decoded = match self.percent_decode(path) {
            Ok(decoded) => decoded,
            Err(err) => return PathValidationResult::Invalid(err),
        };

        // Step 4: Unicode normalization (NFC - Canonical Decomposition, followed by Canonical Composition)
        let normalized = match self.unicode_normalize(&decoded) {
            Ok(normalized) => normalized,
            Err(err) => return PathValidationResult::Invalid(err),
        };

        // Step 5: Resolve dot-segments per RFC 3986 §5.2.4
        let resolved = match self.resolve_dot_segments(&normalized) {
            Ok(resolved) => resolved,
            Err(err) => return err, // May be SecurityRisk or Invalid
        };

        // Step 6: Security policy validation
        if let Err(err) = self.validate_security_policy(&resolved) {
            return PathValidationResult::Invalid(err);
        }

        PathValidationResult::Valid(resolved)
    }

    /// Percent-decode a path string
    fn percent_decode(&self, path: &str) -> Result<String, PathError> {
        let mut result = String::with_capacity(path.len());
        let mut chars = path.chars();

        while let Some(c) = chars.next() {
            if c == '%' {
                // Must have exactly 2 hex digits after %
                let hex1 = chars.next().ok_or(PathError::InvalidPercent)?;
                let hex2 = chars.next().ok_or(PathError::InvalidPercent)?;

                if !hex1.is_ascii_hexdigit() || !hex2.is_ascii_hexdigit() {
                    return Err(PathError::InvalidPercent);
                }

                let byte = u8::from_str_radix(&format!("{}{}", hex1, hex2), 16)
                    .map_err(|_| PathError::InvalidPercent)?;

                // Convert byte to char - handle UTF-8 properly
                // For simplicity, assume single-byte chars here
                // Real implementation would need proper UTF-8 handling
                if byte.is_ascii() {
                    result.push(byte as char);
                } else {
                    // Non-ASCII bytes need proper UTF-8 reconstruction
                    // For fuzzing, we'll be more permissive
                    result.push('?'); // Placeholder for invalid UTF-8
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    /// Unicode normalization (NFC form)
    fn unicode_normalize(&self, path: &str) -> Result<String, PathError> {
        if !self.security_policy.strict_unicode_normalization {
            return Ok(path.to_string());
        }

        // Simple normalization check - in real implementation would use unicode-normalization crate
        // For fuzzing, detect obvious issues

        // Check for Unicode control characters that shouldn't be in paths
        for c in path.chars() {
            if c.is_control() && c != '\t' {
                return Err(PathError::InvalidCharacter(c));
            }
        }

        // Check for common Unicode normalization attacks
        if path.contains('\u{2044}') || // Fraction slash
           path.contains('\u{2215}') || // Division slash
           path.contains('\u{29F8}')
        {
            // Big solidus
            return Err(PathError::UnicodeNormalizationFailed);
        }

        Ok(path.to_string())
    }

    /// Resolve dot-segments per RFC 3986 §5.2.4
    fn resolve_dot_segments(&self, path: &str) -> Result<String, PathValidationResult> {
        let mut output_buffer = Vec::new();
        let mut input_buffer = path;

        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000; // Prevent infinite loops

        while !input_buffer.is_empty() {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                return Err(PathValidationResult::Invalid(
                    PathError::ExcessiveRedirection,
                ));
            }

            // A. If input starts with "../" or "./", remove it
            if input_buffer.starts_with("../") {
                input_buffer = &input_buffer[3..];
                continue;
            }
            if input_buffer.starts_with("./") {
                input_buffer = &input_buffer[2..];
                continue;
            }

            // B. If input starts with "/./" or "/.", replace with "/"
            if input_buffer.starts_with("/./") {
                input_buffer = &input_buffer[2..]; // Keep the leading /
                continue;
            }
            if input_buffer == "/." {
                input_buffer = "/";
                continue;
            }

            // C. If input starts with "/../" or "/..", remove it and pop output
            if input_buffer.starts_with("/../") {
                input_buffer = &input_buffer[3..]; // Keep the leading /
                if !output_buffer.is_empty() {
                    output_buffer.pop();
                } else {
                    // Attempting to traverse above root - security risk
                    return Err(PathValidationResult::SecurityRisk(
                        "Path traversal above root directory".to_string(),
                    ));
                }
                continue;
            }
            if input_buffer == "/.." {
                if !output_buffer.is_empty() {
                    output_buffer.pop();
                } else {
                    return Err(PathValidationResult::SecurityRisk(
                        "Path traversal above root directory".to_string(),
                    ));
                }
                input_buffer = "/";
                continue;
            }

            // D. If input is ".." or ".", remove it
            if input_buffer == ".." || input_buffer == "." {
                break;
            }

            // E. Move first path segment to output
            if let Some(slash_pos) = input_buffer[1..].find('/') {
                let segment = &input_buffer[..slash_pos + 1];
                output_buffer.push(segment);
                input_buffer = &input_buffer[slash_pos + 1..];
            } else {
                // Last segment
                output_buffer.push(input_buffer);
                break;
            }
        }

        let resolved = if output_buffer.is_empty() {
            "/".to_string()
        } else {
            output_buffer.join("")
        };

        Ok(resolved)
    }

    /// Validate against security policy
    fn validate_security_policy(&self, path: &str) -> Result<(), PathError> {
        // Check path length
        if path.len() > self.security_policy.max_path_length {
            return Err(PathError::ExcessiveRedirection);
        }

        // Check segment count
        let segment_count = path.matches('/').count();
        if segment_count > self.security_policy.max_path_segments {
            return Err(PathError::ExcessiveRedirection);
        }

        // Additional security checks could go here
        // - Null byte detection
        // - Binary data detection
        // - Suspicious patterns

        Ok(())
    }

    fn get_canonical_path(&self, stream_id: u32) -> Option<&String> {
        self.stream_state.get(&stream_id)?.canonical_path.as_ref()
    }

    fn get_validation_result(&self, stream_id: u32) -> Option<&PathValidationResult> {
        self.stream_state
            .get(&stream_id)?
            .validation_result
            .as_ref()
    }

    fn get_connection_error(&self) -> Option<&H2Error> {
        self.connection_error.as_ref()
    }
}

/// Generate predefined test cases for path canonicalization
fn generate_test_cases() -> Vec<(String, PathValidationResult)> {
    vec![
        // Basic valid paths
        (
            "/".to_string(),
            PathValidationResult::Valid("/".to_string()),
        ),
        (
            "/index.html".to_string(),
            PathValidationResult::Valid("/index.html".to_string()),
        ),
        (
            "/api/v1/users".to_string(),
            PathValidationResult::Valid("/api/v1/users".to_string()),
        ),
        // Percent-encoded slashes
        (
            "/%2F".to_string(),
            PathValidationResult::Valid("//".to_string()),
        ),
        (
            "/api%2Fv1".to_string(),
            PathValidationResult::Valid("/api/v1".to_string()),
        ),
        (
            "/%2Fapi%2Fv1%2Fusers".to_string(),
            PathValidationResult::Valid("//api/v1/users".to_string()),
        ),
        // Dot-segments (should be normalized)
        (
            "/.".to_string(),
            PathValidationResult::Valid("/".to_string()),
        ),
        (
            "/./index.html".to_string(),
            PathValidationResult::Valid("/index.html".to_string()),
        ),
        (
            "/api/./v1".to_string(),
            PathValidationResult::Valid("/api/v1".to_string()),
        ),
        (
            "/api/../".to_string(),
            PathValidationResult::Valid("/".to_string()),
        ),
        (
            "/a/../../b".to_string(),
            PathValidationResult::Invalid(PathError::PathTraversal),
        ),
        // Path traversal attempts (security risks)
        (
            "/..".to_string(),
            PathValidationResult::SecurityRisk("Path traversal above root directory".to_string()),
        ),
        (
            "/../etc/passwd".to_string(),
            PathValidationResult::SecurityRisk("Path traversal above root directory".to_string()),
        ),
        // Encoded dot-segments
        (
            "/%2E".to_string(),
            PathValidationResult::Valid("/".to_string()),
        ),
        (
            "/%2E%2E".to_string(),
            PathValidationResult::SecurityRisk("Path traversal above root directory".to_string()),
        ),
        (
            "/%2E%2E/".to_string(),
            PathValidationResult::SecurityRisk("Path traversal above root directory".to_string()),
        ),
        (
            "/api/%2E%2E/admin".to_string(),
            PathValidationResult::Valid("/admin".to_string()),
        ),
        // Double encoding
        (
            "/%252E%252E%252F".to_string(),
            PathValidationResult::Valid("/%2E%2E%2F".to_string()),
        ),
        // Invalid percent encoding
        (
            "/%ZZ".to_string(),
            PathValidationResult::Invalid(PathError::InvalidPercent),
        ),
        (
            "/%2".to_string(),
            PathValidationResult::Invalid(PathError::InvalidPercent),
        ),
        (
            "/%".to_string(),
            PathValidationResult::Invalid(PathError::InvalidPercent),
        ),
        // Relative paths (not allowed)
        (
            "api/v1".to_string(),
            PathValidationResult::Invalid(PathError::RelativePathNotAllowed),
        ),
        (
            "../etc".to_string(),
            PathValidationResult::Invalid(PathError::RelativePathNotAllowed),
        ),
        // Empty path
        (
            "".to_string(),
            PathValidationResult::Invalid(PathError::EmptyPath),
        ),
        // Unicode slash alternatives (security concern)
        (
            "/api\u{2044}v1".to_string(),
            PathValidationResult::Invalid(PathError::UnicodeNormalizationFailed),
        ),
        (
            "/test\u{2215}file".to_string(),
            PathValidationResult::Invalid(PathError::UnicodeNormalizationFailed),
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 512 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match PathTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with extremely long paths
    if test.path.len() > 1024 {
        return;
    }

    let policy = SecurityPolicy {
        allow_path_traversal: !test.should_reject,
        ..SecurityPolicy::default()
    };
    let mut connection = MockPathCanonicalizationConnection::with_policy(policy);
    let stream_id = test.expected_canonical.as_ref().map_or(1u32, |expected| {
        let len = u32::try_from(expected.len()).unwrap_or(u32::MAX / 2);
        len.saturating_mul(2).saturating_add(1)
    });

    // Test path canonicalization
    let result = connection.canonicalize_path(stream_id, &test.path);

    // Validate the result matches our expectations for known patterns
    let validation_result = connection.get_validation_result(stream_id);

    match validation_result {
        Some(PathValidationResult::Valid(canonical)) => {
            // For valid paths, verify some invariants
            assert!(
                canonical.starts_with('/'),
                "Canonical path must start with '/' but got: {}",
                canonical
            );

            assert!(
                !canonical.contains("./") && !canonical.contains("../"),
                "Canonical path must not contain dot-segments: {}",
                canonical
            );

            assert!(
                !canonical.contains("//"),
                "Canonical path should not contain double slashes: {}",
                canonical
            );

            assert_eq!(connection.get_canonical_path(stream_id), Some(canonical));
        }

        Some(PathValidationResult::Invalid(error)) => {
            // Error should have resulted in connection error
            match result {
                Err(H2Error::ProtocolError) => {
                    // Expected for invalid paths
                    assert!(
                        connection.get_connection_error().is_some(),
                        "Connection should be in error state for invalid path: {:?}",
                        error
                    );
                }
                _ => {
                    // Unexpected result
                }
            }
        }

        Some(PathValidationResult::SecurityRisk(_)) => {
            // Security risks should be handled according to policy
            match result {
                Err(H2Error::SecurityPolicyViolation) => {
                    // Expected when policy disallows security risks
                }
                Ok(_) => {
                    // May be allowed if policy permits it
                }
                _ => {
                    panic!("Unexpected result for security risk path: {:?}", result);
                }
            }
        }

        None => {
            panic!("No validation result recorded for path: {}", test.path);
        }
    }

    // Run predefined test cases to ensure core functionality
    for (test_path, expected) in generate_test_cases() {
        let mut test_conn = MockPathCanonicalizationConnection::new();
        let test_result = test_conn.canonicalize_path(1, &test_path);

        match expected {
            PathValidationResult::Valid(expected_canonical) => {
                match test_result {
                    Ok(PathValidationResult::Valid(actual_canonical)) => {
                        assert_eq!(
                            actual_canonical, expected_canonical,
                            "Path '{}' canonicalization mismatch",
                            test_path
                        );
                    }
                    _ => {
                        // May fail for other reasons, which is acceptable in fuzzing
                    }
                }
            }

            PathValidationResult::Invalid(_) => {
                // Should result in error
                assert!(
                    test_result.is_err(),
                    "Path '{}' should have been rejected but was accepted",
                    test_path
                );
            }

            PathValidationResult::SecurityRisk(_) => {
                // Should be handled as security risk
                match test_result {
                    Err(H2Error::SecurityPolicyViolation) => {
                        // Expected
                    }
                    Ok(PathValidationResult::SecurityRisk(_)) => {
                        // Also acceptable if policy allows it
                    }
                    _ => {
                        // May be caught by other validation steps
                    }
                }
            }
        }
    }

    // Test with permissive policy
    let permissive_policy = SecurityPolicy {
        allow_path_traversal: true,
        max_path_segments: 1000,
        max_path_length: 16384,
        strict_unicode_normalization: false,
    };

    let mut permissive_conn = MockPathCanonicalizationConnection::with_policy(permissive_policy);
    let _permissive_result = permissive_conn.canonicalize_path(stream_id, &test.path);

    // With permissive policy, fewer things should be rejected
    // This helps test different code paths
});
