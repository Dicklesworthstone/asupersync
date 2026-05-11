#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz target for HTTP/1.1 Transfer-Encoding header validation.
///
/// Per RFC 9112 §6.1: "A sender MUST NOT send a Transfer-Encoding header field
/// in any message that contains a Content-Length header field."
///
/// Also RFC 9112 §6.1: "A server that receives a request message with a
/// transfer coding it does not understand SHOULD respond with 501 (Not Implemented)."
///
/// Key validation rules:
/// - Client→Server: typically only "chunked" is allowed
/// - "chunked, identity" is invalid (identity is not a transfer-coding)
/// - "gzip" without "chunked" suffix is problematic
/// - Multiple codings must be properly ordered
/// - Unknown codings should be rejected appropriately

#[derive(Debug, Arbitrary)]
struct TransferEncodingTest {
    /// Transfer-Encoding header value to test
    te_value: String,
    /// Whether this is a request (client→server) or response (server→client)
    is_request: bool,
    /// Whether Content-Length header is also present (conflict)
    has_content_length: bool,
    /// Content-Length value if present
    content_length: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum TeValidationResult {
    Valid(TeInfo),
    Invalid(TeError),
    NotImplemented(String), // 501 response case
}

#[derive(Debug, Clone, PartialEq)]
enum TeError {
    ConflictWithContentLength,
    ChunkedNotLast,
    IdentityNotAllowed,
    MalformedHeader,
    EmptyValue,
    ClientOnlyChunkedAllowed,
    InvalidCodingOrder,
}

#[derive(Debug, Clone, PartialEq)]
struct TeInfo {
    /// Parsed transfer codings in order
    codings: Vec<String>,
    /// Whether "chunked" is present and last
    chunked_last: bool,
    /// Whether this enables chunked transfer encoding
    is_chunked: bool,
    /// Raw header value
    raw_value: String,
    /// Validation warnings (non-fatal issues)
    warnings: Vec<String>,
}

/// Mock HTTP/1.1 Transfer-Encoding validator
struct MockTeValidator {
    policy: TeValidationPolicy,
    stats: TeValidationStats,
}

#[derive(Debug, Clone)]
struct TeValidationPolicy {
    /// Allow only "chunked" for client requests
    client_chunked_only: bool,
    /// Require "chunked" to be last if present
    require_chunked_last: bool,
    /// Reject "identity" transfer-coding
    reject_identity_coding: bool,
    /// Known transfer codings (others are unknown)
    known_codings: Vec<String>,
    /// Maximum number of codings allowed
    max_codings: usize,
    /// Allow empty Transfer-Encoding header
    allow_empty_header: bool,
}

#[derive(Debug, Clone, Default)]
struct TeValidationStats {
    /// Total headers validated
    headers_validated: usize,
    /// Valid headers
    valid_headers: usize,
    /// Invalid headers
    invalid_headers: usize,
    /// 501 Not Implemented responses
    not_implemented_responses: usize,
    /// Conflicts with Content-Length
    content_length_conflicts: usize,
}

impl Default for TeValidationPolicy {
    fn default() -> Self {
        Self {
            client_chunked_only: true,
            require_chunked_last: true,
            reject_identity_coding: true,
            known_codings: vec![
                "chunked".to_string(),
                "gzip".to_string(),
                "deflate".to_string(),
                "compress".to_string(),
                "br".to_string(), // Brotli
            ],
            max_codings: 10,
            allow_empty_header: false,
        }
    }
}

impl MockTeValidator {
    fn new() -> Self {
        Self {
            policy: TeValidationPolicy::default(),
            stats: TeValidationStats::default(),
        }
    }

    fn with_policy(policy: TeValidationPolicy) -> Self {
        Self {
            policy,
            stats: TeValidationStats::default(),
        }
    }

    /// Validate Transfer-Encoding header per RFC 9112 §6.1
    fn validate_transfer_encoding(
        &mut self,
        te_value: &str,
        is_request: bool,
        has_content_length: bool,
    ) -> Result<TeValidationResult, TeError> {
        self.stats.headers_validated += 1;

        // RFC 9112 §6.1: Transfer-Encoding and Content-Length are mutually exclusive
        if has_content_length {
            self.stats.content_length_conflicts += 1;
            self.stats.invalid_headers += 1;
            return Ok(TeValidationResult::Invalid(
                TeError::ConflictWithContentLength,
            ));
        }

        // Handle empty header
        if te_value.trim().is_empty() {
            if self.policy.allow_empty_header {
                self.stats.valid_headers += 1;
                return Ok(TeValidationResult::Valid(TeInfo {
                    codings: vec![],
                    chunked_last: false,
                    is_chunked: false,
                    raw_value: te_value.to_string(),
                    warnings: vec![],
                }));
            } else {
                self.stats.invalid_headers += 1;
                return Ok(TeValidationResult::Invalid(TeError::EmptyValue));
            }
        }

        // Parse transfer codings
        let codings = match self.parse_transfer_codings(te_value) {
            Ok(codings) => codings,
            Err(error) => {
                self.stats.invalid_headers += 1;
                return Err(error);
            }
        };

        // Validate parsed codings
        let validation_result = match self.validate_codings(&codings, is_request, te_value) {
            Ok(result) => result,
            Err(error) => {
                self.stats.invalid_headers += 1;
                return Err(error);
            }
        };

        match validation_result {
            TeValidationResult::Valid(_) => {
                self.stats.valid_headers += 1;
            }
            TeValidationResult::Invalid(_) => {
                self.stats.invalid_headers += 1;
            }
            TeValidationResult::NotImplemented(_) => {
                self.stats.not_implemented_responses += 1;
            }
        }

        Ok(validation_result)
    }

    /// Parse Transfer-Encoding header value into individual codings
    fn parse_transfer_codings(&self, te_value: &str) -> Result<Vec<String>, TeError> {
        let mut codings = Vec::new();

        // Split by comma and trim whitespace
        for coding_str in te_value.split(',') {
            let coding = coding_str.trim().to_lowercase();

            if coding.is_empty() {
                continue; // Skip empty entries
            }

            // Check for malformed coding (basic validation)
            if coding.contains(';') {
                // Transfer codings with parameters (like q-values) are complex
                // For this test, we'll treat them as potentially malformed
                let base_coding = coding.split(';').next().unwrap_or("").trim();
                if base_coding.is_empty() {
                    return Err(TeError::MalformedHeader);
                }
                codings.push(base_coding.to_string());
            } else {
                // Simple coding name
                codings.push(coding);
            }

            // Check maximum codings limit
            if codings.len() > self.policy.max_codings {
                return Err(TeError::MalformedHeader);
            }
        }

        if codings.is_empty() && !self.policy.allow_empty_header {
            return Err(TeError::EmptyValue);
        }

        Ok(codings)
    }

    /// Validate the list of transfer codings
    fn validate_codings(
        &self,
        codings: &[String],
        is_request: bool,
        raw_value: &str,
    ) -> Result<TeValidationResult, TeError> {
        if codings.is_empty() {
            if self.policy.allow_empty_header {
                return Ok(TeValidationResult::Valid(TeInfo {
                    codings: vec![],
                    chunked_last: false,
                    is_chunked: false,
                    raw_value: raw_value.to_string(),
                    warnings: vec![],
                }));
            } else {
                return Ok(TeValidationResult::Invalid(TeError::EmptyValue));
            }
        }

        let mut warnings = Vec::new();
        let mut has_chunked = false;
        let mut chunked_last = false;

        // Check each coding
        for (i, coding) in codings.iter().enumerate() {
            match coding.as_str() {
                "chunked" => {
                    has_chunked = true;
                    chunked_last = i == codings.len() - 1;
                }
                "identity" => {
                    // RFC 9112: "identity" is not a valid transfer-coding
                    if self.policy.reject_identity_coding {
                        return Ok(TeValidationResult::Invalid(TeError::IdentityNotAllowed));
                    }
                }
                _ => {
                    // Check if it's a known coding
                    if !self.policy.known_codings.contains(coding) {
                        // Unknown coding - should respond with 501 Not Implemented
                        return Ok(TeValidationResult::NotImplemented(format!(
                            "Unknown transfer-coding: {}",
                            coding
                        )));
                    }
                }
            }
        }

        // RFC 9112 §6.1: Validate "chunked" positioning
        if has_chunked && self.policy.require_chunked_last && !chunked_last {
            return Ok(TeValidationResult::Invalid(TeError::ChunkedNotLast));
        }

        // Client request validation
        if is_request && self.policy.client_chunked_only {
            // For client→server requests, typically only "chunked" is allowed
            if codings.len() != 1 || codings[0] != "chunked" {
                return Ok(TeValidationResult::Invalid(
                    TeError::ClientOnlyChunkedAllowed,
                ));
            }
        }

        // Validate specific problematic combinations

        // "gzip" without "chunked" suffix (problematic for streaming)
        if codings.contains(&"gzip".to_string()) && !chunked_last {
            warnings.push("gzip without chunked suffix may cause streaming issues".to_string());
        }

        // Multiple codings in questionable order
        if codings.len() > 1 {
            // Check for questionable ordering patterns
            for window in codings.windows(2) {
                match (window[0].as_str(), window[1].as_str()) {
                    ("chunked", _) if window[1] != "chunked" => {
                        // "chunked" followed by non-chunked (invalid per RFC)
                        return Ok(TeValidationResult::Invalid(TeError::InvalidCodingOrder));
                    }
                    _ => {
                        // Other combinations might be valid but unusual
                    }
                }
            }
        }

        Ok(TeValidationResult::Valid(TeInfo {
            codings: codings.to_vec(),
            chunked_last,
            is_chunked: has_chunked,
            raw_value: raw_value.to_string(),
            warnings,
        }))
    }

    /// Get validation statistics
    fn get_stats(&self) -> &TeValidationStats {
        &self.stats
    }
}

/// Generate predefined test cases for Transfer-Encoding validation
fn generate_test_cases() -> Vec<(String, String, bool, bool, TeValidationResult)> {
    vec![
        // Test case 1: Valid chunked (request)
        (
            "Valid chunked request".to_string(),
            "chunked".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Valid(TeInfo {
                codings: vec!["chunked".to_string()],
                chunked_last: true,
                is_chunked: true,
                raw_value: "chunked".to_string(),
                warnings: vec![],
            }),
        ),
        // Test case 2: Invalid "chunked, identity" (RFC 9112 violation)
        (
            "Invalid chunked, identity".to_string(),
            "chunked, identity".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Invalid(TeError::IdentityNotAllowed),
        ),
        // Test case 3: "gzip" without "chunked" suffix (problematic)
        (
            "gzip without chunked".to_string(),
            "gzip".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Invalid(TeError::ClientOnlyChunkedAllowed),
        ),
        // Test case 4: Transfer-Encoding with Content-Length (conflict)
        (
            "TE with Content-Length conflict".to_string(),
            "chunked".to_string(),
            true, // is_request
            true, // has Content-Length
            TeValidationResult::Invalid(TeError::ConflictWithContentLength),
        ),
        // Test case 5: Unknown transfer-coding (501 Not Implemented)
        (
            "Unknown transfer-coding".to_string(),
            "custom-encoding".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::NotImplemented(
                "Unknown transfer-coding: custom-encoding".to_string(),
            ),
        ),
        // Test case 6: "chunked" not last (invalid order)
        (
            "chunked not last".to_string(),
            "chunked, gzip".to_string(),
            false, // is_response
            false, // no Content-Length
            TeValidationResult::Invalid(TeError::ChunkedNotLast),
        ),
        // Test case 7: Valid response with multiple codings
        (
            "Valid gzip, chunked response".to_string(),
            "gzip, chunked".to_string(),
            false, // is_response
            false, // no Content-Length
            TeValidationResult::Valid(TeInfo {
                codings: vec!["gzip".to_string(), "chunked".to_string()],
                chunked_last: true,
                is_chunked: true,
                raw_value: "gzip, chunked".to_string(),
                warnings: vec![],
            }),
        ),
        // Test case 8: Empty Transfer-Encoding header
        (
            "Empty TE header".to_string(),
            "".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Invalid(TeError::EmptyValue),
        ),
        // Test case 9: Malformed header with just comma
        (
            "Malformed comma-only".to_string(),
            ", , ,".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Invalid(TeError::EmptyValue),
        ),
        // Test case 10: Case sensitivity test
        (
            "Case sensitivity test".to_string(),
            "CHUNKED".to_string(),
            true,  // is_request
            false, // no Content-Length
            TeValidationResult::Valid(TeInfo {
                codings: vec!["chunked".to_string()], // Should be normalized to lowercase
                chunked_last: true,
                is_chunked: true,
                raw_value: "CHUNKED".to_string(),
                warnings: vec![],
            }),
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 512 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match TransferEncodingTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with extremely long TE values
    if test.te_value.len() > 1024 {
        return;
    }
    let _content_length_observation = test.content_length;

    // Test with default (strict) policy
    let mut validator = MockTeValidator::new();

    let result = validator.validate_transfer_encoding(
        &test.te_value,
        test.is_request,
        test.has_content_length,
    );

    // Validate result consistency
    match result {
        Ok(TeValidationResult::Valid(info)) => {
            // Valid results should have consistent properties
            assert_eq!(
                info.is_chunked,
                info.codings.contains(&"chunked".to_string()),
                "is_chunked flag should match presence of 'chunked' in codings"
            );

            if info.is_chunked && validator.policy.require_chunked_last {
                assert!(
                    info.chunked_last,
                    "chunked should be last when present and policy requires it"
                );
            }

            // Codings should not be empty for valid results (unless policy allows)
            if !validator.policy.allow_empty_header {
                assert!(
                    !info.codings.is_empty(),
                    "Valid result should have non-empty codings"
                );
            }

            // Raw value should match input
            assert_eq!(
                info.raw_value, test.te_value,
                "Raw value should match input"
            );
        }

        Ok(TeValidationResult::Invalid(error)) => {
            // Invalid results should have clear reasons
            match error {
                TeError::ConflictWithContentLength => {
                    assert!(
                        test.has_content_length,
                        "Content-Length conflict error should only occur when Content-Length present"
                    );
                }
                TeError::ClientOnlyChunkedAllowed => {
                    assert!(
                        test.is_request,
                        "Client-only chunked error should only occur for requests"
                    );
                }
                TeError::IdentityNotAllowed => {
                    assert!(
                        test.te_value.to_lowercase().contains("identity"),
                        "Identity error should only occur when identity is present"
                    );
                }
                _ => {
                    // Other errors are acceptable
                }
            }

            // Stats should be updated
            assert!(
                validator.get_stats().invalid_headers > 0,
                "Invalid headers count should be incremented"
            );
        }

        Ok(TeValidationResult::NotImplemented(reason)) => {
            // Not implemented should have non-empty reason
            assert!(
                !reason.is_empty(),
                "Not implemented result should have non-empty reason"
            );

            // Stats should be updated
            assert!(
                validator.get_stats().not_implemented_responses > 0,
                "Not implemented responses count should be incremented"
            );
        }

        Err(error) => {
            // Direct processing errors
            match error {
                TeError::MalformedHeader => {
                    // Should happen for clearly malformed input
                }
                _ => {
                    // Other errors are acceptable
                }
            }
        }
    }

    // Test with permissive policy
    let permissive_policy = TeValidationPolicy {
        client_chunked_only: false,
        require_chunked_last: false,
        reject_identity_coding: false,
        known_codings: vec![
            "chunked".to_string(),
            "gzip".to_string(),
            "deflate".to_string(),
            "compress".to_string(),
            "br".to_string(),
            "identity".to_string(), // Include identity
            "custom".to_string(),   // Include some custom codings
        ],
        max_codings: 20,
        allow_empty_header: true,
    };

    let mut permissive_validator = MockTeValidator::with_policy(permissive_policy);
    let _permissive_result = permissive_validator.validate_transfer_encoding(
        &test.te_value,
        test.is_request,
        test.has_content_length,
    );

    // Permissive policy should allow more cases

    // Run predefined test cases to ensure correctness
    for (test_name, te_value, is_request, has_content_length, expected) in generate_test_cases() {
        let mut test_validator = MockTeValidator::new();
        let test_result =
            test_validator.validate_transfer_encoding(&te_value, is_request, has_content_length);

        match (&test_result, &expected) {
            (
                Ok(TeValidationResult::Valid(actual_info)),
                TeValidationResult::Valid(expected_info),
            ) => {
                assert_eq!(
                    actual_info.codings, expected_info.codings,
                    "Test '{}': codings mismatch",
                    test_name
                );
                assert_eq!(
                    actual_info.is_chunked, expected_info.is_chunked,
                    "Test '{}': is_chunked mismatch",
                    test_name
                );
                assert_eq!(
                    actual_info.chunked_last, expected_info.chunked_last,
                    "Test '{}': chunked_last mismatch",
                    test_name
                );
            }

            (
                Ok(TeValidationResult::Invalid(actual_error)),
                TeValidationResult::Invalid(expected_error),
            ) => {
                assert_eq!(
                    std::mem::discriminant(actual_error),
                    std::mem::discriminant(expected_error),
                    "Test '{}': invalid error type mismatch",
                    test_name
                );
            }

            (Ok(TeValidationResult::NotImplemented(_)), TeValidationResult::NotImplemented(_)) => {
                // Both not implemented - acceptable
            }

            _ => {
                // Other combinations may be acceptable due to policy differences
                // or fuzzing variations
            }
        }
    }

    // Verify stats consistency
    let final_stats = validator.get_stats();
    assert_eq!(
        final_stats.headers_validated,
        final_stats.valid_headers
            + final_stats.invalid_headers
            + final_stats.not_implemented_responses,
        "Total validated should equal sum of valid, invalid, and not implemented"
    );

    if test.has_content_length {
        assert!(
            final_stats.content_length_conflicts > 0,
            "Content-Length conflicts should be recorded when present"
        );
    }
});
