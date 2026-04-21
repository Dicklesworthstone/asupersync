//! RFC 9112 HTTP/1.1 conformance test suite.
//!
//! This test suite implements conformance testing for HTTP/1.1 per RFC 9112,
//! with focus on Section 7: Transfer Codings and chunked transfer-encoding.
//!
//! ## Test Coverage Areas
//!
//! - **Chunked Encoding**: RFC 9112 §7.1 chunked transfer-encoding
//! - **Chunk Extensions**: RFC 9112 §7.1.1 chunk-ext parameter handling
//! - **Trailer Fields**: RFC 9112 §7.1.2 trailer-field processing
//! - **Transfer Coding**: RFC 9112 §7 transfer coding stacking
//! - **Error Handling**: Malformed chunks, oversized headers, invalid hex
//! - **Line Ending Tolerance**: CRLF vs LF handling per RFC requirements
//! - **Case Sensitivity**: Hex chunk-size case variants
//!
//! ## Golden Test Approach
//!
//! Uses golden test files with known inputs/outputs for systematic validation
//! of edge cases and RFC compliance corner cases.

mod chunked_encoding_tests;
mod golden_test_vectors;
mod harness;

// Public re-exports for conformance testing
pub use harness::{
    H1ConformanceHarness, H1ConformanceResult, H1TestCategory, RequirementLevel, TestVerdict,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the complete RFC 9112 HTTP/1.1 conformance test suite.
    #[test]
    fn rfc9112_complete_conformance_suite() {
        let harness = H1ConformanceHarness::new();
        let results = harness.run_all_tests();

        let passed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .count();
        let xfail = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::ExpectedFailure)
            .count();
        let total = results.len();

        println!(
            "\nRFC 9112 HTTP/1.1 Conformance: {passed}/{total} pass, {failed} fail, {xfail} expected-fail"
        );

        // Assert no unexpected failures
        assert_eq!(failed, 0, "{failed} conformance tests failed unexpectedly");

        // Coverage requirement: ≥95% MUST clause coverage
        let must_tests: Vec<_> = results
            .iter()
            .filter(|r| r.requirement_level == RequirementLevel::Must)
            .collect();
        let must_passed = must_tests
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        let must_total = must_tests.len();
        let must_coverage = if must_total > 0 {
            (must_passed as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };

        assert!(
            must_coverage >= 95.0,
            "MUST clause coverage too low: {must_coverage:.1}% (target: ≥95%)"
        );
    }

    /// Validate test infrastructure is working correctly.
    #[test]
    fn validate_h1_conformance_infrastructure() {
        let harness = H1ConformanceHarness::new();

        // Test basic chunked encoding/decoding functionality
        let test_request = concat!(
            "POST /upload HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request(test_request);
        assert!(result.is_ok(), "Basic chunked decoding should succeed");

        let decoded = result.unwrap();
        assert_eq!(decoded.body, b"hello", "Decoded body should match");
    }

    /// Test chunked encoding edge cases from RFC 9112 §7.1.
    #[test]
    fn rfc9112_chunked_encoding_edge_cases() {
        let harness = H1ConformanceHarness::new();

        // Test chunk-ext parsing and preservation
        let chunk_ext_request = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5;ext=value\r\nhello\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request(chunk_ext_request);
        assert!(result.is_ok(), "Chunk-ext should be parsed correctly");

        // Test trailer fields after final chunk
        let trailer_request = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n",
            "X-Trailer: test\r\n",
            "\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request(trailer_request);
        assert!(result.is_ok(), "Trailer fields should be handled correctly");
        let trailer_request = result.unwrap();
        assert_eq!(trailer_request.body, b"hello");
        assert_eq!(
            trailer_request.trailers,
            vec![("X-Trailer".to_string(), "test".to_string())]
        );

        // Test hex case variants (lowercase/uppercase)
        let hex_case_request = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "A\r\nhelloworld\r\n",
            "a\r\nhelloworld\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request(hex_case_request);
        assert!(result.is_ok(), "Mixed case hex should be accepted");
        assert_eq!(result.unwrap().body, b"helloworldhelloworld");
    }

    /// Test error handling for malformed chunked encoding.
    #[test]
    fn rfc9112_chunked_encoding_error_handling() {
        let harness = H1ConformanceHarness::new();

        // Test oversized chunk size line
        let oversized_request = format!(
            "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\nhello\r\n0\r\n\r\n",
            "F".repeat(1000) // Oversized hex number
        );

        let result = harness.decode_chunked_request(oversized_request.as_bytes());
        assert!(result.is_err(), "Oversized chunk header should be rejected");

        // Test invalid hex characters
        let invalid_hex_request = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "G\r\nhello\r\n", // G is not valid hex
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request(invalid_hex_request);
        assert!(result.is_err(), "Invalid hex should be rejected");
    }

    /// Test that chunked decoding preserves the next pipelined request boundary.
    #[test]
    fn rfc9112_chunked_preserves_pipelined_followup() {
        let harness = H1ConformanceHarness::new();

        let pipelined_request = concat!(
            "POST /upload HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n\r\n",
            "GET /next HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "\r\n"
        )
        .as_bytes();

        let result = harness.decode_chunked_request_with_remainder(pipelined_request);
        assert!(
            result.is_ok(),
            "Chunked request with a pipelined follow-up should decode"
        );

        let (decoded, remaining) = result.unwrap();
        assert_eq!(decoded.body, b"hello");
        assert!(decoded.trailers.is_empty());
        assert!(
            remaining.starts_with(b"GET /next HTTP/1.1\r\n"),
            "Pipelined follow-up request must remain available after chunk decode"
        );
    }
}
