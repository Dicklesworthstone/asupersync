#![allow(warnings)]
#![allow(clippy::all)]
//! RFC 7541 HPACK conformance test suite.
//!
//! This test suite implements Pattern 1 (Differential Testing) conformance harness
//! for HPACK header compression per RFC 7541. It validates our implementation
//! against reference test vectors and ensures spec compliance.
//!
//! ## Test Coverage Areas
//!
//! - **Static Table Compliance**: RFC 7541 Appendix A static table entries
//! - **Dynamic Table Management**: Section 4.1-4.3 table operations
//! - **Indexing Strategies**: Sections 6.1-6.3 literal/indexed representations
//! - **Huffman Encoding**: Appendix B Huffman code compliance
//! - **Context Management**: Table size updates and synchronization
//! - **Error Recovery**: Invalid input and malformed header handling
//!
//! ## RFC 7541 Test Vectors
//!
//! Uses test vectors from RFC 7541 Appendix C for systematic validation.

mod differential_tests;
mod error_tests;
mod fixtures;
mod harness;
mod test_vectors;

// Public re-exports for conformance testing
pub use harness::{HpackConformanceHarness, RequirementLevel, TestCategory, TestVerdict};

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the complete RFC 7541 conformance test suite.
    #[test]
    #[allow(dead_code)]
    fn rfc7541_complete_conformance_suite() {
        let harness = HpackConformanceHarness::new();
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
            "\nRFC 7541 HPACK Conformance: {passed}/{total} pass, {failed} fail, {xfail} expected-fail"
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
        let must_coverage = (must_passed as f64 / must_total as f64) * 100.0;

        assert!(
            must_coverage >= 95.0,
            "MUST clause coverage too low: {must_coverage:.1}% (target: ≥95%)"
        );
    }

    /// Validate test infrastructure is working correctly.
    #[test]
    #[allow(dead_code)]
    fn validate_conformance_infrastructure() {
        let harness = HpackConformanceHarness::new();

        // Test basic encoder/decoder functionality
        let test_headers = vec![
            asupersync::http::h2::hpack::Header::new(":method", "GET"),
            asupersync::http::h2::hpack::Header::new(":path", "/test"),
        ];

        let encoded = harness.encode_headers(&test_headers, true);
        assert!(!encoded.is_empty(), "Encoding should produce output");

        let decoded = harness.decode_headers(&encoded);
        assert!(decoded.is_ok(), "Decoding should succeed");

        let decoded_headers = decoded.unwrap();
        assert_eq!(
            decoded_headers.len(),
            test_headers.len(),
            "Decoded header count should match"
        );
    }
}
