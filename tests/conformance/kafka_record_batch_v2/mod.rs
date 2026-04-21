#![allow(warnings)]
#![allow(clippy::all)]
//! Kafka RecordBatch v2 format conformance test suite per KIP-98.
//!
//! This test suite validates the Kafka RecordBatch v2 format implementation
//! against the KIP-98 specification for exactly-once delivery and transactional
//! messaging. It ensures our producer batching and wire format handling
//! conforms to the Kafka protocol specification.
//!
//! ## Test Coverage Areas
//!
//! - **Record Attribute Bits**: Compression, transactional, and control flags
//! - **Producer Identity**: ProducerId/epoch/sequence validation for exactly-once
//! - **Timestamp Encoding**: Delta encoding for compact representation
//! - **Variable-Length Encoding**: Varint encoding for key/value lengths
//! - **Headers Array**: Header encoding and parsing
//! - **Offset Management**: Base_offset and last_offset_delta relationships
//!
//! ## KIP-98 RecordBatch v2 Format
//!
//! Uses test vectors derived from librdkafka and Kafka source where possible
//! to ensure interoperability and specification compliance.

mod format;
mod golden_tests;
mod harness;
mod test_vectors;

// Public re-exports for conformance testing
pub use format::{RecordAttribute, RecordBatchV2, RecordV2, TimestampType};
pub use harness::{
    ConformanceTestResult, KafkaConformanceHarness, RequirementLevel, TestCategory, TestVerdict,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the complete KIP-98 RecordBatch v2 conformance test suite.
    #[test]
    #[allow(dead_code)]
    fn kip98_record_batch_v2_complete_conformance_suite() {
        let harness = KafkaConformanceHarness::new();
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
            "\nKIP-98 RecordBatch v2 Conformance: {passed}/{total} pass, {failed} fail, {xfail} expected-fail"
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
        let harness = KafkaConformanceHarness::new();

        // Test basic RecordBatch encoding/decoding functionality
        let record_batch = RecordBatchV2::new_test_batch();

        let encoded = harness.encode_record_batch(&record_batch);
        assert!(!encoded.is_empty(), "Encoding should produce output");

        let decoded = harness.decode_record_batch(&encoded);
        assert!(decoded.is_ok(), "Decoding should succeed");

        let decoded_batch = decoded.unwrap();
        assert_eq!(
            decoded_batch.record_count(),
            record_batch.record_count(),
            "Decoded record count should match"
        );
    }
}
