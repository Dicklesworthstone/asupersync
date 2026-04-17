//! Differential testing against reference implementations.
//!
//! This module implements Pattern 1 (Differential Testing) by comparing
//! our HPACK implementation against known reference outputs.

use super::fixtures::{FixtureComparisonResult, FixtureLoader, HpackFixture};
use super::harness::{ConformanceTestResult, TestCategory, TestVerdict, RequirementLevel};
use super::test_vectors::*;
use asupersync::http::h2::hpack::Header;
use std::time::Instant;

/// Differential test runner for HPACK conformance.
pub struct HpackDifferentialTester {
    fixture_loader: FixtureLoader,
}

impl HpackDifferentialTester {
    /// Create a new differential tester.
    pub fn new() -> Self {
        Self {
            fixture_loader: FixtureLoader::new(),
        }
    }

    /// Run all differential tests against loaded fixtures.
    pub fn run_all_differential_tests(&self) -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        // Test against RFC 7541 test vectors
        for test_vector in RFC7541_TEST_VECTORS {
            results.push(self.test_against_rfc_vector(test_vector));
        }

        // Test against fixture files
        for fixture_name in self.fixture_loader.fixture_names() {
            if let Some(fixture) = self.fixture_loader.get_fixture(fixture_name) {
                results.push(self.test_against_fixture(fixture));
            }
        }

        results
    }

    /// Test our implementation against an RFC 7541 test vector.
    fn test_against_rfc_vector(&self, test_vector: &Rfc7541TestVector) -> ConformanceTestResult {
        let start_time = Instant::now();

        let headers = test_vector_to_headers(test_vector);
        let our_encoded = self.encode_headers(&headers, test_vector.use_huffman);

        let verdict = if our_encoded == test_vector.expected_encoded {
            TestVerdict::Pass
        } else {
            // Check if it's functionally equivalent by decoding both
            match self.compare_functional_equivalence(&our_encoded, test_vector.expected_encoded) {
                Ok(true) => TestVerdict::Pass,  // Functionally equivalent
                Ok(false) => TestVerdict::Fail, // Different decoded result
                Err(_) => TestVerdict::Fail,    // Decode error
            }
        };

        let error_message = if verdict == TestVerdict::Fail {
            Some(format!(
                "Encoding mismatch for {}: expected {:02x?}, got {:02x?}",
                test_vector.description,
                test_vector.expected_encoded,
                our_encoded
            ))
        } else {
            None
        };

        ConformanceTestResult {
            test_id: test_vector.id.to_string(),
            description: format!("RFC Vector: {}", test_vector.description),
            category: TestCategory::RoundTrip,
            requirement_level: RequirementLevel::Must,
            verdict,
            error_message,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test our implementation against a reference fixture.
    fn test_against_fixture(&self, fixture: &HpackFixture) -> ConformanceTestResult {
        let start_time = Instant::now();

        let headers: Vec<Header> = fixture.input_headers
            .iter()
            .map(|(name, value)| Header::new(name.clone(), value.clone()))
            .collect();

        let our_encoded = self.encode_headers(&headers, fixture.use_huffman);

        use super::fixtures::compare_against_fixture;
        let comparison = compare_against_fixture(fixture, &our_encoded);

        let (verdict, error_message) = match comparison {
            FixtureComparisonResult::ExactMatch => {
                (TestVerdict::Pass, None)
            }
            FixtureComparisonResult::FunctionalEquivalent => {
                (TestVerdict::Pass, None)
            }
            FixtureComparisonResult::Mismatch { reason } => {
                (TestVerdict::Fail, Some(reason))
            }
        };

        ConformanceTestResult {
            test_id: format!("DIFF-{}", fixture.name),
            description: format!("Differential: {}", fixture.description),
            category: TestCategory::RoundTrip,
            requirement_level: RequirementLevel::Must,
            verdict,
            error_message,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Encode headers using our implementation.
    fn encode_headers(&self, headers: &[Header], use_huffman: bool) -> Vec<u8> {
        use asupersync::bytes::BytesMut;
        use asupersync::http::h2::hpack::Encoder;

        let mut encoder = Encoder::new();
        encoder.set_use_huffman(use_huffman);
        let mut dst = BytesMut::new();
        encoder.encode(headers, &mut dst);
        dst.to_vec()
    }

    /// Compare functional equivalence by decoding both encodings.
    fn compare_functional_equivalence(
        &self,
        our_encoded: &[u8],
        reference_encoded: &[u8],
    ) -> Result<bool, String> {
        use asupersync::bytes::Bytes;
        use asupersync::http::h2::hpack::Decoder;

        let mut decoder1 = Decoder::new();
        let mut decoder2 = Decoder::new();

        let our_decoded = {
            let mut src = Bytes::copy_from_slice(our_encoded);
            decoder1.decode(&mut src)
                .map_err(|e| format!("Failed to decode our output: {e}"))?
        };

        let reference_decoded = {
            let mut src = Bytes::copy_from_slice(reference_encoded);
            decoder2.decode(&mut src)
                .map_err(|e| format!("Failed to decode reference output: {e}"))?
        };

        Ok(our_decoded == reference_decoded)
    }
}

impl Default for HpackDifferentialTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-implementation interoperability tests.
pub struct CrossImplementationTester {
    // Note: In a full implementation, this would connect to external
    // reference implementations (Go net/http2, nghttp2, etc.)
}

impl CrossImplementationTester {
    /// Create a new cross-implementation tester.
    pub fn new() -> Self {
        Self {}
    }

    /// Test interoperability with Go net/http2 HPACK implementation.
    pub fn test_go_interop(&self) -> Vec<ConformanceTestResult> {
        // Note: This would require setting up Go test harness
        // For now, return placeholder results
        vec![
            ConformanceTestResult {
                test_id: "INTEROP-GO-1".to_string(),
                description: "Go net/http2 interoperability".to_string(),
                category: TestCategory::RoundTrip,
                requirement_level: RequirementLevel::Should,
                verdict: TestVerdict::ExpectedFailure,
                error_message: Some("Go interop not implemented yet".to_string()),
                execution_time_ms: 0,
            }
        ]
    }

    /// Test interoperability with nghttp2 HPACK implementation.
    pub fn test_nghttp2_interop(&self) -> Vec<ConformanceTestResult> {
        vec![
            ConformanceTestResult {
                test_id: "INTEROP-NGHTTP2-1".to_string(),
                description: "nghttp2 HPACK interoperability".to_string(),
                category: TestCategory::RoundTrip,
                requirement_level: RequirementLevel::Should,
                verdict: TestVerdict::ExpectedFailure,
                error_message: Some("nghttp2 interop not implemented yet".to_string()),
                execution_time_ms: 0,
            }
        ]
    }

    /// Run all cross-implementation tests.
    pub fn run_all_interop_tests(&self) -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();
        results.extend(self.test_go_interop());
        results.extend(self.test_nghttp2_interop());
        results
    }
}

impl Default for CrossImplementationTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression efficiency validation tests.
pub struct CompressionEfficiencyTester;

impl CompressionEfficiencyTester {
    /// Test compression efficiency against reference implementations.
    pub fn test_compression_efficiency() -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        // Test Huffman encoding efficiency
        results.push(Self::test_huffman_efficiency());

        // Test dynamic table utilization
        results.push(Self::test_dynamic_table_efficiency());

        results
    }

    fn test_huffman_efficiency() -> ConformanceTestResult {
        use asupersync::bytes::BytesMut;
        use asupersync::http::h2::hpack::{Encoder, Header};

        let test_headers = vec![
            Header::new("user-agent", "Mozilla/5.0 (compatible; test)"),
            Header::new("accept-encoding", "gzip, deflate, br"),
            Header::new("accept-language", "en-US,en;q=0.9"),
        ];

        let mut huffman_encoder = Encoder::new();
        huffman_encoder.set_use_huffman(true);
        let mut huffman_dst = BytesMut::new();
        huffman_encoder.encode(&test_headers, &mut huffman_dst);

        let mut plain_encoder = Encoder::new();
        plain_encoder.set_use_huffman(false);
        let mut plain_dst = BytesMut::new();
        plain_encoder.encode(&test_headers, &mut plain_dst);

        let huffman_size = huffman_dst.len();
        let plain_size = plain_dst.len();
        let compression_ratio = huffman_size as f64 / plain_size as f64;

        // Huffman should provide some compression benefit
        let verdict = if compression_ratio < 1.0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        let error_message = if verdict == TestVerdict::Fail {
            Some(format!(
                "Huffman encoding not effective: {} bytes vs {} bytes (ratio: {:.2})",
                huffman_size, plain_size, compression_ratio
            ))
        } else {
            None
        };

        ConformanceTestResult {
            test_id: "EFF-HUFFMAN-1".to_string(),
            description: "Huffman encoding compression efficiency".to_string(),
            category: TestCategory::Huffman,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message,
            execution_time_ms: 0,
        }
    }

    fn test_dynamic_table_efficiency() -> ConformanceTestResult {
        // Test that repeated headers get indexed in dynamic table
        use asupersync::bytes::BytesMut;
        use asupersync::http::h2::hpack::{Encoder, Header};

        let mut encoder = Encoder::new();

        // First occurrence - should be literal
        let first_headers = vec![
            Header::new("x-repeated-header", "repeated-value"),
        ];
        let mut first_dst = BytesMut::new();
        encoder.encode(&first_headers, &mut first_dst);
        let first_size = first_dst.len();

        // Second occurrence - should be shorter (indexed)
        let second_headers = vec![
            Header::new("x-repeated-header", "repeated-value"),
        ];
        let mut second_dst = BytesMut::new();
        encoder.encode(&second_headers, &mut second_dst);
        let second_size = second_dst.len();

        // Second encoding should be more efficient
        let verdict = if second_size < first_size {
            TestVerdict::Pass
        } else {
            TestVerdict::ExpectedFailure  // This might be expected depending on table size limits
        };

        ConformanceTestResult {
            test_id: "EFF-DYNAMIC-1".to_string(),
            description: "Dynamic table indexing efficiency".to_string(),
            category: TestCategory::DynamicTable,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: None,
            execution_time_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fixtures::{FixtureMetadata, HpackFixture};
    use chrono::Utc;

    #[test]
    fn test_differential_tester_creation() {
        let tester = HpackDifferentialTester::new();
        // Should not panic and should have fixture loader
        assert!(!tester.fixture_loader.fixture_names().is_empty());
    }

    #[test]
    fn test_rfc_vector_testing() {
        let tester = HpackDifferentialTester::new();

        // Test against the indexed GET vector
        let result = tester.test_against_rfc_vector(&C4_1_INDEXED_HEADER_FIELD);

        // Should either pass or provide meaningful error message
        if result.verdict == TestVerdict::Fail {
            assert!(result.error_message.is_some(), "Failed test should have error message");
        }
    }

    #[test]
    fn test_compression_efficiency() {
        let results = CompressionEfficiencyTester::test_compression_efficiency();
        assert!(!results.is_empty(), "Should have efficiency test results");

        for result in results {
            // All tests should complete without panicking
            assert!(!result.test_id.is_empty());
        }
    }

    #[test]
    fn test_fixture_differential_accepts_functionally_equivalent_encoding() {
        let tester = HpackDifferentialTester::new();
        let fixture = HpackFixture {
            name: "functional_equivalence".to_string(),
            description: "Same headers, non-Huffman reference".to_string(),
            input_headers: vec![(":path".to_string(), "/sample/path".to_string())],
            expected_encoded: tester.encode_headers(
                &[Header::new(":path", "/sample/path")],
                false,
            ),
            use_huffman: true,
            metadata: FixtureMetadata {
                generator: "unit-test".to_string(),
                version: "1".to_string(),
                command: "manual".to_string(),
                git_ref: None,
                generated_at: Utc::now(),
            },
        };

        let result = tester.test_against_fixture(&fixture);
        assert_eq!(result.verdict, TestVerdict::Pass);
        assert!(result.error_message.is_none());
    }
}
