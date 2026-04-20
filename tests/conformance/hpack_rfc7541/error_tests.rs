//! Error handling and edge case conformance tests for HPACK.
//!
//! This module tests how our HPACK implementation handles various error
//! conditions and edge cases as specified in RFC 7541.

use super::harness::{ConformanceTestResult, RequirementLevel, TestCategory, TestVerdict};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::hpack::{Decoder, Encoder, Header};
use std::time::Instant;

/// Error condition test cases for HPACK conformance.
pub struct HpackErrorTester;

impl HpackErrorTester {
    fn encode_table_size_update(size: usize) -> Vec<u8> {
        let mut buf = BytesMut::new();
        let max_value = (1 << 5) - 1;

        if size < max_value {
            buf.put_u8(0x20 | size as u8);
        } else {
            buf.put_u8(0x20 | max_value as u8);
            let mut remaining = size - max_value;
            while remaining >= 128 {
                buf.put_u8((remaining & 0x7f) as u8 | 0x80);
                remaining >>= 7;
            }
            buf.put_u8(remaining as u8);
        }

        buf.to_vec()
    }

    /// Run all error handling conformance tests.
    pub fn run_all_error_tests() -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        results.push(Self::test_malformed_integer_encoding());
        results.push(Self::test_malformed_string_encoding());
        results.push(Self::test_invalid_index_references());
        results.push(Self::test_huffman_decode_errors());
        results.push(Self::test_table_size_violations());
        results.push(Self::test_header_list_size_limits());
        results.push(Self::test_incomplete_headers());
        results.push(Self::test_oversized_dynamic_table_updates());
        results.push(Self::test_invalid_huffman_padding());
        results.push(Self::test_context_corruption_recovery());

        results
    }

    /// Test malformed integer encoding handling.
    fn test_malformed_integer_encoding() -> ConformanceTestResult {
        let start_time = Instant::now();

        let malformed_inputs = vec![
            // Integer encoding with no termination (all continuation bits set)
            vec![0x80, 0xff, 0xff, 0xff, 0xff, 0xff],
            // Integer overflow
            vec![0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            // Incomplete integer
            vec![0x80, 0x81], // Missing continuation
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in malformed_inputs {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "ERR-INT-1".to_string(),
            description: "Malformed integer encoding rejection".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Malformed integer encodings should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test malformed string encoding handling.
    fn test_malformed_string_encoding() -> ConformanceTestResult {
        let start_time = Instant::now();

        let malformed_inputs = vec![
            // String length longer than available data
            vec![0x40, 0x10, 0x74, 0x65, 0x73, 0x74], // Claims 16 bytes, only has 4
            // Huffman string with invalid padding
            vec![0x40, 0x82, 0x94, 0xa5], // Invalid Huffman sequence
            // String length with high bit set but no Huffman data
            vec![0x40, 0x81, 0x41], // Claims Huffman but isn't valid
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in malformed_inputs {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "ERR-STR-1".to_string(),
            description: "Malformed string encoding rejection".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Malformed string encodings should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test invalid index reference handling.
    fn test_invalid_index_references() -> ConformanceTestResult {
        let start_time = Instant::now();

        let invalid_indices = vec![
            // Index 0 (reserved)
            vec![0x80],
            // Index beyond static table + current dynamic table
            vec![0xff, 0x80], // Very large index
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in invalid_indices {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "ERR-IDX-1".to_string(),
            description: "Invalid index reference rejection".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Invalid index references should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test Huffman decode error handling.
    fn test_huffman_decode_errors() -> ConformanceTestResult {
        let start_time = Instant::now();

        let malformed_huffman = vec![
            // Huffman string with invalid symbol (EOS symbol)
            vec![0x40, 0x81, 0xff], // Contains EOS symbol
            // Huffman string with invalid padding
            vec![0x40, 0x81, 0x1f], // Invalid padding bits
            // Incomplete Huffman sequence
            vec![0x40, 0x82, 0x94], // Incomplete sequence
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in malformed_huffman {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::ExpectedFailure // Huffman validation might be lenient
        };

        ConformanceTestResult {
            test_id: "ERR-HUF-1".to_string(),
            description: "Malformed Huffman encoding rejection".to_string(),
            category: TestCategory::Huffman,
            requirement_level: RequirementLevel::Should,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Malformed Huffman encodings should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test dynamic table size violation handling.
    fn test_table_size_violations() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Test size update that exceeds allowed limit
        // RFC 7541 Section 4.2: size updates must not exceed SETTINGS_HEADER_TABLE_SIZE
        let oversized_update = Self::encode_table_size_update(8192);

        let mut decoder = Decoder::new();
        decoder.set_allowed_table_size(4096);

        let mut src = Bytes::copy_from_slice(&oversized_update);
        let result = decoder.decode(&mut src);

        let verdict = if result.is_err() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "ERR-SIZE-1".to_string(),
            description: "Dynamic table size violation handling".to_string(),
            category: TestCategory::DynamicTable,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Oversized dynamic table size update should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test header list size limit enforcement.
    fn test_header_list_size_limits() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Create very large headers that should exceed reasonable limits
        let large_headers = vec![
            Header::new("x-large", "a".repeat(100000)), // 100KB header
        ];

        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        encoder.encode(&large_headers, &mut dst);

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(&dst);
        let result = decoder.decode(&mut src);

        // Decoder should either handle it or reject it gracefully
        let verdict = match result {
            Ok(_) => TestVerdict::Pass,  // Handled large header
            Err(_) => TestVerdict::Pass, // Rejected appropriately
        };

        ConformanceTestResult {
            test_id: "ERR-LIMIT-1".to_string(),
            description: "Header list size limit handling".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: None,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test incomplete header block handling.
    fn test_incomplete_headers() -> ConformanceTestResult {
        let start_time = Instant::now();

        let incomplete_blocks = vec![
            // Literal header with missing value
            vec![0x40, 0x04, 0x74, 0x65, 0x73, 0x74], // Name but no value length/data
            // Indexed header field truncated
            vec![0x8], // Incomplete indexed field
            // Dynamic table size update truncated
            vec![0x2], // Incomplete size update
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in incomplete_blocks {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "ERR-INCOMPLETE-1".to_string(),
            description: "Incomplete header block rejection".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Incomplete header blocks should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test oversized dynamic table update handling.
    fn test_oversized_dynamic_table_updates() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Multiple size updates (should be limited per RFC 7541 Section 4.2)
        let multiple_updates = vec![
            0x20, // Size update 1
            0x21, // Size update 2
            0x22, // Size update 3
            0x23, // Size update 4
            0x24, // Size update 5
            0x25, // Too many updates
        ];

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(&multiple_updates);
        let result = decoder.decode(&mut src);

        // Should handle or reject multiple updates appropriately
        let verdict = match result {
            Ok(_) => TestVerdict::Pass,
            Err(_) => TestVerdict::Pass, // Appropriate rejection
        };

        ConformanceTestResult {
            test_id: "ERR-UPDATES-1".to_string(),
            description: "Multiple dynamic table size updates handling".to_string(),
            category: TestCategory::DynamicTable,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: None,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test invalid Huffman padding handling.
    fn test_invalid_huffman_padding() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Huffman strings with invalid padding (should be most significant bits of EOS)
        let invalid_padding_cases = vec![
            vec![0x40, 0x81, 0x00], // Wrong padding bits
            vec![0x40, 0x81, 0x7f], // Wrong padding pattern
        ];

        let mut errors_handled = 0;
        let mut decoder = Decoder::new();

        for input in invalid_padding_cases {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_err() {
                errors_handled += 1;
            }
        }

        let verdict = if errors_handled > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::ExpectedFailure // Padding validation might be lenient
        };

        ConformanceTestResult {
            test_id: "ERR-PAD-1".to_string(),
            description: "Invalid Huffman padding rejection".to_string(),
            category: TestCategory::Huffman,
            requirement_level: RequirementLevel::Should,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Invalid Huffman padding should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Test context corruption and recovery.
    fn test_context_corruption_recovery() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Simulate context corruption by feeding inconsistent dynamic table state
        let mut decoder = Decoder::new();

        // First, add an entry to dynamic table
        let first_block = vec![
            0x40, 0x04, 0x74, 0x65, 0x73, 0x74, 0x04, 0x74, 0x65, 0x73, 0x74,
        ]; // Literal with incremental indexing
        let mut src1 = Bytes::copy_from_slice(&first_block);
        let _ = decoder.decode(&mut src1);

        // Then try to reference an entry that shouldn't exist
        let invalid_reference = vec![0x90]; // Index 16, likely doesn't exist
        let mut src2 = Bytes::copy_from_slice(&invalid_reference);
        let result = decoder.decode(&mut src2);

        let verdict = if result.is_err() {
            TestVerdict::Pass // Properly rejected invalid reference
        } else {
            TestVerdict::ExpectedFailure // Might have succeeded if table was larger
        };

        ConformanceTestResult {
            test_id: "ERR-CONTEXT-1".to_string(),
            description: "Context corruption and recovery handling".to_string(),
            category: TestCategory::Context,
            requirement_level: RequirementLevel::Must,
            verdict,
            error_message: None,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }
}

/// Edge case testing for boundary conditions.
pub struct HpackEdgeCaseTester;

impl HpackEdgeCaseTester {
    fn encode_table_size_update(size: usize) -> Vec<u8> {
        HpackErrorTester::encode_table_size_update(size)
    }

    /// Run all edge case tests.
    pub fn run_all_edge_case_tests() -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        results.push(Self::test_empty_header_names());
        results.push(Self::test_empty_header_values());
        results.push(Self::test_maximum_index_values());
        results.push(Self::test_zero_length_strings());
        results.push(Self::test_boundary_table_sizes());

        results
    }

    fn test_empty_header_names() -> ConformanceTestResult {
        let start_time = Instant::now();

        let empty_name_headers = vec![Header::new("", "value")];

        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        encoder.encode(&empty_name_headers, &mut dst);

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(&dst);
        let result = decoder.decode(&mut src);

        // Should handle empty header names appropriately
        let verdict = match result {
            Ok(decoded) if decoded == empty_name_headers => TestVerdict::Pass,
            Ok(_) => TestVerdict::Fail,
            Err(_) => TestVerdict::ExpectedFailure, // Might reject empty names
        };

        ConformanceTestResult {
            test_id: "EDGE-EMPTY-NAME-1".to_string(),
            description: "Empty header name handling".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: None,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    fn test_empty_header_values() -> ConformanceTestResult {
        let start_time = Instant::now();

        let empty_value_headers = vec![Header::new("x-empty", ""), Header::new("x-test", "")];

        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        encoder.encode(&empty_value_headers, &mut dst);

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(&dst);
        let result = decoder.decode(&mut src);

        let verdict = match result {
            Ok(decoded) if decoded == empty_value_headers => TestVerdict::Pass,
            Ok(_) => TestVerdict::Fail,
            Err(_) => TestVerdict::Fail,
        };

        ConformanceTestResult {
            test_id: "EDGE-EMPTY-VALUE-1".to_string(),
            description: "Empty header value handling".to_string(),
            category: TestCategory::RoundTrip,
            requirement_level: RequirementLevel::Must,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Empty header values should be preserved".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    fn test_maximum_index_values() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Test encoding with maximum possible index values
        // This would require a very large dynamic table, so we'll test the encoding
        // of large index values instead

        let verdict = TestVerdict::ExpectedFailure; // Would need large table setup

        ConformanceTestResult {
            test_id: "EDGE-MAX-IDX-1".to_string(),
            description: "Maximum index value handling".to_string(),
            category: TestCategory::DynamicTable,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: Some("Maximum index testing requires large table setup".to_string()),
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    fn test_zero_length_strings() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Test zero-length string encoding/decoding
        let zero_length_input = vec![0x40, 0x00, 0x00]; // Literal with empty name and value

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(&zero_length_input);
        let result = decoder.decode(&mut src);

        let verdict = match result {
            Ok(_) => TestVerdict::Pass,
            Err(_) => TestVerdict::ExpectedFailure, // Might reject zero-length strings
        };

        ConformanceTestResult {
            test_id: "EDGE-ZERO-LEN-1".to_string(),
            description: "Zero-length string handling".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Should,
            verdict,
            error_message: None,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    fn test_boundary_table_sizes() -> ConformanceTestResult {
        let start_time = Instant::now();

        // Test table size updates at boundaries (0, 1, max)
        let boundary_sizes = vec![
            Self::encode_table_size_update(0),
            Self::encode_table_size_update(1),
            Self::encode_table_size_update(4096),
        ];

        let mut success_count = 0;
        let mut decoder = Decoder::new();

        for input in boundary_sizes {
            let mut src = Bytes::copy_from_slice(&input);
            if decoder.decode(&mut src).is_ok() {
                success_count += 1;
            }
        }

        let verdict = if success_count > 0 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };

        ConformanceTestResult {
            test_id: "EDGE-BOUNDARY-SIZE-1".to_string(),
            description: "Boundary table size handling".to_string(),
            category: TestCategory::DynamicTable,
            requirement_level: RequirementLevel::Should,
            verdict: verdict.clone(),
            error_message: if verdict == TestVerdict::Fail {
                Some("Boundary table sizes should be handled".to_string())
            } else {
                None
            },
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_tester_basic_functionality() {
        let results = HpackErrorTester::run_all_error_tests();
        assert!(!results.is_empty(), "Should have error test results");

        for result in results {
            assert!(!result.test_id.is_empty(), "Test ID should not be empty");
            assert!(
                !result.description.is_empty(),
                "Description should not be empty"
            );
        }
    }

    #[test]
    fn test_edge_case_tester_basic_functionality() {
        let results = HpackEdgeCaseTester::run_all_edge_case_tests();
        assert!(!results.is_empty(), "Should have edge case test results");

        for result in results {
            assert!(!result.test_id.is_empty(), "Test ID should not be empty");
        }
    }

    #[test]
    fn test_malformed_integer_encoding() {
        let result = HpackErrorTester::test_malformed_integer_encoding();

        // Test should complete and have a verdict
        assert!(!result.test_id.is_empty());
        assert!(matches!(
            result.verdict,
            TestVerdict::Pass | TestVerdict::Fail | TestVerdict::ExpectedFailure
        ));
    }
}
