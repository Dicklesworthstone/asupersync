#![allow(warnings)]
#![allow(clippy::all)]
//! Huffman padding strictness validation tests.
//!
//! Tests RFC 7541 Appendix B Huffman padding validation requirements
//! to address DISC-003 - ensuring malformed Huffman padding is properly rejected.

use super::*;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::http::h2::hpack::Decoder;

/// Run all Huffman padding strictness validation tests.
#[allow(dead_code)]
pub fn run_huffman_padding_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_huffman_padding_validation());
    results.push(test_malformed_huffman_rejection());
    results.push(test_padding_length_validation());
    results.push(test_eos_symbol_validation());
    results.push(test_incomplete_symbol_rejection());

    results
}

/// RFC 7541 Appendix B: Huffman padding validation.
#[allow(dead_code)]
fn test_huffman_padding_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Valid Huffman encodings with correct padding
        let valid_huffman_samples = vec![
            (
                vec![
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
                "www.example.com",
                "valid encoding with proper padding",
            ),
            (
                vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf],
                "no-cache",
                "valid short encoding with padding",
            ),
            (
                vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
                "private",
                "valid encoding ending with padding bits",
            ),
        ];

        for (encoded_bytes, expected_text, description) in valid_huffman_samples {
            let decoded_result = huffman_decode(&encoded_bytes);

            match decoded_result {
                Ok(decoded) => {
                    let decoded_str = String::from_utf8(decoded)
                        .map_err(|e| format!("Decoded bytes are not valid UTF-8: {}", e))?;

                    if decoded_str != expected_text {
                        return Err(format!(
                            "Huffman decode mismatch for {}: expected '{}', got '{}'",
                            description, expected_text, decoded_str
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "Valid Huffman encoding was rejected ({}): {}",
                        description, e
                    ));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7541-B-HUFFMAN-PADDING",
        "Huffman padding validation for valid encodings",
        TestCategory::HeaderCompression,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7541 Appendix B: Malformed Huffman encoding rejection.
#[allow(dead_code)]
fn test_malformed_huffman_rejection() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Malformed Huffman encodings that should be rejected
        let malformed_huffman_samples = vec![
            (
                vec![0xff, 0xff, 0xff, 0xff], // All 1s - invalid padding
                "all ones padding (invalid)",
            ),
            (
                vec![0x80], // Single bit set in padding area
                "single bit in padding",
            ),
            (
                vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf, 0x80], // Valid sequence + invalid padding
                "valid sequence with invalid padding suffix",
            ),
            (
                vec![0x00, 0x00], // All zeros with incorrect length
                "all zeros with wrong length",
            ),
            (
                vec![
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x00,
                ], // Valid prefix + wrong padding
                "valid prefix with wrong padding",
            ),
        ];

        for (malformed_bytes, description) in malformed_huffman_samples {
            let decoded_result = huffman_decode(&malformed_bytes);

            if decoded_result.is_ok() {
                return Err(format!(
                    "Malformed Huffman encoding was accepted: {}",
                    description
                ));
            }

            // Verify the error indicates padding/format issue
            if let Err(error_msg) = decoded_result {
                if !error_msg.to_lowercase().contains("padding")
                    && !error_msg.to_lowercase().contains("invalid")
                    && !error_msg.to_lowercase().contains("malformed")
                {
                    return Err(format!(
                        "Error message for {} should mention padding/invalid format, got: {}",
                        description, error_msg
                    ));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7541-B-HUFFMAN-MALFORMED",
        "Malformed Huffman encoding rejection",
        TestCategory::HeaderCompression,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7541 Appendix B: Huffman padding length validation.
#[allow(dead_code)]
fn test_padding_length_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let padding_test_cases = vec![
            (
                vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf],
                true,
                "RFC Appendix C no-cache encoding with EOS-prefix padding",
            ),
            (
                vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xb8],
                false,
                "no-cache encoding with final padding bits cleared",
            ),
            (
                vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
                true,
                "RFC Appendix C private encoding with EOS-prefix padding",
            ),
            (
                vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x70],
                false,
                "private encoding with final padding bits cleared",
            ),
        ];

        for (encoded_bytes, should_be_valid, description) in padding_test_cases {
            let decode_result = huffman_decode(&encoded_bytes);

            if should_be_valid {
                if decode_result.is_err() {
                    return Err(format!(
                        "Valid padding case was rejected: {} - {:?}",
                        description,
                        decode_result.err()
                    ));
                }
            } else {
                if decode_result.is_ok() {
                    return Err(format!(
                        "Invalid padding case was accepted: {}",
                        description
                    ));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7541-B-HUFFMAN-PADDING-LENGTH",
        "Huffman padding length validation",
        TestCategory::HeaderCompression,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7541 Appendix B: EOS symbol validation in padding.
#[allow(dead_code)]
fn test_eos_symbol_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid_eos_terminated = vec![
            (
                vec![
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
                "www.example.com",
            ),
            (vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf], "no-cache"),
            (
                vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
                "private",
            ),
        ];

        for (encoded, expected_text) in valid_eos_terminated {
            let decoded = huffman_decode(&encoded)
                .map_err(|err| format!("valid EOS-terminated encoding rejected: {}", err))?;
            let decoded_str = String::from_utf8(decoded)
                .map_err(|err| format!("decoded bytes are not valid UTF-8: {}", err))?;
            if decoded_str != expected_text {
                return Err(format!(
                    "valid EOS-terminated encoding decoded to '{}', expected '{}'",
                    decoded_str, expected_text
                ));
            }
        }

        let invalid_patterns = vec![
            (
                vec![
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x00,
                ],
                "www.example.com with zero padding",
            ),
            (
                vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xb0],
                "no-cache with zero padding",
            ),
            (
                vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x00],
                "private with zero padding",
            ),
        ];

        for (encoded, description) in invalid_patterns {
            if huffman_decode(&encoded).is_ok() {
                return Err(format!(
                    "invalid EOS padding pattern was accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7541-B-HUFFMAN-EOS",
        "Huffman EOS symbol validation in padding",
        TestCategory::HeaderCompression,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7541 Appendix B: Incomplete symbol rejection.
#[allow(dead_code)]
fn test_incomplete_symbol_rejection() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test that incomplete symbols are properly rejected

        let incomplete_symbol_cases = vec![
            (
                vec![
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                ], // Missing final bits
                "truncated encoding missing padding",
            ),
            (
                vec![0x80, 0x00], // Incomplete symbol start
                "incomplete symbol at start",
            ),
            (
                vec![0xff, 0x80], // Symbol that doesn't complete properly
                "symbol without proper termination",
            ),
        ];

        for (incomplete_bytes, description) in incomplete_symbol_cases {
            let decode_result = huffman_decode(&incomplete_bytes);

            if decode_result.is_ok() {
                return Err(format!("Incomplete symbol was accepted: {}", description));
            }

            // Error should indicate incomplete/truncated symbol
            if let Err(error_msg) = decode_result {
                let error_lower = error_msg.to_lowercase();
                if !error_lower.contains("incomplete")
                    && !error_lower.contains("truncated")
                    && !error_lower.contains("invalid")
                {
                    return Err(format!(
                        "Error for incomplete symbol ({}) should mention incomplete/truncated, got: {}",
                        description, error_msg
                    ));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7541-B-HUFFMAN-INCOMPLETE",
        "Huffman incomplete symbol rejection",
        TestCategory::HeaderCompression,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[derive(Debug)]
enum HpackHuffmanError {
    Compression(String),
    MissingDecodedHeader,
}

impl std::fmt::Display for HpackHuffmanError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HpackHuffmanError::Compression(message) => write!(f, "{}", message),
            HpackHuffmanError::MissingDecodedHeader => {
                write!(f, "Invalid HPACK block: missing decoded header")
            }
        }
    }
}

fn huffman_decode(encoded: &[u8]) -> Result<Vec<u8>, HpackHuffmanError> {
    let mut header_block = BytesMut::new();

    // Literal Header Field without indexing, new name (RFC 7541 §6.2.2).
    header_block.put_u8(0x00);
    encode_plain_hpack_string(&mut header_block, b"x-huffman-test");
    encode_huffman_hpack_string(&mut header_block, encoded);

    let mut decoder = Decoder::new();
    let mut encoded_block = header_block.freeze();
    let decoded_headers = decoder
        .decode(&mut encoded_block)
        .map_err(|err| HpackHuffmanError::Compression(err.to_string()))?;
    let header = decoded_headers
        .into_iter()
        .next()
        .ok_or(HpackHuffmanError::MissingDecodedHeader)?;
    Ok(header.value.into_bytes())
}

fn encode_plain_hpack_string(dst: &mut BytesMut, value: &[u8]) {
    encode_hpack_integer(dst, value.len(), 7, 0x00);
    dst.extend_from_slice(value);
}

fn encode_huffman_hpack_string(dst: &mut BytesMut, value: &[u8]) {
    encode_hpack_integer(dst, value.len(), 7, 0x80);
    dst.extend_from_slice(value);
}

fn encode_hpack_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1_usize << prefix_bits).saturating_sub(1);

    if value < max_first {
        dst.put_u8(prefix | value as u8);
        return;
    }

    dst.put_u8(prefix | max_first as u8);
    let mut remaining = value - max_first;
    while remaining >= 128 {
        dst.put_u8((remaining & 0x7f) as u8 | 0x80);
        remaining >>= 7;
    }
    dst.put_u8(remaining as u8);
}

#[test]
fn real_hpack_huffman_padding_results_pass() {
    let results = run_huffman_padding_tests();
    assert!(
        results
            .iter()
            .all(|result| result.verdict == TestVerdict::Pass),
        "HPACK Huffman padding conformance failures: {:?}",
        results
    );
}
