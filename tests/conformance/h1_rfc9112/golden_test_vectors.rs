//! Golden test vectors for RFC 9112 HTTP/1.1 chunked encoding.
//!
//! Contains known-good test cases from RFC examples and edge cases
//! that implementations should handle correctly.

use super::harness::H1ConformanceHarness;

/// RFC 9112 Example chunked request from Section 7.1.
pub const RFC9112_EXAMPLE_CHUNKED: &[u8] = concat!(
    "POST /upload HTTP/1.1\r\n",
    "Host: example.com\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "7\r\n",
    "Mozilla\r\n",
    "11\r\n",
    " Developer Network\r\n",
    "0\r\n",
    "\r\n"
)
.as_bytes();

/// Expected result for RFC 9112 example.
pub const RFC9112_EXAMPLE_EXPECTED_BODY: &[u8] = b"Mozilla Developer Network";

/// Chunked request with extensions (RFC 9112 §7.1.1).
pub const CHUNKED_WITH_EXTENSIONS: &[u8] = concat!(
    "POST /upload HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "7;charset=utf-8\r\n",
    "Mozilla\r\n",
    "11;lang=en\r\n",
    " Developer Network\r\n",
    "0\r\n",
    "\r\n"
)
.as_bytes();

/// Chunked request with trailer fields (RFC 9112 §7.1.2).
pub const CHUNKED_WITH_TRAILERS: &[u8] = concat!(
    "POST /upload HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "7\r\n",
    "Mozilla\r\n",
    "11\r\n",
    " Developer Network\r\n",
    "0\r\n",
    "Content-MD5: Q2h1Y2sgSW50ZWdyaXR5IQ==\r\n",
    "X-Content-Length: 25\r\n",
    "\r\n"
)
.as_bytes();

/// Mixed case hex digits.
pub const CHUNKED_MIXED_CASE_HEX: &[u8] = concat!(
    "POST /test HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "A\r\n", // Uppercase A = 10
    "0123456789\r\n",
    "a\r\n", // Lowercase a = 10
    "abcdefghij\r\n",
    "1F\r\n", // Mixed case 1F = 31
    "This chunk is exactly 31 chars!\r\n",
    "0\r\n",
    "\r\n"
)
.as_bytes();

/// Expected body for mixed case hex test.
pub const MIXED_CASE_HEX_EXPECTED_BODY: &[u8] =
    b"0123456789abcdefghijThis chunk is exactly 31 chars!";

/// Complex chunk extensions with quoted strings.
pub const CHUNKED_COMPLEX_EXTENSIONS: &[u8] = concat!(
    "POST /complex HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "5;name=\"quoted value\";other=simple\r\n",
    "hello\r\n",
    "6;empty=\"\";flag\r\n", // Empty quoted string and flag-only extension
    " world\r\n",
    "0\r\n",
    "\r\n"
)
.as_bytes();

/// Expected body for complex extensions.
pub const COMPLEX_EXTENSIONS_EXPECTED_BODY: &[u8] = b"hello world";

/// Large chunk size in various hex formats.
pub const CHUNKED_LARGE_HEX_VARIANTS: &[u8] = concat!(
    "POST /large HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "100\r\n", // 256 in decimal
)
.as_bytes();

// Note: The actual 256-byte data would be generated in tests

/// Edge case: Single byte chunks.
pub const CHUNKED_SINGLE_BYTES: &[u8] = concat!(
    "POST /single HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "1\r\nH\r\n",
    "1\r\ne\r\n",
    "1\r\nl\r\n",
    "1\r\nl\r\n",
    "1\r\no\r\n",
    "0\r\n",
    "\r\n"
)
.as_bytes();

/// Expected body for single bytes.
pub const SINGLE_BYTES_EXPECTED_BODY: &[u8] = b"Hello";

/// Malformed chunked requests that should be rejected.
pub mod malformed {
    /// Chunk size with leading whitespace (RFC violation).
    pub const LEADING_WHITESPACE: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        " 5\r\nhello\r\n", // Leading space before chunk size
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Chunk size with trailing whitespace (RFC violation).
    pub const TRAILING_WHITESPACE: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5 \r\nhello\r\n", // Trailing space after chunk size
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Invalid hex characters.
    pub const INVALID_HEX: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "G\r\nhello\r\n", // G is not valid hex
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Missing final chunk.
    pub const MISSING_FINAL_CHUNK: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello\r\n" // Missing "0\r\n\r\n"
    )
    .as_bytes();

    /// Chunk data length mismatch.
    pub const LENGTH_MISMATCH: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello world\r\n", // Data is longer than chunk size (5)
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Empty chunk size line.
    pub const EMPTY_CHUNK_SIZE: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "\r\nhello\r\n", // Empty line where chunk size should be
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Negative chunk size.
    pub const NEGATIVE_CHUNK_SIZE: &[u8] = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "-5\r\nhello\r\n", // Negative sign is not valid hex
        "0\r\n\r\n"
    )
    .as_bytes();

    /// Oversized chunk size.
    pub const OVERSIZED_CHUNK_SIZE: &str = "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nhello\r\n0\r\n\r\n";
}

/// Test all golden test vectors.
#[test]
#[allow(dead_code)]
fn test_all_golden_vectors() {
    let harness = H1ConformanceHarness::new();

    // Test RFC 9112 example
    let result = harness.decode_chunked_request(RFC9112_EXAMPLE_CHUNKED);
    assert!(
        result.is_ok(),
        "RFC 9112 example should decode successfully"
    );
    let decoded = result.unwrap();
    assert_eq!(decoded.body, RFC9112_EXAMPLE_EXPECTED_BODY);
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.uri, "/upload");

    // Test chunked with extensions
    let result = harness.decode_chunked_request(CHUNKED_WITH_EXTENSIONS);
    assert!(
        result.is_ok(),
        "Chunked with extensions should decode successfully"
    );
    assert_eq!(result.unwrap().body, RFC9112_EXAMPLE_EXPECTED_BODY);

    // Test chunked with trailers
    let result = harness.decode_chunked_request(CHUNKED_WITH_TRAILERS);
    assert!(
        result.is_ok(),
        "Chunked with trailers should decode successfully"
    );
    assert_eq!(result.unwrap().body, RFC9112_EXAMPLE_EXPECTED_BODY);

    // Test mixed case hex
    let result = harness.decode_chunked_request(CHUNKED_MIXED_CASE_HEX);
    assert!(result.is_ok(), "Mixed case hex should decode successfully");
    assert_eq!(result.unwrap().body, MIXED_CASE_HEX_EXPECTED_BODY);

    // Test complex extensions
    let result = harness.decode_chunked_request(CHUNKED_COMPLEX_EXTENSIONS);
    assert!(
        result.is_ok(),
        "Complex extensions should decode successfully"
    );
    assert_eq!(result.unwrap().body, COMPLEX_EXTENSIONS_EXPECTED_BODY);

    // Test single byte chunks
    let result = harness.decode_chunked_request(CHUNKED_SINGLE_BYTES);
    assert!(
        result.is_ok(),
        "Single byte chunks should decode successfully"
    );
    assert_eq!(result.unwrap().body, SINGLE_BYTES_EXPECTED_BODY);
}

/// Test all malformed vectors are properly rejected.
#[test]
#[allow(dead_code)]
fn test_malformed_vectors_rejected() {
    let harness = H1ConformanceHarness::new();

    // All of these should be rejected
    let malformed_tests = vec![
        (malformed::LEADING_WHITESPACE, "leading whitespace"),
        (malformed::TRAILING_WHITESPACE, "trailing whitespace"),
        (malformed::INVALID_HEX, "invalid hex characters"),
        (malformed::MISSING_FINAL_CHUNK, "missing final chunk"),
        (malformed::LENGTH_MISMATCH, "chunk length mismatch"),
        (malformed::EMPTY_CHUNK_SIZE, "empty chunk size"),
        (malformed::NEGATIVE_CHUNK_SIZE, "negative chunk size"),
        (
            malformed::OVERSIZED_CHUNK_SIZE.as_bytes(),
            "oversized chunk size",
        ),
    ];

    for (test_data, description) in malformed_tests {
        let result = harness.decode_chunked_request(test_data);
        assert!(
            result.is_err(),
            "Malformed test should be rejected: {description}"
        );
    }
}

/// Test large hex variants.
#[test]
#[allow(dead_code)]
fn test_large_hex_variants() {
    let harness = H1ConformanceHarness::new();

    // Generate 256 bytes of data
    let data_256 = "x".repeat(256);
    let test_request = format!(
        "POST /large HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n100\r\n{}\r\n0\r\n\r\n",
        data_256
    );

    let result = harness.decode_chunked_request(test_request.as_bytes());
    assert!(
        result.is_ok(),
        "Large chunk (256 bytes) should decode successfully"
    );
    assert_eq!(result.unwrap().body.len(), 256);

    // Test various hex formats for the same value
    let test_cases = vec![
        ("a", 10, "lowercase hex"),
        ("A", 10, "uppercase hex"),
        ("ff", 255, "lowercase ff"),
        ("FF", 255, "uppercase FF"),
        ("Ff", 255, "mixed case Ff"),
        ("fF", 255, "mixed case fF"),
        ("1a2b", 6699, "mixed case large number"),
    ];

    for (hex_str, expected_len, description) in test_cases {
        let data = "x".repeat(expected_len);
        let test_request = format!(
            "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\n{}\r\n0\r\n\r\n",
            hex_str, data
        );

        let result = harness.decode_chunked_request(test_request.as_bytes());
        assert!(result.is_ok(), "Failed for {description}: {hex_str}");
        assert_eq!(
            result.unwrap().body.len(),
            expected_len,
            "Length mismatch for {description}"
        );
    }
}
