//! RFC 9112 §7.1 Chunked Transfer-Encoding edge case tests.
//!
//! Tests specific edge cases and corner cases for chunked transfer-encoding
//! per RFC 9112 Section 7.1, including chunk extensions, trailer fields,
//! and error conditions.

use super::harness::H1ConformanceHarness;

/// Test chunk extension parsing with various forms.
#[test]
fn test_chunk_extensions_edge_cases() {
    let harness = H1ConformanceHarness::new();

    // Test chunk extension with quoted-string containing LF (should be valid per RFC)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5;name=\"quoted\nvalue\"\r\nhello\r\n",
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    match result {
        Ok(req) => {
            assert_eq!(req.body, b"hello", "Body should be decoded correctly");
            println!("✓ Chunk extension with LF in quoted-string accepted");
        }
        Err(e) => {
            // This might be rejected by strict parsers, which is also valid
            println!("✗ Chunk extension with LF in quoted-string rejected: {e:?}");
        }
    }

    // Test chunk extension with multiple parameters
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5;a=1;b=2;c=\"test\"\r\nhello\r\n",
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(result.is_ok(), "Multiple chunk extensions should be valid");
    assert_eq!(result.unwrap().body, b"hello");

    // Test chunk extension with no value (just name)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5;ext\r\nhello\r\n",
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(
        result.is_ok(),
        "Chunk extension without value should be valid"
    );
    assert_eq!(result.unwrap().body, b"hello");
}

/// Test trailer field parsing after final chunk.
#[test]
fn test_trailer_fields_edge_cases() {
    let harness = H1ConformanceHarness::new();

    // Test multiple trailer fields
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello\r\n",
        "0\r\n",
        "X-Trailer-1: value1\r\n",
        "X-Trailer-2: value2\r\n",
        "X-Trailer-3: value3\r\n",
        "\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(result.is_ok(), "Multiple trailer fields should be valid");
    assert_eq!(result.unwrap().body, b"hello");

    // Test trailer field with folded value (obsolete but might appear)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello\r\n",
        "0\r\n",
        "X-Folded: line one\r\n",
        " line two\r\n", // Folded continuation (obsolete in HTTP/1.1 but legacy)
        "\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    // This should be rejected in modern HTTP/1.1 parsers
    match result {
        Ok(_) => println!("⚠ Folded trailer headers were accepted (legacy behavior)"),
        Err(_) => println!("✓ Folded trailer headers rejected (RFC 9112 compliant)"),
    }

    // Test empty trailer section (just final CRLF)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello\r\n",
        "0\r\n",
        "\r\n" // Empty trailer section
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(result.is_ok(), "Empty trailer section should be valid");
    assert_eq!(result.unwrap().body, b"hello");
}

/// Test CRLF vs LF tolerance (RFC 9112 is strict about line endings).
#[test]
fn test_line_ending_strictness() {
    let harness = H1ConformanceHarness::new();

    // Test LF-only chunk size line (should be rejected)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\nhello\n", // LF only
        "0\n\n"       // LF only
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    // RFC 9112 requires CRLF, so this should be rejected
    assert!(
        result.is_err(),
        "LF-only line endings should be rejected per RFC 9112"
    );

    // Test mixed CRLF/LF (should be rejected for consistency)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5\r\nhello\n", // CRLF then LF
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    // Mixed line endings should be rejected
    match result {
        Ok(_) => println!("⚠ Mixed line endings were accepted (lenient)"),
        Err(_) => println!("✓ Mixed line endings rejected (strict RFC compliance)"),
    }
}

/// Test hex chunk-size case variants.
#[test]
fn test_hex_case_sensitivity() {
    let harness = H1ConformanceHarness::new();

    // Test all hex digits in both cases
    let test_cases = vec![
        ("a", "lowercase hex a = 10"),
        ("A", "uppercase hex A = 10"),
        ("b", "lowercase hex b = 11"),
        ("B", "uppercase hex B = 11"),
        ("c", "lowercase hex c = 12"),
        ("C", "uppercase hex C = 12"),
        ("d", "lowercase hex d = 13"),
        ("D", "uppercase hex D = 13"),
        ("e", "lowercase hex e = 14"),
        ("E", "uppercase hex E = 14"),
        ("f", "lowercase hex f = 15"),
        ("F", "uppercase hex F = 15"),
    ];

    for (hex_digit, description) in test_cases {
        let expected_len = usize::from_str_radix(hex_digit, 16).unwrap();
        let test_body = "x".repeat(expected_len);

        let test_data = format!(
            "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\n{}\r\n0\r\n\r\n",
            hex_digit, test_body
        );

        let result = harness.decode_chunked_request(test_data.as_bytes());
        assert!(result.is_ok(), "Failed for {description}");
        assert_eq!(
            result.unwrap().body,
            test_body.as_bytes(),
            "Body mismatch for {description}"
        );
    }

    // Test large hex numbers with mixed case
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "1A2b\r\n", // Mixed case hex = 6699 decimal
    )
    .to_string()
        + &"x".repeat(6699)
        + "\r\n0\r\n\r\n";

    let result = harness.decode_chunked_request(test_data.as_bytes());
    assert!(result.is_ok(), "Mixed case large hex should be valid");
    assert_eq!(result.unwrap().body.len(), 6699);
}

/// Test oversized chunk headers and resource limits.
#[test]
fn test_resource_limit_enforcement() {
    let harness = H1ConformanceHarness::new();

    // Test very large chunk size (should be rejected to prevent DoS)
    let huge_chunk_size = "F".repeat(100); // 100 hex F's
    let test_data = format!(
        "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\nhello\r\n0\r\n\r\n",
        huge_chunk_size
    );

    let result = harness.decode_chunked_request(test_data.as_bytes());
    // This should be rejected to prevent integer overflow attacks
    assert!(result.is_err(), "Oversized chunk size should be rejected");

    // Test many chunk extensions (potential DoS vector)
    let many_extensions = (0..1000)
        .map(|i| format!("ext{}=val{}", i, i))
        .collect::<Vec<_>>()
        .join(";");

    let test_data = format!(
        "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;{}\r\nhello\r\n0\r\n\r\n",
        many_extensions
    );

    let result = harness.decode_chunked_request(test_data.as_bytes());
    // This might be rejected if there are limits on extension length
    match result {
        Ok(req) => {
            assert_eq!(req.body, b"hello");
            println!("✓ Many chunk extensions accepted (no length limit)");
        }
        Err(_) => {
            println!("✓ Many chunk extensions rejected (length limit enforced)");
        }
    }
}

/// Test error conditions and malformed input.
#[test]
fn test_malformed_input_handling() {
    let harness = H1ConformanceHarness::new();

    // Test chunk size with leading whitespace (should be rejected per RFC)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        " 5\r\nhello\r\n", // Leading space
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(
        result.is_err(),
        "Leading whitespace in chunk size should be rejected"
    );

    // Test chunk size with trailing whitespace
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5 \r\nhello\r\n", // Trailing space
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(
        result.is_err(),
        "Trailing whitespace in chunk size should be rejected"
    );

    // Test negative chunk size (invalid hex)
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "-5\r\nhello\r\n", // Negative sign not valid in hex
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(result.is_err(), "Negative chunk size should be rejected");

    // Test empty chunk size line
    let test_data = concat!(
        "POST /test HTTP/1.1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "\r\nhello\r\n", // Empty chunk size line
        "0\r\n\r\n"
    )
    .as_bytes();

    let result = harness.decode_chunked_request(test_data);
    assert!(result.is_err(), "Empty chunk size line should be rejected");
}
