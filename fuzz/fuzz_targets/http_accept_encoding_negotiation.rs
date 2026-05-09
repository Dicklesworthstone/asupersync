#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for HTTP Accept-Encoding compression negotiation parsing.
///
/// This target tests the robustness of HTTP compression negotiation functions:
/// - `parse_accept_encoding()`: Parses Accept-Encoding headers with quality values
/// - `ContentEncoding::from_token()`: Parses individual encoding tokens
/// - `negotiate_encoding()`: Negotiates best encoding from client preferences
///
/// The fuzzer generates malformed, edge case, and malicious Accept-Encoding headers
/// to verify the parser is robust against untrusted input and doesn't crash.
use asupersync::http::compress::{ContentEncoding, negotiate_encoding};
use std::str;

/// Test parse individual encoding tokens for robustness.
fn test_content_encoding_from_token(data: &[u8]) {
    if let Ok(token) = str::from_utf8(data) {
        // Should not crash on any input
        observe_content_encoding_token("raw token", token, ContentEncoding::from_token(token));

        // Test with leading/trailing whitespace
        let trimmed = token.trim();
        observe_content_encoding_token(
            "trimmed token",
            trimmed,
            ContentEncoding::from_token(trimmed),
        );

        // Test case variations
        let lowercase = token.to_lowercase();
        observe_content_encoding_token(
            "lowercase token",
            &lowercase,
            ContentEncoding::from_token(&lowercase),
        );

        let uppercase = token.to_uppercase();
        observe_content_encoding_token(
            "uppercase token",
            &uppercase,
            ContentEncoding::from_token(&uppercase),
        );
    }
}

/// Test Accept-Encoding header negotiation with various supported encodings.
fn test_encoding_negotiation(accept_encoding_header: &str) {
    // Test with different supported encoding sets
    let test_cases = [
        // Empty supported encodings
        vec![],
        // Single encoding support
        vec![ContentEncoding::Identity],
        vec![ContentEncoding::Gzip],
        vec![ContentEncoding::Deflate],
        vec![ContentEncoding::Brotli],
        // Multiple encoding support
        vec![ContentEncoding::Gzip, ContentEncoding::Deflate],
        vec![ContentEncoding::Gzip, ContentEncoding::Brotli],
        vec![ContentEncoding::Identity, ContentEncoding::Gzip],
        // All encodings supported
        vec![
            ContentEncoding::Identity,
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ],
    ];

    for supported in &test_cases {
        // Test with Some(header)
        observe_negotiation_result(
            "header negotiation",
            Some(accept_encoding_header),
            supported,
            negotiate_encoding(Some(accept_encoding_header), supported),
        );

        // Test with None (no header)
        observe_negotiation_result(
            "absent header negotiation",
            None,
            supported,
            negotiate_encoding(None, supported),
        );
    }

    // Test with empty header
    observe_negotiation_result(
        "empty header negotiation",
        Some(""),
        &[ContentEncoding::Gzip],
        negotiate_encoding(Some(""), &[ContentEncoding::Gzip]),
    );

    // Test with whitespace-only header
    observe_negotiation_result(
        "whitespace header negotiation",
        Some("   \t\n  "),
        &[ContentEncoding::Gzip],
        negotiate_encoding(Some("   \t\n  "), &[ContentEncoding::Gzip]),
    );
}

fn observe_content_encoding_token(context: &str, token: &str, encoding: Option<ContentEncoding>) {
    if let Some(encoding) = encoding {
        let canonical = encoding.as_token();
        assert!(
            !canonical.is_empty(),
            "{context}: accepted encoding should expose a canonical token"
        );
        assert_eq!(
            ContentEncoding::from_token(canonical),
            Some(encoding),
            "{context}: accepted token {token:?} should round-trip through canonical token"
        );
    }
}

fn observe_negotiation_result(
    context: &str,
    accept_encoding: Option<&str>,
    supported: &[ContentEncoding],
    result: Option<ContentEncoding>,
) {
    if supported.is_empty() {
        assert!(
            result.is_none(),
            "{context}: unsupported server set must not negotiate an encoding"
        );
        return;
    }

    if let Some(encoding) = result {
        assert!(
            supported.contains(&encoding),
            "{context}: negotiated encoding {encoding:?} was not server-supported"
        );
        assert!(
            !encoding.as_token().is_empty(),
            "{context}: negotiated encoding should expose a response token"
        );
    }

    match accept_encoding {
        None => {
            let expected = if supported.contains(&ContentEncoding::Identity) {
                Some(ContentEncoding::Identity)
            } else {
                supported.first().copied()
            };
            assert_eq!(
                result, expected,
                "{context}: absent Accept-Encoding should preserve server fallback semantics"
            );
        }
        Some(header) if header.trim().is_empty() => {
            let expected = supported
                .contains(&ContentEncoding::Identity)
                .then_some(ContentEncoding::Identity);
            assert_eq!(
                result, expected,
                "{context}: empty Accept-Encoding should only permit identity"
            );
        }
        Some(_) => {}
    }
}

/// Create various malformed Accept-Encoding headers for edge case testing.
fn test_malformed_headers(base_data: &[u8]) {
    if let Ok(base_str) = str::from_utf8(base_data) {
        let test_headers = vec![
            // Basic variations
            base_str.to_string(),
            // Add quality values
            format!("{};q=0.5", base_str),
            format!("{};q=1.0", base_str),
            format!("{};q=0.0", base_str),
            // Multiple encodings
            format!("{}, gzip", base_str),
            format!("gzip, {}", base_str),
            format!("{}, deflate, br", base_str),
            // With problematic quality values
            format!("{};q=1.5", base_str),      // > 1.0
            format!("{};q=-0.5", base_str),     // negative
            format!("{};q=abc", base_str),      // non-numeric
            format!("{};q=NaN", base_str),      // NaN
            format!("{};q=infinity", base_str), // infinity
            format!("{};q=", base_str),         // empty q value
            format!("{};q", base_str),          // no q value
            // Whitespace variations
            format!("  {}  ", base_str),
            format!("{}  ;  q=0.5", base_str),
            format!("{} ; q = 0.8 ", base_str),
            // Case variations
            base_str.to_uppercase(),
            base_str.to_lowercase(),
            // Special characters
            format!("{}*", base_str),
            format!("{}+", base_str),
            format!("{}@", base_str),
            format!("{}#", base_str),
            // Very long headers
            base_str.repeat(100),
            format!("{}={}", base_str.repeat(50), "x".repeat(1000)),
            // Unicode and control characters
            format!("{}\u{1F4A9}", base_str), // emoji
            format!("{}\x00", base_str),      // null byte
            format!("{}\x1F", base_str),      // control char
            format!("{}\u{FEFF}", base_str),  // BOM
            // Malformed separators
            format!("{};", base_str),       // trailing semicolon
            format!("{},", base_str),       // trailing comma
            format!(";{}", base_str),       // leading semicolon
            format!(",{}", base_str),       // leading comma
            format!("{};;q=0.5", base_str), // double semicolon
            format!("{},,gzip", base_str),  // double comma
            // Duplicate parameters
            format!("{};q=0.5;q=0.8", base_str),
            format!("{};q=0.5;q=0.5", base_str),
            // Empty parts
            format!("{}, ,gzip", base_str), // empty part
            format!("gzip, , {}", base_str),
            // Boundary values
            format!("{};q=0.000", base_str),
            format!("{};q=1.000", base_str),
            format!("{};q=0.999", base_str),
            format!("{};q=0.001", base_str),
        ];

        for header in &test_headers {
            test_encoding_negotiation(header);
        }
    }
}

/// Test edge cases with specific problematic patterns.
fn test_edge_cases() {
    let mut edge_case_headers = [
        // Empty and whitespace
        "",
        " ",
        "\t",
        "\n",
        "\r\n",
        "   \t\n\r   ",
        // Just quality without encoding
        "q=0.5",
        ";q=0.5",
        "q=",
        "q",
        // Just separators
        ",",
        ";",
        ",,",
        ";;",
        ",;,",
        // Wildcard variations
        "*",
        "*;q=0",
        "*;q=1.0",
        "*;q=0.5",
        "*, gzip",
        "gzip, *",
        "gzip;q=0.8, *;q=0.1",
        // Real-world headers
        "gzip, deflate, br",
        "gzip;q=1.0, deflate;q=0.5, *;q=0",
        "br;q=1.0, gzip;q=0.8, deflate;q=0.6, *;q=0.1",
        "identity",
        "gzip, identity; q=0.5, *;q=0",
        // Browser-style headers
        "gzip, deflate, br, zstd",
        "gzip, compress, deflate",
        "deflate, gzip;q=1.0, *;q=0.5",
        "\u{FFFF}gzip\u{FFFE}", // unicode edge chars
        "gzip\r\ngzip",         // line breaks
        // Float edge cases
        "gzip;q=1.7976931348623157e+308", // max f64
        "gzip;q=4.9406564584124654e-324", // min f64
        "gzip;q=1.0000000000000002",      // precision test
        "gzip;q=0.9999999999999999",      // precision test
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    edge_case_headers.extend([
        "x".repeat(10000),                         // very long
        "gzip;q=".to_string() + &"9".repeat(1000), // huge quality value
        "a,".repeat(10000),                        // many parts
        ("\x00".repeat(100)) + "gzip",             // null bytes
    ]);

    for header in &edge_case_headers {
        test_encoding_negotiation(header);
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as Accept-Encoding header
    if let Ok(header_str) = str::from_utf8(data) {
        test_encoding_negotiation(header_str);
    }

    // Test 2: Parse as individual encoding token
    test_content_encoding_from_token(data);

    // Test 3: Generate malformed headers based on input
    test_malformed_headers(data);

    // Test 4: Always test known edge cases
    test_edge_cases();

    // Test 5: Chunked parsing (test partial headers)
    if data.len() > 1 {
        for chunk_size in [1, 2, 4, 8, 16] {
            if chunk_size < data.len() {
                let partial = &data[..chunk_size];
                test_content_encoding_from_token(partial);

                if let Ok(partial_str) = str::from_utf8(partial) {
                    test_encoding_negotiation(partial_str);
                }
            }
        }
    }

    // Test 6: Concatenation tests (test long headers)
    if let Ok(base_str) = str::from_utf8(data)
        && !base_str.is_empty()
        && base_str.len() < 1000
    {
        // Test repeated concatenation
        let repeated = base_str.repeat(10);
        test_encoding_negotiation(&repeated);

        // Test comma-separated concatenation
        let comma_separated = format!("{},{},{}", base_str, base_str, base_str);
        test_encoding_negotiation(&comma_separated);

        // Test with quality parameters
        let with_quality = format!("{};q=0.5,{};q=0.8", base_str, base_str);
        test_encoding_negotiation(&with_quality);
    }

    // Test 7: Binary data interpretation
    // Try to interpret raw bytes as different string encodings
    if data.len() <= 1000 {
        // Test with lossy UTF-8 conversion
        let lossy_string = String::from_utf8_lossy(data);
        test_encoding_negotiation(&lossy_string);

        // Test Latin-1 interpretation
        let latin1_string: String = data.iter().map(|&b| b as char).collect();
        test_encoding_negotiation(&latin1_string);
    }

    // Test 8: Stress test with extreme values
    if data.is_empty() {
        return;
    }

    let first_byte = data[0];
    let quality_values = [
        "0.0", "0.1", "0.5", "0.9", "1.0", "0.000", "1.000", "0.999", "0.001", "00.5", "01.0",
        "1.00000", // Leading zeros, extra precision
    ];

    for &q in &quality_values {
        let test_header = format!("test{};q={}", first_byte, q);
        test_encoding_negotiation(&test_header);
    }

    // Test 9: Protocol compliance edge cases
    let protocol_tests = vec![
        // RFC 2616 compliant headers
        "compress, gzip",
        "compress;q=0.5, gzip;q=1.0",
        "gzip;q=1.0, identity; q=0.5, *;q=0",
        // Edge cases from specification
        "br;level=4",       // with parameters (not quality)
        "gzip; q=0.001",    // minimum quality
        "deflate; q=0.999", // near maximum quality
    ];

    for header in &protocol_tests {
        test_encoding_negotiation(header);
    }
});
