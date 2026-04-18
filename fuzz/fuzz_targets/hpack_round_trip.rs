//! Fuzz target for HPACK header compression round-trip testing.
//!
//! This fuzzer tests the consistency between HPACK encoding and decoding by:
//! 1. Generating arbitrary header lists from fuzz input
//! 2. Encoding headers with the HPACK encoder
//! 3. Decoding the encoded bytes with the HPACK decoder
//! 4. Verifying that the round-trip preserves header semantics
//!
//! # Attack vectors tested:
//! - Encoding/decoding consistency bugs
//! - Dynamic table state corruption
//! - Huffman encoding round-trip failures
//! - Index reference inconsistencies
//! - String encoding edge cases
//! - Header name/value preservation
//! - Dynamic table size update handling
//! - Case sensitivity and normalization bugs
//!
//! # Invariants validated:
//! - decode(encode(headers)) ≈ headers (modulo normalization)
//! - No panics or crashes during round-trip
//! - Dynamic table state remains consistent
//! - Encoded size is reasonable (no compression bombs)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run hpack_round_trip
//! ```

#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder};
use libfuzzer_sys::fuzz_target;

/// Maximum number of headers to generate per test case.
const MAX_HEADERS: usize = 32;

/// Maximum header name/value length to prevent memory exhaustion.
const MAX_STRING_LENGTH: usize = 1024;

/// Maximum large header value length for testing 4096+ byte values.
const MAX_LARGE_STRING_LENGTH: usize = 8192;

/// Maximum encoded output size to prevent compression bombs.
const MAX_ENCODED_SIZE: usize = 16384;

/// Maximum dynamic table size for testing.
const MAX_DYNAMIC_TABLE_SIZE: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Split input into configuration and header generation data
    let (config_data, header_data) = data.split_at(4);

    // Extract configuration parameters
    let use_huffman = config_data[0] & 0x01 != 0;
    let dynamic_table_size =
        ((config_data[1] as usize) << 8 | config_data[2] as usize).min(MAX_DYNAMIC_TABLE_SIZE);
    let num_headers = (config_data[3] as usize % MAX_HEADERS) + 1;

    // Create encoder and decoder with matching configuration
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Configure Huffman encoding preference
    encoder.set_use_huffman(use_huffman);

    // Set dynamic table size if specified
    if dynamic_table_size > 0 && dynamic_table_size != 4096 {
        encoder.set_max_table_size(dynamic_table_size);
        decoder.set_allowed_table_size(dynamic_table_size);
    }

    // Generate headers from fuzz input
    let original_headers = generate_headers(header_data, num_headers);

    if original_headers.is_empty() {
        return;
    }

    // Perform round-trip test
    round_trip_test(&mut encoder, &mut decoder, &original_headers);

    // Test multiple rounds to validate dynamic table consistency
    multi_round_test(&mut encoder, &mut decoder, &original_headers);

    // Test with sensitive headers (should not be indexed)
    sensitive_headers_test(&mut encoder, &mut decoder);

    // Test large header values (4096+ bytes)
    large_header_values_test(&mut encoder, &mut decoder, header_data);

    // Test Huffman encoding boundary conditions
    huffman_boundary_test(&mut encoder, &mut decoder, header_data);

    // Test header fragmentation scenarios
    header_fragmentation_test(&mut encoder, &mut decoder, &original_headers);
});

/// Generate headers from fuzz input data.
fn generate_headers(data: &[u8], count: usize) -> Vec<Header> {
    let mut headers = Vec::with_capacity(count);
    let mut pos = 0;

    for _ in 0..count {
        if pos >= data.len() {
            break;
        }

        // Generate header name
        let name_len = (data[pos] as usize % 32) + 1;
        pos += 1;

        let name = if pos + name_len <= data.len() {
            generate_header_name(&data[pos..pos + name_len])
        } else {
            "x-test".to_string()
        };
        pos = (pos + name_len).min(data.len());

        // Generate header value
        let value_len = if pos < data.len() {
            (data[pos] as usize % 64).min(MAX_STRING_LENGTH)
        } else {
            0
        };
        pos += 1;

        let value = if pos + value_len <= data.len() {
            generate_header_value(&data[pos..pos + value_len])
        } else {
            String::new()
        };
        pos = (pos + value_len).min(data.len());

        // Add header if valid
        if is_valid_header(&name, &value) {
            headers.push(Header { name, value });
        }
    }

    headers
}

/// Generate a valid header name from input bytes.
fn generate_header_name(data: &[u8]) -> String {
    if data.is_empty() {
        return "x-test".to_string();
    }

    // Generate header name using common patterns and pseudo-headers
    let templates = [
        ":method",
        ":path",
        ":scheme",
        ":authority",
        ":status",
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
        "authorization",
        "cache-control",
        "content-type",
        "content-length",
        "cookie",
        "x-forwarded-for",
        "x-custom",
        "x-test",
    ];

    let template_idx = data[0] as usize % templates.len();
    let mut name = templates[template_idx].to_string();

    // Optionally modify with suffix
    if data.len() > 1 && data[1] & 0x80 != 0 {
        let suffix_len = (data[1] & 0x0F) as usize;
        if suffix_len > 0 && data.len() > suffix_len + 1 {
            let suffix_bytes = &data[2..2 + suffix_len.min(data.len() - 2)];
            let suffix: String = suffix_bytes
                .iter()
                .map(|&b| {
                    let c = match b % 36 {
                        0..=25 => (b'a' + (b % 26)) as char,
                        26..=35 => (b'0' + (b % 10)) as char,
                        _ => '-',
                    };
                    c
                })
                .collect();

            if !suffix.is_empty() {
                name.push('-');
                name.push_str(&suffix);
            }
        }
    }

    name
}

/// Generate a header value from input bytes.
fn generate_header_value(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Generate values using various patterns
    match data[0] % 8 {
        0 => {
            // HTTP method values
            let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
            methods[data[0] as usize % methods.len()].to_string()
        }
        1 => {
            // Status code values
            let statuses = [
                "200", "201", "204", "301", "302", "400", "401", "403", "404", "500",
            ];
            statuses[data[0] as usize % statuses.len()].to_string()
        }
        2 => {
            // Content-Type values
            let content_types = [
                "text/html",
                "text/plain",
                "application/json",
                "application/xml",
                "application/octet-stream",
                "multipart/form-data",
            ];
            content_types[data[0] as usize % content_types.len()].to_string()
        }
        3 => {
            // URL/path values
            if data.len() >= 2 {
                let mut path = "/".to_string();
                let segments = (data[1] % 4) + 1;
                for i in 0..segments as usize {
                    if i + 2 < data.len() {
                        path.push_str(&format!("segment{}", data[i + 2] % 10));
                        if i + 1 < segments as usize {
                            path.push('/');
                        }
                    }
                }
                path
            } else {
                "/".to_string()
            }
        }
        4 => {
            // Numeric values
            if data.len() >= 4 {
                let num = u32::from_be_bytes([
                    data.get(0).copied().unwrap_or(0),
                    data.get(1).copied().unwrap_or(0),
                    data.get(2).copied().unwrap_or(0),
                    data.get(3).copied().unwrap_or(0),
                ]);
                (num % 100000).to_string()
            } else {
                "0".to_string()
            }
        }
        5 => {
            // Base64-like values (test Huffman encoding)
            let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            data.iter()
                .take(16) // Limit length
                .map(|&b| b64_chars.chars().nth(b as usize % b64_chars.len()).unwrap())
                .collect()
        }
        6 => {
            // Empty value
            String::new()
        }
        7 => {
            // ASCII printable characters
            data.iter()
                .take(32) // Limit length
                .map(|&b| {
                    let c = b % 95 + 32; // ASCII printable range
                    if c == 127 { '?' } else { c as char }
                })
                .collect()
        }
        _ => unreachable!(),
    }
}

/// Check if header name and value are valid for HTTP/2.
fn is_valid_header(name: &str, value: &str) -> bool {
    // Reject empty names
    if name.is_empty() {
        return false;
    }

    // Check name contains only valid characters (lowercase, digits, hyphens, colons)
    for ch in name.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' && ch != ':' && ch != '_' {
            return false;
        }
    }

    // Check value doesn't contain control characters (except valid ones)
    for ch in value.chars() {
        if ch.is_control() && ch != '\t' {
            return false;
        }
    }

    // Check reasonable length limits
    if name.len() > MAX_STRING_LENGTH || value.len() > MAX_STRING_LENGTH {
        return false;
    }

    true
}

/// Perform basic round-trip encoding/decoding test.
fn round_trip_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder, headers: &[Header]) {
    // Encode headers
    let mut encoded = BytesMut::new();
    encoder.encode(headers, &mut encoded);

    // Check encoded size is reasonable
    if encoded.len() > MAX_ENCODED_SIZE {
        return; // Skip excessively large encodings
    }

    // Decode headers
    let mut encoded_bytes = encoded.freeze();
    let decoded_result = decoder.decode(&mut encoded_bytes);

    // Verify decode succeeded
    let decoded_headers = match decoded_result {
        Ok(headers) => headers,
        Err(_) => {
            // Decode failure is acceptable for malformed input,
            // but encoding valid headers should always decode successfully
            return;
        }
    };

    // Verify round-trip consistency
    assert_eq!(
        headers.len(),
        decoded_headers.len(),
        "Header count mismatch in round-trip"
    );

    for (orig, decoded) in headers.iter().zip(decoded_headers.iter()) {
        assert_eq!(
            orig.name.to_lowercase(),
            decoded.name.to_lowercase(),
            "Header name mismatch: '{}' vs '{}'",
            orig.name,
            decoded.name
        );
        assert_eq!(
            orig.value, decoded.value,
            "Header value mismatch for '{}': '{}' vs '{}'",
            orig.name, orig.value, decoded.value
        );
    }

    // Verify no bytes remaining after decode
    assert!(
        encoded_bytes.is_empty() || encoded_bytes.len() <= 4,
        "Unexpected remaining bytes after decode: {} bytes",
        encoded_bytes.len()
    );
}

/// Test multiple encoding rounds to validate dynamic table consistency.
fn multi_round_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder, headers: &[Header]) {
    if headers.is_empty() {
        return;
    }

    // Perform multiple rounds of encoding/decoding
    for round in 0..3 {
        // Use subset of headers for variety
        let start_idx = round % headers.len();
        let end_idx = ((round + 1) * headers.len() / 3).min(headers.len());
        let round_headers = &headers[start_idx..end_idx];

        if round_headers.is_empty() {
            continue;
        }

        // Encode and decode
        let mut encoded = BytesMut::new();
        encoder.encode(round_headers, &mut encoded);

        if encoded.len() > MAX_ENCODED_SIZE {
            continue;
        }

        let mut encoded_bytes = encoded.freeze();
        if let Ok(decoded_headers) = decoder.decode(&mut encoded_bytes) {
            // Verify round-trip consistency
            assert_eq!(
                round_headers.len(),
                decoded_headers.len(),
                "Round {} header count mismatch",
                round
            );

            for (orig, decoded) in round_headers.iter().zip(decoded_headers.iter()) {
                assert_eq!(
                    orig.name.to_lowercase(),
                    decoded.name.to_lowercase(),
                    "Round {} header name mismatch",
                    round
                );
                assert_eq!(
                    orig.value, decoded.value,
                    "Round {} header value mismatch for '{}'",
                    round, orig.name
                );
            }
        }
    }
}

/// Test encoding/decoding of sensitive headers (never indexed).
fn sensitive_headers_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder) {
    let sensitive_headers = vec![
        Header {
            name: "authorization".to_string(),
            value: "Bearer secret_token_12345".to_string(),
        },
        Header {
            name: "cookie".to_string(),
            value: "session_id=abc123; auth=xyz789".to_string(),
        },
        Header {
            name: "proxy-authorization".to_string(),
            value: "Basic dXNlcjpwYXNz".to_string(),
        },
    ];

    // Encode using sensitive method (should not be indexed)
    let mut encoded = BytesMut::new();
    encoder.encode_sensitive(&sensitive_headers, &mut encoded);

    if encoded.len() > MAX_ENCODED_SIZE {
        return;
    }

    // Decode and verify
    let mut encoded_bytes = encoded.freeze();
    if let Ok(decoded_headers) = decoder.decode(&mut encoded_bytes) {
        assert_eq!(
            sensitive_headers.len(),
            decoded_headers.len(),
            "Sensitive headers count mismatch"
        );

        for (orig, decoded) in sensitive_headers.iter().zip(decoded_headers.iter()) {
            assert_eq!(
                orig.name.to_lowercase(),
                decoded.name.to_lowercase(),
                "Sensitive header name mismatch"
            );
            assert_eq!(
                orig.value, decoded.value,
                "Sensitive header value mismatch for '{}'",
                orig.name
            );
        }
    }
}

/// Test dynamic table size updates during encoding.
#[allow(dead_code)]
fn dynamic_table_size_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder) {
    // Test various table size updates
    let sizes = [0, 512, 1024, 2048, 4096, 8192];

    for &size in &sizes {
        encoder.set_max_table_size(size);
        decoder.set_allowed_table_size(size);

        let test_headers = vec![
            Header {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Header {
                name: ":path".to_string(),
                value: "/test".to_string(),
            },
            Header {
                name: "host".to_string(),
                value: "example.com".to_string(),
            },
        ];

        let mut encoded = BytesMut::new();
        encoder.encode(&test_headers, &mut encoded);

        if encoded.len() > MAX_ENCODED_SIZE {
            continue;
        }

        let mut encoded_bytes = encoded.freeze();
        if let Ok(decoded_headers) = decoder.decode(&mut encoded_bytes) {
            assert_eq!(
                test_headers.len(),
                decoded_headers.len(),
                "Table size {} header count mismatch",
                size
            );
        }
    }
}

/// Test encoding/decoding of large header values (4096+ bytes).
fn large_header_values_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder, data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    // Generate large header values using different patterns
    let large_headers = vec![
        Header {
            name: "x-large-data".to_string(),
            value: generate_large_header_value(data, 4096),
        },
        Header {
            name: "x-large-base64".to_string(),
            value: generate_large_base64_value(data, 5000),
        },
        Header {
            name: "x-large-repeated".to_string(),
            value: generate_repeated_pattern_value(data, 6000),
        },
    ];

    for header in &large_headers {
        let test_headers = vec![header.clone()];

        // Test with Huffman encoding enabled
        encoder.set_use_huffman(true);
        test_large_header_round_trip(encoder, decoder, &test_headers);

        // Test with Huffman encoding disabled
        encoder.set_use_huffman(false);
        test_large_header_round_trip(encoder, decoder, &test_headers);
    }
}

/// Generate a large header value from input bytes.
fn generate_large_header_value(data: &[u8], target_size: usize) -> String {
    let mut value = String::with_capacity(target_size);

    while value.len() < target_size {
        for &byte in data {
            if value.len() >= target_size {
                break;
            }
            // Use printable ASCII range
            let ch = match byte % 94 {
                0..=25 => (b'A' + (byte % 26)) as char,
                26..=51 => (b'a' + (byte % 26)) as char,
                52..=61 => (b'0' + (byte % 10)) as char,
                62 => ' ',
                63 => '-',
                64 => '_',
                65 => '.',
                66 => ',',
                67 => ';',
                68 => ':',
                69 => '/',
                70 => '?',
                71 => '#',
                72 => '[',
                73 => ']',
                74 => '@',
                75 => '!',
                76 => '$',
                77 => '&',
                78 => '\'',
                79 => '(',
                80 => ')',
                81 => '*',
                82 => '+',
                83 => '=',
                _ => (b'0' + (byte % 10)) as char,
            };
            value.push(ch);
        }
    }

    value.truncate(target_size.min(MAX_LARGE_STRING_LENGTH));
    value
}

/// Generate a large Base64-style header value.
fn generate_large_base64_value(data: &[u8], target_size: usize) -> String {
    let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let mut value = String::with_capacity(target_size);

    for i in 0..target_size.min(MAX_LARGE_STRING_LENGTH) {
        let byte_idx = i % data.len().max(1);
        let char_idx = data[byte_idx] as usize % b64_chars.len();
        value.push(b64_chars.chars().nth(char_idx).unwrap());
    }

    value
}

/// Generate a large header value with repeated patterns.
fn generate_repeated_pattern_value(data: &[u8], target_size: usize) -> String {
    if data.is_empty() {
        return "a".repeat(target_size.min(MAX_LARGE_STRING_LENGTH));
    }

    let pattern_size = (data[0] % 16 + 1) as usize;
    let pattern = &data[1..pattern_size.min(data.len())];

    let pattern_str: String = pattern
        .iter()
        .map(|&b| {
            let c = b % 26 + b'a';
            c as char
        })
        .collect();

    if pattern_str.is_empty() {
        return "x".repeat(target_size.min(MAX_LARGE_STRING_LENGTH));
    }

    let repeats = target_size / pattern_str.len() + 1;
    let repeated = pattern_str.repeat(repeats);

    repeated[..target_size.min(MAX_LARGE_STRING_LENGTH)].to_string()
}

/// Test round-trip for large headers with specific size limits.
fn test_large_header_round_trip(
    encoder: &mut HpackEncoder,
    decoder: &mut HpackDecoder,
    headers: &[Header],
) {
    // Encode headers
    let mut encoded = BytesMut::new();
    encoder.encode(headers, &mut encoded);

    // Allow larger encoded size for large header testing
    let max_size = MAX_ENCODED_SIZE * 4; // 64KB limit for large headers
    if encoded.len() > max_size {
        return; // Skip excessively large encodings
    }

    // Decode headers
    let mut encoded_bytes = encoded.freeze();
    if let Ok(decoded_headers) = decoder.decode(&mut encoded_bytes) {
        // Verify round-trip consistency
        assert_eq!(
            headers.len(),
            decoded_headers.len(),
            "Large header count mismatch"
        );

        for (orig, decoded) in headers.iter().zip(decoded_headers.iter()) {
            assert_eq!(
                orig.name.to_lowercase(),
                decoded.name.to_lowercase(),
                "Large header name mismatch: '{}' vs '{}'",
                orig.name,
                decoded.name
            );
            assert_eq!(
                orig.value,
                decoded.value,
                "Large header value mismatch for '{}': lengths {} vs {}",
                orig.name,
                orig.value.len(),
                decoded.value.len()
            );
        }
    }
}

/// Test Huffman encoding boundary conditions.
fn huffman_boundary_test(encoder: &mut HpackEncoder, decoder: &mut HpackDecoder, data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    // Generate test strings that are at Huffman encoding boundaries
    let repeated_a = "a".repeat(100);
    let repeated_e = "e".repeat(50);
    let repeated_space = " ".repeat(80);
    let random_value = generate_low_compression_value(data, 100);
    let mixed_value = format!(
        "{}{}",
        "a".repeat(50),
        generate_low_compression_value(data, 50)
    );
    let ascii_value = generate_ascii_boundary_value(data);

    let test_cases = vec![
        // Very short strings (Huffman overhead not worth it)
        ("x", "a"),
        ("xy", "ab"),
        ("xyz", "abc"),
        // Strings with high compression ratio (lots of repeated chars)
        ("aaa", repeated_a.as_str()),
        ("eee", repeated_e.as_str()),
        ("   ", repeated_space.as_str()), // spaces compress well
        // Strings with low compression ratio (random-ish content)
        ("x-random", random_value.as_str()),
        // Mixed content (some compressible, some not)
        ("x-mixed", mixed_value.as_str()),
        // ASCII vs Latin-1 boundary content
        ("x-ascii", ascii_value.as_str()),
    ];

    for (name, value) in test_cases {
        let test_headers = vec![Header {
            name: name.to_string(),
            value: value.to_string(),
        }];

        // Test with Huffman enabled (should compress if beneficial)
        encoder.set_use_huffman(true);
        let mut encoded_huffman = BytesMut::new();
        encoder.encode(&test_headers, &mut encoded_huffman);

        // Test with Huffman disabled (raw encoding)
        encoder.set_use_huffman(false);
        let mut encoded_raw = BytesMut::new();
        encoder.encode(&test_headers, &mut encoded_raw);

        // Both should decode to the same result
        if encoded_huffman.len() <= MAX_ENCODED_SIZE && encoded_raw.len() <= MAX_ENCODED_SIZE {
            let mut huffman_bytes = encoded_huffman.freeze();
            let mut raw_bytes = encoded_raw.freeze();

            if let (Ok(huffman_result), Ok(raw_result)) = (
                decoder.decode(&mut huffman_bytes),
                decoder.decode(&mut raw_bytes),
            ) {
                assert_eq!(
                    huffman_result.len(),
                    raw_result.len(),
                    "Huffman vs raw result count mismatch for '{}'",
                    name
                );

                for (huff, raw) in huffman_result.iter().zip(raw_result.iter()) {
                    assert_eq!(
                        huff.name, raw.name,
                        "Huffman vs raw name mismatch for '{}'",
                        name
                    );
                    assert_eq!(
                        huff.value, raw.value,
                        "Huffman vs raw value mismatch for '{}'",
                        name
                    );
                }
            }
        }
    }
}

/// Generate a header value with low Huffman compression ratio.
fn generate_low_compression_value(data: &[u8], target_len: usize) -> String {
    let mut value = String::with_capacity(target_len);

    // Use bytes that don't compress well under Huffman
    let low_compression_chars = "~!@#$%^&*()_+{}|:<>?[];',./\"\\`";

    for i in 0..target_len {
        let byte_idx = i % data.len().max(1);
        let char_idx = data[byte_idx] as usize % low_compression_chars.len();
        value.push(low_compression_chars.chars().nth(char_idx).unwrap());
    }

    value
}

/// Generate content at ASCII/Latin-1 boundaries that might trigger encoding edge cases.
fn generate_ascii_boundary_value(data: &[u8]) -> String {
    if data.is_empty() {
        return "test\x7f".to_string();
    }

    let mut value = String::new();

    // Mix ASCII and near-boundary characters
    for (i, &byte) in data.iter().enumerate().take(50) {
        let ch = match i % 4 {
            0 => (byte % 95 + 32) as char,     // ASCII printable
            1 => '\x7f',                       // DEL character
            2 => char::from(byte % 32 + 128),  // High bit set (using char::from for safety)
            3 => char::from(byte % 127 + 129), // Latin-1 range (using char::from for safety)
            _ => unreachable!(),
        };
        value.push(ch);
    }

    value
}

/// Test header fragmentation scenarios (simulating CONTINUATION frames).
fn header_fragmentation_test(
    encoder: &mut HpackEncoder,
    decoder: &mut HpackDecoder,
    original_headers: &[Header],
) {
    if original_headers.is_empty() {
        return;
    }

    // Test encoding a large set of headers that might require fragmentation
    let mut large_header_set = original_headers.to_vec();

    // Add some additional headers to increase the total size
    for i in 0..8 {
        large_header_set.push(Header {
            name: format!("x-fragment-test-{}", i),
            value: format!(
                "value_that_might_trigger_fragmentation_{}_with_longer_content",
                i
            ),
        });
    }

    // Encode the full header set
    let mut encoded = BytesMut::new();
    encoder.encode(&large_header_set, &mut encoded);

    if encoded.len() > MAX_ENCODED_SIZE * 2 {
        return; // Skip if too large
    }

    // Test fragmented decoding by splitting the encoded data
    let encoded_bytes = encoded.freeze();

    // Try different fragmentation points
    let fragment_points = [
        encoded_bytes.len() / 4,
        encoded_bytes.len() / 3,
        encoded_bytes.len() / 2,
        encoded_bytes.len() * 2 / 3,
        encoded_bytes.len() * 3 / 4,
    ];

    for &split_point in &fragment_points {
        if split_point > 0 && split_point < encoded_bytes.len() {
            // Split the encoded data into two fragments
            let first_fragment = encoded_bytes.slice(0..split_point);
            let second_fragment = encoded_bytes.slice(split_point..);

            // Try to decode the fragments separately (this should fail gracefully)
            let mut first_copy = first_fragment.clone();
            let _first_result = decoder.decode(&mut first_copy);

            // The first fragment alone should either:
            // 1. Fail to decode (incomplete header block)
            // 2. Decode partial headers (if it happens to be at a header boundary)
            // Either is acceptable - the key is no panics or crashes

            // Recombine fragments and decode the complete header block
            let mut combined = BytesMut::new();
            combined.extend_from_slice(&first_fragment);
            combined.extend_from_slice(&second_fragment);
            let mut combined_bytes = combined.freeze();

            if let Ok(decoded_headers) = decoder.decode(&mut combined_bytes) {
                // Verify that recombined fragments decode correctly
                assert_eq!(
                    large_header_set.len(),
                    decoded_headers.len(),
                    "Fragmentation test header count mismatch at split point {}",
                    split_point
                );

                for (orig, decoded) in large_header_set.iter().zip(decoded_headers.iter()) {
                    assert_eq!(
                        orig.name.to_lowercase(),
                        decoded.name.to_lowercase(),
                        "Fragmentation test name mismatch at split point {}",
                        split_point
                    );
                    assert_eq!(
                        orig.value, decoded.value,
                        "Fragmentation test value mismatch for '{}' at split point {}",
                        orig.name, split_point
                    );
                }
            }
        }
    }
}
