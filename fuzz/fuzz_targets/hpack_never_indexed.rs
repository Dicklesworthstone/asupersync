//! HPACK Never-Indexed literal flag preservation fuzz target.
//!
//! This fuzzer tests HPACK Never-Indexed flag handling per RFC 7541 Section 6.2.3
//! "Literal Header Field Never Indexed" with emphasis on:
//! - Never-Indexed flag set on sensitive headers (Authorization, Cookie, Set-Cookie)
//! - Flag preservation through decode+re-encode cycles
//! - Sensitive headers never entering the dynamic table
//! - Mixed-type header handling with Never-Indexed and regular headers
//! - max_table_size independence for Never-Indexed entries

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

use asupersync::bytes::BytesMut;
use asupersync::http::h2::hpack::{Decoder, Encoder, Header};

/// Sensitive header names that should always be encoded as Never-Indexed.
/// These headers contain authentication tokens, session data, or other
/// sensitive information that must not be stored in compression tables.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "www-authenticate",
    "proxy-authenticate",
];

/// Non-sensitive header names for mixed-type testing
const REGULAR_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "content-encoding",
    "user-agent",
    "host",
    "referer",
    "cache-control",
];

/// Header type for fuzz input generation
#[derive(Arbitrary, Debug, Clone)]
enum HeaderType {
    /// Sensitive header that should be Never-Indexed
    Sensitive {
        name_index: u8, // Index into SENSITIVE_HEADERS
        value: String,
    },
    /// Regular header for mixed testing
    Regular {
        name_index: u8, // Index into REGULAR_HEADERS
        value: String,
    },
    /// Custom header name
    Custom {
        name: String,
        value: String,
        force_sensitive: bool, // Force as sensitive even if name doesn't match
    },
}

impl HeaderType {
    fn to_header(&self) -> Header {
        match self {
            HeaderType::Sensitive { name_index, value } => {
                let name = SENSITIVE_HEADERS[(*name_index as usize) % SENSITIVE_HEADERS.len()];
                Header::new(name.to_string(), value.clone())
            }
            HeaderType::Regular { name_index, value } => {
                let name = REGULAR_HEADERS[(*name_index as usize) % REGULAR_HEADERS.len()];
                Header::new(name.to_string(), value.clone())
            }
            HeaderType::Custom { name, value, .. } => Header::new(name.clone(), value.clone()),
        }
    }

    fn is_sensitive(&self) -> bool {
        match self {
            HeaderType::Sensitive { .. } => true,
            HeaderType::Regular { .. } => false,
            HeaderType::Custom {
                name,
                force_sensitive,
                ..
            } => {
                *force_sensitive
                    || SENSITIVE_HEADERS
                        .iter()
                        .any(|&s| s.eq_ignore_ascii_case(name))
            }
        }
    }
}

/// Fuzz input structure for Never-Indexed testing
#[derive(Arbitrary, Debug)]
struct HpackNeverIndexedFuzz {
    /// Mixed set of headers including sensitive and regular ones
    headers: Vec<HeaderType>,
    /// Dynamic table max size for testing independence
    max_table_size: u16,
    /// Whether to use Huffman encoding
    use_huffman: bool,
    /// Test decode-reencode cycle
    test_reencode: bool,
}

/// Check if a header name is considered sensitive
fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|&sensitive| sensitive.eq_ignore_ascii_case(name))
}

/// Extract Never-Indexed flag from encoded HPACK bytes
fn has_never_indexed_flag(encoded: &[u8], header_start: usize) -> bool {
    if header_start >= encoded.len() {
        return false;
    }
    // Never-Indexed literals use pattern 0001xxxx (0x10-0x1F)
    let first_byte = encoded[header_start];
    (first_byte & 0xF0) == 0x10
}

/// Find the start positions of each header in encoded HPACK data
fn find_header_starts(encoded: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut pos = 0;

    while pos < encoded.len() {
        positions.push(pos);
        let first_byte = encoded[pos];

        if first_byte & 0x80 != 0 {
            // Indexed header field - single integer
            pos += count_integer_bytes(&encoded[pos..], 7);
        } else if first_byte & 0x40 != 0 || (first_byte & 0x10 != 0) || (first_byte & 0xF0 == 0x00)
        {
            // Literal header (with indexing, never indexed, or without indexing)
            let prefix_bits = if first_byte & 0x40 != 0 { 6 } else { 4 };
            pos += count_integer_bytes(&encoded[pos..], prefix_bits);

            // Skip name string if index was 0
            let (index, index_bytes) =
                decode_integer_at(&encoded[positions.last().unwrap()..], prefix_bits);
            if index == 0 {
                pos += count_string_bytes(&encoded[pos..]);
            }

            // Skip value string
            pos += count_string_bytes(&encoded[pos..]);
        } else if first_byte & 0x20 != 0 {
            // Dynamic table size update
            pos += count_integer_bytes(&encoded[pos..], 5);
        } else {
            // Unknown pattern, advance by 1 to avoid infinite loop
            pos += 1;
        }

        if pos == positions[positions.len() - 1] {
            // No progress made, avoid infinite loop
            break;
        }
    }

    positions
}

/// Count bytes used by an integer encoding with given prefix
fn count_integer_bytes(data: &[u8], prefix_bits: u8) -> usize {
    if data.is_empty() {
        return 1; // Assume at least 1 byte
    }

    let mask = (1u8 << prefix_bits) - 1;
    if (data[0] & mask) < mask {
        1 // Single byte integer
    } else {
        // Multi-byte integer
        let mut bytes = 1;
        for &byte in &data[1..] {
            bytes += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        bytes
    }
}

/// Count bytes used by a string encoding
fn count_string_bytes(data: &[u8]) -> usize {
    if data.is_empty() {
        return 1;
    }

    let huffman = data[0] & 0x80 != 0;
    let length_bytes = count_integer_bytes(data, 7);
    let (length, _) = decode_integer_at(data, 7);

    length_bytes + length
}

/// Decode integer at specific position with given prefix
fn decode_integer_at(data: &[u8], prefix_bits: u8) -> (usize, usize) {
    if data.is_empty() {
        return (0, 1);
    }

    let mask = (1u8 << prefix_bits) - 1;
    let first = data[0] & mask;

    if first < mask {
        (first as usize, 1)
    } else {
        let mut value = mask as usize;
        let mut m = 0;
        let mut bytes = 1;

        for &byte in &data[1..] {
            bytes += 1;
            value += ((byte & 0x7F) as usize) << m;
            m += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }

        (value, bytes)
    }
}

fuzz_target!(|input: HpackNeverIndexedFuzz| {
    if input.headers.is_empty() {
        return;
    }

    // Convert input headers to HPACK Header structs
    let headers: Vec<Header> = input.headers.iter().map(|h| h.to_header()).collect();
    let sensitive_headers: Vec<Header> = headers
        .iter()
        .filter(|h| is_sensitive_header(&h.name))
        .cloned()
        .collect();
    let regular_headers: Vec<Header> = headers
        .iter()
        .filter(|h| !is_sensitive_header(&h.name))
        .cloned()
        .collect();

    // Create encoder with specified settings
    let mut encoder = Encoder::new();
    encoder.set_huffman(input.use_huffman);

    // Test different table sizes to verify independence
    let table_size = (input.max_table_size as usize).min(16384); // Cap at reasonable size
    encoder.set_max_table_size(table_size);

    let mut encoded_sensitive = BytesMut::new();
    let mut encoded_regular = BytesMut::new();
    let mut encoded_mixed = BytesMut::new();

    // Encode sensitive headers using encode_sensitive method
    if !sensitive_headers.is_empty() {
        encoder.encode_sensitive(&sensitive_headers, &mut encoded_sensitive);
    }

    // Encode regular headers using regular encode method
    if !regular_headers.is_empty() {
        encoder.encode(&regular_headers, &mut encoded_regular);
    }

    // Encode mixed headers (sensitive with encode_sensitive, regular with encode)
    if !headers.is_empty() {
        // First encode all sensitive headers as Never-Indexed
        let mut temp_encoder = encoder.clone(); // Start fresh for mixed test
        temp_encoder.encode_sensitive(&sensitive_headers, &mut encoded_mixed);
        temp_encoder.encode(&regular_headers, &mut encoded_mixed);
    }

    // ASSERTION 1: Never-Indexed set on sensitive headers (Authorization/Cookie/Set-Cookie)
    if !encoded_sensitive.is_empty() {
        let header_starts = find_header_starts(&encoded_sensitive);
        for (i, start) in header_starts.iter().enumerate() {
            if i < sensitive_headers.len() {
                assert!(
                    has_never_indexed_flag(&encoded_sensitive, *start),
                    "Sensitive header '{}' not encoded with Never-Indexed flag",
                    sensitive_headers[i].name
                );
            }
        }
    }

    // ASSERTION 2: Flag preserved through decode+re-encode
    if input.test_reencode && !encoded_sensitive.is_empty() {
        let mut decoder = Decoder::new();
        let decoded_result = decoder.decode(encoded_sensitive.clone().freeze());

        if let Ok(decoded_headers) = decoded_result {
            // Re-encode the decoded headers as sensitive
            let mut reencoder = Encoder::new();
            reencoder.set_huffman(input.use_huffman);
            let mut reencoded = BytesMut::new();
            reencoder.encode_sensitive(&decoded_headers, &mut reencoded);

            // Verify Never-Indexed flags are preserved
            let reencoded_starts = find_header_starts(&reencoded);
            for (i, start) in reencoded_starts.iter().enumerate() {
                if i < decoded_headers.len() && is_sensitive_header(&decoded_headers[i].name) {
                    assert!(
                        has_never_indexed_flag(&reencoded, *start),
                        "Never-Indexed flag not preserved for '{}' through decode+re-encode",
                        decoded_headers[i].name
                    );
                }
            }
        }
    }

    // ASSERTION 3: Sensitive headers never enter dynamic table
    // Check dynamic table before and after encoding sensitive headers
    let initial_table_size = encoder.dynamic_table_size();
    let mut table_test_encoder = Encoder::new();
    table_test_encoder.set_max_table_size(table_size);

    let mut temp_encoded = BytesMut::new();
    table_test_encoder.encode_sensitive(&sensitive_headers, &mut temp_encoded);

    let final_table_size = table_test_encoder.dynamic_table_size();
    assert_eq!(
        initial_table_size, final_table_size,
        "Dynamic table size changed after encoding sensitive headers (Never-Indexed should not add to table)"
    );

    // Additional check: encode regular headers first, then sensitive
    let mut mixed_table_encoder = Encoder::new();
    mixed_table_encoder.set_max_table_size(table_size);
    let mut mixed_temp = BytesMut::new();

    // First encode regular headers (should add to table)
    mixed_table_encoder.encode(&regular_headers, &mut mixed_temp);
    let table_size_after_regular = mixed_table_encoder.dynamic_table_size();

    // Then encode sensitive headers (should NOT add to table)
    mixed_table_encoder.encode_sensitive(&sensitive_headers, &mut mixed_temp);
    let table_size_after_sensitive = mixed_table_encoder.dynamic_table_size();

    assert_eq!(
        table_size_after_regular, table_size_after_sensitive,
        "Dynamic table size changed after adding Never-Indexed sensitive headers"
    );

    // ASSERTION 4: Mixed-type headers handled correctly
    if !encoded_mixed.is_empty() && !sensitive_headers.is_empty() && !regular_headers.is_empty() {
        let mixed_starts = find_header_starts(&encoded_mixed);
        let mut sensitive_count = 0;
        let mut regular_count = 0;

        for (i, start) in mixed_starts.iter().enumerate() {
            let is_never_indexed = has_never_indexed_flag(&encoded_mixed, *start);

            // Determine expected header type based on encoding order
            // Sensitive headers are encoded first in our mixed test
            if i < sensitive_headers.len() {
                // Should be Never-Indexed
                assert!(
                    is_never_indexed,
                    "Mixed headers: sensitive header at position {} not encoded as Never-Indexed",
                    i
                );
                sensitive_count += 1;
            } else if i - sensitive_headers.len() < regular_headers.len() {
                // Should NOT be Never-Indexed (regular header)
                assert!(
                    !is_never_indexed,
                    "Mixed headers: regular header at position {} incorrectly encoded as Never-Indexed",
                    i
                );
                regular_count += 1;
            }
        }

        assert!(
            sensitive_count > 0 && regular_count > 0,
            "Mixed-type test should include both sensitive ({}) and regular ({}) headers",
            sensitive_count,
            regular_count
        );
    }

    // ASSERTION 5: max_table_size does not affect Never-Indexed entries
    // Test with different table sizes
    for &test_table_size in &[0, 1024, 4096, 8192] {
        if test_table_size <= table_size * 2 {
            // Avoid excessive sizes
            let mut size_test_encoder = Encoder::new();
            size_test_encoder.set_huffman(input.use_huffman);
            size_test_encoder.set_max_table_size(test_table_size);

            let mut size_encoded = BytesMut::new();
            size_test_encoder.encode_sensitive(&sensitive_headers, &mut size_encoded);

            // Never-Indexed encoding should be consistent regardless of table size
            let size_starts = find_header_starts(&size_encoded);
            for (i, start) in size_starts.iter().enumerate() {
                if i < sensitive_headers.len() {
                    assert!(
                        has_never_indexed_flag(&size_encoded, *start),
                        "Never-Indexed encoding affected by table size {} for header '{}'",
                        test_table_size,
                        sensitive_headers[i].name
                    );
                }
            }

            // Table size should remain 0 or minimal since nothing is indexed
            assert_eq!(
                size_test_encoder.dynamic_table_size(),
                0,
                "Dynamic table should remain empty when only Never-Indexed headers are encoded"
            );
        }
    }

    // Additional validation: Decode and verify header content integrity
    if !encoded_sensitive.is_empty() {
        let mut validator_decoder = Decoder::new();
        if let Ok(decoded) = validator_decoder.decode(encoded_sensitive.clone().freeze()) {
            assert_eq!(
                decoded.len(),
                sensitive_headers.len(),
                "Number of decoded headers doesn't match input"
            );

            for (original, decoded) in sensitive_headers.iter().zip(decoded.iter()) {
                assert_eq!(
                    original.name.to_lowercase(),
                    decoded.name.to_lowercase(),
                    "Header name changed during encoding/decoding"
                );
                assert_eq!(
                    original.value, decoded.value,
                    "Header value changed during encoding/decoding"
                );
            }
        }
    }
});
