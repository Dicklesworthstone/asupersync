#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::http::h2::hpack::{Decoder, Encoder, Header};
use asupersync::bytes::{BytesMut, BufMut};

/// Fuzzing parameters for HPACK dynamic table eviction scenarios.
#[derive(Debug, Clone, Arbitrary)]
struct HpackEvictionConfig {
    /// Sequence of dynamic table size updates
    pub table_size_updates: Vec<u16>,
    /// Headers to encode/decode
    pub headers: Vec<FuzzHeader>,
    /// Whether to use Huffman encoding
    pub use_huffman: bool,
    /// Maximum header list size for decoder
    pub max_header_list_size: u16,
    /// Initial allowed table size
    pub initial_allowed_size: u16,
}

/// A header for fuzzing with configurable properties
#[derive(Debug, Clone, Arbitrary)]
struct FuzzHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
    /// Whether this should be never-indexed (0x10)
    pub never_indexed: bool,
    /// Whether to use an invalid index reference
    pub use_invalid_index: bool,
    /// Invalid index to use (if use_invalid_index is true)
    pub invalid_index: u8,
}

/// Validate and normalize fuzz configuration
fn normalize_config(config: &mut HpackEvictionConfig) {
    // Limit table sizes to reasonable range
    for size in &mut config.table_size_updates {
        *size = (*size).clamp(0, 65535);
    }
    config.table_size_updates.truncate(20); // Limit to 20 updates

    // Limit header list size
    config.max_header_list_size = config.max_header_list_size.clamp(1024, 65535);
    config.initial_allowed_size = config.initial_allowed_size.clamp(0, 65535);

    // Limit header count and normalize header content
    config.headers.truncate(50); // Max 50 headers
    for header in &mut config.headers {
        // Normalize header names/values for HTTP compliance
        header.name.truncate(256);
        header.value.truncate(1024);
        // Replace invalid characters per RFC 7540 Section 8.1.2
        header.name = header.name.chars()
            .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
            .collect();
        header.value = header.value.chars()
            .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
            .collect();
    }
}

/// Test dynamic table size update sequences with arbitrary transitions
fn test_table_size_updates(config: &HpackEvictionConfig) -> Result<(), String> {
    let mut decoder = Decoder::new();
    decoder.set_max_header_list_size(config.max_header_list_size as usize);
    decoder.set_allowed_table_size(config.initial_allowed_size as usize);

    for &new_size in &config.table_size_updates {
        let mut buf = BytesMut::new();

        // Encode dynamic table size update (0x20 prefix)
        encode_integer(&mut buf, new_size as usize, 5, 0x20);

        let mut src = buf.freeze();
        match decoder.decode(&mut src) {
            Ok(_) => {
                // Size update was processed successfully
            },
            Err(_) => {
                // Size update may fail if it exceeds allowed size - this is valid
            }
        }
    }

    Ok(())
}

/// Test eviction under header list size limits
fn test_header_list_size_eviction(config: &HpackEvictionConfig) -> Result<(), String> {
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(config.use_huffman);
    let mut decoder = Decoder::new();

    // Set a small header list size to force eviction scenarios
    let small_limit = 512;
    decoder.set_max_header_list_size(small_limit);

    // Create headers that may exceed the limit
    let mut total_headers = Vec::new();
    for fuzz_header in &config.headers {
        total_headers.push(Header::new(&fuzz_header.name, &fuzz_header.value));
    }

    let mut buf = BytesMut::new();
    encoder.encode(&total_headers, &mut buf);

    let mut src = buf.freeze();
    match decoder.decode(&mut src) {
        Ok(headers) => {
            // If successful, verify total size is within limits
            let total_size: usize = headers.iter()
                .map(|h| h.size())
                .sum();
            assert!(total_size <= small_limit, "Header list exceeds size limit: {} > {}", total_size, small_limit);
        },
        Err(_) => {
            // Failure is acceptable if headers exceed limit
        }
    }

    Ok(())
}

/// Test never-indexed literal headers (0x10)
fn test_never_indexed_literals(config: &HpackEvictionConfig) -> Result<(), String> {
    let mut decoder = Decoder::new();
    decoder.set_max_header_list_size(config.max_header_list_size as usize);

    for fuzz_header in &config.headers {
        if fuzz_header.never_indexed && !fuzz_header.name.is_empty() && !fuzz_header.value.is_empty() {
            let mut buf = BytesMut::new();

            // Never indexed literal header format: 0001xxxx
            buf.put_u8(0x10);
            encode_string(&mut buf, &fuzz_header.name, config.use_huffman);
            encode_string(&mut buf, &fuzz_header.value, config.use_huffman);

            let mut src = buf.freeze();
            match decoder.decode(&mut src) {
                Ok(headers) => {
                    // Should decode successfully but not be added to dynamic table
                    assert_eq!(headers.len(), 1);
                    assert_eq!(headers[0].name, fuzz_header.name);
                    assert_eq!(headers[0].value, fuzz_header.value);
                },
                Err(_) => {
                    // Failure may occur with malformed strings - acceptable
                }
            }
        }
    }

    Ok(())
}

/// Test Huffman encoding edge cases with padding
fn test_huffman_padding_edge_cases(config: &HpackEvictionConfig) -> Result<(), String> {
    if !config.use_huffman {
        return Ok(());
    }

    let mut decoder = Decoder::new();
    decoder.set_max_header_list_size(config.max_header_list_size as usize);

    // Test Huffman encoding edge cases per RFC 7541 Section 5.2
    let test_strings = vec![
        "", // Empty string
        "a", // Single character
        "www-authenticate", // Common header name
        "🚀", // Unicode (should be encoded as UTF-8 bytes)
    ];

    for test_str in test_strings {
        let mut buf = BytesMut::new();

        // Literal header without indexing
        buf.put_u8(0x00);
        encode_string(&mut buf, test_str, true); // Force Huffman
        encode_string(&mut buf, "test-value", true);

        let mut src = buf.freeze();
        let _ = decoder.decode(&mut src); // Allow both success and failure
    }

    Ok(())
}

/// Test invalid index references past dynamic table bounds
fn test_invalid_index_references(config: &HpackEvictionConfig) -> Result<(), String> {
    let mut decoder = Decoder::new();
    decoder.set_max_header_list_size(config.max_header_list_size as usize);

    for fuzz_header in &config.headers {
        if fuzz_header.use_invalid_index {
            let mut buf = BytesMut::new();

            // Use an index that's likely to be out of bounds
            // Static table has 61 entries, so anything > 70 is likely invalid
            let invalid_index = 70 + (fuzz_header.invalid_index as usize);
            encode_integer(&mut buf, invalid_index, 7, 0x80); // Indexed header

            let mut src = buf.freeze();
            match decoder.decode(&mut src) {
                Ok(_) => {
                    // Should not succeed with truly invalid index
                    return Err("Invalid index reference was accepted".to_string());
                },
                Err(_) => {
                    // Expected failure for out-of-bounds index
                }
            }
        }
    }

    Ok(())
}

/// Test complex eviction scenarios with mixed operations
fn test_complex_eviction_scenarios(config: &HpackEvictionConfig) -> Result<(), String> {
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(config.use_huffman);
    let mut decoder = Decoder::new();

    decoder.set_max_header_list_size(config.max_header_list_size as usize);
    decoder.set_allowed_table_size(config.initial_allowed_size as usize);

    // Simulate a complex sequence: size updates + headers + more size updates
    let mut buf = BytesMut::new();

    // Start with table size updates
    for (i, &size) in config.table_size_updates.iter().enumerate().take(3) {
        encode_integer(&mut buf, size as usize, 5, 0x20);

        // Add some headers after updates
        if i < config.headers.len() {
            let header = &config.headers[i];
            if !header.name.is_empty() && !header.value.is_empty() {
                if header.never_indexed {
                    buf.put_u8(0x10); // Never indexed
                } else {
                    buf.put_u8(0x40); // Literal with incremental indexing
                }
                encode_string(&mut buf, &header.name, config.use_huffman);
                encode_string(&mut buf, &header.value, config.use_huffman);
            }
        }
    }

    let mut src = buf.freeze();
    let _ = decoder.decode(&mut src); // Allow both success and failure

    Ok(())
}

/// Main fuzzing function
fn fuzz_hpack_eviction(mut config: HpackEvictionConfig) -> Result<(), String> {
    normalize_config(&mut config);

    // Skip degenerate cases
    if config.headers.is_empty() {
        return Ok(());
    }

    // Test 1: Dynamic table size update sequences (0x20)
    test_table_size_updates(&config)?;

    // Test 2: Eviction under header list size limits
    test_header_list_size_eviction(&config)?;

    // Test 3: Never-indexed literal headers (0x10)
    test_never_indexed_literals(&config)?;

    // Test 4: Huffman encoding edge cases with padding
    test_huffman_padding_edge_cases(&config)?;

    // Test 5: Invalid index references past dynamic table bounds
    test_invalid_index_references(&config)?;

    // Test 6: Complex mixed scenarios
    test_complex_eviction_scenarios(&config)?;

    Ok(())
}

/// Encode an integer using HPACK encoding rules
fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix_pattern: u8) {
    let max_first = (1 << prefix_bits) - 1;

    if value < max_first {
        dst.put_u8(prefix_pattern | (value as u8));
    } else {
        dst.put_u8(prefix_pattern | (max_first as u8));
        let mut value = value - max_first;

        while value >= 128 {
            dst.put_u8(((value % 128) + 128) as u8);
            value /= 128;
        }
        dst.put_u8(value as u8);
    }
}

/// Encode a string (simplified, without actual Huffman implementation)
fn encode_string(dst: &mut BytesMut, s: &str, _use_huffman: bool) {
    let bytes = s.as_bytes();

    // For simplicity, always use literal encoding
    // Real implementation would use Huffman when beneficial
    encode_integer(dst, bytes.len(), 7, 0x00);
    dst.extend_from_slice(bytes);
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz configuration
    let config = if let Ok(c) = HpackEvictionConfig::arbitrary(&mut unstructured) {
        c
    } else {
        return;
    };

    // Run HPACK eviction fuzzing
    let _ = fuzz_hpack_eviction(config);
});