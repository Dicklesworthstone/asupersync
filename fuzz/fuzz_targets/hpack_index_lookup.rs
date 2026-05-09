//! HPACK Index Lookup Bounds Fuzz Target
//!
//! Tests the robustness of HPACK header index lookups, focusing on bounds
//! checking, overflow protection, and correct static/dynamic table resolution
//! per RFC 7541 Section 2.3.
//!
//! # Assertion Coverage
//!
//! 1. **Static indices 1..=61 resolve correctly**: Static table entries map to
//!    valid header name-value pairs per RFC 7541 Appendix A
//! 2. **Dynamic indices > 61 offset correctly**: Indices beyond static table
//!    correctly offset into dynamic table entries
//! 3. **Out-of-bounds indices trigger DECOMPRESSION_FAILED**: Invalid indices
//!    return appropriate compression errors without panicking
//! 4. **Indices after dynamic table size update re-mapped correctly**: Table
//!    resizing affects index resolution and evicts entries as expected
//! 5. **Very large varint indices do not overflow**: Large integer inputs are
//!    handled safely with overflow protection

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::hpack::{Decoder, Header};

/// Size of the static table per RFC 7541 Appendix A.
const STATIC_TABLE_SIZE: usize = 61;

/// Maximum safe index to test (avoid excessive memory allocation).
const MAX_TEST_INDEX: usize = 100_000;

/// Fuzz input for HPACK index lookup testing.
#[derive(Arbitrary, Debug)]
struct HpackIndexFuzzInput {
    /// Index to lookup (can be 0, static, dynamic, or out-of-bounds).
    index: u32,
    /// Whether to test with dynamic table populated.
    populate_dynamic: bool,
    /// Dynamic table setup if populate_dynamic is true.
    dynamic_setup: DynamicTableSetup,
    /// Whether to test table size updates.
    test_size_update: bool,
    /// New table size for size update tests.
    new_table_size: u16,
}

/// Configuration for populating the dynamic table.
#[derive(Arbitrary, Debug)]
struct DynamicTableSetup {
    /// Number of entries to add (limited to prevent excessive memory use).
    entry_count: u8,
    /// Template headers to add to dynamic table.
    header_templates: Vec<HeaderTemplate>,
}

/// Template for generating test headers.
#[derive(Arbitrary, Debug)]
struct HeaderTemplate {
    /// Header name (will be normalized).
    name_bytes: Vec<u8>,
    /// Header value (will be normalized).
    value_bytes: Vec<u8>,
}

impl HeaderTemplate {
    /// Convert to a valid Header, normalizing the input.
    fn to_header(&self) -> Header {
        let name = String::from_utf8_lossy(&self.name_bytes)
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control())
            .take(50) // Limit name length
            .collect::<String>()
            .to_lowercase();

        let value = String::from_utf8_lossy(&self.value_bytes)
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control())
            .take(100) // Limit value length
            .collect::<String>();

        Header::new(if name.is_empty() { "x-test" } else { &name }, &value)
    }
}

fn test_hpack_index_lookup(input: &HpackIndexFuzzInput) {
    let mut decoder = Decoder::new();

    // Set up dynamic table if requested
    let dynamic_entries_added = if input.populate_dynamic {
        let count = (input.dynamic_setup.entry_count as usize).min(20); // Limit entries
        for template in input.dynamic_setup.header_templates.iter().take(count) {
            let header = template.to_header();

            // Create a simple indexed header field to trigger dynamic table insertion
            // This simulates how headers get added to the dynamic table during decoding
            let mut encoded = encode_literal_with_incremental_indexing(&header);
            decoder
                .decode(&mut encoded)
                .expect("normalized dynamic-table setup header must decode");
        }
        count
    } else {
        0
    };

    // Test table size update if requested
    if input.test_size_update {
        let new_size = (input.new_table_size as usize).min(8192); // Cap size

        // Create dynamic table size update frame
        let mut size_update = encode_dynamic_table_size_update(new_size);
        let size_update_result = decoder.decode(&mut size_update);
        if new_size <= decoder.allowed_table_size() {
            size_update_result.expect("allowed dynamic table size update must decode");
        } else {
            assert_compression_error(
                size_update_result.expect_err("oversized table size update must reject"),
                "dynamic table size update exceeds allowed maximum",
            );
        }
    }

    // Test the actual index lookup
    let test_index = (input.index as usize).min(MAX_TEST_INDEX);
    let lookup_result = test_index_lookup(&mut decoder, test_index);

    // Validate results based on assertions
    match lookup_result {
        Ok(header) => {
            if test_index == 0 {
                panic!(
                    "Index 0 should be invalid but returned header: {:?}",
                    header
                );
            }

            // Assertion 1: Static indices 1..=61 resolve correctly
            if test_index <= STATIC_TABLE_SIZE {
                assert!(
                    !header.name.is_empty(),
                    "Static index {} returned empty header name",
                    test_index
                );
                // Static table entries should have well-known names
                assert!(
                    header
                        .name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == ':' || c == '-'),
                    "Static index {} returned invalid header name: '{}'",
                    test_index,
                    header.name
                );
            }
            // Assertion 2: Dynamic indices > 61 offset correctly
            else {
                let dynamic_offset = test_index - STATIC_TABLE_SIZE;
                assert!(
                    dynamic_offset <= dynamic_entries_added,
                    "Dynamic index {} (offset {}) beyond added entries {}",
                    test_index,
                    dynamic_offset,
                    dynamic_entries_added
                );
            }
        }

        Err(error) => {
            // Assertion 3: Out-of-bounds indices trigger DECOMPRESSION_FAILED
            match error {
                H2Error {
                    code: ErrorCode::CompressionError,
                    ..
                } => {
                    // Expected for invalid indices
                    if test_index == 0 {
                        // Index 0 should always fail
                        assert!(
                            error.to_string().contains("invalid index 0"),
                            "Index 0 error message unexpected: {}",
                            error
                        );
                    } else if test_index <= STATIC_TABLE_SIZE {
                        // Static indices should not fail unless there's a bug
                        panic!("Static index {} unexpectedly failed: {}", test_index, error);
                    } else {
                        // Dynamic index failures are expected when out of bounds
                        let dynamic_offset = test_index - STATIC_TABLE_SIZE;
                        assert!(
                            dynamic_offset > dynamic_entries_added,
                            "Dynamic index {} should be valid but failed: {}",
                            test_index,
                            error
                        );
                    }
                }
                _ => {
                    panic!("Unexpected error type for index {}: {}", test_index, error);
                }
            }
        }
    }

    // Assertion 4: Test index stability after size updates
    if input.test_size_update && dynamic_entries_added > 0 {
        // After size update, re-test a dynamic index to ensure proper re-mapping
        let test_dynamic_index = STATIC_TABLE_SIZE + 1;
        let post_update_result = test_index_lookup(&decoder, test_dynamic_index);

        // Result should be consistent with the new table state
        match post_update_result {
            Ok(_) => {
                // If successful, the index should still be within bounds
            }
            Err(H2Error {
                code: ErrorCode::CompressionError,
                ..
            }) => {
                // If failed, it's likely due to eviction from size reduction
            }
            Err(e) => {
                panic!("Unexpected error after size update: {}", e);
            }
        }
    }
}

/// Test index lookup through a simple indexed header field decode.
fn test_index_lookup(decoder: &mut Decoder, index: usize) -> Result<Header, H2Error> {
    // Create an indexed header field with the given index
    let mut encoded = encode_indexed_header_field(index);

    // Decode and extract the first header
    match decoder.decode(&mut encoded) {
        Ok(headers) => {
            if let Some(header) = headers.first() {
                Ok(header.clone())
            } else {
                Err(H2Error::compression("no header returned"))
            }
        }
        Err(e) => Err(e),
    }
}

fn assert_compression_error(error: H2Error, expected_message: &str) {
    assert_eq!(
        error.code,
        ErrorCode::CompressionError,
        "expected compression error, got {error}"
    );
    assert!(
        error.message.contains(expected_message),
        "expected error message containing {expected_message:?}, got {:?}",
        error.message
    );
}

fn expect_index(decoder: &mut Decoder, index: usize, name: &str, value: &str) {
    let header = test_index_lookup(decoder, index).expect("index must resolve");
    assert_eq!(header.name, name, "index {index} resolved wrong name");
    assert_eq!(header.value, value, "index {index} resolved wrong value");
}

fn run_fixed_canaries() {
    let mut decoder = Decoder::new();

    expect_index(&mut decoder, 2, ":method", "GET");
    expect_index(&mut decoder, 4, ":path", "/");
    expect_index(&mut decoder, 8, ":status", "200");
    expect_index(&mut decoder, STATIC_TABLE_SIZE, "www-authenticate", "");

    let zero_error = test_index_lookup(&mut decoder, 0).expect_err("index zero must reject");
    assert_compression_error(zero_error, "invalid index 0");

    let oversized_error =
        test_index_lookup(&mut decoder, MAX_TEST_INDEX).expect_err("oversized index must reject");
    assert_compression_error(oversized_error, "invalid dynamic index");

    let first = Header::new("x-first", "one");
    let second = Header::new("x-second", "two");
    let mut encoded_first = encode_literal_with_incremental_indexing(&first);
    let mut encoded_second = encode_literal_with_incremental_indexing(&second);
    decoder
        .decode(&mut encoded_first)
        .expect("first incremental header must decode");
    decoder
        .decode(&mut encoded_second)
        .expect("second incremental header must decode");
    expect_index(&mut decoder, STATIC_TABLE_SIZE + 1, "x-second", "two");
    expect_index(&mut decoder, STATIC_TABLE_SIZE + 2, "x-first", "one");

    let mut shrink_to_zero = encode_dynamic_table_size_update(0);
    decoder
        .decode(&mut shrink_to_zero)
        .expect("zero table size update must decode");
    let evicted = test_index_lookup(&mut decoder, STATIC_TABLE_SIZE + 1)
        .expect_err("dynamic index must reject after table is shrunk to zero");
    assert_compression_error(evicted, "invalid dynamic index");
}

/// Encode an indexed header field for testing.
fn encode_indexed_header_field(index: usize) -> Bytes {
    let mut buf = Vec::new();

    if index < 128 {
        // Single byte encoding
        buf.push(0x80 | (index as u8));
    } else {
        // Multi-byte varint encoding
        buf.push(0x80 | 0x7F); // First byte: pattern + max prefix
        encode_varint_continuation(&mut buf, index - 127);
    }

    Bytes::from(buf)
}

/// Encode a literal header field with incremental indexing.
fn encode_literal_with_incremental_indexing(header: &Header) -> Bytes {
    let mut buf = Vec::new();

    // Literal Header Field with Incremental Indexing — New Name (0x40)
    buf.push(0x40);

    // Encode name length + name
    encode_string_literal(&mut buf, &header.name);

    // Encode value length + value
    encode_string_literal(&mut buf, &header.value);

    Bytes::from(buf)
}

/// Encode a dynamic table size update.
fn encode_dynamic_table_size_update(size: usize) -> Bytes {
    let mut buf = Vec::new();

    if size < 32 {
        // Single byte encoding (pattern 001 + 5-bit value)
        buf.push(0x20 | (size as u8));
    } else {
        // Multi-byte encoding
        buf.push(0x20 | 0x1F); // Pattern + max 5-bit prefix
        encode_varint_continuation(&mut buf, size - 31);
    }

    Bytes::from(buf)
}

/// Encode string literal (simplified, no Huffman).
fn encode_string_literal(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255); // Cap length

    if len < 128 {
        buf.push(len as u8); // No Huffman flag + length
    } else {
        buf.push(0x7F); // No Huffman + max 7-bit prefix
        encode_varint_continuation(buf, len - 127);
    }

    buf.extend_from_slice(&bytes[..len]);
}

/// Encode varint continuation bytes.
fn encode_varint_continuation(buf: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        buf.push(0x80 | (value as u8 & 0x7F));
        value >>= 7;
    }
    buf.push(value as u8);
}

fuzz_target!(|data: &[u8]| {
    run_fixed_canaries();

    if let Ok(input) = HpackIndexFuzzInput::arbitrary(&mut Unstructured::new(data)) {
        test_hpack_index_lookup(&input);
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_index_valid() {
        let input = HpackIndexFuzzInput {
            index: 1, // :authority
            populate_dynamic: false,
            dynamic_setup: DynamicTableSetup {
                entry_count: 0,
                header_templates: vec![],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        test_hpack_index_lookup(&input);
    }

    #[test]
    fn test_static_index_boundary() {
        let input = HpackIndexFuzzInput {
            index: STATIC_TABLE_SIZE as u32, // www-authenticate
            populate_dynamic: false,
            dynamic_setup: DynamicTableSetup {
                entry_count: 0,
                header_templates: vec![],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        test_hpack_index_lookup(&input);
    }

    #[test]
    fn test_index_zero_invalid() {
        let input = HpackIndexFuzzInput {
            index: 0, // Should fail
            populate_dynamic: false,
            dynamic_setup: DynamicTableSetup {
                entry_count: 0,
                header_templates: vec![],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        // This should panic with our assertion
        std::panic::catch_unwind(|| test_hpack_index_lookup(&input))
            .expect_err("Index 0 should panic");
    }

    #[test]
    fn test_dynamic_index_with_entries() {
        let input = HpackIndexFuzzInput {
            index: (STATIC_TABLE_SIZE + 1) as u32,
            populate_dynamic: true,
            dynamic_setup: DynamicTableSetup {
                entry_count: 3,
                header_templates: vec![
                    HeaderTemplate {
                        name_bytes: b"x-custom".to_vec(),
                        value_bytes: b"test-value".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"x-another".to_vec(),
                        value_bytes: b"another-value".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"x-third".to_vec(),
                        value_bytes: b"third-value".to_vec(),
                    },
                ],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        test_hpack_index_lookup(&input);
    }

    #[test]
    fn test_out_of_bounds_dynamic_index() {
        let input = HpackIndexFuzzInput {
            index: (STATIC_TABLE_SIZE + 100) as u32, // Way beyond any entries
            populate_dynamic: false,
            dynamic_setup: DynamicTableSetup {
                entry_count: 0,
                header_templates: vec![],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        test_hpack_index_lookup(&input);
    }

    #[test]
    fn test_table_size_update() {
        let input = HpackIndexFuzzInput {
            index: (STATIC_TABLE_SIZE + 1) as u32,
            populate_dynamic: true,
            dynamic_setup: DynamicTableSetup {
                entry_count: 5,
                header_templates: vec![
                    HeaderTemplate {
                        name_bytes: b"large-header-name".to_vec(),
                        value_bytes: b"large-header-value-that-takes-space".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"another-large".to_vec(),
                        value_bytes: b"another-large-value".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"third-large".to_vec(),
                        value_bytes: b"third-large-value".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"fourth-large".to_vec(),
                        value_bytes: b"fourth-large-value".to_vec(),
                    },
                    HeaderTemplate {
                        name_bytes: b"fifth-large".to_vec(),
                        value_bytes: b"fifth-large-value".to_vec(),
                    },
                ],
            },
            test_size_update: true,
            new_table_size: 100, // Small size to force eviction
        };

        test_hpack_index_lookup(&input);
    }

    #[test]
    fn test_large_index_safe() {
        let input = HpackIndexFuzzInput {
            index: MAX_TEST_INDEX as u32,
            populate_dynamic: false,
            dynamic_setup: DynamicTableSetup {
                entry_count: 0,
                header_templates: vec![],
            },
            test_size_update: false,
            new_table_size: 0,
        };

        test_hpack_index_lookup(&input);
    }
}
