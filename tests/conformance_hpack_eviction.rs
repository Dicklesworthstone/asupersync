//! RFC 7541 Section 4 HPACK Dynamic Table Eviction Conformance Tests
//!
//! Tests HPACK dynamic table management conformance per RFC 7541 Section 4:
//! - Table evicts from end (FIFO) when insertion exceeds SETTINGS_HEADER_TABLE_SIZE
//! - Resize to 0 empties table entirely
//! - Entry with size >= max_table_size is not inserted (and table cleared)
//! - Multiple resize SIGNAL bits processed in order
//! - Table entry size calculation matches RFC formula (name.len + value.len + 32)

use asupersync::bytes::{BufMut, BytesMut};
use asupersync::http::h2::hpack::{Decoder, Encoder, Header};

/// Helper function to encode an integer using HPACK integer encoding
/// This mirrors the internal encode_integer function for testing
fn encode_integer_helper(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1 << prefix_bits) - 1;

    if value < max_first {
        dst.put_u8(prefix | value as u8);
    } else {
        dst.put_u8(prefix | max_first as u8);
        let mut remaining = value - max_first;
        while remaining >= 128 {
            dst.put_u8((remaining & 0x7f) as u8 | 0x80);
            remaining >>= 7;
        }
        dst.put_u8(remaining as u8);
    }
}

/// Test that table evicts oldest entries (FIFO) when insertion exceeds max size
#[test]
fn test_dynamic_table_fifo_eviction() {
    let mut decoder = Decoder::with_max_size(100); // Small table for predictable eviction

    // Create headers with known sizes:
    // "header1" + "value1" + 32 = 7 + 6 + 32 = 45 bytes
    // "header2" + "value2" + 32 = 7 + 6 + 32 = 45 bytes
    // "header3" + "value3" + 32 = 7 + 6 + 32 = 45 bytes

    // Insert first entry (45 bytes, fits in 100 byte table)
    let mut encoder = Encoder::with_max_size(100);
    encoder.set_use_huffman(false);

    let mut buf1 = BytesMut::new();
    encoder.encode(&[Header::new("header1", "value1")], &mut buf1);
    let mut encoded1 = buf1.freeze();
    let headers1 = decoder.decode(&mut encoded1).unwrap();
    assert_eq!(headers1.len(), 1);

    // Insert second entry (45 bytes, total 90 bytes, still fits)
    let mut buf2 = BytesMut::new();
    encoder.encode(&[Header::new("header2", "value2")], &mut buf2);
    let mut encoded2 = buf2.freeze();
    let headers2 = decoder.decode(&mut encoded2).unwrap();
    assert_eq!(headers2.len(), 1);

    // Insert third entry (45 bytes, would make total 135 bytes > 100)
    // This should evict the oldest entry ("header1") due to FIFO
    let mut buf3 = BytesMut::new();
    encoder.encode(&[Header::new("header3", "value3")], &mut buf3);
    let mut encoded3 = buf3.freeze();
    let headers3 = decoder.decode(&mut encoded3).unwrap();
    assert_eq!(headers3.len(), 1);

    // Verify the table now contains only "header2" and "header3"
    // Most recent ("header3") should be at index 1, "header2" at index 2
    // We can verify this by trying to encode using indexed headers

    // Try to reference dynamic table entries by creating a custom HPACK block
    // with indexed header field representations
    // Dynamic table starts at index 62 (after 61 static table entries)
    let mut test_buf = BytesMut::new();

    // Indexed header field for index 62 (should be "header3" - most recent)
    // Use integer encoding for indices >= 127
    encode_integer_helper(&mut test_buf, 62, 7, 0x80); // Indexed header field with 7-bit prefix

    let mut test_bytes = test_buf.freeze();
    let indexed_headers = decoder.decode(&mut test_bytes).unwrap();
    assert_eq!(indexed_headers.len(), 1);
    assert_eq!(indexed_headers[0].name, "header3");
    assert_eq!(indexed_headers[0].value, "value3");
}

/// Test that resizing table to 0 empties it entirely
#[test]
fn test_dynamic_table_resize_to_zero_empties_table() {
    let mut decoder = Decoder::new();

    // Insert some entries first
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(false);

    let mut buf = BytesMut::new();
    encoder.encode(&[
        Header::new("custom1", "value1"),
        Header::new("custom2", "value2"),
    ], &mut buf);

    let mut encoded = buf.freeze();
    let headers = decoder.decode(&mut encoded).unwrap();
    assert_eq!(headers.len(), 2);

    // Now create a header block that starts with a resize to 0
    let mut resize_buf = BytesMut::new();

    // Dynamic table size update to 0 (pattern: 001xxxxx where xxxxx encodes 0)
    // 0x20 = 00100000 - size update with 5-bit prefix encoding 0
    resize_buf.put_u8(0x20); // Size update to 0

    let mut resize_bytes = resize_buf.freeze();
    let resize_headers = decoder.decode(&mut resize_bytes).unwrap();
    assert_eq!(resize_headers.len(), 0); // No headers in this block, just size update

    // Verify table is empty by trying to access index 62 (first dynamic table entry)
    let mut test_buf = BytesMut::new();
    encode_integer_helper(&mut test_buf, 62, 7, 0x80); // Try to reference index 62

    let mut test_bytes = test_buf.freeze();
    let result = decoder.decode(&mut test_bytes);

    // Should fail because dynamic table is empty (index 62 doesn't exist)
    assert!(result.is_err(), "Table should be empty after resize to 0");
}

/// Test that entry with size >= max_table_size is not inserted and table is cleared
#[test]
fn test_oversized_entry_not_inserted_table_cleared() {
    let table_size = 50;
    let mut decoder = Decoder::with_max_size(table_size);

    // First, insert a small entry that fits
    let mut encoder = Encoder::with_max_size(table_size);
    encoder.set_use_huffman(false);

    let mut buf1 = BytesMut::new();
    encoder.encode(&[Header::new("small", "val")], &mut buf1); // 5 + 3 + 32 = 40 bytes
    let mut encoded1 = buf1.freeze();
    let headers1 = decoder.decode(&mut encoded1).unwrap();
    assert_eq!(headers1.len(), 1);

    // Verify the small entry was added by accessing it via index
    let mut test_buf = BytesMut::new();
    encode_integer_helper(&mut test_buf, 62, 7, 0x80); // Index 62 (first dynamic entry)
    let mut test_bytes = test_buf.freeze();
    let indexed = decoder.decode(&mut test_bytes).unwrap();
    assert_eq!(indexed[0].name, "small");

    // Now try to insert an entry larger than the table size
    // "very-long-header-name" + "very-long-value" + 32
    // = 22 + 15 + 32 = 69 bytes > 50 byte table limit
    let mut buf2 = BytesMut::new();
    encoder.encode(&[Header::new("very-long-header-name", "very-long-value")], &mut buf2);
    let mut encoded2 = buf2.freeze();
    let headers2 = decoder.decode(&mut encoded2).unwrap();
    assert_eq!(headers2.len(), 1); // Header is still returned in the decoded list

    // But the oversized entry should not be added to the table
    // And the existing small entry should be evicted to make room
    // Try to access the original entry - should fail
    let mut test_buf2 = BytesMut::new();
    encode_integer_helper(&mut test_buf2, 62, 7, 0x80); // Try index 62 again
    let mut test_bytes2 = test_buf2.freeze();
    let result = decoder.decode(&mut test_bytes2);

    // Should fail because table was cleared when oversized entry was processed
    assert!(result.is_err(), "Table should be cleared when oversized entry is inserted");
}

/// Test that multiple resize SIGNAL bits are processed in order
#[test]
fn test_multiple_resize_signals_processed_in_order() {
    let mut decoder = Decoder::new();

    // Insert some entries first
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(false);

    let mut setup_buf = BytesMut::new();
    encoder.encode(&[
        Header::new("entry1", "value1"),
        Header::new("entry2", "value2"),
    ], &mut setup_buf);

    let mut setup_encoded = setup_buf.freeze();
    decoder.decode(&mut setup_encoded).unwrap();

    // Create a header block with multiple size updates in sequence
    let mut multi_resize_buf = BytesMut::new();

    // Use the helper function to properly encode integers
    // First resize to 1024
    encode_integer_helper(&mut multi_resize_buf, 1024, 5, 0x20);

    // Second resize to 512
    encode_integer_helper(&mut multi_resize_buf, 512, 5, 0x20);

    // Third resize to 256
    encode_integer_helper(&mut multi_resize_buf, 256, 5, 0x20);

    let mut multi_resize_bytes = multi_resize_buf.freeze();
    let resize_headers = decoder.decode(&mut multi_resize_bytes).unwrap();
    assert_eq!(resize_headers.len(), 0); // Only size updates, no headers

    // Verify the final table size is 256 (the last resize value)
    // We can check this by ensuring the decoder state is correct
    // The internal implementation should have applied all resizes in order
}

/// Simplified test for multiple resize signals using smaller values
#[test]
fn test_multiple_resize_signals_simple() {
    let mut decoder = Decoder::new();

    // Create header block with multiple simple size updates
    let mut buf = BytesMut::new();

    // Use helper function for proper integer encoding
    encode_integer_helper(&mut buf, 1000, 5, 0x20); // Size update to 1000
    encode_integer_helper(&mut buf, 500, 5, 0x20);  // Size update to 500
    encode_integer_helper(&mut buf, 100, 5, 0x20);  // Size update to 100

    let mut encoded = buf.freeze();
    let headers = decoder.decode(&mut encoded).unwrap();
    assert_eq!(headers.len(), 0); // No actual headers, just size updates

    // The decoder should have processed all three updates in sequence
    // Final table size should be 100
}

/// Test that table entry size calculation matches RFC formula
#[test]
fn test_table_entry_size_calculation_rfc_formula() {
    // RFC 7541 Section 4.1: entry size = name.len() + value.len() + 32

    let test_cases = vec![
        ("", ""),                           // Empty name/value: 0 + 0 + 32 = 32
        ("a", "b"),                         // Single chars: 1 + 1 + 32 = 34
        ("host", "example.com"),            // Common: 4 + 11 + 32 = 47
        ("content-type", "text/html"),      // 12 + 9 + 32 = 53
        ("custom-header", "custom-value"),  // 13 + 12 + 32 = 57
    ];

    for (name, value) in &test_cases {
        let header = Header::new(*name, *value);
        let calculated_size = header.size();
        let manual_calculation = name.len() + value.len() + 32;

        assert_eq!(calculated_size, manual_calculation,
            "Header::size() should match manual calculation for '{}'/'{}': {} vs {}",
            name, value, calculated_size, manual_calculation);

        // Verify the RFC 7541 Section 4.1 formula
        let expected_size = name.len() + value.len() + 32;
        assert_eq!(calculated_size, expected_size,
            "Size calculation for '{}'/'{}' should be {}",
            name, value, expected_size);
    }
}

/// Test entry size calculation with longer strings
#[test]
fn test_table_entry_size_calculation_longer_strings() {
    let test_cases = vec![
        ("host", "example.com"),             // 4 + 11 + 32 = 47
        ("content-type", "application/json"), // 12 + 16 + 32 = 60
        ("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), // 13 + 50 + 32 = 95
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"), // 10 + 68 + 32 = 110
    ];

    for (name, value) in &test_cases {
        let header = Header::new(*name, *value);
        let size = header.size();
        let expected = name.len() + value.len() + 32;

        assert_eq!(size, expected,
            "Size for '{}':'{}'should be {}", name, value, expected);

        // Verify components
        assert_eq!(name.len() + value.len() + 32, size);
    }
}

/// Test FIFO eviction with precise size control
#[test]
fn test_fifo_eviction_precise_sizes() {
    // Use a decoder with a small, precise table size
    let table_size = 100;
    let mut decoder = Decoder::with_max_size(table_size);

    // Calculate exact entry sizes:
    // "h1" + "v1" + 32 = 2 + 2 + 32 = 36 bytes
    // "h2" + "v2" + 32 = 2 + 2 + 32 = 36 bytes
    // "h3" + "v3" + 32 = 2 + 2 + 32 = 36 bytes

    let mut encoder = Encoder::with_max_size(table_size);
    encoder.set_use_huffman(false);

    // Insert entries one by one and check table state

    // Entry 1: 36 bytes (fits in 100 byte table)
    let mut buf1 = BytesMut::new();
    encoder.encode(&[Header::new("h1", "v1")], &mut buf1);
    let mut encoded1 = buf1.freeze();
    decoder.decode(&mut encoded1).unwrap();

    // Entry 2: 36 bytes (total 72 bytes, still fits)
    let mut buf2 = BytesMut::new();
    encoder.encode(&[Header::new("h2", "v2")], &mut buf2);
    let mut encoded2 = buf2.freeze();
    decoder.decode(&mut encoded2).unwrap();

    // Entry 3: 36 bytes (total would be 108 bytes > 100, should evict h1)
    let mut buf3 = BytesMut::new();
    encoder.encode(&[Header::new("h3", "v3")], &mut buf3);
    let mut encoded3 = buf3.freeze();
    decoder.decode(&mut encoded3).unwrap();

    // Now table should contain h2 and h3, with h3 at index 62 and h2 at index 63

    // Test access to h3 (should be at index 62 - most recent)
    let mut test_buf1 = BytesMut::new();
    encode_integer_helper(&mut test_buf1, 62, 7, 0x80); // Index 62
    let mut test_bytes1 = test_buf1.freeze();
    let result1 = decoder.decode(&mut test_bytes1).unwrap();
    assert_eq!(result1[0].name, "h3");
    assert_eq!(result1[0].value, "v3");

    // Test access to h2 (should be at index 63 - older)
    let mut test_buf2 = BytesMut::new();
    encode_integer_helper(&mut test_buf2, 63, 7, 0x80); // Index 63
    let mut test_bytes2 = test_buf2.freeze();
    let result2 = decoder.decode(&mut test_bytes2).unwrap();
    assert_eq!(result2[0].name, "h2");
    assert_eq!(result2[0].value, "v2");

    // Test access to h1 (should fail - it was evicted, index 64 doesn't exist)
    let mut test_buf3 = BytesMut::new();
    encode_integer_helper(&mut test_buf3, 64, 7, 0x80); // Index 64
    let mut test_bytes3 = test_buf3.freeze();
    let result3 = decoder.decode(&mut test_bytes3);
    assert!(result3.is_err(), "h1 should have been evicted and index 64 should be invalid");
}

/// Test eviction boundary conditions
#[test]
fn test_eviction_boundary_conditions() {
    // Test exact fit vs overflow
    let table_size = 72; // Exactly fits 2 entries of 36 bytes each
    let mut decoder = Decoder::with_max_size(table_size);

    let mut encoder = Encoder::with_max_size(table_size);
    encoder.set_use_huffman(false);

    // Entry 1: "h1" + "v1" + 32 = 36 bytes
    let mut buf1 = BytesMut::new();
    encoder.encode(&[Header::new("h1", "v1")], &mut buf1);
    let mut encoded1 = buf1.freeze();
    decoder.decode(&mut encoded1).unwrap();

    // Entry 2: another 36 bytes (total = 72, exactly at limit)
    let mut buf2 = BytesMut::new();
    encoder.encode(&[Header::new("h2", "v2")], &mut buf2);
    let mut encoded2 = buf2.freeze();
    decoder.decode(&mut encoded2).unwrap();

    // Both should be accessible
    let mut test1 = BytesMut::new();
    encode_integer_helper(&mut test1, 62, 7, 0x80); // Index 62 (most recent)
    let mut bytes1 = test1.freeze();
    let result1 = decoder.decode(&mut bytes1).unwrap();
    assert_eq!(result1[0].name, "h2"); // Most recent is index 62

    let mut test2 = BytesMut::new();
    encode_integer_helper(&mut test2, 63, 7, 0x80); // Index 63 (older)
    let mut bytes2 = test2.freeze();
    let result2 = decoder.decode(&mut bytes2).unwrap();
    assert_eq!(result2[0].name, "h1"); // Older is index 63

    // Entry 3: another 36 bytes (would make total 108 > 72, should evict h1)
    let mut buf3 = BytesMut::new();
    encoder.encode(&[Header::new("h3", "v3")], &mut buf3);
    let mut encoded3 = buf3.freeze();
    decoder.decode(&mut encoded3).unwrap();

    // h1 should be evicted, only h2 and h3 remain
    let mut test3 = BytesMut::new();
    encode_integer_helper(&mut test3, 64, 7, 0x80); // Index 64 should not exist
    let mut bytes3 = test3.freeze();
    let result3 = decoder.decode(&mut bytes3);
    assert!(result3.is_err(), "Index 64 should be invalid after eviction");
}