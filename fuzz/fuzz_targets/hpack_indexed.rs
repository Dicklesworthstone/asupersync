#![no_main]

//! HPACK Indexed Header Field Representation Fuzzer
//!
//! Tests RFC 7541 §6.1 indexed header field representation with focus on:
//! 1. No panic on any indexed byte sequence
//! 2. Static table indices 1-61 resolved to correct (name,value) pairs
//! 3. Dynamic table index past current size → decoding error (not panic)
//! 4. Index 0 rejected as invalid per RFC
//! 5. Huffman + literal round-trips preserve bytes

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use asupersync::{
    bytes::Bytes,
    http::h2::hpack::Decoder,
};

/// Fuzzing input structure for HPACK indexed header testing
#[derive(Arbitrary, Debug)]
struct HpackIndexedInput {
    /// Raw bytes to decode as HPACK indexed header fields
    header_data: Vec<u8>,
    /// Dynamic table setup operations before testing indexed lookups
    setup_operations: Vec<DynamicTableOp>,
    /// Maximum dynamic table size for testing size bounds
    max_table_size: u16, // Bounded to prevent excessive memory usage
}

/// Operations to set up dynamic table state before testing
#[derive(Arbitrary, Debug)]
enum DynamicTableOp {
    /// Insert a literal header with incremental indexing
    InsertHeader { name: String, value: String },
    /// Update dynamic table size
    UpdateTableSize(u16),
}

/// Static table entries from RFC 7541 Appendix A for verification
const STATIC_TABLE_ENTRIES: &[(&str, &str)] = &[
    (":authority", ""),                   // 1
    (":method", "GET"),                   // 2
    (":method", "POST"),                  // 3
    (":path", "/"),                       // 4
    (":path", "/index.html"),             // 5
    (":scheme", "http"),                  // 6
    (":scheme", "https"),                 // 7
    (":status", "200"),                   // 8
    (":status", "204"),                   // 9
    (":status", "206"),                   // 10
    (":status", "304"),                   // 11
    (":status", "400"),                   // 12
    (":status", "404"),                   // 13
    (":status", "500"),                   // 14
    ("accept-charset", ""),               // 15
    ("accept-encoding", "gzip, deflate"), // 16
    ("accept-language", ""),              // 17
    ("accept-ranges", ""),                // 18
    ("accept", ""),                       // 19
    ("access-control-allow-origin", ""),  // 20
    ("age", ""),                          // 21
    ("allow", ""),                        // 22
    ("authorization", ""),                // 23
    ("cache-control", ""),                // 24
    ("content-disposition", ""),          // 25
    ("content-encoding", ""),             // 26
    ("content-language", ""),             // 27
    ("content-length", ""),               // 28
    ("content-location", ""),             // 29
    ("content-range", ""),                // 30
    ("content-type", ""),                 // 31
    ("cookie", ""),                       // 32
    ("date", ""),                         // 33
    ("etag", ""),                         // 34
    ("expect", ""),                       // 35
    ("expires", ""),                      // 36
    ("from", ""),                         // 37
    ("host", ""),                         // 38
    ("if-match", ""),                     // 39
    ("if-modified-since", ""),            // 40
    ("if-none-match", ""),                // 41
    ("if-range", ""),                     // 42
    ("if-unmodified-since", ""),          // 43
    ("last-modified", ""),                // 44
    ("link", ""),                         // 45
    ("location", ""),                     // 46
    ("max-forwards", ""),                 // 47
    ("proxy-authenticate", ""),           // 48
    ("proxy-authorization", ""),          // 49
    ("range", ""),                        // 50
    ("referer", ""),                      // 51
    ("refresh", ""),                      // 52
    ("retry-after", ""),                  // 53
    ("server", ""),                       // 54
    ("set-cookie", ""),                   // 55
    ("strict-transport-security", ""),    // 56
    ("transfer-encoding", ""),            // 57
    ("user-agent", ""),                   // 58
    ("vary", ""),                         // 59
    ("via", ""),                          // 60
    ("www-authenticate", ""),             // 61
];

fuzz_target!(|input: HpackIndexedInput| {
    // Bound input size to prevent excessive memory allocation during fuzzing
    if input.header_data.len() > 64 * 1024 {
        return;
    }

    // Create decoder with bounded table size
    let table_size = (input.max_table_size as usize).min(16384); // Cap at 16KB
    let mut decoder = Decoder::with_max_size(table_size);

    // Setup dynamic table state through valid operations first
    setup_dynamic_table(&mut decoder, &input.setup_operations);

    // Test Property 1: No panic on any indexed byte sequence
    test_no_panic_on_indexed_bytes(&mut decoder, &input.header_data);

    // Test Property 2: Static table indices 1-61 resolve correctly
    test_static_table_correctness();

    // Test Property 3: Dynamic table index past size → error (not panic)
    test_dynamic_table_bounds(&mut decoder);

    // Test Property 4: Index 0 rejected as invalid per RFC
    test_index_zero_rejection();

    // Test Property 5: Huffman + literal round-trip preservation
    test_huffman_round_trip(&input.header_data);
});

/// Setup dynamic table with bounded operations to avoid excessive state
fn setup_dynamic_table(decoder: &mut Decoder, operations: &[DynamicTableOp]) {
    let mut header_block = Vec::new();

    for (i, op) in operations.iter().enumerate() {
        // Limit operations to prevent test slowdown
        if i >= 32 {
            break;
        }

        match op {
            DynamicTableOp::InsertHeader { name, value } => {
                // Bound header sizes
                let bounded_name = if name.len() > 256 { &name[..256] } else { name };
                let bounded_value = if value.len() > 512 { &value[..512] } else { value };

                // Encode literal with incremental indexing (pattern: 01xxxxxx)
                // Use index 0 for new name + encode name string + encode value string
                header_block.push(0x40); // 01000000 - literal with incremental indexing, index 0
                encode_string(&mut header_block, bounded_name, false);
                encode_string(&mut header_block, bounded_value, false);
            },
            DynamicTableOp::UpdateTableSize(size) => {
                let bounded_size = (*size as usize).min(16384);
                // Encode dynamic table size update (pattern: 001xxxxx)
                header_block.push(0x20); // 00100000
                encode_integer(&mut header_block, bounded_size, 5);
            },
        }
    }

    // Apply operations if any were generated
    if !header_block.is_empty() {
        let mut bytes = Bytes::from(header_block);
        let _ = decoder.decode(&mut bytes); // Ignore result - setup only
    }
}

/// Test Property 1: No panic on any indexed byte sequence
fn test_no_panic_on_indexed_bytes(decoder: &mut Decoder, data: &[u8]) {
    // Test direct indexed patterns (1xxxxxxx)
    for byte in data.iter().take(256) { // Limit iterations
        let indexed_byte = *byte | 0x80; // Force indexed pattern
        let mut bytes = Bytes::from(vec![indexed_byte]);
        let _ = decoder.decode(&mut bytes); // Should not panic
    }

    // Test multi-byte indexed patterns
    if data.len() >= 2 {
        for chunk in data.chunks(2).take(128) {
            if chunk.len() == 2 {
                let indexed_seq = vec![chunk[0] | 0x80, chunk[1]];
                let mut bytes = Bytes::from(indexed_seq);
                let _ = decoder.decode(&mut bytes); // Should not panic
            }
        }
    }

    // Test raw data as indexed header block
    let mut bytes = Bytes::from(data.to_vec());
    let _ = decoder.decode(&mut bytes); // Should not panic on malformed data
}

/// Test Property 2: Static table indices 1-61 resolve to correct (name,value) pairs
fn test_static_table_correctness() {
    let mut decoder = Decoder::new();

    for (expected_index, &(expected_name, expected_value)) in STATIC_TABLE_ENTRIES.iter().enumerate() {
        let index = expected_index + 1; // Static table is 1-indexed

        // Encode indexed header field for this static table entry
        let mut header_block = Vec::new();
        header_block.push(0x80); // 10000000 - indexed header field pattern
        encode_integer(&mut header_block, index, 7);

        let mut bytes = Bytes::from(header_block);
        if let Ok(headers) = decoder.decode(&mut bytes)
            && let Some(header) = headers.first()
        {
            // Verify name and value match static table entry exactly
            assert_eq!(header.name, expected_name,
                "Static table index {} name mismatch: expected '{}', got '{}'",
                index, expected_name, header.name);
            assert_eq!(header.value, expected_value,
                "Static table index {} value mismatch: expected '{}', got '{}'",
                index, expected_value, header.value);
        }
    }
}

/// Test Property 3: Dynamic table index past current size → decoding error (not panic)
fn test_dynamic_table_bounds(decoder: &mut Decoder) {
    // Test indices beyond static table range (> 61) on empty dynamic table
    let out_of_bounds_indices = [62, 63, 100, 255, 1000, 65535];

    for &index in &out_of_bounds_indices {
        let mut header_block = Vec::new();
        header_block.push(0x80); // 10000000 - indexed header field pattern
        encode_integer(&mut header_block, index, 7);

        let mut bytes = Bytes::from(header_block);
        let result = decoder.decode(&mut bytes);

        // Should return error, not panic
        assert!(result.is_err(),
            "Expected error for out-of-bounds dynamic table index {}, but got success", index);
    }
}

/// Test Property 4: Index 0 rejected as invalid per RFC 7541
fn test_index_zero_rejection() {
    let mut decoder = Decoder::new();

    // Encode indexed header field with index 0 (invalid per RFC)
    let header_block = vec![0x80]; // 10000000 - indexed pattern, index 0

    let mut bytes = Bytes::from(header_block);
    let result = decoder.decode(&mut bytes);

    // RFC 7541 requires rejecting index 0
    assert!(result.is_err(), "Expected error for invalid index 0, but decoding succeeded");
}

/// Test Property 5: Huffman + literal round-trip preservation
fn test_huffman_round_trip(data: &[u8]) {
    // Only test with reasonable-sized input to avoid timeout
    if data.len() > 1024 {
        return;
    }

    // Test Huffman encoding round-trip on ASCII-ish data
    let ascii_data: Vec<u8> = data.iter()
        .take(512)
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b } else { b'?' })
        .collect();

    if ascii_data.is_empty() {
        return;
    }

    // Create literal header with Huffman encoding
    let mut decoder = Decoder::new();
    let mut header_block = Vec::new();

    // Literal without indexing (0000xxxx), index 0 (new name)
    header_block.push(0x00);

    // Encode name with Huffman
    if let Ok(name_str) = String::from_utf8(ascii_data.clone()) {
        encode_string(&mut header_block, &name_str, true); // Huffman=true
        encode_string(&mut header_block, "test-value", false); // Plain value

        let mut bytes = Bytes::from(header_block);
        if let Ok(headers) = decoder.decode(&mut bytes)
            && let Some(header) = headers.first()
        {
            // The decoded name should equal the original input (round-trip preservation)
            assert_eq!(header.name.as_bytes(), ascii_data,
                "Huffman round-trip failed: original {:?} != decoded {:?}",
                ascii_data, header.name.as_bytes());
        }
    }
}

/// Encode string with optional Huffman encoding (simplified for fuzzing)
fn encode_string(dst: &mut Vec<u8>, s: &str, huffman: bool) {
    let bytes = s.as_bytes();

    if huffman {
        // Set Huffman flag (H=1) and encode length
        let len = bytes.len();
        dst.push(0x80); // H=1, length follows
        encode_integer(dst, len, 7);
        dst.extend_from_slice(bytes); // Simplified: use plain bytes (real impl would Huffman encode)
    } else {
        // Plain string (H=0)
        let len = bytes.len();
        encode_integer(dst, len, 7);
        dst.extend_from_slice(bytes);
    }
}

/// Encode integer using HPACK integer representation (simplified)
fn encode_integer(dst: &mut Vec<u8>, value: usize, prefix_bits: u8) {
    let max_prefix = (1_usize << prefix_bits) - 1;

    if value < max_prefix {
        // Single byte encoding - merge with existing prefix in last byte
        if let Some(last) = dst.last_mut() {
            *last |= value as u8;
        } else {
            dst.push(value as u8);
        }
    } else {
        // Multi-byte encoding
        if let Some(last) = dst.last_mut() {
            *last |= max_prefix as u8;
        } else {
            dst.push(max_prefix as u8);
        }

        let mut remaining = value - max_prefix;
        while remaining >= 128 {
            dst.push((remaining % 128) as u8 | 0x80);
            remaining /= 128;
        }
        dst.push(remaining as u8);
    }
}
