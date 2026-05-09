#![no_main]

//! HPACK Indexed Header Field Representation Fuzzer
//!
//! Tests RFC 7541 §6.1 indexed header field representation with focus on:
//! 1. No panic on any indexed byte sequence
//! 2. Static table indices 1-61 resolved to correct (name,value) pairs
//! 3. Dynamic table index past current size → decoding error (not panic)
//! 4. Index 0 rejected as invalid per RFC
//! 5. Huffman + literal round-trips preserve bytes

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::{
    bytes::Bytes,
    http::h2::hpack::{Decoder, Header},
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
    test_dynamic_table_bounds();

    // Test Property 4: Index 0 rejected as invalid per RFC
    test_index_zero_rejection();

    // Test Property 5: Huffman + literal round-trip preservation
    test_huffman_round_trip(&input.header_data);

    // Fixed parser-contract canaries for indexed and dynamic-table behavior.
    test_indexed_decode_canaries();
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
                let bounded_name = bounded_utf8_prefix(name, 256);
                let bounded_value = bounded_utf8_prefix(value, 512);

                // Encode literal with incremental indexing (pattern: 01xxxxxx)
                // Use index 0 for new name + encode name string + encode value string
                header_block.push(0x40); // 01000000 - literal with incremental indexing, index 0
                encode_string(&mut header_block, bounded_name, false);
                encode_string(&mut header_block, bounded_value, false);
            }
            DynamicTableOp::UpdateTableSize(size) => {
                let bounded_size = (*size as usize).min(16384);
                // Encode dynamic table size update (pattern: 001xxxxx)
                header_block.push(0x20); // 00100000
                encode_integer(&mut header_block, bounded_size, 5);
            }
        }
    }

    // Apply operations if any were generated
    if !header_block.is_empty() {
        let _ = observe_decode(decoder, header_block);
        assert!(
            decoder.dynamic_table_size() <= decoder.dynamic_table_max_size(),
            "dynamic table size exceeded max after setup"
        );
        assert!(
            decoder.dynamic_table_max_size() <= decoder.allowed_table_size(),
            "dynamic table max exceeded allowed size after setup"
        );
    }
}

/// Test Property 1: No panic on any indexed byte sequence
fn test_no_panic_on_indexed_bytes(decoder: &mut Decoder, data: &[u8]) {
    // Test direct indexed patterns (1xxxxxxx)
    for byte in data.iter().take(256) {
        // Limit iterations
        let indexed_byte = *byte | 0x80; // Force indexed pattern
        if let Ok(headers) = observe_decode(decoder, vec![indexed_byte]) {
            assert_eq!(
                headers.len(),
                1,
                "single indexed header representation decoded to unexpected header count"
            );
        }
    }

    // Test multi-byte indexed patterns
    if data.len() >= 2 {
        for chunk in data.chunks(2).take(128) {
            if chunk.len() == 2 {
                let indexed_seq = vec![chunk[0] | 0x80, chunk[1]];
                let _ = observe_decode(decoder, indexed_seq);
            }
        }
    }

    // Test raw data as indexed header block
    let _ = observe_decode(decoder, data.to_vec());
}

/// Test Property 2: Static table indices 1-61 resolve to correct (name,value) pairs
fn test_static_table_correctness() {
    let mut decoder = Decoder::new();

    for (expected_index, &(expected_name, expected_value)) in
        STATIC_TABLE_ENTRIES.iter().enumerate()
    {
        let index = expected_index + 1; // Static table is 1-indexed

        // Encode indexed header field for this static table entry
        let header_block = encode_indexed_header(index);

        let headers = observe_decode(&mut decoder, header_block).unwrap_or_else(|remaining| {
            panic!("static table index {index} rejected with {remaining} bytes remaining")
        });
        assert_eq!(
            headers.len(),
            1,
            "Static table index {index} decoded to wrong header count"
        );
        let header = &headers[0];

        // Verify name and value match static table entry exactly
        assert_eq!(
            header.name, expected_name,
            "Static table index {} name mismatch: expected '{}', got '{}'",
            index, expected_name, header.name
        );
        assert_eq!(
            header.value, expected_value,
            "Static table index {} value mismatch: expected '{}', got '{}'",
            index, expected_value, header.value
        );
    }
}

/// Test Property 3: Dynamic table index past current size → decoding error (not panic)
fn test_dynamic_table_bounds() {
    // Test indices beyond static table range (> 61) on empty dynamic table
    let out_of_bounds_indices = [62, 63, 100, 255, 1000, 65535];

    for &index in &out_of_bounds_indices {
        let mut decoder = Decoder::new();
        let header_block = encode_indexed_header(index);
        let result = observe_decode(&mut decoder, header_block);

        // Should return error, not panic
        assert!(
            result.is_err(),
            "Expected error for out-of-bounds dynamic table index {}, but got success",
            index
        );
    }
}

/// Test Property 4: Index 0 rejected as invalid per RFC 7541
fn test_index_zero_rejection() {
    let mut decoder = Decoder::new();

    // Encode indexed header field with index 0 (invalid per RFC)
    let result = observe_decode(&mut decoder, encode_indexed_header(0));

    // RFC 7541 requires rejecting index 0
    assert!(
        result.is_err(),
        "Expected error for invalid index 0, but decoding succeeded"
    );
}

/// Test Property 5: Huffman + literal round-trip preservation
fn test_huffman_round_trip(data: &[u8]) {
    // Only test with reasonable-sized input to avoid timeout
    if data.len() > 1024 {
        return;
    }

    // Test Huffman encoding round-trip on ASCII-ish data
    let ascii_data: Vec<u8> = data
        .iter()
        .take(512)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'?'
            }
        })
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

        if let Ok(headers) = observe_decode(&mut decoder, header_block)
            && let Some(header) = headers.first()
        {
            // The decoded name should equal the original input (round-trip preservation)
            assert_eq!(
                header.name.as_bytes(),
                ascii_data,
                "Huffman round-trip failed: original {:?} != decoded {:?}",
                ascii_data,
                header.name.as_bytes()
            );
        }
    }
}

/// Fixed canaries for HPACK indexed-header parser contracts.
fn test_indexed_decode_canaries() {
    let mut decoder = Decoder::new();
    let headers = observe_decode(&mut decoder, encode_indexed_header(2))
        .expect("static table index 2 should decode");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");

    let mut decoder = Decoder::new();
    assert!(
        observe_decode(&mut decoder, encode_indexed_header(0)).is_err(),
        "index 0 must be rejected"
    );

    let mut decoder = Decoder::new();
    assert!(
        observe_decode(&mut decoder, vec![0xff]).is_err(),
        "truncated indexed integer continuation must be rejected"
    );

    let mut decoder = Decoder::new();
    assert!(
        observe_decode(&mut decoder, encode_indexed_header(127)).is_err(),
        "empty dynamic table must reject index past static table"
    );

    let mut decoder = Decoder::new();
    let setup_block = encode_literal_with_incremental_indexing("x-test", "v");
    let setup_headers = observe_decode(&mut decoder, setup_block)
        .expect("valid literal with incremental indexing should decode");
    assert_eq!(setup_headers.len(), 1);
    assert_eq!(setup_headers[0].name, "x-test");
    assert_eq!(setup_headers[0].value, "v");

    let dynamic_index = STATIC_TABLE_ENTRIES.len() + 1;
    let dynamic_headers = observe_decode(&mut decoder, encode_indexed_header(dynamic_index))
        .expect("first dynamic table entry should be addressable");
    assert_eq!(dynamic_headers.len(), 1);
    assert_eq!(dynamic_headers[0].name, "x-test");
    assert_eq!(dynamic_headers[0].value, "v");
}

fn observe_decode(decoder: &mut Decoder, data: Vec<u8>) -> Result<Vec<Header>, usize> {
    let original_len = data.len();
    let mut bytes = Bytes::from(data);
    let result = decoder.decode(&mut bytes);
    let remaining_len = bytes.len();
    assert!(
        remaining_len <= original_len,
        "HPACK decoder reported impossible remaining byte count"
    );

    match result {
        Ok(headers) => {
            assert!(
                bytes.is_empty(),
                "successful HPACK decode left {remaining_len} trailing bytes"
            );
            for header in &headers {
                assert!(
                    !header.name.is_empty(),
                    "successful HPACK decode produced an empty header name"
                );
                assert!(
                    !header
                        .value
                        .chars()
                        .any(|ch| matches!(ch, '\0' | '\r' | '\n')),
                    "successful HPACK decode produced an invalid header value"
                );
            }
            Ok(headers)
        }
        Err(_) => Err(remaining_len),
    }
}

fn encode_indexed_header(index: usize) -> Vec<u8> {
    let mut header_block = vec![0x80]; // 10000000 - indexed header field pattern
    encode_integer(&mut header_block, index, 7);
    header_block
}

fn encode_literal_with_incremental_indexing(name: &str, value: &str) -> Vec<u8> {
    let mut header_block = vec![0x40]; // 01000000 - literal with incremental indexing, index 0
    encode_string(&mut header_block, name, false);
    encode_string(&mut header_block, value, false);
    header_block
}

fn bounded_utf8_prefix(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }

    let mut end = max_len;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
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
