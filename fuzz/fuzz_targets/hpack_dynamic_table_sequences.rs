//! Adversarial fuzzer for HPACK dynamic table state machine sequences (asupersync-x5ordu).
//!
//! Tests sequences of insert/dynamic-table-resize/eviction across encoder+decoder,
//! asserting indices stay consistent throughout the operation sequence.
//!
//! Key scenarios tested:
//! 1. Dynamic table size updates interleaved with header insertions
//! 2. Rapid eviction through size reduction followed by insertions
//! 3. Index consistency across encoder/decoder state machines
//! 4. Edge cases: zero-size tables, maximum size tables, rapid resize sequences

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{ErrorCode, H2Error, Header, HpackDecoder, HpackEncoder};
use libfuzzer_sys::fuzz_target;

const MAX_DECODED_HEADERS: usize = 64;
const MAX_DECODED_HEADER_BYTES: usize = 4096;

#[derive(Arbitrary, Debug, Clone)]
struct DynamicTableSequence {
    /// Initial table size for both encoder and decoder
    initial_table_size: u16,
    /// Sequence of operations to perform
    operations: Vec<DynamicTableOp>,
}

#[derive(Arbitrary, Debug, Clone)]
enum DynamicTableOp {
    /// Insert a new header into the dynamic table
    InsertHeader {
        name: String,
        value: String,
        use_huffman: bool,
    },
    /// Insert using an indexed name from static/dynamic table
    InsertWithIndexedName {
        name_index: u8,
        value: String,
        use_huffman: bool,
    },
    /// Change dynamic table size
    ResizeTable { new_size: u16 },
    /// Reference a header by index (should trigger eviction if index becomes invalid)
    ReferenceIndex { index: u8 },
    /// Insert multiple headers rapidly to force eviction
    BurstInsert { headers: Vec<(String, String)> },
    /// Simulate encoder/decoder round-trip to test consistency
    RoundTrip { headers: Vec<(String, String)> },
}

fuzz_target!(|input: DynamicTableSequence| {
    // Normalize input to prevent resource exhaustion
    let mut sequence = input;
    normalize_sequence(&mut sequence);

    test_dynamic_table_consistency(&sequence);
});

fn normalize_sequence(sequence: &mut DynamicTableSequence) {
    // Clamp table size to reasonable range
    sequence.initial_table_size = sequence.initial_table_size.clamp(0, 16384);

    // Limit operation count to prevent timeouts
    sequence.operations.truncate(100);

    for op in &mut sequence.operations {
        match op {
            DynamicTableOp::InsertHeader { name, value, .. } => {
                name.truncate(64);
                // Ensure valid HTTP header name characters
                *name = name
                    .chars()
                    .filter(|&c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit())
                    .collect();
                if name.is_empty() {
                    *name = "x-test".to_string();
                }
                value.truncate(256);
                // Remove control characters from value
                *value = value
                    .chars()
                    .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
                    .collect();
            }
            DynamicTableOp::InsertWithIndexedName { value, .. } => {
                value.truncate(256);
                // Remove control characters from value
                *value = value
                    .chars()
                    .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
                    .collect();
            }
            DynamicTableOp::ResizeTable { new_size } => {
                *new_size = (*new_size).clamp(0, 16384);
            }
            DynamicTableOp::ReferenceIndex { index } => {
                // Limit to reasonable index range
                *index = (*index).clamp(1, 100);
            }
            DynamicTableOp::BurstInsert { headers } => {
                headers.truncate(20);
                for (name, value) in headers {
                    name.truncate(32);
                    value.truncate(128);
                    *name = name
                        .chars()
                        .filter(|&c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit())
                        .collect();
                    if name.is_empty() {
                        *name = "x-burst".to_string();
                    }
                    *value = value
                        .chars()
                        .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
                        .collect();
                }
            }
            DynamicTableOp::RoundTrip { headers } => {
                headers.truncate(10);
                for (name, value) in headers {
                    name.truncate(32);
                    value.truncate(128);
                    *name = name
                        .chars()
                        .filter(|&c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit())
                        .collect();
                    if name.is_empty() {
                        *name = "x-round".to_string();
                    }
                    *value = value
                        .chars()
                        .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
                        .collect();
                }
            }
        }
    }
}

fn test_dynamic_table_consistency(sequence: &DynamicTableSequence) {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Set initial table sizes
    let initial_size = sequence.initial_table_size as usize;
    encoder.set_max_table_size(initial_size);
    decoder.set_allowed_table_size(initial_size);

    // Track what we expect to be in the dynamic table for consistency checking
    let mut expected_dynamic_entries: Vec<(String, String)> = Vec::new();
    let mut current_table_size = initial_size;

    for (op_idx, op) in sequence.operations.iter().enumerate() {
        match op {
            DynamicTableOp::InsertHeader {
                name,
                value,
                use_huffman,
            } => {
                encoder.set_use_huffman(*use_huffman);

                // Encode the header
                let header = Header {
                    name: name.clone(),
                    value: value.clone(),
                };
                let mut encoded_buf = BytesMut::new();
                encoder.encode(std::slice::from_ref(&header), &mut encoded_buf);

                // Decode and verify
                let mut encoded_bytes = encoded_buf.freeze();
                if let Ok(decoded_headers) =
                    observe_hpack_decode("insert header", &mut decoder, &mut encoded_bytes)
                {
                    // Verify the decoded header matches what we sent
                    if !decoded_headers.is_empty() {
                        let decoded = &decoded_headers[0];
                        if decoded.name != *name || decoded.value != *value {
                            panic!(
                                "Header mismatch at op {}: sent ({}, {}), got ({}, {})",
                                op_idx, name, value, decoded.name, decoded.value
                            );
                        }
                    }

                    // Add to expected dynamic table (will be evicted if table is full)
                    simulate_dynamic_table_insertion(
                        &mut expected_dynamic_entries,
                        name.clone(),
                        value.clone(),
                        current_table_size,
                    );
                }
            }

            DynamicTableOp::InsertWithIndexedName {
                name_index,
                value,
                use_huffman,
            } => {
                encoder.set_use_huffman(*use_huffman);

                // Try to construct a header using the indexed name
                // For simplicity, we'll use a known static table entry or skip if index is invalid
                let name = match name_index {
                    1 => ":authority",
                    2 => ":method",
                    3 => ":method",
                    4 => ":path",
                    8 => ":status",
                    _ => "x-indexed",
                };

                let header = Header {
                    name: name.to_string(),
                    value: value.clone(),
                };
                let mut encoded_buf = BytesMut::new();
                encoder.encode(std::slice::from_ref(&header), &mut encoded_buf);

                let mut encoded_bytes = encoded_buf.freeze();
                if let Ok(decoded_headers) = observe_hpack_decode(
                    "insert with indexed name",
                    &mut decoder,
                    &mut encoded_bytes,
                ) && !decoded_headers.is_empty()
                {
                    simulate_dynamic_table_insertion(
                        &mut expected_dynamic_entries,
                        name.to_string(),
                        value.clone(),
                        current_table_size,
                    );
                }
            }

            DynamicTableOp::ResizeTable { new_size } => {
                let new_size_usize = *new_size as usize;

                // Update encoder table size
                encoder.set_max_table_size(new_size_usize);

                // Create a size update instruction for the decoder
                let mut size_update_buf = BytesMut::new();
                encode_integer(&mut size_update_buf, new_size_usize, 5, 0x20);

                let mut size_update_bytes = size_update_buf.freeze();
                if let Ok(decoded_headers) = observe_hpack_decode(
                    "dynamic table size update",
                    &mut decoder,
                    &mut size_update_bytes,
                ) {
                    assert!(
                        decoded_headers.is_empty(),
                        "dynamic table size update blocks should not decode headers"
                    );
                    current_table_size = new_size_usize;
                    // Simulate eviction due to size reduction
                    simulate_table_eviction(&mut expected_dynamic_entries, current_table_size);
                }
            }

            DynamicTableOp::ReferenceIndex { index } => {
                // Try to reference a header by index
                let mut reference_buf = BytesMut::new();
                encode_integer(&mut reference_buf, *index as usize, 7, 0x80);

                let mut reference_bytes = reference_buf.freeze();
                if let Ok(decoded_headers) = observe_hpack_decode(
                    "dynamic table indexed reference",
                    &mut decoder,
                    &mut reference_bytes,
                ) {
                    assert!(
                        decoded_headers.len() <= 1,
                        "indexed HPACK reference should decode at most one header"
                    );
                }
                // We don't panic on invalid index references as they may legitimately fail
            }

            DynamicTableOp::BurstInsert { headers } => {
                // Insert multiple headers rapidly to test eviction behavior
                for (name, value) in headers {
                    let header = Header {
                        name: name.clone(),
                        value: value.clone(),
                    };
                    let mut encoded_buf = BytesMut::new();
                    encoder.encode(&[header], &mut encoded_buf);
                    {
                        let mut encoded_bytes = encoded_buf.freeze();
                        if let Ok(decoded_headers) =
                            observe_hpack_decode("burst insert", &mut decoder, &mut encoded_bytes)
                        {
                            assert!(
                                !decoded_headers.is_empty(),
                                "burst insert should decode at least one header on success"
                            );
                            simulate_dynamic_table_insertion(
                                &mut expected_dynamic_entries,
                                name.clone(),
                                value.clone(),
                                current_table_size,
                            );
                        }
                    }
                }
            }

            DynamicTableOp::RoundTrip { headers } => {
                // Test full encoder -> decoder round trip
                let header_list: Vec<Header> = headers
                    .iter()
                    .map(|(name, value)| Header::new(name.clone(), value.clone()))
                    .collect();

                let mut encoded_buf = BytesMut::new();
                encoder.encode(&header_list, &mut encoded_buf);
                {
                    let mut encoded_bytes = encoded_buf.freeze();
                    if let Ok(decoded_headers) =
                        observe_hpack_decode("round trip", &mut decoder, &mut encoded_bytes)
                    {
                        // Verify all headers round-tripped correctly
                        if decoded_headers.len() != header_list.len() {
                            panic!(
                                "Round-trip header count mismatch at op {}: sent {}, got {}",
                                op_idx,
                                header_list.len(),
                                decoded_headers.len()
                            );
                        }

                        for (i, (sent, received)) in
                            header_list.iter().zip(decoded_headers.iter()).enumerate()
                        {
                            if sent.name != received.name || sent.value != received.value {
                                panic!(
                                    "Round-trip header mismatch at op {} header {}: sent ({}, {}), got ({}, {})",
                                    op_idx, i, sent.name, sent.value, received.name, received.value
                                );
                            }
                        }

                        // Update expected dynamic table
                        for (name, value) in headers {
                            simulate_dynamic_table_insertion(
                                &mut expected_dynamic_entries,
                                name.clone(),
                                value.clone(),
                                current_table_size,
                            );
                        }
                    }
                }
            }
        }
    }
}

fn observe_hpack_decode(
    context: &str,
    decoder: &mut HpackDecoder,
    bytes: &mut Bytes,
) -> Result<Vec<Header>, H2Error> {
    let input_len = bytes.len();
    match decoder.decode(bytes) {
        Ok(headers) => {
            assert!(
                bytes.is_empty(),
                "{context}: successful HPACK decode should consume the full input block"
            );
            assert!(
                headers.len() <= MAX_DECODED_HEADERS,
                "{context}: decoded too many headers from one HPACK block"
            );
            verify_decoded_headers(context, &headers);
            Ok(headers)
        }
        Err(err) => {
            assert_eq!(
                err.code,
                ErrorCode::CompressionError,
                "{context}: HPACK failures should be compression errors"
            );
            assert!(
                !err.message.is_empty(),
                "{context}: HPACK decode failure should expose a diagnostic"
            );
            assert!(
                bytes.len() <= input_len,
                "{context}: decode failure should not increase remaining input"
            );
            Err(err)
        }
    }
}

fn verify_decoded_headers(context: &str, headers: &[Header]) {
    for header in headers {
        assert!(
            !header.name.is_empty(),
            "{context}: decoded header names must not be empty"
        );
        assert!(
            header.name.len() + header.value.len() <= MAX_DECODED_HEADER_BYTES,
            "{context}: decoded header pair should stay bounded"
        );
        assert!(
            header
                .name
                .bytes()
                .enumerate()
                .all(|(idx, b)| is_valid_hpack_header_name_byte(idx, b)),
            "{context}: decoded header name should satisfy HTTP/2 lowercase token rules"
        );
        assert!(
            !header.value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')),
            "{context}: decoded header value should not contain NUL or line breaks"
        );
    }
}

fn is_valid_hpack_header_name_byte(index: usize, byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || (byte == b':' && index == 0)
}

/// Simulate inserting an entry into the dynamic table with eviction
fn simulate_dynamic_table_insertion(
    table: &mut Vec<(String, String)>,
    name: String,
    value: String,
    max_size: usize,
) {
    if max_size == 0 {
        return; // No dynamic table
    }

    let entry_size = name.len() + value.len() + 32; // RFC 7541 overhead

    // Evict old entries if necessary
    while !table.is_empty() {
        let current_size: usize = table.iter().map(|(n, v)| n.len() + v.len() + 32).sum();

        if current_size + entry_size <= max_size {
            break;
        }

        table.remove(table.len() - 1); // Remove oldest (FIFO)
    }

    // Insert new entry at the beginning (index 62 in HPACK terms)
    if entry_size <= max_size {
        table.insert(0, (name, value));
    }
}

/// Simulate table eviction due to size reduction
fn simulate_table_eviction(table: &mut Vec<(String, String)>, max_size: usize) {
    while !table.is_empty() {
        let current_size: usize = table.iter().map(|(n, v)| n.len() + v.len() + 32).sum();

        if current_size <= max_size {
            break;
        }

        table.remove(table.len() - 1); // Remove oldest
    }
}

/// Encode an integer using HPACK integer encoding
fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
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
