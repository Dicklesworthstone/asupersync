//! RFC 7541 edge case fuzz target for HPACK decoder
//!
//! Specifically targets the edge cases mentioned in RFC 7541 that are most likely
//! to cause decoder issues:
//! 1. 2-byte Huffman prefix edge cases
//! 2. Dynamic table max-size update mid-block (compression error scenarios)
//! 3. Indexed literal with never-indexed flag combinations
//! 4. Table-size shrink with eviction edge cases
//! 5. Malformed varint edge cases and overflows

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::Decoder;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_SIZE: usize = 8192; // Smaller focused inputs
const MAX_HEADERS: usize = 32;

#[derive(Arbitrary, Debug, Clone)]
enum RFC7541EdgeCase {
    /// RFC 7541 §5.2: Huffman prefix edge cases with 2-byte sequences
    HuffmanPrefixEdge {
        /// 2-byte Huffman codes near boundary conditions
        huffman_sequences: Vec<u16>, // 16-bit codes for 2-byte sequences
        string_data: Vec<u8>,
        literal_name: bool,
        literal_value: bool,
    },
    /// RFC 7541 §4.2: Dynamic table size update after header (COMPRESSION_ERROR)
    MidBlockSizeUpdate {
        /// Headers before the illegal size update
        initial_headers: Vec<HeaderInstruction>,
        /// Size update that should be rejected (after header field)
        illegal_size_update: u16,
        /// Additional headers after the illegal update
        trailing_headers: Vec<HeaderInstruction>,
    },
    /// RFC 7541 §6.2.3: Never indexed literal combinations
    NeverIndexedLiteral {
        /// Mix of never-indexed and regular literals
        literals: Vec<NeverIndexedPattern>,
        /// Dynamic table manipulations
        table_updates: Vec<u16>,
    },
    /// RFC 7541 §4.3: Table size shrink causing eviction edge cases
    TableShrinkEviction {
        /// Initial large table size
        initial_size: u16,
        /// Headers to populate the table
        populate_headers: Vec<(Vec<u8>, Vec<u8>)>, // (name, value) pairs
        /// Shrink to smaller size, triggering evictions
        shrink_size: u16,
        /// Access patterns after shrink (some indices now invalid)
        access_patterns: Vec<u16>,
    },
    /// RFC 7541 §5.1: Malformed varint edge cases
    MalformedVarint {
        /// Varint patterns that should trigger errors
        varint_patterns: Vec<VarintPattern>,
        /// Context where the varint appears
        varint_context: VarintContext,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderInstruction {
    pattern: u8, // Instruction pattern bits
    index_or_name: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
}

#[derive(Arbitrary, Debug, Clone)]
struct NeverIndexedPattern {
    use_indexed_name: bool,
    name_index_or_literal: Vec<u8>,
    value: Vec<u8>,
    never_indexed: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct VarintPattern {
    prefix_bits: u8, // 1-8
    initial_byte: u8,
    continuation_bytes: Vec<u8>, // Potentially malformed continuations
}

#[derive(Arbitrary, Debug, Clone)]
enum VarintContext {
    IndexedHeaderField,
    LiteralHeaderFieldIndex,
    DynamicTableSizeUpdate,
    StringLength,
}

fuzz_target!(|edge_case: RFC7541EdgeCase| {
    match edge_case {
        RFC7541EdgeCase::HuffmanPrefixEdge {
            huffman_sequences,
            string_data,
            literal_name,
            literal_value,
        } => fuzz_huffman_prefix_edge(huffman_sequences, string_data, literal_name, literal_value),

        RFC7541EdgeCase::MidBlockSizeUpdate {
            initial_headers,
            illegal_size_update,
            trailing_headers,
        } => fuzz_mid_block_size_update(initial_headers, illegal_size_update, trailing_headers),

        RFC7541EdgeCase::NeverIndexedLiteral {
            literals,
            table_updates,
        } => fuzz_never_indexed_literal(literals, table_updates),

        RFC7541EdgeCase::TableShrinkEviction {
            initial_size,
            populate_headers,
            shrink_size,
            access_patterns,
        } => fuzz_table_shrink_eviction(initial_size, populate_headers, shrink_size, access_patterns),

        RFC7541EdgeCase::MalformedVarint {
            varint_patterns,
            varint_context,
        } => fuzz_malformed_varint(varint_patterns, varint_context),
    }
});

/// Test 2-byte Huffman prefix edge cases (RFC 7541 §5.2)
fn fuzz_huffman_prefix_edge(
    huffman_sequences: Vec<u16>,
    string_data: Vec<u8>,
    literal_name: bool,
    literal_value: bool,
) {
    let mut decoder = Decoder::new();
    let mut buffer = Vec::new();

    for (i, &seq) in huffman_sequences.iter().take(MAX_HEADERS).enumerate() {
        // Literal Header Field without Indexing (0000xxxx)
        buffer.push(0x00);

        // Name field
        if literal_name {
            let name_len = (i % 8) + 1;
            encode_string_with_huffman(&mut buffer, &string_data[i..i.min(string_data.len())], name_len, true);
        } else {
            // Use static table index for name
            encode_integer(&mut buffer, (i % 20) + 1, 4);
        }

        // Value field with 2-byte Huffman edge cases
        let value_data = construct_2byte_huffman_edge(seq, &string_data, i);
        encode_string_with_huffman(&mut buffer, &value_data, value_data.len(), literal_value);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    // Test the decoder with potentially malformed Huffman sequences
    let mut bytes = Bytes::from(buffer);
    let _result = decoder.decode(&mut bytes);
}

/// Test dynamic table size update after header field (RFC 7541 §4.2)
/// This should trigger COMPRESSION_ERROR according to the spec
fn fuzz_mid_block_size_update(
    initial_headers: Vec<HeaderInstruction>,
    illegal_size_update: u16,
    trailing_headers: Vec<HeaderInstruction>,
) {
    let mut decoder = Decoder::with_max_size(4096);
    let mut buffer = Vec::new();

    // Add initial headers
    for header in initial_headers.iter().take(8) {
        encode_header_instruction(&mut buffer, header);
    }

    // Add illegal size update AFTER header fields (should be compression error)
    if !buffer.is_empty() {
        buffer.push(0x20); // Dynamic Table Size Update (001xxxxx)
        encode_integer(&mut buffer, illegal_size_update as usize, 5);
    }

    // Add trailing headers after the illegal update
    for header in trailing_headers.iter().take(8) {
        encode_header_instruction(&mut buffer, header);
    }

    let mut bytes = Bytes::from(buffer);
    // According to RFC 7541 §4.2, this should fail with compression error
    let _result = decoder.decode(&mut bytes);
}

/// Test never-indexed literal combinations (RFC 7541 §6.2.3)
fn fuzz_never_indexed_literal(literals: Vec<NeverIndexedPattern>, table_updates: Vec<u16>) {
    let mut decoder = Decoder::new();
    let mut buffer = Vec::new();

    // Add some table size updates first
    for &size in table_updates.iter().take(4) {
        buffer.push(0x20); // Dynamic Table Size Update
        encode_integer(&mut buffer, size as usize, 5);
    }

    for literal in literals.iter().take(MAX_HEADERS) {
        if literal.never_indexed {
            // Never Indexed Literal Header Field (0001xxxx)
            buffer.push(0x10);
        } else {
            // Literal Header Field without Indexing (0000xxxx)
            buffer.push(0x00);
        }

        // Name
        if literal.use_indexed_name && !literal.name_index_or_literal.is_empty() {
            // Use index for name
            let index = literal.name_index_or_literal[0] as usize;
            encode_integer(&mut buffer, index, 4);
        } else {
            // Literal name
            buffer.push(0x00); // Index 0 = literal name follows
            encode_string_literal(&mut buffer, &literal.name_index_or_literal);
        }

        // Value
        encode_string_literal(&mut buffer, &literal.value);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    let mut bytes = Bytes::from(buffer);
    let _result = decoder.decode(&mut bytes);
}

/// Test table size shrink causing eviction (RFC 7541 §4.3)
fn fuzz_table_shrink_eviction(
    initial_size: u16,
    populate_headers: Vec<(Vec<u8>, Vec<u8>)>,
    shrink_size: u16,
    access_patterns: Vec<u16>,
) {
    let initial_size = (initial_size as usize).min(8192);
    let shrink_size = (shrink_size as usize).min(initial_size);

    let mut decoder = Decoder::with_max_size(initial_size);
    let mut buffer = Vec::new();

    // Set initial large table size
    buffer.push(0x20); // Dynamic Table Size Update
    encode_integer(&mut buffer, initial_size, 5);

    // Populate the dynamic table with headers
    for (name, value) in populate_headers.iter().take(16) {
        buffer.push(0x40); // Literal with Incremental Indexing (01xxxxxx)
        buffer.push(0x00); // Literal name follows
        encode_string_literal(&mut buffer, name);
        encode_string_literal(&mut buffer, value);

        if buffer.len() > MAX_INPUT_SIZE / 2 {
            break;
        }
    }

    // Decode first to populate table
    let mut bytes1 = Bytes::from(buffer.clone());
    let _result1 = decoder.decode(&mut bytes1);

    // Now shrink the table, causing evictions
    buffer.clear();
    buffer.push(0x20); // Dynamic Table Size Update
    encode_integer(&mut buffer, shrink_size, 5);

    // Try to access indices that may have been evicted
    for &index in access_patterns.iter().take(16) {
        buffer.push(0x80); // Indexed Header Field (1xxxxxxx)
        encode_integer(&mut buffer, index as usize, 7);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    let mut bytes2 = Bytes::from(buffer);
    let _result2 = decoder.decode(&mut bytes2);
}

/// Test malformed varint edge cases (RFC 7541 §5.1)
fn fuzz_malformed_varint(varint_patterns: Vec<VarintPattern>, context: VarintContext) {
    let mut decoder = Decoder::new();

    for pattern in varint_patterns.iter().take(16) {
        let mut buffer = Vec::new();

        // Create the context for the varint
        match context {
            VarintContext::IndexedHeaderField => {
                buffer.push(0x80); // 1xxxxxxx pattern
            }
            VarintContext::LiteralHeaderFieldIndex => {
                buffer.push(0x40); // 01xxxxxx pattern
            }
            VarintContext::DynamicTableSizeUpdate => {
                buffer.push(0x20); // 001xxxxx pattern
            }
            VarintContext::StringLength => {
                buffer.push(0x00); // Literal header
                buffer.push(0x00); // Literal name follows
            }
        }

        // Encode malformed varint
        encode_malformed_varint(&mut buffer, pattern);

        // Add dummy data if needed for string length context
        if matches!(context, VarintContext::StringLength) {
            buffer.extend_from_slice(b"dummy");
            buffer.push(0x00); // Value length 0
        }

        if buffer.len() <= MAX_INPUT_SIZE {
            let mut bytes = Bytes::from(buffer);
            let _result = decoder.decode(&mut bytes);
        }
    }
}

/// Construct 2-byte Huffman edge cases
fn construct_2byte_huffman_edge(seq: u16, data: &[u8], offset: usize) -> Vec<u8> {
    let mut result = Vec::new();

    // Focus on 2-byte Huffman sequences (9-16 bit codes)
    // These are the most complex and error-prone

    // Some critical 2-byte boundary codes from the Huffman table
    let critical_codes = [
        0x1ff8, // 13-bit code for space (common)
        0x3ffc, // 14-bit code for '/'
        0x7ffc, // 15-bit code for '='
        0xffff, // Invalid 16-bit sequence
        0x1ff0 | (offset & 0xf), // Mutated boundary codes
    ];

    let code = if (seq as usize) < critical_codes.len() {
        critical_codes[seq as usize]
    } else {
        seq
    };

    // Encode as 2-byte sequence with potential padding issues
    result.push((code >> 8) as u8);
    result.push(code as u8);

    // Add some actual string data
    if let Some(byte) = data.get(offset) {
        result.push(*byte);
    }

    result
}

/// Encode string with Huffman encoding flag
fn encode_string_with_huffman(buffer: &mut Vec<u8>, data: &[u8], len: usize, use_huffman: bool) {
    let huffman_flag = if use_huffman { 0x80 } else { 0x00 };
    let actual_len = len.min(data.len()).min(127);

    buffer.push(huffman_flag | (actual_len as u8));
    buffer.extend_from_slice(&data[..actual_len]);
}

/// Encode a regular string literal
fn encode_string_literal(buffer: &mut Vec<u8>, data: &[u8]) {
    let len = data.len().min(127);
    buffer.push(len as u8);
    buffer.extend_from_slice(&data[..len]);
}

/// Encode header instruction
fn encode_header_instruction(buffer: &mut Vec<u8>, header: &HeaderInstruction) {
    buffer.push(header.pattern);

    if let Some(ref name) = header.index_or_name {
        encode_string_literal(buffer, name);
    }

    if let Some(ref value) = header.value {
        encode_string_literal(buffer, value);
    }
}

/// Encode potentially malformed varint
fn encode_malformed_varint(buffer: &mut Vec<u8>, pattern: &VarintPattern) {
    let prefix_bits = pattern.prefix_bits.clamp(1, 7);
    let prefix_max = (1u8 << prefix_bits) - 1;

    // Set the prefix to maximum to trigger multi-byte encoding
    if let Some(last) = buffer.last_mut() {
        *last |= prefix_max;
    }

    // Add potentially malformed continuation bytes
    for &byte in &pattern.continuation_bytes {
        buffer.push(byte);
        // Stop if we've added enough malformed bytes
        if buffer.len() % 8 == 0 {
            break;
        }
    }
}

/// Standard HPACK integer encoding
fn encode_integer(buffer: &mut Vec<u8>, mut value: usize, prefix_bits: u8) {
    let prefix_max = (1usize << prefix_bits) - 1;

    if value < prefix_max {
        if let Some(last) = buffer.last_mut() {
            *last |= value as u8;
        }
        return;
    }

    if let Some(last) = buffer.last_mut() {
        *last |= prefix_max as u8;
    }

    value -= prefix_max;
    while value >= 128 {
        buffer.push(0x80 | (value as u8 & 0x7F));
        value >>= 7;
    }
    buffer.push(value as u8);
}