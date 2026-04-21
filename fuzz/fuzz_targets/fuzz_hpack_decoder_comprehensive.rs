//! Comprehensive fuzz target for src/http/h2/hpack.rs HPACK header decoder.
//!
//! This target fuzzes the actual HPACK decoder implementation with adversarial inputs:
//! 1. Malformed Huffman codes and invalid bit sequences
//! 2. Dynamic table manipulation attacks (indexing beyond bounds, size bombs)
//! 3. Integer encoding edge cases (overflow, underflow)
//! 4. Header field combinations that trigger memory exhaustion
//! 5. Mixed valid/invalid instruction sequences
//!
//! Unlike the basic hpack_decode.rs that manually parses the protocol, this target
//! exercises the real Decoder::decode() method and its internal functions.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::Decoder;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_SIZE: usize = 64 * 1024; // 64KB
const MAX_HEADERS: usize = 100;
const MAX_ITERATIONS: usize = 16;

#[derive(Arbitrary, Debug)]
enum FuzzScenario {
    /// Single header block decode with various table sizes
    SingleBlock {
        max_table_size: u16,
        max_header_list_size: u16,
        block: Vec<u8>,
    },
    /// Multiple header blocks to test table state persistence
    MultipleBlocks {
        max_table_size: u16,
        max_header_list_size: u16,
        blocks: Vec<Vec<u8>>,
        table_size_changes: Vec<u16>,
    },
    /// Adversarial Huffman encoding fuzzing
    HuffmanAdversarial {
        huffman_data: Vec<u8>,
        string_lengths: Vec<u16>,
        mix_literal_huffman: bool,
    },
    /// Dynamic table manipulation attack
    TableManipulation {
        initial_size: u16,
        size_updates: Vec<u16>,
        header_insertions: Vec<Vec<u8>>,
        index_accesses: Vec<u16>,
    },
    /// Integer encoding edge cases
    IntegerEdgeCases {
        prefix_bits: u8,
        values: Vec<u32>,
        malformed_continuations: Vec<u8>,
    },
}

fuzz_target!(|scenario: FuzzScenario| match scenario {
    FuzzScenario::SingleBlock {
        max_table_size,
        max_header_list_size,
        block,
    } => fuzz_single_block(max_table_size, max_header_list_size, block),

    FuzzScenario::MultipleBlocks {
        max_table_size,
        max_header_list_size,
        blocks,
        table_size_changes,
    } => fuzz_multiple_blocks(max_table_size, max_header_list_size, blocks, table_size_changes),

    FuzzScenario::HuffmanAdversarial {
        huffman_data,
        string_lengths,
        mix_literal_huffman,
    } => fuzz_huffman_adversarial(huffman_data, string_lengths, mix_literal_huffman),

    FuzzScenario::TableManipulation {
        initial_size,
        size_updates,
        header_insertions,
        index_accesses,
    } => fuzz_table_manipulation(initial_size, size_updates, header_insertions, index_accesses),

    FuzzScenario::IntegerEdgeCases {
        prefix_bits,
        values,
        malformed_continuations,
    } => fuzz_integer_edge_cases(prefix_bits, values, malformed_continuations),
});

fn fuzz_single_block(max_table_size: u16, max_header_list_size: u16, block: Vec<u8>) {
    if block.len() > MAX_INPUT_SIZE {
        return;
    }

    let table_size = (max_table_size as usize).min(64 * 1024);
    let header_list_size = (max_header_list_size as usize).min(32 * 1024);

    let mut decoder = Decoder::with_max_size(table_size);
    decoder.set_max_header_list_size(header_list_size);
    let mut bytes = Bytes::from(block);

    // Decoder should never panic, regardless of input
    let _result = decoder.decode(&mut bytes);

    // Test with table size changes during decode
    decoder.set_allowed_table_size(table_size / 2);
    let mut bytes2 = bytes.clone();
    let _result2 = decoder.decode(&mut bytes2);
}

fn fuzz_multiple_blocks(
    max_table_size: u16,
    max_header_list_size: u16,
    blocks: Vec<Vec<u8>>,
    table_size_changes: Vec<u16>,
) {
    let table_size = (max_table_size as usize).min(64 * 1024);
    let header_list_size = (max_header_list_size as usize).min(32 * 1024);

    let mut decoder = Decoder::with_max_size(table_size);
    decoder.set_max_header_list_size(header_list_size);

    // Process multiple blocks to test state persistence
    for (i, block) in blocks.iter().take(MAX_ITERATIONS).enumerate() {
        if block.len() > MAX_INPUT_SIZE {
            continue;
        }

        // Apply table size changes between blocks
        if let Some(&size_change) = table_size_changes.get(i) {
            let new_size = (size_change as usize).min(64 * 1024);
            decoder.set_allowed_table_size(new_size);
        }

        let mut bytes = Bytes::from(block.clone());
        let _result = decoder.decode(&mut bytes);

        // Verify decoder state is consistent
        let _table_size = decoder.dynamic_table_size();
        let _max_size = decoder.dynamic_table_max_size();
    }
}

fn fuzz_huffman_adversarial(huffman_data: Vec<u8>, string_lengths: Vec<u16>, mix_literal_huffman: bool) {
    let mut decoder = Decoder::new();
    let mut buffer = Vec::new();

    // Create adversarial string literals with Huffman encoding
    for (i, &length) in string_lengths.iter().take(MAX_HEADERS).enumerate() {
        let use_huffman = mix_literal_huffman && (i % 2 == 0);
        let data_slice = huffman_data.get(i * 16..(i + 1) * 16).unwrap_or(&[]);

        // Literal header field without indexing (0000xxxx)
        buffer.push(0x00);

        // Literal name length with optional Huffman flag
        let name_len = length.min(1024) as usize;
        encode_string_header(&mut buffer, name_len, use_huffman);
        buffer.extend_from_slice(&data_slice[..data_slice.len().min(name_len)]);

        // Literal value length with optional Huffman flag
        let value_len = length.wrapping_add(100).min(1024) as usize;
        encode_string_header(&mut buffer, value_len, use_huffman);
        buffer.extend_from_slice(&data_slice[..data_slice.len().min(value_len)]);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    let mut bytes = Bytes::from(buffer);
    let _result = decoder.decode(&mut bytes);
}

fn fuzz_table_manipulation(
    initial_size: u16,
    size_updates: Vec<u16>,
    header_insertions: Vec<Vec<u8>>,
    index_accesses: Vec<u16>,
) {
    let mut decoder = Decoder::with_max_size((initial_size as usize).min(64 * 1024));
    let mut buffer = Vec::new();

    // Apply dynamic table size updates (001xxxxx)
    for &size in size_updates.iter().take(8) {
        let update_size = size as usize;
        buffer.push(0x20); // 001xxxxx pattern
        encode_integer(&mut buffer, update_size, 5);

        if buffer.len() > MAX_INPUT_SIZE / 4 {
            break;
        }
    }

    // Insert headers that will populate the dynamic table (01xxxxxx)
    for insertion in header_insertions.iter().take(MAX_HEADERS / 2) {
        if insertion.len() > 256 {
            continue;
        }

        buffer.push(0x40); // 01xxxxxx - literal with incremental indexing
        buffer.push(0x00); // Literal name follows
        encode_string_header(&mut buffer, insertion.len().min(64), false);
        buffer.extend_from_slice(&insertion[..insertion.len().min(64)]);
        encode_string_header(&mut buffer, insertion.len().min(64), false);
        buffer.extend_from_slice(&insertion[..insertion.len().min(64)]);

        if buffer.len() > MAX_INPUT_SIZE / 2 {
            break;
        }
    }

    // Access indices (including out-of-bounds) (1xxxxxxx)
    for &index in index_accesses.iter().take(MAX_HEADERS / 2) {
        let idx = index as usize;
        buffer.push(0x80); // 1xxxxxxx - indexed header field
        encode_integer(&mut buffer, idx, 7);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    let mut bytes = Bytes::from(buffer);
    let _result = decoder.decode(&mut bytes);
}

fn fuzz_integer_edge_cases(prefix_bits: u8, values: Vec<u32>, malformed_continuations: Vec<u8>) {
    let mut decoder = Decoder::new();
    let mut buffer = Vec::new();
    let _prefix = prefix_bits.clamp(1, 8);

    // Test various integer encoding edge cases
    for &value in values.iter().take(MAX_HEADERS) {
        // Dynamic table size update with edge case integer
        buffer.push(0x20); // 001xxxxx
        encode_integer(&mut buffer, value as usize, 5);

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    // Test malformed multi-byte integer continuations
    for &continuation in malformed_continuations.iter().take(16) {
        buffer.push(0x20); // Start a size update
        buffer.push(0x1F); // Max value for 5-bit prefix, triggers multi-byte
        buffer.push(continuation); // Potentially malformed continuation

        if buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    let mut bytes = Bytes::from(buffer);
    let _result = decoder.decode(&mut bytes);
}

/// Encode a string length header with optional Huffman flag
fn encode_string_header(buffer: &mut Vec<u8>, length: usize, huffman: bool) {
    let huffman_flag = if huffman { 0x80 } else { 0x00 };

    if length < 127 {
        buffer.push(huffman_flag | (length as u8));
    } else {
        buffer.push(huffman_flag | 0x7F);
        encode_integer(buffer, length - 127, 7);
    }
}

/// Encode an integer using HPACK integer encoding
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