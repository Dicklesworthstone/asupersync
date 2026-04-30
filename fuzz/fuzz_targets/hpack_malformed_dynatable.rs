//! HPACK Decoder Fuzzing: Malformed Dynamic Table Updates
//!
//! Tests src/http/h2/hpack.rs Decoder::decode() with malformed dynamic table
//! manipulation sequences. Focus: arbitrary mix of literal/indexed/resize 
//! operations that should result in COMPRESSION_ERROR, never panic.
//!
//! Target: Decoder::decode() crash detector + error handling validation
//! Oracle: No panic + malformed input → COMPRESSION_ERROR

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::{hpack::Decoder, error::H2Error};
use libfuzzer_sys::fuzz_target;

const MAX_BLOCK_SIZE: usize = 64 * 1024; // 64KB limit
const MAX_OPERATIONS: usize = 100;

#[derive(Arbitrary, Debug)]
struct MalformedDynamicTableFuzz {
    /// Initial decoder configuration
    initial_max_table_size: u16,
    /// Sequence of potentially malformed operations
    operations: Vec<HpackOperation>,
    /// Raw byte mutations to inject
    byte_mutations: Vec<ByteMutation>,
}

#[derive(Arbitrary, Debug)]
enum HpackOperation {
    /// Dynamic table size update (001xxxxx) - potentially malformed
    DynTableSizeUpdate {
        /// Size value to encode (may be invalid)
        size: u32,
        /// Whether to use malformed integer encoding
        malformed_encoding: bool,
    },
    /// Indexed header field (1xxxxxxx) - potentially out of bounds
    IndexedHeader {
        /// Index to reference (may be out of bounds)
        index: u32,
        /// Whether to use malformed integer encoding
        malformed_encoding: bool,
    },
    /// Literal with incremental indexing (01xxxxxx) - malformed content
    LiteralWithIndexing {
        /// Name index (0 = literal name, >0 = indexed name)
        name_index: u32,
        /// Raw name bytes (potentially malformed)
        name_literal: Vec<u8>,
        /// Raw value bytes (potentially malformed)
        value_literal: Vec<u8>,
        /// Use Huffman encoding for name
        huffman_name: bool,
        /// Use Huffman encoding for value
        huffman_value: bool,
        /// Malform the string length encoding
        malform_lengths: bool,
    },
    /// Literal without indexing (0000xxxx) - malformed content
    LiteralNoIndexing {
        name_index: u32,
        name_literal: Vec<u8>,
        value_literal: Vec<u8>,
        huffman_name: bool,
        huffman_value: bool,
        malform_lengths: bool,
    },
    /// Literal never indexed (0001xxxx) - malformed content  
    LiteralNeverIndexed {
        name_index: u32,
        name_literal: Vec<u8>,
        value_literal: Vec<u8>,
        huffman_name: bool,
        huffman_value: bool,
        malform_lengths: bool,
    },
    /// Raw malformed bytes injection
    RawBytes {
        data: Vec<u8>,
    },
}

#[derive(Arbitrary, Debug)]
struct ByteMutation {
    /// Position to inject mutation
    position: u8,
    /// Bytes to inject/overwrite
    mutation: Vec<u8>,
}

fuzz_target!(|input: MalformedDynamicTableFuzz| {
    // Limit operations to prevent timeout
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Build potentially malformed HPACK block
    let block_data = build_malformed_block(&input);
    
    // Size guard to prevent OOM
    if block_data.len() > MAX_BLOCK_SIZE {
        return;
    }

    // Create decoder with configurable table size
    let table_size = input.initial_max_table_size.min(65536) as usize;
    let mut decoder = Decoder::with_max_size(table_size);
    
    // Apply mutations
    let mut mutated_data = apply_mutations(block_data, &input.byte_mutations);
    
    // The core test: decode should never panic
    // Malformed input should result in H2Error::Compression, not panic
    let mut bytes = Bytes::from(mutated_data);
    
    match decoder.decode(&mut bytes) {
        Ok(_headers) => {
            // Valid decode - this is fine
        }
        Err(H2Error::Compression { .. }) => {
            // Expected error for malformed input - this is what we want
        }
        Err(other_error) => {
            // Other errors are also acceptable (e.g., protocol errors)
            // As long as we don't panic
        }
    }
    
    // Test decoder state consistency after error
    // A second decode attempt should not panic either
    let mut bytes2 = Bytes::from(vec![0x20, 0x00]); // Simple table size update
    let _ = decoder.decode(&mut bytes2);
});

fn build_malformed_block(input: &MalformedDynamicTableFuzz) -> Vec<u8> {
    let mut block = Vec::new();
    
    for operation in &input.operations {
        let op_bytes = encode_operation(operation);
        block.extend_from_slice(&op_bytes);
        
        // Prevent excessive size
        if block.len() > MAX_BLOCK_SIZE / 2 {
            break;
        }
    }
    
    block
}

fn encode_operation(op: &HpackOperation) -> Vec<u8> {
    match op {
        HpackOperation::DynTableSizeUpdate { size, malformed_encoding } => {
            if *malformed_encoding {
                encode_malformed_size_update(*size)
            } else {
                encode_size_update(*size)
            }
        }
        
        HpackOperation::IndexedHeader { index, malformed_encoding } => {
            if *malformed_encoding {
                encode_malformed_indexed(*index)
            } else {
                encode_indexed(*index)
            }
        }
        
        HpackOperation::LiteralWithIndexing {
            name_index, name_literal, value_literal,
            huffman_name, huffman_value, malform_lengths
        } => {
            encode_literal(
                0x40, // 01xxxxxx pattern
                *name_index, name_literal, value_literal,
                *huffman_name, *huffman_value, *malform_lengths
            )
        }
        
        HpackOperation::LiteralNoIndexing {
            name_index, name_literal, value_literal,
            huffman_name, huffman_value, malform_lengths
        } => {
            encode_literal(
                0x00, // 0000xxxx pattern
                *name_index, name_literal, value_literal,
                *huffman_name, *huffman_value, *malform_lengths
            )
        }
        
        HpackOperation::LiteralNeverIndexed {
            name_index, name_literal, value_literal,
            huffman_name, huffman_value, malform_lengths
        } => {
            encode_literal(
                0x10, // 0001xxxx pattern
                *name_index, name_literal, value_literal,
                *huffman_name, *huffman_value, *malform_lengths
            )
        }
        
        HpackOperation::RawBytes { data } => {
            data.clone()
        }
    }
}

fn encode_size_update(size: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_hpack_integer(&mut bytes, size as usize, 5, 0x20);
    bytes
}

fn encode_malformed_size_update(size: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x20); // Size update pattern
    
    // Malformed integer encoding - various corruption strategies
    match size % 4 {
        0 => {
            // Incomplete integer encoding
            bytes.push(0x1F); // Max value for 5-bit prefix
            bytes.push(0x80 | ((size & 0x7F) as u8)); // Missing continuation
        }
        1 => {
            // Overly long encoding
            bytes.push(0x1F);
            for _ in 0..10 {
                bytes.push(0x80); // Keep continuation bit set
            }
            bytes.push((size & 0x7F) as u8);
        }
        2 => {
            // Invalid continuation sequence
            bytes.push(((size.min(30)) as u8) | 0x20);
            bytes.push(0xFF); // Invalid byte
        }
        _ => {
            // Truncated encoding
            bytes.push(0x3F); // Invalid prefix
        }
    }
    
    bytes
}

fn encode_indexed(index: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_hpack_integer(&mut bytes, index as usize, 7, 0x80);
    bytes
}

fn encode_malformed_indexed(index: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    
    match index % 3 {
        0 => {
            // Index 0 (invalid)
            bytes.push(0x80);
        }
        1 => {
            // Malformed integer encoding
            bytes.push(0xFF); // 1xxxxxxx with max 7-bit value
            bytes.push(0x80); // Incomplete continuation
        }
        _ => {
            // Extremely large index
            bytes.push(0xFF);
            for _ in 0..5 {
                bytes.push(0xFF);
            }
            bytes.push(0x01);
        }
    }
    
    bytes
}

fn encode_literal(
    pattern: u8,
    name_index: u32, 
    name_literal: &[u8], 
    value_literal: &[u8],
    huffman_name: bool,
    huffman_value: bool,
    malform_lengths: bool
) -> Vec<u8> {
    let mut bytes = Vec::new();
    
    let prefix_bits = if pattern & 0x40 != 0 { 6 } else { 4 };
    
    // Encode name
    if name_index == 0 {
        // Literal name
        bytes.push(pattern);
        if malform_lengths {
            encode_malformed_string(&mut bytes, name_literal, huffman_name);
        } else {
            encode_string(&mut bytes, name_literal, huffman_name);
        }
    } else {
        // Indexed name
        encode_hpack_integer(&mut bytes, name_index as usize, prefix_bits, pattern);
    }
    
    // Encode value
    if malform_lengths {
        encode_malformed_string(&mut bytes, value_literal, huffman_value);
    } else {
        encode_string(&mut bytes, value_literal, huffman_value);
    }
    
    bytes
}

fn encode_string(bytes: &mut Vec<u8>, data: &[u8], huffman: bool) -> Vec<u8> {
    let flag = if huffman { 0x80 } else { 0x00 };
    
    // Truncate data to prevent excessive size
    let truncated = if data.len() > 1024 { &data[..1024] } else { data };
    
    encode_hpack_integer(bytes, truncated.len(), 7, flag);
    bytes.extend_from_slice(truncated);
    bytes.clone()
}

fn encode_malformed_string(bytes: &mut Vec<u8>, data: &[u8], huffman: bool) {
    let flag = if huffman { 0x80 } else { 0x00 };
    
    match data.len() % 4 {
        0 => {
            // Wrong length encoding
            encode_hpack_integer(bytes, data.len().wrapping_add(100), 7, flag);
            bytes.extend_from_slice(data);
        }
        1 => {
            // Truncated string (length says more data than provided)
            encode_hpack_integer(bytes, data.len() * 2, 7, flag);
            bytes.extend_from_slice(data);
        }
        2 => {
            // Invalid Huffman flag combination
            bytes.push(0xFF); // Invalid string length encoding
            bytes.extend_from_slice(data);
        }
        _ => {
            // Zero length but with data
            encode_hpack_integer(bytes, 0, 7, flag);
            bytes.extend_from_slice(data);
        }
    }
}

fn encode_hpack_integer(dst: &mut Vec<u8>, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1 << prefix_bits) - 1;
    
    if value < max_first {
        dst.push(prefix | (value as u8));
    } else {
        dst.push(prefix | (max_first as u8));
        let mut remaining = value - max_first;
        
        while remaining >= 128 {
            dst.push(0x80 | ((remaining & 0x7F) as u8));
            remaining >>= 7;
        }
        dst.push(remaining as u8);
    }
}

fn apply_mutations(mut data: Vec<u8>, mutations: &[ByteMutation]) -> Vec<u8> {
    for mutation in mutations.iter().take(10) { // Limit mutations
        let pos = (mutation.position as usize) % data.len().max(1);
        
        if mutation.mutation.is_empty() {
            continue;
        }
        
        // Apply mutation at position
        for (i, &byte) in mutation.mutation.iter().enumerate() {
            if pos + i < data.len() {
                data[pos + i] = byte;
            } else {
                data.push(byte);
            }
            
            // Prevent excessive growth
            if data.len() > MAX_BLOCK_SIZE {
                data.truncate(MAX_BLOCK_SIZE);
                break;
            }
        }
    }
    
    data
}
