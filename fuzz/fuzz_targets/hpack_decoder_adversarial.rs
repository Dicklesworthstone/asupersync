//! Adversarial fuzz target for HPACK decoder (asupersync-qwebw7).
//!
//! Focuses on:
//! 1. Huffman-encoded header blocks (malformed/edge cases)
//! 2. Dynamic table index overflow
//! 3. Never-indexed fields (Literal Header Field Never Indexed)
//! 4. Max-table-size updates (multiple updates, extreme values)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::{Decoder, Header};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct AdversarialInput {
    /// Initial max table size for the decoder
    initial_max_table_size: u32,
    /// Sequence of operations to perform on the decoder
    ops: Vec<HpackOp>,
}

#[derive(Arbitrary, Debug)]
enum HpackOp {
    /// Dynamic Table Size Update (001xxxxx)
    SizeUpdate {
        new_size: u32,
    },
    /// Indexed Header Field (1xxxxxxx)
    IndexedField {
        index: u32,
    },
    /// Literal Header Field with Incremental Indexing (01xxxxxx)
    LiteralWithIndexing {
        name_indexed: bool,
        name_index: u32,
        name_literal: Vec<u8>,
        value_literal: Vec<u8>,
        huffman_name: bool,
        huffman_value: bool,
    },
    /// Literal Header Field without Indexing (0000xxxx)
    LiteralWithoutIndexing {
        name_indexed: bool,
        name_index: u32,
        name_literal: Vec<u8>,
        value_literal: Vec<u8>,
        huffman_name: bool,
        huffman_value: bool,
    },
    /// Literal Header Field Never Indexed (0001xxxx)
    LiteralNeverIndexed {
        name_indexed: bool,
        name_index: u32,
        name_literal: Vec<u8>,
        value_literal: Vec<u8>,
        huffman_name: bool,
        huffman_value: bool,
    },
    /// Raw bytes to inject directly into the decode stream
    RawBytes(Vec<u8>),
}

fuzz_target!(|input: AdversarialInput| {
    let mut decoder = Decoder::with_max_size(input.initial_max_table_size as usize);
    
    let mut block = Vec::new();
    for op in input.ops {
        match op {
            HpackOp::SizeUpdate { new_size } => {
                encode_integer(&mut block, new_size as usize, 5, 0x20);
            }
            HpackOp::IndexedField { index } => {
                encode_integer(&mut block, index as usize, 7, 0x80);
            }
            HpackOp::LiteralWithIndexing { 
                name_indexed, name_index, name_literal, value_literal, huffman_name, huffman_value 
            } => {
                encode_literal(&mut block, 0x40, 6, name_indexed, name_index, &name_literal, &value_literal, huffman_name, huffman_value);
            }
            HpackOp::LiteralWithoutIndexing { 
                name_indexed, name_index, name_literal, value_literal, huffman_name, huffman_value 
            } => {
                encode_literal(&mut block, 0x00, 4, name_indexed, name_index, &name_literal, &value_literal, huffman_name, huffman_value);
            }
            HpackOp::LiteralNeverIndexed { 
                name_indexed, name_index, name_literal, value_literal, huffman_name, huffman_value 
            } => {
                encode_literal(&mut block, 0x10, 4, name_indexed, name_index, &name_literal, &value_literal, huffman_name, huffman_value);
            }
            HpackOp::RawBytes(bytes) => {
                block.extend_from_slice(&bytes);
            }
        }
        
        // After each op (or a few ops), try to decode
        if block.len() > 1024 {
            let mut src = Bytes::from(std::mem::take(&mut block));
            let _ = decoder.decode(&mut src);
        }
    }
    
    if !block.is_empty() {
        let mut src = Bytes::from(block);
        let _ = decoder.decode(&mut src);
    }
});

fn encode_integer(dst: &mut Vec<u8>, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1 << prefix_bits) - 1;
    if value < max_first {
        dst.push(prefix | value as u8);
    } else {
        dst.push(prefix | max_first as u8);
        let mut remaining = value - max_first;
        while remaining >= 128 {
            dst.push((remaining & 0x7f) as u8 | 0x80);
            remaining >>= 7;
        }
        dst.push(remaining as u8);
    }
}

fn encode_literal(
    dst: &mut Vec<u8>,
    prefix: u8,
    prefix_bits: u8,
    name_indexed: bool,
    name_index: u32,
    name_literal: &[u8],
    value_literal: &[u8],
    huffman_name: bool,
    huffman_value: bool,
) {
    if name_indexed {
        encode_integer(dst, name_index as usize, prefix_bits, prefix);
    } else {
        dst.push(prefix);
        encode_string(dst, name_literal, huffman_name);
    }
    encode_string(dst, value_literal, huffman_value);
}

fn encode_string(dst: &mut Vec<u8>, data: &[u8], huffman: bool) {
    let huffman_flag = if huffman { 0x80 } else { 0x00 };
    // We don't actually perform Huffman encoding here because we want to fuzz
    // the decoder's ability to handle potentially invalid Huffman sequences.
    // So we just set the flag and provide the raw data.
    encode_integer(dst, data.len(), 7, huffman_flag);
    dst.extend_from_slice(data);
}
