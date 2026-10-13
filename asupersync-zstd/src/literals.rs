//! The literals section of a compressed block, RFC 8878 §3.1.1.3.1.

use crate::frame::DecodeError;
use crate::huffman::{HuffmanCode, HuffmanTable, read_tree_description};

fn field(block: &[u8], start: usize, width: usize) -> Result<u64, DecodeError> {
    let bytes = block
        .get(start..start + width)
        .ok_or(DecodeError::Truncated)?;
    let mut word = [0_u8; 8];
    word.get_mut(..width)
        .ok_or(DecodeError::Truncated)?
        .copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
}

fn size(value: u64) -> Result<usize, DecodeError> {
    usize::try_from(value).map_err(|_| DecodeError::Malformed("literals size"))
}

/// Decodes the literals section at the start of `block` into `literals`
/// (cleared first). `block_maximum` is the frame's Block_Maximum_Size, the
/// most literals one block may regenerate. `huffman` holds the previous
/// block's table for Treeless literals and receives a newly described
/// table. Returns the bytes the section used.
pub fn decode_literals(
    block: &[u8],
    block_maximum: usize,
    huffman: &mut Option<HuffmanTable>,
    literals: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    literals.clear();
    let first = *block.first().ok_or(DecodeError::Truncated)?;
    let kind = first & 3;
    let format = (first >> 2) & 3;
    if kind < 2 {
        // Raw (0) or RLE (1).
        let (regenerated, header) = match format {
            0 | 2 => (usize::from(first >> 3), 1),
            1 => (size((field(block, 0, 2)? >> 4) & 0x0FFF)?, 2),
            _ => (size((field(block, 0, 3)? >> 4) & 0x000F_FFFF)?, 3),
        };
        if regenerated > block_maximum {
            return Err(DecodeError::Malformed("literals exceed the block maximum"));
        }
        if kind == 0 {
            let bytes = block
                .get(header..header + regenerated)
                .ok_or(DecodeError::Truncated)?;
            literals.extend_from_slice(bytes);
            return Ok(header + regenerated);
        }
        let byte = *block.get(header).ok_or(DecodeError::Truncated)?;
        literals.resize(regenerated, byte);
        return Ok(header + 1);
    }
    // Compressed (2) or Treeless (3).
    let (header, bits) = match format {
        0 | 1 => (3, 10),
        2 => (4, 14),
        _ => (5, 18),
    };
    let value = field(block, 0, header)?;
    let mask = (1_u64 << bits) - 1;
    let regenerated = size((value >> 4) & mask)?;
    let compressed = size((value >> (4 + bits)) & mask)?;
    if regenerated > block_maximum {
        return Err(DecodeError::Malformed("literals exceed the block maximum"));
    }
    let data = block
        .get(header..header + compressed)
        .ok_or(DecodeError::Truncated)?;
    let streams = if kind == 2 {
        let (table, used) = read_tree_description(data)
            .map_err(|_| DecodeError::Malformed("Huffman tree description"))?;
        *huffman = Some(table);
        data.get(used..).ok_or(DecodeError::Truncated)?
    } else {
        data
    };
    let table = huffman.as_ref().ok_or(DecodeError::Malformed(
        "treeless literals without a previous table",
    ))?;
    let result = if format == 0 {
        table.decode_stream(streams, regenerated, literals)
    } else {
        table.decode_four_streams(streams, regenerated, literals)
    };
    result.map_err(|_| DecodeError::Malformed("Huffman-coded literals"))?;
    Ok(header + compressed)
}

/// Appends the literals section for `literals` (at most one 128 KiB block's
/// worth): Huffman-compressed when that is smaller than storing them raw.
pub fn encode_literals(literals: &[u8], out: &mut Vec<u8>) {
    if let Some(section) = compressed_section(literals) {
        out.extend_from_slice(&section);
        return;
    }
    let count = u32::try_from(literals.len()).unwrap_or(0);
    if count < 32 {
        out.push(u8::try_from(count << 3).unwrap_or(0));
    } else if count < 4096 {
        out.extend_from_slice(&((count << 4) | 0b0100).to_le_bytes()[..2]);
    } else {
        out.extend_from_slice(&((count << 4) | 0b1100).to_le_bytes()[..3]);
    }
    out.extend_from_slice(literals);
}

/// A Compressed_Literals_Block section: one Huffman stream below 256
/// literals, four from 256 on. `None` when Huffman coding does not beat the
/// raw section or the sizes do not fit any header format.
fn compressed_section(literals: &[u8]) -> Option<Vec<u8>> {
    let count = literals.len();
    if count < 64 {
        return None;
    }
    let code = HuffmanCode::build(literals)?;
    let description = code.description()?;
    let streams = if count < 256 {
        code.encode_stream(literals)
    } else {
        // Four streams of count.div_ceil(4) literals (the last one shorter)
        // behind a jump table of the first three sizes.
        let encoded: Vec<Vec<u8>> = literals
            .chunks(count.div_ceil(4))
            .map(|part| code.encode_stream(part))
            .collect();
        let mut streams = Vec::with_capacity(6 + encoded.iter().map(Vec::len).sum::<usize>());
        for stream in encoded.iter().take(3) {
            streams.extend_from_slice(&u16::try_from(stream.len()).ok()?.to_le_bytes());
        }
        for stream in &encoded {
            streams.extend_from_slice(stream);
        }
        streams
    };
    let compressed = description.len() + streams.len();
    let largest = count.max(compressed);
    let (format, header_len, bits) = if count < 256 {
        if compressed > 1023 {
            return None;
        }
        (0_u64, 3, 10)
    } else if largest <= 1023 {
        (1, 3, 10)
    } else if largest <= 16_383 {
        (2, 4, 14)
    } else if largest <= 262_143 {
        (3, 5, 18)
    } else {
        return None;
    };
    let header = 2
        | (format << 2)
        | (u64::try_from(count).ok()? << 4)
        | (u64::try_from(compressed).ok()? << (4 + bits));
    let raw_cost = count
        + match count {
            0..32 => 1,
            32..4096 => 2,
            _ => 3,
        };
    if header_len + compressed >= raw_cost {
        return None;
    }
    let mut section = Vec::with_capacity(header_len + compressed);
    section.extend_from_slice(&header.to_le_bytes()[..header_len]);
    section.extend_from_slice(&description);
    section.extend_from_slice(&streams);
    Some(section)
}
