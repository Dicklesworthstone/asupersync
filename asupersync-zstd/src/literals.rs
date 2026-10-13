//! The literals section of a compressed block, RFC 8878 §3.1.1.3.1.

use crate::frame::DecodeError;
use crate::huffman::{HuffmanTable, read_tree_description};

/// The largest literals section a block may regenerate (Block_Maximum_Size).
const MAX_LITERALS: usize = 128 * 1024;

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
/// (cleared first). `huffman` holds the previous block's table for
/// Treeless literals and receives a newly described table. Returns the
/// bytes the section used.
pub fn decode_literals(
    block: &[u8],
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
        if regenerated > MAX_LITERALS {
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
    if regenerated > MAX_LITERALS {
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
