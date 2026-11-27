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

/// Emits the smallest of raw, newly described and reusable Huffman literals.
/// A new table only takes effect if the caller commits this compressed block.
pub fn encode_literals(
    literals: &[u8],
    previous: Option<&HuffmanCode>,
    out: &mut Vec<u8>,
) -> Option<HuffmanCode> {
    if literals.is_empty() {
        out.push(0);
        return None;
    }
    let raw_size = literals.len()
        + match literals.len() {
            0..32 => 1,
            32..4096 => 2,
            _ => 3,
        };
    let prior = previous.and_then(|code| {
        let size = SectionLayout::new(literals, code, 0, 3)?;
        (size.bytes < raw_size).then_some((code, size))
    });
    let best_size = prior.as_ref().map_or(raw_size, |(_, layout)| layout.bytes);
    if literals.len() >= 64
        && let Some(code) = HuffmanCode::build(literals)
        && let Some(description) = code.description()
        && let Some(layout) = SectionLayout::new(literals, &code, description.len(), 2)
        && layout.bytes < best_size
    {
        layout.write(literals, &code, &description, out);
        return Some(code);
    }
    if let Some((code, layout)) = prior {
        layout.write(literals, code, &[], out);
    } else {
        raw_literals(literals, out);
    }
    None
}

fn raw_literals(literals: &[u8], out: &mut Vec<u8>) {
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

/// The exact cost includes an end bit and byte padding in each stream.
struct SectionLayout {
    header: u64,
    header_len: usize,
    bytes: usize,
}

impl SectionLayout {
    fn new(literals: &[u8], code: &HuffmanCode, tree_bytes: usize, kind: u64) -> Option<Self> {
        let count = literals.len();
        let mut compressed = tree_bytes;
        if count < 256 {
            compressed += code.stream_size(literals)?;
        } else {
            compressed += 6;
            for part in literals.chunks(count.div_ceil(4)) {
                compressed += code.stream_size(part)?;
            }
        }
        let largest = count.max(compressed);
        let (format, header_len, bits) = match (count, largest) {
            (0..256, 0..=1023) => (0_u64, 3, 10),
            (0..256, _) => return None,
            (_, 0..=1023) => (1, 3, 10),
            (_, 1024..=16_383) => (2, 4, 14),
            (_, 16_384..=262_143) => (3, 5, 18),
            _ => return None,
        };
        let header = kind
            | (format << 2)
            | (u64::try_from(count).ok()? << 4)
            | (u64::try_from(compressed).ok()? << (4 + bits));
        Some(Self {
            header,
            header_len,
            bytes: header_len + compressed,
        })
    }

    fn write(self, literals: &[u8], code: &HuffmanCode, description: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.to_le_bytes()[..self.header_len]);
        out.extend_from_slice(description);
        if literals.len() < 256 {
            out.extend_from_slice(&code.encode_stream(literals));
        } else {
            let jump = out.len();
            out.resize(jump + 6, 0);
            for (i, part) in literals.chunks(literals.len().div_ceil(4)).enumerate() {
                let stream = code.encode_stream(part);
                if i < 3 {
                    // At most 32 KiB of input and 11 code bits per symbol.
                    let size = u16::try_from(stream.len()).expect("bounded Huffman stream");
                    out[jump + 2 * i..jump + 2 * i + 2].copy_from_slice(&size.to_le_bytes());
                }
                out.extend_from_slice(&stream);
            }
        }
    }
}
