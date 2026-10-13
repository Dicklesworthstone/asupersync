//! Huffman literal decoding, RFC 8878 §4.2.

// The literals section decoder (br-asupersync-t1fblr.8) is the consumer.
#![allow(
    dead_code,
    reason = "consumed by the zstd literals decoder, br-asupersync-t1fblr.8"
)]

use crate::bitio::BackwardBitReader;
use crate::fse::{DecodeTable, FseError, read_table_description};

/// The longest Huffman code zstd allows.
pub const MAX_CODE_BITS: u8 = 11;

/// A malformed Huffman tree description or stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HuffmanError {
    /// The description or a stream runs past its input.
    Truncated,
    /// The FSE-compressed weights are malformed.
    Weights(FseError),
    /// The weights describe no symbol, more than 256, or a tree deeper than
    /// [`MAX_CODE_BITS`], or one that does not complete to a power of two.
    InvalidTree,
    /// A stream ends with bits left over, or reads past its start.
    StreamMismatch,
    /// The four-stream jump table does not fit the input.
    BadJumpTable,
}

/// A single-symbol decoding table indexed by the next `max_bits` bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HuffmanTable {
    max_bits: u8,
    /// `(symbol, code length)` per index.
    entries: Vec<(u8, u8)>,
}

/// Reads a Huffman tree description (RFC 8878 §4.2.1) and builds its
/// decoding table. Returns the table and the bytes the description used.
pub fn read_tree_description(data: &[u8]) -> Result<(HuffmanTable, usize), HuffmanError> {
    let header = *data.first().ok_or(HuffmanError::Truncated)?;
    let (mut weights, used) = if header >= 128 {
        let count = usize::from(header - 127);
        let bytes = data
            .get(1..1 + count.div_ceil(2))
            .ok_or(HuffmanError::Truncated)?;
        let weights: Vec<u8> = bytes
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0F])
            .take(count)
            .collect();
        (weights, 1 + bytes.len())
    } else {
        let size = usize::from(header);
        let compressed = data.get(1..1 + size).ok_or(HuffmanError::Truncated)?;
        (fse_weights(compressed)?, 1 + size)
    };
    let total: u32 = weights
        .iter()
        .filter(|&&weight| weight > 0)
        .try_fold(0_u32, |sum, &weight| {
            if weight > MAX_CODE_BITS + 1 {
                None
            } else {
                sum.checked_add(1 << (weight - 1))
            }
        })
        .ok_or(HuffmanError::InvalidTree)?;
    if total == 0 {
        return Err(HuffmanError::InvalidTree);
    }
    let max_bits = total.bit_width();
    if max_bits > u32::from(MAX_CODE_BITS) {
        return Err(HuffmanError::InvalidTree);
    }
    let rest = (1_u32 << max_bits) - total;
    if !rest.is_power_of_two() {
        return Err(HuffmanError::InvalidTree);
    }
    let last = u8::try_from(rest.bit_width()).map_err(|_| HuffmanError::InvalidTree)?;
    weights.push(last);
    if weights.len() > 256 {
        return Err(HuffmanError::InvalidTree);
    }
    let max_bits = u8::try_from(max_bits).map_err(|_| HuffmanError::InvalidTree)?;
    let size = 1_usize << max_bits;
    let mut entries = vec![(0_u8, 0_u8); size];
    let mut position = 0_usize;
    // Lowest weight first; within a weight, symbols in natural order.
    for weight in 1..=max_bits {
        let length = 1_usize << (weight - 1);
        for (symbol, _) in weights.iter().enumerate().filter(|(_, w)| **w == weight) {
            let entry = (
                u8::try_from(symbol).map_err(|_| HuffmanError::InvalidTree)?,
                max_bits + 1 - weight,
            );
            let cells = entries
                .get_mut(position..position + length)
                .ok_or(HuffmanError::InvalidTree)?;
            cells.fill(entry);
            position += length;
        }
    }
    if position != size {
        return Err(HuffmanError::InvalidTree);
    }
    Ok((HuffmanTable { max_bits, entries }, used))
}

/// Decodes FSE-compressed Huffman weights (RFC 8878 §4.2.1.2): two
/// interleaved states over one table, ending at the stream's overflow.
fn fse_weights(data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    let (log, counts, used) = read_table_description(data, 6, usize::from(MAX_CODE_BITS) + 2)
        .map_err(HuffmanError::Weights)?;
    let table = DecodeTable::new(&counts, log).map_err(HuffmanError::Weights)?;
    let stream = data.get(used..).ok_or(HuffmanError::Truncated)?;
    let mut reader = BackwardBitReader::new(stream).map_err(|_| HuffmanError::StreamMismatch)?;
    let mut first = table.initial_state(&mut reader);
    let mut second = table.initial_state(&mut reader);
    let mut weights = Vec::new();
    loop {
        weights.push(table.cell(first).symbol);
        first = table.next_state(first, &mut reader);
        if reader.overflowed() {
            weights.push(table.cell(second).symbol);
            break;
        }
        weights.push(table.cell(second).symbol);
        second = table.next_state(second, &mut reader);
        if reader.overflowed() {
            weights.push(table.cell(first).symbol);
            break;
        }
        if weights.len() > 255 {
            return Err(HuffmanError::InvalidTree);
        }
    }
    Ok(weights)
}

impl HuffmanTable {
    /// The table's code depth.
    pub const fn max_bits(&self) -> u8 {
        self.max_bits
    }

    /// Decodes `count` symbols from one backward stream into `out`. The
    /// stream must end exactly where the last symbol ends.
    pub fn decode_stream(
        &self,
        stream: &[u8],
        count: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), HuffmanError> {
        let mut reader =
            BackwardBitReader::new(stream).map_err(|_| HuffmanError::StreamMismatch)?;
        let width = u32::from(self.max_bits);
        out.reserve(count);
        for _ in 0..count {
            let index = usize::try_from(reader.peek_bits(width)).unwrap_or(usize::MAX);
            let &(symbol, bits) = self
                .entries
                .get(index)
                .ok_or(HuffmanError::StreamMismatch)?;
            out.push(symbol);
            reader.consume(u32::from(bits));
        }
        if reader.is_exhausted() {
            Ok(())
        } else {
            Err(HuffmanError::StreamMismatch)
        }
    }

    /// Decodes `regenerated` symbols from four streams behind a 6-byte jump
    /// table (RFC 8878 §3.1.1.3.1.6).
    pub fn decode_four_streams(
        &self,
        data: &[u8],
        regenerated: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), HuffmanError> {
        let jump = data.get(..6).ok_or(HuffmanError::BadJumpTable)?;
        let size = |i: usize| usize::from(u16::from_le_bytes([jump[i], jump[i + 1]]));
        let first_end = 6 + size(0);
        let second_end = first_end + size(2);
        let third_end = second_end + size(4);
        if third_end > data.len() {
            return Err(HuffmanError::BadJumpTable);
        }
        let segment = regenerated.div_ceil(4);
        let last = regenerated
            .checked_sub(3 * segment)
            .ok_or(HuffmanError::BadJumpTable)?;
        for (range, count) in [
            (6..first_end, segment),
            (first_end..second_end, segment),
            (second_end..third_end, segment),
            (third_end..data.len(), last),
        ] {
            let stream = data.get(range).ok_or(HuffmanError::BadJumpTable)?;
            self.decode_stream(stream, count, out)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{HuffmanError, read_tree_description};
    use crate::xxhash64::xxh64;

    const LIBZSTD_STREAMS: &str = include_str!("../tests/vectors/huffman_streams_libzstd.txt");

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode(data: &[u8], regenerated: usize, four: bool) -> Result<Vec<u8>, HuffmanError> {
        let (table, used) = read_tree_description(data)?;
        let mut out = Vec::new();
        if four {
            table.decode_four_streams(&data[used..], regenerated, &mut out)?;
        } else {
            table.decode_stream(&data[used..], regenerated, &mut out)?;
        }
        Ok(out)
    }

    #[test]
    fn decodes_every_libzstd_stream() {
        let (mut one, mut four) = (0, 0);
        for line in LIBZSTD_STREAMS
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let streams: u8 = fields[0].parse().unwrap();
            let regenerated: usize = fields[1].parse().unwrap();
            let expected = u64::from_str_radix(fields[2], 16).unwrap();
            let data = hex(fields[3]);
            let out = decode(&data, regenerated, streams == 4).unwrap();
            assert_eq!(out.len(), regenerated);
            assert_eq!(
                xxh64(&out, 0),
                expected,
                "{streams} streams, {regenerated} bytes"
            );
            if streams == 4 {
                four += 1;
            } else {
                one += 1;
            }
        }
        assert_eq!(
            (one, four),
            (30, 30),
            "the oracle file must keep all 60 vectors"
        );
    }

    /// RFC 8878 Tables 23 and 25: direct weights 4, 3, 2, 0, 1 with literal 5
    /// implied at weight 1, so 0 -> "1", 1 -> "01", 4 -> "0000", 5 -> "0001".
    #[test]
    fn decodes_the_rfc_direct_header_example() {
        let data = [0x84, 0x43, 0x20, 0x10, 0x01, 0x0d];
        let (table, used) = read_tree_description(&data).unwrap();
        assert_eq!(table.max_bits(), 4);
        assert_eq!(used, 4);
        let mut out = Vec::new();
        table.decode_stream(&data[used..], 4, &mut out).unwrap();
        assert_eq!(out, [0, 1, 4, 5]);
    }

    #[test]
    fn rejects_malformed_trees_and_streams() {
        // Direct weights 2, 2, 1 sum to 2 + 2 + 1 = 5; completing to 8 leaves
        // 3, which is not a power of two, so no last weight exists.
        assert_eq!(
            read_tree_description(&[0x82, 0x22, 0x10]).err(),
            Some(HuffmanError::InvalidTree)
        );
        // Header promises bytes that are missing.
        assert_eq!(
            read_tree_description(&[0x90, 0x11]).err(),
            Some(HuffmanError::Truncated)
        );
        // The RFC example stream asked for one symbol too many.
        let data = [0x84, 0x43, 0x20, 0x10, 0x01, 0x0d];
        let (table, used) = read_tree_description(&data).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            table.decode_stream(&data[used..], 5, &mut out),
            Err(HuffmanError::StreamMismatch)
        );
        // A jump table pointing past the input.
        assert_eq!(
            table.decode_four_streams(&[0xFF, 0xFF, 0, 0, 0, 0, 1], 8, &mut out),
            Err(HuffmanError::BadJumpTable)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x243F_6A88_85A3_08D3_u64;
        for round in 0..3_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = usize::try_from(state >> 57).unwrap();
            let data: Vec<u8> = (0..len)
                .map(|i| (state.rotate_left(u32::try_from(i % 64).unwrap())).to_le_bytes()[0])
                .collect();
            let _ = decode(&data, round % 300, round % 2 == 0);
        }
    }
}
