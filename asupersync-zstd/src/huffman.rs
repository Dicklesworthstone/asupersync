//! Huffman literal coding, RFC 8878 §4.2: tree descriptions and streams,
//! decoded and encoded.

use crate::bitio::{BackwardBitReader, BitWriter};
use crate::fse::{
    DecodeTable, EncodeTable, FseError, normalize, read_table_description, write_table_description,
};

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
    #[cfg(test)]
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

/// A length-limited canonical Huffman code for one literals section, laid
/// out exactly as [`read_tree_description`] rebuilds it.
#[derive(Clone, Debug)]
pub struct HuffmanCode {
    /// Weights of symbols `0..last`; the last present symbol's weight is
    /// implied by the others (RFC 8878 §4.2.1).
    weights: Vec<u8>,
    /// `(code, length)` per byte value; length 0 for an absent symbol.
    codes: Vec<(u16, u8)>,
}

/// A package-merge item: a leaf symbol, or a package of the two items at
/// `first_child` and `first_child + 1` of the previous level.
#[derive(Clone, Copy)]
struct Item {
    weight: u64,
    leaf: Option<u8>,
    first_child: usize,
}

/// Optimal code lengths no longer than `limit` for the symbols with nonzero
/// frequency (package-merge, Larmore and Hirschberg). Ties keep leaves ahead
/// of packages and lower symbols ahead of higher ones, so the result is
/// deterministic.
fn limited_lengths(freqs: &[u64; 256], limit: u8) -> [u8; 256] {
    let mut lengths = [0_u8; 256];
    let mut leaves: Vec<Item> = (0..=u8::MAX)
        .filter(|&symbol| freqs[usize::from(symbol)] > 0)
        .map(|symbol| Item {
            weight: freqs[usize::from(symbol)],
            leaf: Some(symbol),
            first_child: 0,
        })
        .collect();
    leaves.sort_by_key(|item| item.weight);
    let count = leaves.len();
    if count <= 1 {
        if let Some(symbol) = leaves.first().and_then(|item| item.leaf) {
            lengths[usize::from(symbol)] = 1;
        }
        return lengths;
    }
    let mut levels: Vec<Vec<Item>> = vec![leaves.clone()];
    for _ in 1..limit {
        let previous = levels.last().map_or(&[][..], Vec::as_slice);
        let packages: Vec<Item> = (0..previous.len().saturating_sub(1))
            .step_by(2)
            .map(|index| Item {
                weight: previous[index].weight + previous[index + 1].weight,
                leaf: None,
                first_child: index,
            })
            .collect();
        // Both inputs are sorted; on equal weights the leaf goes first.
        let mut merged = Vec::with_capacity(leaves.len() + packages.len());
        let (mut leaf, mut package) = (0, 0);
        while leaf < leaves.len() || package < packages.len() {
            let take_leaf = package == packages.len()
                || (leaf < leaves.len() && leaves[leaf].weight <= packages[package].weight);
            if take_leaf {
                merged.push(leaves[leaf]);
                leaf += 1;
            } else {
                merged.push(packages[package]);
                package += 1;
            }
        }
        levels.push(merged);
    }
    // Every leaf inside the first 2n - 2 items of the last level adds one
    // to that symbol's length.
    let top = levels.len() - 1;
    let mut pending: Vec<(usize, usize)> = (0..levels[top].len().min(2 * count - 2))
        .map(|index| (top, index))
        .collect();
    while let Some((level, index)) = pending.pop() {
        let item = levels[level][index];
        if let Some(symbol) = item.leaf {
            lengths[usize::from(symbol)] += 1;
        } else if level > 0 {
            pending.push((level - 1, item.first_child));
            pending.push((level - 1, item.first_child + 1));
        }
    }
    lengths
}

impl HuffmanCode {
    /// The code for `literals`, or `None` when fewer than two distinct bytes
    /// occur (such a section is stored raw or as RLE instead).
    pub fn build(literals: &[u8]) -> Option<Self> {
        let mut freqs = [0_u64; 256];
        for &byte in literals {
            freqs[usize::from(byte)] += 1;
        }
        if freqs.iter().filter(|&&freq| freq > 0).count() < 2 {
            return None;
        }
        let lengths = limited_lengths(&freqs, MAX_CODE_BITS);
        let max_len = lengths.iter().copied().max()?;
        let last = lengths.iter().rposition(|&length| length > 0)?;
        let weights: Vec<u8> = lengths
            .iter()
            .map(|&length| if length == 0 { 0 } else { max_len + 1 - length })
            .collect();
        // Canonical codes, in the order the decoder fills its table: lowest
        // weight first, then by symbol.
        let mut codes = vec![(0_u16, 0_u8); 256];
        let mut position = 0_u32;
        for weight in 1..=max_len {
            for symbol in 0..=last {
                if weights[symbol] == weight {
                    let code = u16::try_from(position >> (weight - 1)).ok()?;
                    codes[symbol] = (code, max_len + 1 - weight);
                    position += 1 << (weight - 1);
                }
            }
        }
        debug_assert_eq!(position, 1 << max_len, "a complete prefix code");
        Some(Self {
            weights: weights[..last].to_vec(),
            codes,
        })
    }

    /// The tree description (RFC 8878 §4.2.1): direct 4-bit weights or
    /// FSE-compressed ones, whichever is shorter (direct on a tie). `None`
    /// when neither form can hold the weights.
    pub fn description(&self) -> Option<Vec<u8>> {
        let count = self.weights.len();
        let direct = (count <= 128).then(|| {
            let mut bytes = Vec::with_capacity(1 + count.div_ceil(2));
            bytes.push(u8::try_from(127 + count).unwrap_or(u8::MAX));
            bytes.extend(
                self.weights
                    .chunks(2)
                    .map(|pair| (pair[0] << 4) | pair.get(1).copied().unwrap_or(0)),
            );
            bytes
        });
        let compressed = if count > 2 {
            fse_compressed_weights(&self.weights)
                .filter(|payload| payload.len() < 128)
                .map(|payload| {
                    let mut bytes = Vec::with_capacity(1 + payload.len());
                    bytes.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
                    bytes.extend_from_slice(&payload);
                    bytes
                })
        } else {
            None
        };
        match (direct, compressed) {
            (Some(direct), Some(compressed)) if compressed.len() < direct.len() => Some(compressed),
            (Some(direct), _) => Some(direct),
            (None, compressed) => compressed,
        }
    }

    /// One backward Huffman stream for `data`: the first byte is read first.
    pub fn encode_stream(&self, data: &[u8]) -> Vec<u8> {
        let mut writer = BitWriter::new();
        for &byte in data.iter().rev() {
            let (code, length) = self.codes[usize::from(byte)];
            debug_assert!(length > 0, "byte {byte} has no code");
            writer.add(u64::from(code), u32::from(length));
        }
        writer.finish()
    }
}

/// FSE-compressed Huffman weights (RFC 8878 §4.2.1.2): one table, two
/// interleaved states, the even-indexed weights on the state read first.
///
/// `None` when every weight is the same. A one-symbol table moves between
/// states without reading bits, so the decoder never reaches the stream
/// overflow that ends the weight list (libzstd refuses this case too).
fn fse_compressed_weights(weights: &[u8]) -> Option<Vec<u8>> {
    let mut counts = vec![0_u32; usize::from(MAX_CODE_BITS) + 2];
    for &weight in weights {
        *counts.get_mut(usize::from(weight))? += 1;
    }
    let present = counts.iter().filter(|&&count| count > 0).count();
    if present < 2 {
        return None;
    }
    let mut log = 6_u8;
    while log > 5 && (1_usize << (log - 1)) >= weights.len().max(present) * 2 {
        log -= 1;
    }
    let norm = normalize(&counts, log)?;
    let mut payload = write_table_description(&norm, log);
    let table = EncodeTable::new(&norm, log);
    let mut writer = BitWriter::new();
    let mut states: [Option<usize>; 2] = [None, None];
    for (index, &weight) in weights.iter().enumerate().rev() {
        let slot = &mut states[index & 1];
        *slot = Some(slot.map_or_else(
            || table.initial_state(weight),
            |state| table.encode(state, weight, &mut writer),
        ));
    }
    let [even, odd] = states;
    table.flush(odd?, &mut writer);
    table.flush(even?, &mut writer);
    payload.extend_from_slice(&writer.finish());
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::{HuffmanCode, HuffmanError, MAX_CODE_BITS, read_tree_description};
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

    /// Builds the code for `data`, writes the description and one stream (or
    /// four), and decodes them with the decoder's own table reader.
    fn encode_then_decode(data: &[u8], four: bool) -> (Vec<u8>, usize) {
        let code = HuffmanCode::build(data).unwrap();
        let description = code.description().unwrap();
        let mut section = description.clone();
        if four {
            let segment = data.len().div_ceil(4);
            let streams: Vec<Vec<u8>> = data
                .chunks(segment)
                .map(|part| code.encode_stream(part))
                .collect();
            assert_eq!(streams.len(), 4);
            for stream in &streams[..3] {
                section.extend_from_slice(&u16::try_from(stream.len()).unwrap().to_le_bytes());
            }
            for stream in &streams {
                section.extend_from_slice(stream);
            }
        } else {
            section.extend_from_slice(&code.encode_stream(data));
        }
        let (table, used) = read_tree_description(&section).unwrap();
        assert_eq!(used, description.len(), "the description is read exactly");
        assert!(table.max_bits() <= MAX_CODE_BITS);
        let mut out = Vec::new();
        if four {
            table
                .decode_four_streams(&section[used..], data.len(), &mut out)
                .unwrap();
        } else {
            table
                .decode_stream(&section[used..], data.len(), &mut out)
                .unwrap();
        }
        (out, description.len())
    }

    #[test]
    fn encoded_literals_decode_with_the_written_tree() {
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        let text = b"The quick brown fox jumps over the lazy dog; pack my box with five dozen liquor jugs."
            .repeat(20);
        let every_byte = every_byte_skewed();
        let uniform_128: Vec<u8> = (0..128_u8).cycle().take(4_096).collect();
        let skewed: Vec<u8> = (0..3_000)
            .map(|_| u8::try_from(next().trailing_zeros().min(40)).unwrap())
            .collect();
        let random: Vec<u8> = (0..1_000)
            .map(|_| u8::try_from(next() & 0xFF).unwrap())
            .collect();
        for (name, data) in [
            ("text", &text[..]),
            ("every byte", &every_byte[..]),
            ("uniform 128", &uniform_128[..]),
            ("skewed", &skewed[..]),
            ("random", &random[..]),
            (
                "two symbols",
                &b"abababababababababababababababababababababababababababababababababab"[..],
            ),
        ] {
            for four in [false, true] {
                let (out, _) = encode_then_decode(data, four);
                assert_eq!(out, data, "{name}, four streams: {four}");
            }
        }
    }

    /// Every byte value, byte `b` repeated `1 + b % 13` times: code lengths
    /// differ, and 255 explicit weights only fit the FSE-compressed form.
    fn every_byte_skewed() -> Vec<u8> {
        (0..=255_u8)
            .flat_map(|byte| std::iter::repeat_n(byte, 1 + usize::from(byte % 13)))
            .collect()
    }

    #[test]
    fn both_description_forms_are_used() {
        let code = HuffmanCode::build(&every_byte_skewed()).unwrap();
        let description = code.description().unwrap();
        assert!(description[0] < 128, "FSE-compressed weights");
        // Frequencies 4, 3, 2, 1 give lengths 1, 2, 3, 3: weights 3, 2, 1
        // (the last symbol's is implied) fit two direct bytes.
        let code = HuffmanCode::build(&[0, 0, 0, 0, 1, 1, 1, 2, 2, 3]).unwrap();
        let description = code.description().unwrap();
        assert_eq!(description, [127 + 3, 0x32, 0x10]);
    }

    /// A uniform alphabet gives every symbol the same weight. Its FSE form
    /// would never end (see `fse_compressed_weights`), so the direct form is
    /// used, and past 128 weights there is no description at all.
    #[test]
    fn equal_weights_never_use_the_fse_form() {
        let uniform_128: Vec<u8> = (0..128_u8).cycle().take(4_096).collect();
        let description = HuffmanCode::build(&uniform_128)
            .unwrap()
            .description()
            .unwrap();
        assert_eq!(description[0], 127 + 127, "direct weights");
        let uniform_256: Vec<u8> = (0..=255_u8).cycle().take(4_096).collect();
        assert_eq!(
            HuffmanCode::build(&uniform_256).unwrap().description(),
            None
        );
    }

    /// Fibonacci frequencies force an unlimited Huffman code 29 bits deep;
    /// the length-limited code must stay within 11 bits and stay complete.
    #[test]
    fn code_lengths_are_limited_to_eleven_bits() {
        let mut data = Vec::new();
        let (mut a, mut b) = (1_usize, 1_usize);
        for symbol in 0..30_u8 {
            data.extend(std::iter::repeat_n(symbol, a));
            (a, b) = (b, a + b);
        }
        let code = HuffmanCode::build(&data).unwrap();
        let longest = code.codes.iter().map(|&(_, length)| length).max().unwrap();
        assert_eq!(longest, MAX_CODE_BITS);
        let kraft: u32 = code
            .codes
            .iter()
            .filter(|&&(_, length)| length > 0)
            .map(|&(_, length)| 1 << (MAX_CODE_BITS - length))
            .sum();
        assert_eq!(kraft, 1 << MAX_CODE_BITS, "a complete prefix code");
        let (out, _) = encode_then_decode(&data, false);
        assert_eq!(out, data);
    }

    #[test]
    fn a_single_distinct_byte_has_no_code() {
        assert!(HuffmanCode::build(b"zzzzzzzz").is_none());
        assert!(HuffmanCode::build(b"").is_none());
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
