//! FSE (finite state entropy) decoding tables, RFC 8878 §4.1.

// The sequences decoder (br-asupersync-t1fblr.8) is the consumer; until it
// lands these tables are exercised only by their tests.
#![allow(
    dead_code,
    reason = "consumed by the zstd sequences decoder, br-asupersync-t1fblr.8"
)]

use crate::bitio::{BackwardBitReader, BitWriter, extract};

/// A malformed FSE table description or distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FseError {
    /// The accuracy log exceeds what the context allows.
    AccuracyLogTooLarge,
    /// The description names more symbols than the context allows.
    TooManySymbols,
    /// The probabilities do not add up to the table size.
    BadProbabilitySum,
    /// The description runs past the end of the input.
    Truncated,
}

/// One decoding-table cell: the symbol a state decodes, and how to reach
/// the next state (read `num_bits` bits and add them to `baseline`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    /// The decoded symbol.
    pub symbol: u8,
    /// Bits to read for the next state.
    pub num_bits: u8,
    /// Added to the bits read to form the next state.
    pub baseline: u16,
}

/// An FSE decoding table with `1 << accuracy_log` cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeTable {
    accuracy_log: u8,
    cells: Vec<Cell>,
}

/// Literals-length predefined distribution (RFC 8878 §3.1.1.3.2.2.1).
pub const LITERALS_LENGTH_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
/// Accuracy log of [`LITERALS_LENGTH_DEFAULT`].
pub const LITERALS_LENGTH_DEFAULT_LOG: u8 = 6;

/// Match-length predefined distribution (RFC 8878 §3.1.1.3.2.2.2).
pub const MATCH_LENGTH_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
/// Accuracy log of [`MATCH_LENGTH_DEFAULT`].
pub const MATCH_LENGTH_DEFAULT_LOG: u8 = 6;

/// Offset-code predefined distribution (RFC 8878 §3.1.1.3.2.2.3).
pub const OFFSET_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
/// Accuracy log of [`OFFSET_DEFAULT`].
pub const OFFSET_DEFAULT_LOG: u8 = 5;

/// The largest accuracy log any FSE table description may declare.
pub const MAX_ACCURACY_LOG: u8 = 15;

/// Reads an FSE table description (RFC 8878 §4.1.1) from the start of
/// `data`. Returns the accuracy log, the normalized counts (−1 means "less
/// than 1") and the number of bytes the description used.
pub fn read_table_description(
    data: &[u8],
    max_log: u8,
    max_symbols: usize,
) -> Result<(u8, Vec<i16>, usize), FseError> {
    let log = extract(data, 0, 4) + 5;
    if log > u64::from(max_log.min(MAX_ACCURACY_LOG)) {
        return Err(FseError::AccuracyLogTooLarge);
    }
    let accuracy_log = u8::try_from(log).map_err(|_| FseError::AccuracyLogTooLarge)?;
    let size: i32 = 1 << accuracy_log;
    let mut remaining = size + 1;
    let mut threshold = size;
    let mut num_bits = usize::from(accuracy_log) + 1;
    let mut pos = 4_usize;
    let mut counts: Vec<i16> = Vec::new();
    let mut previous_zero = false;
    while remaining > 1 {
        if previous_zero {
            // A zero probability is followed by 2-bit repeat flags: 3 means
            // three more zeros and another flag, 0-2 ends the run.
            let mut zeros = 0_usize;
            loop {
                let flag = extract(data, pos, 2);
                pos += 2;
                zeros += usize::try_from(flag).unwrap_or(0);
                if counts.len() + zeros >= max_symbols {
                    return Err(FseError::TooManySymbols);
                }
                if flag != 3 {
                    break;
                }
            }
            counts.resize(counts.len() + zeros, 0);
        }
        let max_small = (2 * threshold - 1) - remaining;
        let low = i32::try_from(extract(data, pos, num_bits - 1)).unwrap_or(i32::MAX);
        let mut count = if low < max_small {
            pos += num_bits - 1;
            low
        } else {
            let mut value = i32::try_from(extract(data, pos, num_bits)).unwrap_or(i32::MAX);
            if value >= threshold {
                value -= max_small;
            }
            pos += num_bits;
            value
        };
        count -= 1;
        remaining -= count.abs();
        counts.push(i16::try_from(count).map_err(|_| FseError::BadProbabilitySum)?);
        if counts.len() > max_symbols {
            return Err(FseError::TooManySymbols);
        }
        previous_zero = count == 0;
        while remaining < threshold && num_bits > 1 {
            num_bits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 {
        return Err(FseError::BadProbabilitySum);
    }
    let used = pos.div_ceil(8);
    if used > data.len() {
        return Err(FseError::Truncated);
    }
    Ok((accuracy_log, counts, used))
}

impl DecodeTable {
    /// Builds the decoding table for a normalized distribution
    /// (RFC 8878 §4.1.1, "The distribution of normalized probabilities...").
    pub fn new(counts: &[i16], accuracy_log: u8) -> Result<Self, FseError> {
        if accuracy_log > MAX_ACCURACY_LOG {
            return Err(FseError::AccuracyLogTooLarge);
        }
        if counts.len() > 256 {
            return Err(FseError::TooManySymbols);
        }
        let size = 1_usize << accuracy_log;
        let mut symbol_at = vec![0_u8; size];
        let mut next_state = vec![0_u32; counts.len()];
        // Cells [high, size) hold the "less than 1" symbols, from the end.
        let mut high = size;
        let mut total = 0_usize;
        for (symbol, &count) in counts.iter().enumerate() {
            let symbol_byte = u8::try_from(symbol).map_err(|_| FseError::TooManySymbols)?;
            if count == -1 {
                high = high.checked_sub(1).ok_or(FseError::BadProbabilitySum)?;
                symbol_at[high] = symbol_byte;
                next_state[symbol] = 1;
                total += 1;
            } else {
                let count = u32::try_from(count).map_err(|_| FseError::BadProbabilitySum)?;
                next_state[symbol] = count;
                total += usize::try_from(count).map_err(|_| FseError::BadProbabilitySum)?;
            }
        }
        if total != size {
            return Err(FseError::BadProbabilitySum);
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut position = 0_usize;
        for (symbol, &count) in counts.iter().enumerate() {
            let symbol_byte = u8::try_from(symbol).map_err(|_| FseError::TooManySymbols)?;
            for _ in 0..count.max(0) {
                symbol_at[position] = symbol_byte;
                loop {
                    position = (position + step) & mask;
                    if position < high {
                        break;
                    }
                }
            }
        }
        if position != 0 {
            return Err(FseError::BadProbabilitySum);
        }
        let table_size = u32::try_from(size).map_err(|_| FseError::AccuracyLogTooLarge)?;
        let mut cells = Vec::with_capacity(size);
        for &symbol in &symbol_at {
            let slot = next_state
                .get_mut(usize::from(symbol))
                .ok_or(FseError::BadProbabilitySum)?;
            let state = *slot;
            if state == 0 {
                return Err(FseError::BadProbabilitySum);
            }
            *slot += 1;
            let high_bit = u32::BITS - 1 - state.leading_zeros();
            let num_bits = u32::from(accuracy_log)
                .checked_sub(high_bit)
                .ok_or(FseError::BadProbabilitySum)?;
            let baseline = (state << num_bits)
                .checked_sub(table_size)
                .ok_or(FseError::BadProbabilitySum)?;
            cells.push(Cell {
                symbol,
                num_bits: u8::try_from(num_bits).map_err(|_| FseError::BadProbabilitySum)?,
                baseline: u16::try_from(baseline).map_err(|_| FseError::BadProbabilitySum)?,
            });
        }
        Ok(Self {
            accuracy_log,
            cells,
        })
    }

    /// The one-cell table of RLE mode: every state decodes `symbol` and
    /// reads no bits.
    pub fn rle(symbol: u8) -> Self {
        Self {
            accuracy_log: 0,
            cells: vec![Cell {
                symbol,
                num_bits: 0,
                baseline: 0,
            }],
        }
    }

    /// The table's accuracy log.
    pub const fn accuracy_log(&self) -> u8 {
        self.accuracy_log
    }

    /// All cells, indexed by state.
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// The cell of `state`. A state never exceeds the table size, because
    /// it is always built from `accuracy_log` bits or a cell's baseline.
    pub fn cell(&self, state: usize) -> Cell {
        self.cells.get(state).copied().unwrap_or_default()
    }

    /// Reads the initial state: `accuracy_log` bits.
    pub fn initial_state(&self, reader: &mut BackwardBitReader<'_>) -> usize {
        usize::try_from(reader.read_bits(u32::from(self.accuracy_log))).unwrap_or(0)
    }

    /// The state after `state`: its baseline plus `num_bits` bits.
    pub fn next_state(&self, state: usize, reader: &mut BackwardBitReader<'_>) -> usize {
        let cell = self.cell(state);
        usize::from(cell.baseline)
            + usize::try_from(reader.read_bits(u32::from(cell.num_bits))).unwrap_or(0)
    }
}

/// Scales `counts` to a distribution over `1 << log` cells. Every present
/// symbol keeps at least one cell; the rounding error is taken from, or given
/// to, the first most probable symbol. `None` when no symbol is present or
/// the table has too few cells for the alphabet.
pub fn normalize(counts: &[u32], log: u8) -> Option<Vec<i16>> {
    let size = 1_i64 << log;
    let total: i64 = counts.iter().map(|&count| i64::from(count)).sum();
    if total == 0 {
        return None;
    }
    let mut norm: Vec<i64> = counts
        .iter()
        .map(|&count| {
            if count == 0 {
                0
            } else {
                (i64::from(count) * size / total).max(1)
            }
        })
        .collect();
    let mut diff = size - norm.iter().sum::<i64>();
    while diff < 0 {
        let most = first_max_index(&norm)?;
        let take = (-diff).min(norm[most] - 1);
        if take <= 0 {
            return None;
        }
        norm[most] -= take;
        diff += take;
    }
    if diff > 0 {
        let most = first_max_index(&norm)?;
        norm[most] += diff;
    }
    norm.into_iter()
        .map(|value| i16::try_from(value).ok())
        .collect()
}

/// The first index of the largest value.
fn first_max_index(values: &[i64]) -> Option<usize> {
    let mut best: Option<(usize, i64)> = None;
    for (index, &value) in values.iter().enumerate() {
        if best.is_none_or(|(_, top)| value > top) {
            best = Some((index, value));
        }
    }
    best.map(|(index, _)| index)
}

/// Writes the FSE table description (RFC 8878 §4.1.1) of `norm`, the inverse
/// of [`read_table_description`], bit for bit as libzstd's `FSE_writeNCount`.
pub fn write_table_description(norm: &[i16], log: u8) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.add(u64::from(log.saturating_sub(5)), 4);
    let Some(last) = norm.iter().rposition(|&count| count != 0) else {
        return writer.into_bytes();
    };
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut num_bits = u32::from(log) + 1;
    let mut symbol = 0_usize;
    let mut previous_zero = false;
    while symbol <= last && remaining > 1 {
        if previous_zero {
            // A run of zeros: 2-bit repeat flags, 3 meaning "three more".
            let mut start = symbol;
            while symbol <= last && norm[symbol] == 0 {
                symbol += 1;
            }
            while symbol >= start + 3 {
                start += 3;
                writer.add(3, 2);
            }
            writer.add(u64::try_from(symbol - start).unwrap_or(0), 2);
        }
        let count = i32::from(norm[symbol]);
        symbol += 1;
        let max_small = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        let mut value = count + 1;
        if value >= threshold {
            value += max_small;
        }
        writer.add(
            u64::try_from(value).unwrap_or(0),
            num_bits - u32::from(value < max_small),
        );
        previous_zero = value == 1;
        while remaining < threshold && num_bits > 1 {
            num_bits -= 1;
            threshold >>= 1;
        }
    }
    debug_assert_eq!(remaining, 1, "a distribution must fill its table");
    writer.into_bytes()
}

/// A tANS encoding table for one normalized distribution: the encoder side
/// of [`DecodeTable`], built as libzstd's `FSE_buildCTable`. A stream encoded
/// with it decodes with the [`DecodeTable`] of the same distribution.
#[derive(Clone, Debug)]
pub struct EncodeTable {
    accuracy_log: u8,
    /// The state that follows each cumulative slot: `size + cell`.
    state_table: Vec<usize>,
    /// Per symbol: (delta number of bits, delta to its first slot).
    transforms: Vec<(i64, i64)>,
}

impl EncodeTable {
    /// The table for `norm` (−1 meaning "less than 1"), which must sum to
    /// `1 << accuracy_log`.
    pub fn new(norm: &[i16], accuracy_log: u8) -> Self {
        let size = 1_usize << accuracy_log;
        let mask = size - 1;
        // Cells above `high` hold the "less than 1" symbols, from the end.
        let mut high = mask;
        let mut cumulative = vec![0_usize; norm.len() + 1];
        let mut symbol_at = vec![0_usize; size];
        for (symbol, &count) in norm.iter().enumerate() {
            let cells = if count == -1 {
                symbol_at[high] = symbol;
                high = high.saturating_sub(1);
                1
            } else {
                usize::try_from(count).unwrap_or(0)
            };
            cumulative[symbol + 1] = cumulative[symbol] + cells;
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mut position = 0_usize;
        for (symbol, &count) in norm.iter().enumerate() {
            for _ in 0..count.max(0) {
                symbol_at[position] = symbol;
                position = (position + step) & mask;
                while position > high {
                    position = (position + step) & mask;
                }
            }
        }
        debug_assert_eq!(position, 0, "a distribution must fill its table");
        let mut next = cumulative;
        let mut state_table = vec![0_usize; size];
        for (cell, &symbol) in symbol_at.iter().enumerate() {
            state_table[next[symbol]] = size + cell;
            next[symbol] += 1;
        }
        let log = i64::from(accuracy_log);
        let table_size = to_i64(size);
        let mut total = 0_i64;
        let transforms = norm
            .iter()
            .map(|&count| match count {
                0 => (((log + 1) << 16) - table_size, 0),
                -1 | 1 => {
                    let transform = ((log << 16) - table_size, total - 1);
                    total += 1;
                    transform
                }
                _ => {
                    let count = i64::from(count);
                    let max_bits_out = log - i64::from((count - 1).max(1).ilog2());
                    let min_state_plus = count << max_bits_out;
                    let transform = ((max_bits_out << 16) - min_state_plus, total - count);
                    total += count;
                    transform
                }
            })
            .collect();
        Self {
            accuracy_log,
            state_table,
            transforms,
        }
    }

    /// The table's accuracy log.
    pub const fn accuracy_log(&self) -> u8 {
        self.accuracy_log
    }

    fn state_at(&self, index: i64) -> usize {
        let state = usize::try_from(index)
            .ok()
            .and_then(|index| self.state_table.get(index).copied());
        debug_assert!(state.is_some(), "state index {index} outside the table");
        state.unwrap_or(0)
    }

    fn transform(&self, symbol: u8) -> (i64, i64) {
        let transform = self.transforms.get(usize::from(symbol)).copied();
        debug_assert!(transform.is_some(), "symbol {symbol} outside the alphabet");
        transform.unwrap_or((0, 0))
    }

    /// The first state of a stream whose last symbol is `symbol`; it costs
    /// no bits.
    pub fn initial_state(&self, symbol: u8) -> usize {
        let (delta_bits, delta_find) = self.transform(symbol);
        let num_bits = (delta_bits + (1 << 15)) >> 16;
        let value = (num_bits << 16) - delta_bits;
        let shift = u32::try_from(num_bits).unwrap_or(0);
        self.state_at((value >> shift) + delta_find)
    }

    /// Writes the bits that lead from `symbol` back to `state` and returns
    /// the state that decodes `symbol`.
    pub fn encode(&self, state: usize, symbol: u8, writer: &mut BitWriter) -> usize {
        let (delta_bits, delta_find) = self.transform(symbol);
        let current = to_i64(state);
        let bits = u32::try_from((current + delta_bits) >> 16).unwrap_or(0);
        let value = u64::try_from(state).unwrap_or(0) & ((1_u64 << bits) - 1);
        writer.add(value, bits);
        self.state_at((current >> bits) + delta_find)
    }

    /// Writes the final state, which the decoder reads first.
    pub fn flush(&self, state: usize, writer: &mut BitWriter) {
        let bits = u32::from(self.accuracy_log);
        writer.add(
            u64::try_from(state).unwrap_or(0) & ((1_u64 << bits) - 1),
            bits,
        );
    }
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Cell, DecodeTable, EncodeTable, FseError, LITERALS_LENGTH_DEFAULT,
        LITERALS_LENGTH_DEFAULT_LOG, MATCH_LENGTH_DEFAULT, MATCH_LENGTH_DEFAULT_LOG,
        OFFSET_DEFAULT, OFFSET_DEFAULT_LOG, normalize, read_table_description,
        write_table_description,
    };
    use crate::bitio::{BackwardBitReader, BitWriter};

    const APPENDIX_A: &str = include_str!("../tests/vectors/rfc8878_appendix_a.txt");
    const LIBZSTD_DESCRIPTIONS: &str =
        include_str!("../tests/vectors/fse_table_descriptions_libzstd.txt");

    fn appendix_table(name: &str) -> (u8, Vec<Cell>) {
        let mut log = None;
        let mut cells = Vec::new();
        let mut inside = false;
        for line in APPENDIX_A.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.first() == Some(&"table") {
                inside = fields.get(1) == Some(&name);
                if inside {
                    log = fields.get(2).and_then(|value| value.parse().ok());
                }
                continue;
            }
            if inside {
                let numbers: Vec<u16> = fields.iter().map(|field| field.parse().unwrap()).collect();
                assert_eq!(usize::from(numbers[0]), cells.len(), "states are in order");
                cells.push(Cell {
                    symbol: u8::try_from(numbers[1]).unwrap(),
                    num_bits: u8::try_from(numbers[2]).unwrap(),
                    baseline: numbers[3],
                });
            }
        }
        (log.expect("table present"), cells)
    }

    #[test]
    fn predefined_tables_match_rfc_8878_appendix_a() {
        for (name, counts, log) in [
            (
                "literals_length",
                &LITERALS_LENGTH_DEFAULT[..],
                LITERALS_LENGTH_DEFAULT_LOG,
            ),
            (
                "match_length",
                &MATCH_LENGTH_DEFAULT[..],
                MATCH_LENGTH_DEFAULT_LOG,
            ),
            ("offset", &OFFSET_DEFAULT[..], OFFSET_DEFAULT_LOG),
        ] {
            let (expected_log, expected) = appendix_table(name);
            assert_eq!(expected_log, log, "{name}");
            assert_eq!(expected.len(), 1 << log, "{name}: appendix rows");
            let table = DecodeTable::new(counts, log).unwrap();
            assert_eq!(table.cells(), &expected[..], "{name}");
        }
    }

    #[test]
    fn reads_every_libzstd_table_description() {
        let mut seen = 0;
        for line in LIBZSTD_DESCRIPTIONS
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let (head, counts) = line.split_once(" | ").unwrap();
            let fields: Vec<&str> = head.split_whitespace().collect();
            let log: u8 = fields[0].parse().unwrap();
            let max_symbol: usize = fields[1].parse().unwrap();
            let used: usize = fields[2].parse().unwrap();
            let bytes: Vec<u8> = (0..fields[3].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).unwrap())
                .collect();
            let expected: Vec<i16> = counts
                .split_whitespace()
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(expected.len(), max_symbol + 1);
            // Trailing bytes after the description must be ignored.
            let mut input = bytes.clone();
            input.extend_from_slice(&[0xA5, 0x5A, 0xFF]);
            let (got_log, got, got_used) = read_table_description(&input, 9, 256).unwrap();
            assert_eq!((got_log, &got, got_used), (log, &expected, used), "{line}");
            DecodeTable::new(&got, got_log).unwrap();
            seen += 1;
        }
        assert_eq!(seen, 63, "the oracle file must keep all 63 vectors");
    }

    #[test]
    fn rejects_oversized_logs_truncation_and_bad_sums() {
        // Accuracy log 5 + 15 = 20 exceeds every limit.
        assert_eq!(
            read_table_description(&[0x0F, 0x00], 9, 256).err(),
            Some(FseError::AccuracyLogTooLarge)
        );
        // A real description cut short.
        let line = LIBZSTD_DESCRIPTIONS
            .lines()
            .find(|line| !line.starts_with('#'))
            .unwrap();
        let hex = line.split_whitespace().nth(3).unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert!(read_table_description(&bytes[..bytes.len() / 2], 9, 256).is_err());
        // Distributions that do not sum to the table size.
        assert_eq!(
            DecodeTable::new(&[1, 1], 5).err(),
            Some(FseError::BadProbabilitySum)
        );
        assert_eq!(
            DecodeTable::new(&[33, -1], 5).err(),
            Some(FseError::BadProbabilitySum)
        );
        assert_eq!(
            DecodeTable::new(&[-2, 34], 5).err(),
            Some(FseError::BadProbabilitySum)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for _ in 0..5_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = usize::try_from(state >> 58).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|i| (state >> ((i % 8) * 8)).to_le_bytes()[0] ^ u8::try_from(i % 251).unwrap())
                .collect();
            if let Ok((log, counts, used)) = read_table_description(&bytes, 9, 64) {
                assert!(used <= bytes.len());
                assert!(counts.len() <= 64);
                let _ = DecodeTable::new(&counts, log);
            }
        }
    }

    /// The description file holds libzstd's own `FSE_writeNCount` output for
    /// each distribution, so the writer must reproduce every byte.
    #[test]
    fn writes_every_libzstd_table_description_byte_for_byte() {
        let mut seen = 0;
        for line in LIBZSTD_DESCRIPTIONS
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let (head, counts) = line.split_once(" | ").unwrap();
            let fields: Vec<&str> = head.split_whitespace().collect();
            let log: u8 = fields[0].parse().unwrap();
            let expected: Vec<u8> = (0..fields[3].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).unwrap())
                .collect();
            let norm: Vec<i16> = counts
                .split_whitespace()
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(write_table_description(&norm, log), expected, "{line}");
            seen += 1;
        }
        assert_eq!(seen, 63);
    }

    fn lcg(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 11
        }
    }

    /// Encodes `symbols` the way zstd does (the last symbol starts the state,
    /// the first one is flushed last) and decodes them with the decoding table
    /// of the same distribution.
    fn round_trip(norm: &[i16], log: u8, symbols: &[u8]) {
        let encoder = EncodeTable::new(norm, log);
        let decoder = DecodeTable::new(norm, log).unwrap();
        let mut writer = BitWriter::new();
        let (&last, rest) = symbols.split_last().unwrap();
        let mut state = encoder.initial_state(last);
        for &symbol in rest.iter().rev() {
            state = encoder.encode(state, symbol, &mut writer);
        }
        encoder.flush(state, &mut writer);
        let stream = writer.finish();
        let mut reader = BackwardBitReader::new(&stream).unwrap();
        let mut state = decoder.initial_state(&mut reader);
        for (index, &symbol) in symbols.iter().enumerate() {
            assert_eq!(decoder.cell(state).symbol, symbol, "symbol {index}");
            if index + 1 < symbols.len() {
                state = decoder.next_state(state, &mut reader);
            }
        }
        assert!(reader.is_exhausted(), "every encoded bit is read back");
    }

    #[test]
    fn encoded_streams_decode_with_the_matching_table() {
        let mut next = lcg(5);
        for (norm, log) in [
            (&LITERALS_LENGTH_DEFAULT[..], LITERALS_LENGTH_DEFAULT_LOG),
            (&MATCH_LENGTH_DEFAULT[..], MATCH_LENGTH_DEFAULT_LOG),
            (&OFFSET_DEFAULT[..], OFFSET_DEFAULT_LOG),
        ] {
            let symbols: Vec<u8> = (0..500)
                .map(|_| u8::try_from(next() % u64::try_from(norm.len()).unwrap()).unwrap())
                .collect();
            round_trip(norm, log, &symbols);
        }
        for case in 0..200 {
            let alphabet = 2 + usize::try_from(next() % 50).unwrap();
            let log = 5 + u8::try_from(next() % 5).unwrap();
            let counts: Vec<u32> = (0..alphabet)
                .map(|_| {
                    if next().is_multiple_of(4) {
                        0
                    } else {
                        u32::try_from(next() % 1000).unwrap()
                    }
                })
                .collect();
            let Some(norm) = normalize(&counts, log) else {
                continue;
            };
            assert_eq!(
                norm.iter().map(|&count| i32::from(count)).sum::<i32>(),
                1 << log,
                "case {case}"
            );
            for (count, normalized) in counts.iter().zip(&norm) {
                assert_eq!(*count == 0, *normalized == 0, "case {case}");
            }
            let present: Vec<u8> = (0..alphabet)
                .filter(|&symbol| counts[symbol] > 0)
                .map(|symbol| u8::try_from(symbol).unwrap())
                .collect();
            let symbols: Vec<u8> = (0..=next() % 300)
                .map(|_| present[usize::try_from(next()).unwrap() % present.len()])
                .collect();
            round_trip(&norm, log, &symbols);
            let description = write_table_description(&norm, log);
            let mut padded = description.clone();
            padded.push(0xFF);
            let trailing_zeros = norm.iter().rev().take_while(|&&count| count == 0).count();
            assert_eq!(
                read_table_description(&padded, 9, 64),
                Ok((
                    log,
                    norm[..norm.len() - trailing_zeros].to_vec(),
                    description.len()
                )),
                "case {case}"
            );
        }
    }

    #[test]
    fn normalize_refuses_impossible_tables() {
        assert_eq!(normalize(&[0, 0, 0], 5), None);
        assert_eq!(
            normalize(&[1; 40], 5),
            None,
            "40 symbols cannot share 32 cells"
        );
        assert_eq!(normalize(&[1; 32], 5), Some(vec![1; 32]));
        assert_eq!(normalize(&[3, 1], 5), Some(vec![24, 8]));
    }

    #[test]
    fn rle_table_reads_no_bits() {
        let table = DecodeTable::rle(7);
        assert_eq!(table.accuracy_log(), 0);
        assert_eq!(
            table.cell(0),
            Cell {
                symbol: 7,
                num_bits: 0,
                baseline: 0
            }
        );
    }
}
