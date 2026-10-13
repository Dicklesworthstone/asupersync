//! FSE (finite state entropy) decoding tables, RFC 8878 §4.1.

// The sequences decoder (br-asupersync-t1fblr.8) is the consumer; until it
// lands these tables are exercised only by their tests.
#![allow(
    dead_code,
    reason = "consumed by the zstd sequences decoder, br-asupersync-t1fblr.8"
)]

use crate::bitio::{BackwardBitReader, extract};

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

#[cfg(test)]
mod tests {
    use super::{
        Cell, DecodeTable, FseError, LITERALS_LENGTH_DEFAULT, LITERALS_LENGTH_DEFAULT_LOG,
        MATCH_LENGTH_DEFAULT, MATCH_LENGTH_DEFAULT_LOG, OFFSET_DEFAULT, OFFSET_DEFAULT_LOG,
        read_table_description,
    };

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
