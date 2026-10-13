//! The sequences section of a compressed block and its execution,
//! RFC 8878 §3.1.1.3.2 and §3.1.1.4-3.1.1.5.

use crate::bitio::BackwardBitReader;
use crate::frame::DecodeError;
use crate::fse::{
    DecodeTable, LITERALS_LENGTH_DEFAULT, LITERALS_LENGTH_DEFAULT_LOG, MATCH_LENGTH_DEFAULT,
    MATCH_LENGTH_DEFAULT_LOG, OFFSET_DEFAULT, OFFSET_DEFAULT_LOG, read_table_description,
};

/// The largest output one block may produce (Block_Maximum_Size).
pub const MAX_BLOCK_OUTPUT: usize = 128 * 1024;

/// (baseline, extra bits) per literals-length code, RFC 8878 Table 16.
const LITERALS_LENGTH_CODES: [(u32, u8); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];

/// (baseline, extra bits) per match-length code, RFC 8878 Table 17.
const MATCH_LENGTH_CODES: [(u32, u8); 53] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 0),
    (17, 0),
    (18, 0),
    (19, 0),
    (20, 0),
    (21, 0),
    (22, 0),
    (23, 0),
    (24, 0),
    (25, 0),
    (26, 0),
    (27, 0),
    (28, 0),
    (29, 0),
    (30, 0),
    (31, 0),
    (32, 0),
    (33, 0),
    (34, 0),
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

/// The largest offset code: 31 extra bits reach any window this decoder
/// accepts.
const MAX_OFFSET_CODE: u8 = 31;

/// Per-frame sequence decoding state: the previous block's tables (for
/// Repeat mode), the predefined tables, and the repeat-offset history.
pub struct SequenceState {
    previous: [Option<DecodeTable>; 3],
    predefined: [DecodeTable; 3],
    repeat_offsets: [usize; 3],
}

const LITERALS_LENGTH: usize = 0;
const OFFSET: usize = 1;
const MATCH_LENGTH: usize = 2;

impl SequenceState {
    /// The state at the start of a frame (repeat offsets 1, 4, 8).
    pub fn new() -> Result<Self, DecodeError> {
        let predefined = |counts: &[i16], log| {
            DecodeTable::new(counts, log).map_err(|_| DecodeError::Malformed("predefined table"))
        };
        Ok(Self {
            previous: [None, None, None],
            predefined: [
                predefined(&LITERALS_LENGTH_DEFAULT, LITERALS_LENGTH_DEFAULT_LOG)?,
                predefined(&OFFSET_DEFAULT, OFFSET_DEFAULT_LOG)?,
                predefined(&MATCH_LENGTH_DEFAULT, MATCH_LENGTH_DEFAULT_LOG)?,
            ],
            repeat_offsets: [1, 4, 8],
        })
    }

    /// Selects the table of one symbol type from its compression mode,
    /// reading any description from `section` at `pos`.
    fn table(
        &mut self,
        kind: usize,
        mode: u8,
        section: &[u8],
        pos: &mut usize,
    ) -> Result<DecodeTable, DecodeError> {
        let (max_log, max_symbols) = match kind {
            LITERALS_LENGTH => (9, LITERALS_LENGTH_CODES.len()),
            OFFSET => (8, usize::from(MAX_OFFSET_CODE) + 1),
            _ => (9, MATCH_LENGTH_CODES.len()),
        };
        let table = match mode {
            0 => self.predefined[kind].clone(),
            1 => {
                let symbol = *section.get(*pos).ok_or(DecodeError::Truncated)?;
                if usize::from(symbol) >= max_symbols {
                    return Err(DecodeError::Malformed("RLE sequence symbol out of range"));
                }
                *pos += 1;
                DecodeTable::rle(symbol)
            }
            2 => {
                let rest = section.get(*pos..).ok_or(DecodeError::Truncated)?;
                let (log, counts, used) = read_table_description(rest, max_log, max_symbols)
                    .map_err(|_| DecodeError::Malformed("sequence FSE table description"))?;
                *pos += used;
                DecodeTable::new(&counts, log)
                    .map_err(|_| DecodeError::Malformed("sequence FSE distribution"))?
            }
            _ => self.previous[kind].clone().ok_or(DecodeError::Malformed(
                "Repeat mode without a previous table",
            ))?,
        };
        self.previous[kind] = Some(table.clone());
        Ok(table)
    }

    /// Resolves an offset value against the repeat-offset history and
    /// updates the history (RFC 8878 §3.1.1.5).
    fn resolve_offset(
        &mut self,
        offset_value: u64,
        literals_length: u64,
    ) -> Result<usize, DecodeError> {
        let rep = &mut self.repeat_offsets;
        if offset_value > 3 {
            let offset =
                usize::try_from(offset_value - 3).map_err(|_| DecodeError::Malformed("offset"))?;
            *rep = [offset, rep[0], rep[1]];
            return Ok(offset);
        }
        let index = usize::try_from(offset_value).map_err(|_| DecodeError::Malformed("offset"))?
            - 1
            + usize::from(literals_length == 0);
        if index == 0 {
            return Ok(rep[0]);
        }
        let offset = if index == 3 {
            rep[0].saturating_sub(1)
        } else {
            rep[index]
        };
        if offset == 0 {
            return Err(DecodeError::Malformed("zero offset"));
        }
        *rep = if index == 1 {
            [offset, rep[0], rep[2]]
        } else {
            [offset, rep[0], rep[1]]
        };
        Ok(offset)
    }
}

fn reserve(out: &[u8], extra: usize, max_output: usize) -> Result<(), DecodeError> {
    match out.len().checked_add(extra) {
        Some(total) if total <= max_output => Ok(()),
        _ => Err(DecodeError::OutputTooLarge),
    }
}

/// Appends `length` bytes copied from `offset` bytes back, where source and
/// destination may overlap (offset < length repeats a pattern).
fn copy_match(out: &mut Vec<u8>, offset: usize, length: usize) {
    let mut source = out.len() - offset;
    let mut remaining = length;
    while remaining > 0 {
        let chunk = remaining.min(out.len() - source);
        out.extend_from_within(source..source + chunk);
        source += chunk;
        remaining -= chunk;
    }
}

/// Decodes the sequences section `section` and executes it against
/// `literals`, appending the block's output to `out`. History for matches is
/// `out[frame_start..]`, limited to `window` bytes.
pub fn decode_sequences(
    section: &[u8],
    literals: &[u8],
    state: &mut SequenceState,
    out: &mut Vec<u8>,
    frame_start: usize,
    window: usize,
    max_output: usize,
) -> Result<(), DecodeError> {
    let block_start = out.len();
    let first = *section.first().ok_or(DecodeError::Truncated)?;
    let (count, mut pos) = match first {
        0 => (0_usize, 1),
        1..=127 => (usize::from(first), 1),
        128..=254 => {
            let second = *section.get(1).ok_or(DecodeError::Truncated)?;
            ((usize::from(first - 128) << 8) + usize::from(second), 2)
        }
        255 => {
            let low = *section.get(1).ok_or(DecodeError::Truncated)?;
            let high = *section.get(2).ok_or(DecodeError::Truncated)?;
            (usize::from(u16::from_le_bytes([low, high])) + 0x7F00, 3)
        }
    };
    if count == 0 {
        if pos != section.len() {
            return Err(DecodeError::Malformed(
                "bytes after an empty sequences section",
            ));
        }
        reserve(out, literals.len(), max_output)?;
        out.extend_from_slice(literals);
        return Ok(());
    }
    let modes = *section.get(pos).ok_or(DecodeError::Truncated)?;
    pos += 1;
    if modes & 3 != 0 {
        return Err(DecodeError::Malformed("reserved sequence mode bits"));
    }
    let literals_length_table = state.table(LITERALS_LENGTH, modes >> 6, section, &mut pos)?;
    let offset_table = state.table(OFFSET, (modes >> 4) & 3, section, &mut pos)?;
    let match_length_table = state.table(MATCH_LENGTH, (modes >> 2) & 3, section, &mut pos)?;
    let stream = section.get(pos..).ok_or(DecodeError::Truncated)?;
    let mut reader = BackwardBitReader::new(stream)
        .map_err(|_| DecodeError::Malformed("sequence bitstream end mark"))?;
    let mut literals_length_state = literals_length_table.initial_state(&mut reader);
    let mut offset_state = offset_table.initial_state(&mut reader);
    let mut match_length_state = match_length_table.initial_state(&mut reader);
    let mut literal_pos = 0_usize;
    for index in 0..count {
        let offset_code = offset_table.cell(offset_state).symbol;
        let match_code = usize::from(match_length_table.cell(match_length_state).symbol);
        let literal_code = usize::from(literals_length_table.cell(literals_length_state).symbol);
        if offset_code > MAX_OFFSET_CODE {
            return Err(DecodeError::Malformed("offset code out of range"));
        }
        let &(match_base, match_bits) = MATCH_LENGTH_CODES
            .get(match_code)
            .ok_or(DecodeError::Malformed("match length code out of range"))?;
        let &(literal_base, literal_bits) = LITERALS_LENGTH_CODES
            .get(literal_code)
            .ok_or(DecodeError::Malformed("literals length code out of range"))?;
        // Extra bits are read offset, match length, literals length.
        let offset_value = (1_u64 << offset_code) + reader.read_bits(u32::from(offset_code));
        let match_length = u64::from(match_base) + reader.read_bits(u32::from(match_bits));
        let literals_length = u64::from(literal_base) + reader.read_bits(u32::from(literal_bits));
        let offset = state.resolve_offset(offset_value, literals_length)?;

        let literals_length = usize::try_from(literals_length)
            .map_err(|_| DecodeError::Malformed("literals length"))?;
        let literal_end = literal_pos
            .checked_add(literals_length)
            .filter(|&end| end <= literals.len())
            .ok_or(DecodeError::Malformed("sequence reads past the literals"))?;
        reserve(out, literals_length, max_output)?;
        out.extend_from_slice(&literals[literal_pos..literal_end]);
        literal_pos = literal_end;

        let match_length =
            usize::try_from(match_length).map_err(|_| DecodeError::Malformed("match length"))?;
        let history = out.len() - frame_start;
        if offset == 0 || offset > history || offset > window {
            return Err(DecodeError::Malformed(
                "offset beyond the available history",
            ));
        }
        reserve(out, match_length, max_output)?;
        if out.len() + match_length - block_start > MAX_BLOCK_OUTPUT {
            return Err(DecodeError::Malformed("block output exceeds 128 KiB"));
        }
        copy_match(out, offset, match_length);

        if index + 1 < count {
            // States update literals length, match length, then offset.
            literals_length_state =
                literals_length_table.next_state(literals_length_state, &mut reader);
            match_length_state = match_length_table.next_state(match_length_state, &mut reader);
            offset_state = offset_table.next_state(offset_state, &mut reader);
        }
    }
    if !reader.is_exhausted() {
        return Err(DecodeError::Malformed(
            "sequence bitstream not exactly consumed",
        ));
    }
    let rest = literals.get(literal_pos..).unwrap_or(&[]);
    reserve(out, rest.len(), max_output)?;
    out.extend_from_slice(rest);
    if out.len() - block_start > MAX_BLOCK_OUTPUT {
        return Err(DecodeError::Malformed("block output exceeds 128 KiB"));
    }
    Ok(())
}
