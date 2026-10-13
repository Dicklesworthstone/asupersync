//! The sequences section of a compressed block and its execution,
//! RFC 8878 §3.1.1.3.2 and §3.1.1.4-3.1.1.5.

use crate::bitio::{BackwardBitReader, BitWriter};
use crate::frame::DecodeError;
use crate::fse::{
    DecodeTable, EncodeTable, LITERALS_LENGTH_DEFAULT, LITERALS_LENGTH_DEFAULT_LOG,
    MATCH_LENGTH_DEFAULT, MATCH_LENGTH_DEFAULT_LOG, OFFSET_DEFAULT, OFFSET_DEFAULT_LOG, normalize,
    read_table_description, write_table_description,
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

/// One sequence as the encoder writes it: `literals_length` literals, then a
/// match of `match_length` bytes. `offset_value` is the RFC 8878 offset value
/// (1-3 name a repeat offset, a new offset `d` is `d + 3`; see
/// [`offset_value`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedSequence {
    /// Literals copied before the match.
    pub literals_length: u32,
    /// The offset value, at least 1.
    pub offset_value: u32,
    /// Bytes the match copies, at least 3.
    pub match_length: u32,
}

/// The offset value that makes the decoder resolve `offset`, given the
/// repeat-offset history `rep`, and the history after the sequence: the
/// inverse of the decoder's repeat-offset rules (RFC 8878 §3.1.1.5).
pub fn offset_value(offset: usize, literals_length: usize, rep: [usize; 3]) -> (usize, [usize; 3]) {
    let candidates = if literals_length > 0 {
        rep
    } else {
        [rep[1], rep[2], rep[0].saturating_sub(1)]
    };
    for (index, &candidate) in candidates.iter().enumerate() {
        if candidate == offset && candidate > 0 {
            let slot = index + usize::from(literals_length == 0);
            let next = match slot {
                0 => rep,
                1 => [offset, rep[0], rep[2]],
                _ => [offset, rep[0], rep[1]],
            };
            return (index + 1, next);
        }
    }
    (offset + 3, [offset, rep[0], rep[1]])
}

/// Writes `value` minus the baseline of `code` in the code's extra bits.
fn add_extra_bits(writer: &mut BitWriter, codes: &[(u32, u8)], code: u8, value: u32) -> Option<()> {
    let &(baseline, bits) = codes.get(usize::from(code))?;
    writer.add(u64::from(value.checked_sub(baseline)?), u32::from(bits));
    Some(())
}

/// The code whose baseline is the largest one not above `value`.
fn code_for(codes: &[(u32, u8)], value: u32) -> u8 {
    let index = codes
        .partition_point(|&(baseline, _)| baseline <= value)
        .saturating_sub(1);
    u8::try_from(index).unwrap_or(u8::MAX)
}

/// The coding limits of one symbol type.
struct SymbolKind {
    alphabet: usize,
    max_log: u8,
    predefined: &'static [i16],
    predefined_log: u8,
}

const LITERALS_LENGTH_KIND: SymbolKind = SymbolKind {
    alphabet: LITERALS_LENGTH_CODES.len(),
    max_log: 9,
    predefined: &LITERALS_LENGTH_DEFAULT,
    predefined_log: LITERALS_LENGTH_DEFAULT_LOG,
};

const OFFSET_KIND: SymbolKind = SymbolKind {
    // Offset codes 0..=MAX_OFFSET_CODE.
    alphabet: 32,
    max_log: 8,
    predefined: &OFFSET_DEFAULT,
    predefined_log: OFFSET_DEFAULT_LOG,
};

const MATCH_LENGTH_KIND: SymbolKind = SymbolKind {
    alphabet: MATCH_LENGTH_CODES.len(),
    max_log: 9,
    predefined: &MATCH_LENGTH_DEFAULT,
    predefined_log: MATCH_LENGTH_DEFAULT_LOG,
};

/// How one symbol type is coded in a block.
enum SymbolTable {
    /// RLE mode: one symbol, no state and no bits.
    Rle,
    /// Predefined or FSE_Compressed mode.
    Fse(EncodeTable),
}

impl SymbolTable {
    fn initial_state(&self, symbol: u8) -> usize {
        match self {
            Self::Rle => 0,
            Self::Fse(table) => table.initial_state(symbol),
        }
    }

    fn encode(&self, state: usize, symbol: u8, writer: &mut BitWriter) -> usize {
        match self {
            Self::Rle => 0,
            Self::Fse(table) => table.encode(state, symbol, writer),
        }
    }

    fn flush(&self, state: usize, writer: &mut BitWriter) {
        if let Self::Fse(table) = self {
            table.flush(state, writer);
        }
    }
}

/// The accuracy log for a table of `distinct` symbols coding `count` codes.
fn pick_log(distinct: usize, count: usize, max_log: u8) -> u8 {
    let bits = u8::try_from(count.max(1).bit_width()).unwrap_or(u8::MAX);
    let mut log = bits.saturating_add(1).min(max_log).max(5);
    while (1_usize << log) < distinct && log < max_log {
        log += 1;
    }
    log
}

/// Chooses the compression mode for one symbol type: RLE for a single
/// symbol, otherwise the predefined table unless a described table costs
/// fewer bits (description included). Costs are whole bits per symbol, an
/// integer estimate that keeps the choice deterministic. Returns the mode,
/// the table description to write, and the table.
fn choose_table(kind: &SymbolKind, codes: &[u8]) -> Option<(u8, Vec<u8>, SymbolTable)> {
    let &first = codes.first()?;
    if codes.iter().all(|&code| code == first) {
        return Some((1, vec![first], SymbolTable::Rle));
    }
    let mut counts = vec![0_u32; kind.alphabet];
    for &code in codes {
        *counts.get_mut(usize::from(code))? += 1;
    }
    let present = || counts.iter().enumerate().filter(|&(_, &count)| count > 0);
    // Bits a state of a symbol with `cells` of `1 << log` cells costs.
    let cost = |count: u32, log: u8, cells: i16| {
        i64::from(count) * (i64::from(log) - i64::from(cells.unsigned_abs().max(1).ilog2()))
    };
    let predefined_cost: Option<i64> = present()
        .map(|(symbol, &count)| {
            let cells = *kind.predefined.get(symbol)?;
            (cells != 0).then(|| cost(count, kind.predefined_log, cells))
        })
        .sum();
    let log = pick_log(present().count(), codes.len(), kind.max_log);
    let norm = normalize(&counts, log)?;
    let description = write_table_description(&norm, log);
    let described_cost = 8 * i64::try_from(description.len()).ok()?
        + present()
            .map(|(symbol, &count)| cost(count, log, norm[symbol]))
            .sum::<i64>();
    if predefined_cost.is_some_and(|predefined| predefined <= described_cost) {
        let table = EncodeTable::new(kind.predefined, kind.predefined_log);
        return Some((0, Vec::new(), SymbolTable::Fse(table)));
    }
    Some((
        2,
        description,
        SymbolTable::Fse(EncodeTable::new(&norm, log)),
    ))
}

/// Appends the sequences section (RFC 8878 §3.1.1.3.2) for `sequences`.
/// `None` only when a sequence is outside what the format can express.
pub fn encode_sequences(sequences: &[EncodedSequence], out: &mut Vec<u8>) -> Option<()> {
    let count = sequences.len();
    match count {
        0..128 => out.push(u8::try_from(count).ok()?),
        128..0x7F00 => out.extend_from_slice(&[
            u8::try_from((count >> 8) + 128).ok()?,
            u8::try_from(count & 0xFF).ok()?,
        ]),
        _ => {
            out.push(255);
            out.extend_from_slice(&u16::try_from(count - 0x7F00).ok()?.to_le_bytes());
        }
    }
    let Some(last) = count.checked_sub(1) else {
        return Some(());
    };
    let literal_codes: Vec<u8> = sequences
        .iter()
        .map(|sequence| code_for(&LITERALS_LENGTH_CODES, sequence.literals_length))
        .collect();
    let match_codes: Vec<u8> = sequences
        .iter()
        .map(|sequence| code_for(&MATCH_LENGTH_CODES, sequence.match_length))
        .collect();
    let offset_codes = sequences
        .iter()
        .map(|sequence| u8::try_from(sequence.offset_value.checked_ilog2()?).ok())
        .collect::<Option<Vec<u8>>>()?;
    let (literal_mode, literal_description, literal_table) =
        choose_table(&LITERALS_LENGTH_KIND, &literal_codes)?;
    let (offset_mode, offset_description, offset_table) =
        choose_table(&OFFSET_KIND, &offset_codes)?;
    let (match_mode, match_description, match_table) =
        choose_table(&MATCH_LENGTH_KIND, &match_codes)?;
    out.push((literal_mode << 6) | (offset_mode << 4) | (match_mode << 2));
    out.extend_from_slice(&literal_description);
    out.extend_from_slice(&offset_description);
    out.extend_from_slice(&match_description);

    let mut writer = BitWriter::new();
    // Extra bits go literals length, match length, offset: the reverse of
    // the order the decoder reads them in.
    let write_extras = |writer: &mut BitWriter, index: usize| -> Option<()> {
        let sequence = sequences.get(index)?;
        add_extra_bits(
            writer,
            &LITERALS_LENGTH_CODES,
            literal_codes[index],
            sequence.literals_length,
        )?;
        add_extra_bits(
            writer,
            &MATCH_LENGTH_CODES,
            match_codes[index],
            sequence.match_length,
        )?;
        // An offset code is its value's bit count: the extra bits are the
        // value below its top bit.
        let bits = offset_codes[index];
        writer.add(
            u64::from(sequence.offset_value - (1 << bits)),
            u32::from(bits),
        );
        Some(())
    };
    let mut match_state = match_table.initial_state(match_codes[last]);
    let mut offset_state = offset_table.initial_state(offset_codes[last]);
    let mut literal_state = literal_table.initial_state(literal_codes[last]);
    write_extras(&mut writer, last)?;
    for index in (0..last).rev() {
        offset_state = offset_table.encode(offset_state, offset_codes[index], &mut writer);
        match_state = match_table.encode(match_state, match_codes[index], &mut writer);
        literal_state = literal_table.encode(literal_state, literal_codes[index], &mut writer);
        write_extras(&mut writer, index)?;
    }
    match_table.flush(match_state, &mut writer);
    offset_table.flush(offset_state, &mut writer);
    literal_table.flush(literal_state, &mut writer);
    out.extend_from_slice(&writer.finish());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::{
        EncodedSequence, LITERALS_LENGTH_CODES, MATCH_LENGTH_CODES, SequenceState, code_for,
        copy_match, decode_sequences, encode_sequences, offset_value,
    };
    use std::collections::BTreeSet;

    fn lcg(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 17
        }
    }

    #[test]
    fn length_codes_cover_their_ranges() {
        for codes in [&LITERALS_LENGTH_CODES[..], &MATCH_LENGTH_CODES[..]] {
            for (code, &(baseline, bits)) in codes.iter().enumerate() {
                let code = u8::try_from(code).unwrap();
                assert_eq!(code_for(codes, baseline), code);
                assert_eq!(code_for(codes, baseline + (1 << bits) - 1), code);
            }
        }
    }

    /// Every offset the encoder names resolves, through the decoder's own
    /// repeat-offset rules, to that offset with the same history afterwards.
    #[test]
    fn offset_values_invert_the_decoder_rules() {
        let mut next = lcg(3);
        let mut state = SequenceState::new().unwrap();
        let mut rep: [usize; 3] = [1, 4, 8];
        let mut kinds = BTreeSet::new();
        for step in 0..20_000 {
            let literals_length = usize::try_from(next() % 3).unwrap();
            let offset = match next() % 6 {
                0 => rep[0],
                1 => rep[1],
                2 => rep[2],
                3 => rep[0].saturating_sub(1).max(1),
                _ => 1 + usize::try_from(next() % 5_000).unwrap(),
            };
            let (value, next_rep) = offset_value(offset, literals_length, rep);
            kinds.insert(value.min(4));
            let resolved = state
                .resolve_offset(
                    u64::try_from(value).unwrap(),
                    u64::try_from(literals_length).unwrap(),
                )
                .unwrap();
            assert_eq!(resolved, offset, "step {step}");
            assert_eq!(state.repeat_offsets, next_rep, "step {step}");
            rep = next_rep;
        }
        assert_eq!(
            kinds,
            BTreeSet::from([1, 2, 3, 4]),
            "every offset value kind"
        );
    }

    /// Encodes random sequences over a history, decodes them with the
    /// decoder, and compares with executing the sequences directly.
    fn round_trip(sequences: &[(usize, usize, usize)], seed: u64) -> u8 {
        let mut next = lcg(seed);
        let history: Vec<u8> = (0..70_000).map(|_| next().to_le_bytes()[0]).collect();
        let total_literals: usize = sequences.iter().map(|&(literals, _, _)| literals).sum();
        let literals: Vec<u8> = (0..total_literals + 9)
            .map(|_| next().to_le_bytes()[0])
            .collect();
        let mut expected = history.clone();
        let mut encoded = Vec::new();
        let mut rep = [1, 4, 8];
        let mut literal_pos = 0;
        for &(literals_length, offset, match_length) in sequences {
            expected.extend_from_slice(&literals[literal_pos..literal_pos + literals_length]);
            literal_pos += literals_length;
            copy_match(&mut expected, offset, match_length);
            let (value, next_rep) = offset_value(offset, literals_length, rep);
            rep = next_rep;
            encoded.push(EncodedSequence {
                literals_length: u32::try_from(literals_length).unwrap(),
                offset_value: u32::try_from(value).unwrap(),
                match_length: u32::try_from(match_length).unwrap(),
            });
        }
        expected.extend_from_slice(&literals[literal_pos..]);
        let mut section = Vec::new();
        encode_sequences(&encoded, &mut section).unwrap();
        let mut state = SequenceState::new().unwrap();
        let mut out = history;
        decode_sequences(
            &section,
            &literals,
            &mut state,
            &mut out,
            0,
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(out, expected);
        // The modes byte follows the 1- or 2-byte sequence count.
        section[if sequences.len() < 128 { 1 } else { 2 }]
    }

    #[test]
    fn encoded_sequences_decode_in_every_mode() {
        let mut next = lcg(11);
        let mut modes = [BTreeSet::new(), BTreeSet::new(), BTreeSet::new()];
        let mut record = |byte: u8| {
            for (slot, shift) in modes.iter_mut().zip([6, 4, 2]) {
                slot.insert((byte >> shift) & 3);
            }
        };
        // One repeated shape: RLE for all three types (offset 1 is repeat
        // offset 1 from the start, so every offset value is 1).
        record(round_trip(&[(4, 1, 20); 50], 1));
        // A few varied sequences: the predefined tables are cheapest.
        let few: Vec<(usize, usize, usize)> =
            (0..6).map(|i| (i + 1, 100 + 37 * i, 3 + i)).collect();
        record(round_trip(&few, 2));
        // Many sequences, skewed lengths and long offsets: described tables.
        for case in 0..20_u64 {
            let count = 50 + usize::try_from(next() % 900).unwrap();
            let sequences: Vec<(usize, usize, usize)> = (0..count)
                .map(|_| {
                    let literals = usize::try_from(next() % 8).unwrap()
                        * usize::from(next().is_multiple_of(3));
                    let offset = 1 + usize::try_from(next() % 60_000).unwrap();
                    let length = 3
                        + usize::try_from(next().trailing_zeros()).unwrap()
                        + usize::try_from(next() % 4).unwrap();
                    (literals, offset, length)
                })
                .collect();
            record(round_trip(&sequences, 100 + case));
        }
        for (name, seen) in ["literals length", "offset", "match length"]
            .iter()
            .zip(&modes)
        {
            assert_eq!(seen, &BTreeSet::from([0, 1, 2]), "{name} modes");
        }
    }

    #[test]
    fn an_empty_section_is_one_zero_byte() {
        let mut section = Vec::new();
        encode_sequences(&[], &mut section).unwrap();
        assert_eq!(section, [0]);
    }
}
