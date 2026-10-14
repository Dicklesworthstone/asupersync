//! Bitstreams for Zstandard (RFC 8878 §4.1, §4.2).
//!
//! FSE and Huffman bitstreams are read backward: the last byte carries an end
//! mark (its highest set bit), and bits are consumed from the highest unread
//! position down toward bit 0 of the first byte. [`BitWriter`] writes them.

/// A malformed bitstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitError {
    /// The stream is empty or its last byte is zero, so it has no end mark.
    MissingEndMark,
}

/// The largest single read: with at most 7 bits of misalignment it still
/// fits one 64-bit window.
pub const MAX_READ_BITS: u32 = 56;

/// Reads a backward bitstream.
pub struct BackwardBitReader<'a> {
    data: &'a [u8],
    /// Bits `[0, remaining)` are still unread.
    remaining: usize,
    /// Set once a read asked for more bits than remained.
    overflowed: bool,
}

impl<'a> BackwardBitReader<'a> {
    /// Starts below the end mark in the last byte.
    pub fn new(data: &'a [u8]) -> Result<Self, BitError> {
        let last = *data.last().ok_or(BitError::MissingEndMark)?;
        if last == 0 {
            return Err(BitError::MissingEndMark);
        }
        let mark: usize = (u8::BITS - 1 - last.leading_zeros())
            .try_into()
            .unwrap_or(0);
        Ok(Self {
            data,
            remaining: (data.len() - 1) * 8 + mark,
            overflowed: false,
        })
    }

    /// Reads `count` (at most [`MAX_READ_BITS`]) bits from the top of the
    /// unread region; the highest position becomes the value's most
    /// significant bit. Reading past bit 0 yields zero bits and sets the
    /// overflow flag, which a well-formed stream never does.
    pub fn read_bits(&mut self, count: u32) -> u64 {
        debug_assert!(count <= MAX_READ_BITS, "read of {count} bits");
        let count = count.min(MAX_READ_BITS);
        let wanted: usize = count.try_into().unwrap_or(0);
        if wanted == 0 {
            return 0;
        }
        if wanted <= self.remaining {
            self.remaining -= wanted;
            extract(self.data, self.remaining, wanted)
        } else {
            let available = self.remaining;
            let value = extract(self.data, 0, available) << (wanted - available);
            self.remaining = 0;
            self.overflowed = true;
            value
        }
    }

    /// The next `count` (at most [`MAX_READ_BITS`]) bits without consuming
    /// them; bits below position 0 read as zero.
    pub fn peek_bits(&self, count: u32) -> u64 {
        let wanted: usize = count.min(MAX_READ_BITS).try_into().unwrap_or(0);
        if wanted <= self.remaining {
            extract(self.data, self.remaining - wanted, wanted)
        } else {
            extract(self.data, 0, self.remaining) << (wanted - self.remaining)
        }
    }

    /// Consumes `count` bits; consuming more than remain sets the overflow
    /// flag.
    pub fn consume(&mut self, count: u32) {
        let wanted: usize = count.try_into().unwrap_or(usize::MAX);
        if wanted > self.remaining {
            self.remaining = 0;
            self.overflowed = true;
        } else {
            self.remaining -= wanted;
        }
    }

    /// Bits not yet read.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Whether a read went past the start of the stream.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// True when every bit was read exactly, with no overflow.
    pub const fn is_exhausted(&self) -> bool {
        self.remaining == 0 && !self.overflowed
    }
}

/// `count` (≤ 56) bits starting at bit `start` of the little-endian bit
/// array `data`, as an integer whose bit 0 is bit `start`. Bits past the end
/// of `data` read as zero.
pub fn extract(data: &[u8], start: usize, count: usize) -> u64 {
    if count == 0 {
        return 0;
    }
    let first = start / 8;
    let shift = start % 8;
    // Eight whole bytes are almost always available: one fixed-size load.
    // Only the last bytes of the input take the bounded copy.
    let window = first
        .checked_add(8)
        .and_then(|end| data.get(first..end))
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .unwrap_or_else(|| {
            let mut window = [0_u8; 8];
            let end = first.saturating_add(8).min(data.len());
            if let (Some(dst), Some(src)) = (
                window.get_mut(..end.saturating_sub(first)),
                data.get(first..end),
            ) {
                dst.copy_from_slice(src);
            }
            window
        });
    let word = u64::from_le_bytes(window) >> shift;
    if count >= 64 {
        word
    } else {
        word & ((1_u64 << count) - 1)
    }
}

/// The low `count` bits set.
const fn low_mask(count: u32) -> u64 {
    if count >= u64::BITS {
        u64::MAX
    } else {
        (1 << count) - 1
    }
}

/// Packs bit fields from bit 0 upward, the order [`BackwardBitReader`]
/// reads in reverse: the field written last is read first.
#[derive(Debug, Default)]
pub struct BitWriter {
    out: Vec<u8>,
    container: u64,
    bits: u32,
}

impl BitWriter {
    /// An empty writer.
    pub const fn new() -> Self {
        Self {
            out: Vec::new(),
            container: 0,
            bits: 0,
        }
    }

    /// An empty writer with room for `bytes` bytes of output.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            out: Vec::with_capacity(bytes),
            container: 0,
            bits: 0,
        }
    }

    /// Appends the low `count` (at most [`MAX_READ_BITS`]) bits of `value`.
    pub fn add(&mut self, value: u64, count: u32) {
        debug_assert!(count <= MAX_READ_BITS, "write of {count} bits");
        debug_assert!(
            value & !low_mask(count) == 0,
            "{value} wider than {count} bits"
        );
        if count == 0 {
            return;
        }
        if self.bits + count > u64::BITS {
            self.flush_bytes();
        }
        self.container |= (value & low_mask(count)) << self.bits;
        self.bits += count;
    }

    /// Makes room for `bits` more bits (at most [`MAX_READ_BITS`]) added
    /// with [`Self::push`], so a run of short fields needs one check.
    pub fn reserve(&mut self, bits: u32) {
        debug_assert!(bits <= MAX_READ_BITS, "reserve of {bits} bits");
        if self.bits + bits > u64::BITS {
            self.flush_bytes();
        }
    }

    /// Appends the low `count` bits of `value` (1 to [`MAX_READ_BITS`]) into
    /// room made by [`Self::reserve`].
    pub fn push(&mut self, value: u64, count: u32) {
        debug_assert!((1..=MAX_READ_BITS).contains(&count), "push of {count} bits");
        debug_assert!(
            self.bits + count <= u64::BITS,
            "push past the reserved room"
        );
        debug_assert!(
            value & !low_mask(count) == 0,
            "{value} wider than {count} bits"
        );
        self.container |= value << self.bits;
        self.bits += count;
    }

    /// Moves every complete byte of the container to the output. The whole
    /// word is appended and the incomplete bytes cut off again, which is a
    /// fixed-size copy instead of a variable one.
    fn flush_bytes(&mut self) {
        let whole = self.bits / 8;
        let len = self.out.len();
        self.out.extend_from_slice(&self.container.to_le_bytes());
        self.out.truncate(len + usize::try_from(whole).unwrap_or(0));
        self.container = self.container.checked_shr(whole * 8).unwrap_or(0);
        self.bits -= whole * 8;
    }

    /// The packed bytes, the last one zero-padded at the top.
    pub fn into_bytes(mut self) -> Vec<u8> {
        self.flush_bytes();
        if self.bits > 0 {
            self.out.push(self.container.to_le_bytes()[0]);
        }
        self.out
    }

    /// Adds the end mark (one set bit above the last field) and returns a
    /// stream that [`BackwardBitReader::new`] accepts.
    pub fn finish(mut self) -> Vec<u8> {
        self.add(1, 1);
        self.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{BackwardBitReader, BitError, BitWriter, MAX_READ_BITS};

    fn lcg(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        }
    }

    /// A deliberately naive model: one bool per bit, little-endian order.
    fn naive_bits(data: &[u8]) -> Vec<bool> {
        data.iter()
            .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1 == 1))
            .collect()
    }

    fn naive_read(bits: &[bool], top: usize, count: usize) -> u64 {
        let mut value = 0_u64;
        for k in 0..count {
            // Bit `top - count + k`; positions below bit 0 read as zero.
            if let Some(position) = (top + k).checked_sub(count)
                && bits[position]
            {
                value |= 1 << k;
            }
        }
        value
    }

    #[test]
    fn end_mark_is_required() {
        assert_eq!(
            BackwardBitReader::new(&[]).err(),
            Some(BitError::MissingEndMark)
        );
        assert_eq!(
            BackwardBitReader::new(&[0x12, 0x00]).err(),
            Some(BitError::MissingEndMark)
        );
    }

    #[test]
    fn single_byte_streams_start_below_the_mark() {
        let mut reader = BackwardBitReader::new(&[0b1010_0001]).unwrap();
        assert_eq!(reader.remaining(), 7);
        assert_eq!(reader.read_bits(7), 0b010_0001);
        assert!(reader.is_exhausted());

        let mut only_mark = BackwardBitReader::new(&[0b0000_0001]).unwrap();
        assert_eq!(only_mark.remaining(), 0);
        assert!(only_mark.is_exhausted());
        assert_eq!(only_mark.read_bits(3), 0);
        assert!(only_mark.overflowed());
        assert!(!only_mark.is_exhausted());
    }

    #[test]
    fn random_streams_match_the_naive_model() {
        let mut next = lcg(42);
        for case in 0..400 {
            let len = 1 + usize::try_from(next() % 40).unwrap();
            let mut data: Vec<u8> = (0..len).map(|_| next().to_be_bytes()[0]).collect();
            if let Some(last) = data.last_mut() {
                *last |= 1 << (next() % 8);
            }
            let bits = naive_bits(&data);
            let last = *data.last().unwrap();
            let mark = 7 - last.leading_zeros() as usize;
            let mut top = (len - 1) * 8 + mark;
            let mut reader = BackwardBitReader::new(&data).unwrap();
            assert_eq!(reader.remaining(), top, "case {case}");
            while top > 0 {
                let count = 1 + u32::try_from(next() % u64::from(MAX_READ_BITS)).unwrap();
                let count_usize = usize::try_from(count).unwrap();
                let expected = naive_read(&bits, top, count_usize);
                assert_eq!(
                    reader.read_bits(count),
                    expected,
                    "case {case} top {top} count {count}"
                );
                top = top.saturating_sub(count_usize);
            }
            assert_eq!(reader.remaining(), 0);
        }
    }

    #[test]
    fn overflow_zero_fills_and_is_reported() {
        let mut reader = BackwardBitReader::new(&[0xFF, 0b0000_0011]).unwrap();
        assert_eq!(reader.remaining(), 9);
        assert_eq!(reader.read_bits(4), 0b1111);
        assert_eq!(reader.read_bits(8), 0b1111_1000);
        assert!(reader.overflowed());
        assert!(!reader.is_exhausted());
    }

    #[test]
    fn writer_fields_read_back_in_reverse_order() {
        let mut next = lcg(7);
        for case in 0..300 {
            let fields: Vec<(u64, u32)> = (0..=next() % 60)
                .map(|_| {
                    let count = u32::try_from(next() % u64::from(MAX_READ_BITS + 1)).unwrap();
                    let value = next() & ((1_u64 << count) - 1);
                    (value, count)
                })
                .collect();
            let mut writer = BitWriter::new();
            for &(value, count) in &fields {
                writer.add(value, count);
            }
            let total: u32 = fields.iter().map(|&(_, count)| count).sum();
            let stream = writer.finish();
            assert_eq!(
                stream.len(),
                usize::try_from(total / 8 + 1).unwrap(),
                "case {case}"
            );
            let mut reader = BackwardBitReader::new(&stream).unwrap();
            for &(value, count) in fields.iter().rev() {
                assert_eq!(reader.read_bits(count), value, "case {case}");
            }
            assert!(reader.is_exhausted(), "case {case}");
        }
    }

    #[test]
    fn writer_packs_low_bits_first() {
        let mut writer = BitWriter::new();
        writer.add(0b101, 3);
        writer.add(0b1_1110, 5);
        writer.add(0x3FF, 10);
        assert_eq!(writer.into_bytes(), [0b1111_0101, 0xFF, 0b11]);
        assert_eq!(BitWriter::new().finish(), [1]);
    }
}
