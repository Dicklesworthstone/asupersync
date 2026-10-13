//! XXH64 with a 64-bit seed.
//!
//! A Zstandard frame with `Content_Checksum_flag` set ends with the low 32
//! bits of XXH64 (seed 0) over the decompressed content (RFC 8878 §3.1.1).

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

const STRIPE: usize = 32;

const fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

const fn merge_round(acc: u64, value: u64) -> u64 {
    (acc ^ round(0, value)).wrapping_mul(P1).wrapping_add(P4)
}

const fn avalanche(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(P3);
    hash ^= hash >> 32;
    hash
}

/// Mixes the trailing (< 32) bytes into `hash` and applies the avalanche.
fn finalize(mut hash: u64, tail: &[u8]) -> u64 {
    let (lanes, rest) = tail.as_chunks::<8>();
    for lane in lanes {
        hash ^= round(0, u64::from_le_bytes(*lane));
        hash = hash.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
    }
    // Fewer than 8 bytes remain: at most one 4-byte word, then single bytes.
    let (words, bytes) = rest.as_chunks::<4>();
    if let Some(word) = words.first() {
        hash ^= u64::from(u32::from_le_bytes(*word)).wrapping_mul(P1);
        hash = hash.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
    }
    for &byte in bytes {
        hash ^= u64::from(byte).wrapping_mul(P5);
        hash = hash.rotate_left(11).wrapping_mul(P1);
    }
    avalanche(hash)
}

/// XXH64 of `data` with `seed`, in one call.
#[must_use]
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut state = Xxh64::new(seed);
    state.update(data);
    state.digest()
}

/// Streaming XXH64 state. Feeding the same bytes in any split gives the same
/// digest as [`xxh64`].
#[derive(Clone, Debug)]
pub struct Xxh64 {
    seed: u64,
    acc: [u64; 4],
    buffer: [u8; STRIPE],
    buffered: usize,
    total_len: u64,
}

impl Xxh64 {
    /// A new state for `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            acc: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            buffer: [0; STRIPE],
            buffered: 0,
            total_len: 0,
        }
    }

    /// Feeds more input.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self
            .total_len
            .wrapping_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if self.buffered > 0 {
            let take = (STRIPE - self.buffered).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(slot) = self.buffer.get_mut(self.buffered..self.buffered + take) {
                slot.copy_from_slice(head);
            }
            self.buffered += take;
            data = rest;
            if self.buffered < STRIPE {
                return;
            }
            let stripe = self.buffer;
            self.consume_stripe(&stripe);
            self.buffered = 0;
        }
        let (stripes, rest) = data.as_chunks::<STRIPE>();
        for stripe in stripes {
            self.consume_stripe(stripe);
        }
        if let Some(slot) = self.buffer.get_mut(..rest.len()) {
            slot.copy_from_slice(rest);
        }
        self.buffered = rest.len();
    }

    fn consume_stripe(&mut self, stripe: &[u8; STRIPE]) {
        let (lanes, _) = stripe.as_chunks::<8>();
        for (acc, lane) in self.acc.iter_mut().zip(lanes) {
            *acc = round(*acc, u64::from_le_bytes(*lane));
        }
    }

    /// The digest of everything fed so far. The state can keep growing.
    #[must_use]
    pub fn digest(&self) -> u64 {
        let hash = if self.total_len >= STRIPE as u64 {
            let [v1, v2, v3, v4] = self.acc;
            let mut hash = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
            for value in self.acc {
                hash = merge_round(hash, value);
            }
            hash
        } else {
            self.seed.wrapping_add(P5)
        };
        let tail = self.buffer.get(..self.buffered).unwrap_or(&[]);
        finalize(hash.wrapping_add(self.total_len), tail)
    }
}

#[cfg(test)]
mod tests {
    use super::{Xxh64, xxh64};

    /// The generator the oracle vectors were made with: an LCG whose top byte
    /// is each output byte (see the provenance note on `REFERENCE`).
    fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect()
    }

    /// (seed, length, low 32 bits of XXH64). Provenance: each input is
    /// `lcg_bytes(seed, length)`, compressed by reference zstd 1.5.7 with
    /// `zstd -q -1 --check -c`; the expected value is the frame's trailing
    /// 4-byte content checksum (the low 32 bits of XXH64, seed 0, RFC 8878
    /// §3.1.1). The lengths cover every path of the algorithm.
    const REFERENCE: [(u64, usize, u32); 22] = [
        (1, 0, 0x51d8_e999),
        (2, 1, 0x18e8_3fb6),
        (3, 3, 0x37f4_8898),
        (4, 4, 0x4715_62b9),
        (5, 7, 0x72e8_a660),
        (6, 8, 0x36e0_19ac),
        (7, 9, 0x80ba_35bf),
        (8, 15, 0xb8dd_2da7),
        (9, 16, 0x738e_9ba3),
        (10, 17, 0x4dde_196d),
        (11, 31, 0x8983_c27b),
        (12, 32, 0x4885_40bf),
        (13, 33, 0x4afe_f68f),
        (14, 63, 0xc34c_b901),
        (15, 64, 0x1370_9de0),
        (16, 65, 0x61c1_f014),
        (17, 100, 0x46fe_6290),
        (18, 255, 0x203a_69a5),
        (19, 1000, 0xa260_6f4a),
        (20, 4096, 0xe9b4_6c30),
        (21, 65_537, 0x2582_3151),
        (22, 1_000_003, 0xd7e0_818c),
    ];

    #[test]
    fn matches_published_full_digests() {
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
    }

    #[test]
    fn matches_reference_zstd_frame_checksums() {
        assert_eq!(REFERENCE.len(), 22, "the oracle table must not shrink");
        for (seed, len, expected) in REFERENCE {
            let data = lcg_bytes(seed, len);
            let low32 = u32::try_from(xxh64(&data, 0) & 0xFFFF_FFFF).unwrap();
            assert_eq!(low32, expected, "seed {seed} length {len}");
        }
    }

    #[test]
    fn streaming_equals_one_shot_for_every_split() {
        for len in [0, 1, 31, 32, 33, 64, 95, 200] {
            let data = lcg_bytes(len as u64 + 100, len);
            let expected = xxh64(&data, 7);
            for split in 0..=len {
                let mut state = Xxh64::new(7);
                let (a, b) = data.split_at(split);
                state.update(a);
                state.update(b);
                assert_eq!(state.digest(), expected, "len {len} split {split}");
            }
            let mut bytewise = Xxh64::new(7);
            for byte in &data {
                bytewise.update(std::slice::from_ref(byte));
            }
            assert_eq!(bytewise.digest(), expected, "len {len} bytewise");
        }
    }

    #[test]
    fn seed_changes_the_digest() {
        let data = lcg_bytes(9, 100);
        assert_ne!(xxh64(&data, 0), xxh64(&data, 1));
    }
}
