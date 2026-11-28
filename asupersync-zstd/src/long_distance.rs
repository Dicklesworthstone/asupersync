//! Content-defined samples for finding distant, possibly unaligned copies.
//! The rolling hash depends only on the most recent 64 bytes. Equal regions
//! therefore produce the same samples even at different file offsets.

use crate::matcher::{DoubleFastFinder, Match, common_prefix};

const SEED: usize = 64;
const EMPTY: usize = usize::MAX;
const LOCAL_WINDOW: usize = 1 << 20;

// SplitMix64 supplies deterministic, well-distributed gear values per byte.
const GEAR: [u64; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < table.len() {
        let mut x = (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        table[i] = x ^ (x >> 31);
        i += 1;
    }
    table
};

pub(crate) struct LongDistanceFinder {
    positions: Vec<usize>,
    local: DoubleFastFinder,
    local_matches: Vec<Match>,
}

impl LongDistanceFinder {
    pub(crate) fn new(content_len: usize) -> Self {
        Self {
            positions: if content_len > LOCAL_WINDOW {
                vec![EMPTY; 1 << 16]
            } else {
                Vec::new()
            },
            local: DoubleFastFinder::new(),
            local_matches: Vec::new(),
        }
    }

    // Append the ordinary matches in the gap. Its remaining literals precede
    // the next long-distance match (or form the trailing literals of a block).
    fn gap(&mut self, src: &[u8], start: usize, end: usize, out: &mut Vec<Match>) -> usize {
        self.local.find(
            src,
            start,
            end,
            end.saturating_sub(LOCAL_WINDOW),
            &mut self.local_matches,
        );
        let mut last = start;
        for m in self.local_matches.drain(..) {
            last += m.literals_length + m.length;
            out.push(m);
        }
        end - last
    }

    pub(crate) fn find(
        &mut self,
        src: &[u8],
        start: usize,
        end: usize,
        window: usize,
        out: &mut Vec<Match>,
    ) {
        out.clear();
        let mut covered = start;
        let mut hash = 0_u64;
        if !self.positions.is_empty() {
            for (i, &byte) in src[start..end].iter().enumerate() {
                hash = (hash << 1).wrapping_add(GEAR[usize::from(byte)]);
                if i + 1 < SEED || (hash >> 32) & 255 != 0 {
                    continue;
                }
                let at = start + i + 1 - SEED;
                let slot = (hash >> 48) as usize;
                let prev = std::mem::replace(&mut self.positions[slot], at);
                if at < covered
                    || prev == EMPTY
                    || at - prev > window
                    || at - prev <= LOCAL_WINDOW
                    || src[prev..prev + SEED] != src[at..at + SEED]
                {
                    continue;
                }
                let length = SEED + common_prefix(&src[prev + SEED..end], &src[at + SEED..end]);
                let mut back = 0;
                while back < at - covered
                    && back < prev
                    && src[at - back - 1] == src[prev - back - 1]
                {
                    back += 1;
                }
                let literals_length = self.gap(src, covered, at - back, out);
                out.push(Match {
                    literals_length,
                    offset: at - prev,
                    length: length + back,
                });
                covered = at + length;
            }
        }
        self.gap(src, covered, end, out);
    }
}
