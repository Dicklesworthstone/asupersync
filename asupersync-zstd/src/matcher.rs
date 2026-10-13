//! The match finder of [`Level::Fast`](crate::Level::Fast): one hash table
//! of recent positions, greedy matching, and a check of the last offset
//! before each hash lookup.

/// Log2 of the hash table size.
const HASH_LOG: u32 = 16;

/// Multiplier of the position hash (the XXH64 prime 1).
const PRIME: u64 = 0x9E37_79B1_85EB_CA87;

/// Content smaller than this hashes and matches at least 5 bytes; larger
/// content uses 6, which finds fewer but longer matches.
const SMALL_CONTENT: usize = 16 * 1024;

/// An empty hash table slot.
const EMPTY: usize = usize::MAX;

/// One match: `literals_length` bytes after the previous match, then
/// `length` bytes that repeat the bytes `offset` back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    /// Unmatched bytes before the match.
    pub literals_length: usize,
    /// Distance back to the source of the match, at least 1.
    pub offset: usize,
    /// Matched bytes, at least 5.
    pub length: usize,
}

/// The hash of the `width` bytes at `position`.
fn hash(src: &[u8], position: usize, width: usize) -> usize {
    let mut word = [0_u8; 8];
    word[..width].copy_from_slice(&src[position..position + width]);
    let key = u64::from_le_bytes(word);
    usize::try_from(key.wrapping_mul(PRIME) >> (u64::BITS - HASH_LOG)).unwrap_or(0)
}

/// A greedy match finder for one frame. Its hash table carries over from
/// block to block, so a block finds matches in earlier blocks; entries that
/// fall out of the window are skipped.
pub struct MatchFinder {
    table: Vec<usize>,
    /// Bytes hashed and the shortest match.
    width: usize,
}

impl MatchFinder {
    /// A finder with an empty table, for a frame of `content_len` bytes.
    pub fn new(content_len: usize) -> Self {
        Self {
            table: vec![EMPTY; 1 << HASH_LOG],
            width: if content_len < SMALL_CONTENT { 5 } else { 6 },
        }
    }

    /// Fills `matches` with greedy matches covering `src[start..end]`, the
    /// next block of the frame. A match may reach back to `window_start` but
    /// never before it. The bytes after the last match are the block's
    /// trailing literals.
    pub fn find(
        &mut self,
        src: &[u8],
        start: usize,
        end: usize,
        window_start: usize,
        matches: &mut Vec<Match>,
    ) {
        matches.clear();
        let width = self.width;
        let mut anchor = start;
        let mut ip = start;
        let mut last_offset = 0_usize;
        let mut misses = 0_usize;
        while ip + width <= end {
            // The last offset first (only after some literals, where it is
            // repeat offset 1), then the hash table.
            let repeat = last_offset > 0
                && ip > anchor
                && ip >= window_start + last_offset
                && src[ip..ip + width] == src[ip - last_offset..ip - last_offset + width];
            let candidate = if repeat {
                Some(ip - last_offset)
            } else {
                let slot = hash(src, ip, width);
                let previous = self.table[slot];
                self.table[slot] = ip;
                (previous != EMPTY
                    && previous >= window_start
                    && src[previous..previous + width] == src[ip..ip + width])
                    .then_some(previous)
            };
            let Some(mut source) = candidate else {
                // Step faster through data that keeps missing.
                misses += 1;
                ip += 1 + (misses >> 8);
                continue;
            };
            misses = 0;
            let mut length = width;
            while ip + length < end && src[source + length] == src[ip + length] {
                length += 1;
            }
            while ip > anchor && source > window_start && src[ip - 1] == src[source - 1] {
                ip -= 1;
                source -= 1;
                length += 1;
            }
            matches.push(Match {
                literals_length: ip - anchor,
                offset: ip - source,
                length,
            });
            last_offset = ip - source;
            for position in [ip + 2, ip + length - 2] {
                if position + width <= end {
                    self.table[hash(src, position, width)] = position;
                }
            }
            ip += length;
            anchor = ip;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Match, MatchFinder};

    /// Executes `matches` over `src[start..]` and checks they rebuild it.
    fn replay(src: &[u8], start: usize, end: usize, window_start: usize, matches: &[Match]) {
        let mut pos = start;
        for found in matches {
            pos += found.literals_length;
            assert!(found.length >= 5);
            assert!(found.offset >= 1 && pos - found.offset >= window_start);
            for k in 0..found.length {
                assert_eq!(src[pos + k], src[pos + k - found.offset], "match at {pos}");
            }
            pos += found.length;
        }
        assert!(pos <= end);
    }

    #[test]
    fn matches_rebuild_the_block_and_respect_the_window() {
        let text: Vec<u8> = b"to be or not to be, that is the question; "
            .iter()
            .copied()
            .cycle()
            .take(200_000)
            .collect();
        let mut matches = Vec::new();
        for (start, end, window_start) in
            [(0, 1_000, 0), (0, 131_072, 0), (131_072, 200_000, 150_000)]
        {
            let mut finder = MatchFinder::new(text.len());
            finder.find(&text, start, end, window_start, &mut matches);
            assert_ne!(
                matches,
                Vec::<Match>::new(),
                "a repetitive text has matches"
            );
            replay(&text, start, end, window_start, &matches);
        }
    }

    /// The table carries over: the second block, a copy of the first, is
    /// one match back into the first block.
    #[test]
    fn later_blocks_match_into_earlier_ones() {
        let mut state = 5_u64;
        let mut data: Vec<u8> = (0..40_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect();
        data.extend_from_within(..);
        let mut finder = MatchFinder::new(data.len());
        let mut matches = Vec::new();
        finder.find(&data, 0, 40_000, 0, &mut matches);
        assert_eq!(matches, Vec::<Match>::new(), "random bytes repeat nothing");
        finder.find(&data, 40_000, 80_000, 0, &mut matches);
        assert_eq!(
            matches,
            [Match {
                literals_length: 0,
                offset: 40_000,
                length: 40_000
            }]
        );
    }

    #[test]
    fn a_repeated_block_is_one_long_match() {
        let mut data: Vec<u8> = (0..=255_u8).collect();
        data.extend_from_within(..);
        let mut finder = MatchFinder::new(data.len());
        let mut matches = Vec::new();
        finder.find(&data, 0, data.len(), 0, &mut matches);
        assert_eq!(
            matches,
            [Match {
                literals_length: 256,
                offset: 256,
                length: 256
            }]
        );
    }

    #[test]
    fn unrelated_bytes_have_no_matches() {
        let mut state = 1_u64;
        let data: Vec<u8> = (0..5_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect();
        let mut finder = MatchFinder::new(data.len());
        let mut matches = Vec::new();
        finder.find(&data, 0, data.len(), 0, &mut matches);
        assert_eq!(matches, Vec::<Match>::new(), "random bytes repeat nothing");
    }
}
