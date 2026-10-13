//! Zstandard frame encoding. Stage E0 (br-asupersync-t1fblr.15): stored
//! frames of raw and RLE blocks, valid RFC 8878 output with no compression.

use crate::xxhash64::xxh64;

/// The largest block (Block_Maximum_Size with a window of at least 128 KiB).
const MAX_BLOCK: usize = 128 * 1024;

/// Content up to this size is written as a single-segment frame (its window
/// is the content size, which the 8 MiB default decode limit accepts).
const SINGLE_SEGMENT_MAX: usize = 8 << 20;

/// Window descriptor for 2^17 bytes: every stored block fits it.
const WINDOW_128_KIB: u8 = 0x38;

/// How hard the encoder works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// No compression: raw blocks, or RLE blocks for runs of one byte.
    Store,
}

/// Encoder settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeParams {
    /// The compression level.
    pub level: Level,
    /// Append the XXH64 content checksum.
    pub checksum: bool,
}

impl EncodeParams {
    /// `level` with the content checksum on.
    pub const fn new(level: Level) -> Self {
        Self {
            level,
            checksum: true,
        }
    }
}

/// Encodes `input` as one Zstandard frame that declares its content size.
pub fn encode_all(input: &[u8], params: &EncodeParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / MAX_BLOCK * 3 + 32);
    encode_into(input, params, &mut out);
    out
}

/// Appends one Zstandard frame encoding `input` to `out`.
pub fn encode_into(input: &[u8], params: &EncodeParams, out: &mut Vec<u8>) {
    let Level::Store = params.level;
    let len = input.len();
    let single_segment = len <= SINGLE_SEGMENT_MAX;
    let len64 = u64::try_from(len).unwrap_or(u64::MAX);
    let (size_flag, size_bytes): (u8, Vec<u8>) = if single_segment && len < 256 {
        (0, vec![u8::try_from(len).unwrap_or(0)])
    } else if (256..65_536 + 256).contains(&len) {
        let stored = u16::try_from(len - 256).unwrap_or(u16::MAX);
        (1, stored.to_le_bytes().to_vec())
    } else if let Ok(small) = u32::try_from(len64) {
        (2, small.to_le_bytes().to_vec())
    } else {
        (3, len64.to_le_bytes().to_vec())
    };
    let descriptor = (size_flag << 6)
        | if single_segment { 0x20 } else { 0 }
        | if params.checksum { 0x04 } else { 0 };
    out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, descriptor]);
    if !single_segment {
        out.push(WINDOW_128_KIB);
    }
    out.extend_from_slice(&size_bytes);

    let mut blocks = input.chunks(MAX_BLOCK).peekable();
    if blocks.peek().is_none() {
        // An empty frame still carries one (empty, last) raw block.
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
    }
    while let Some(block) = blocks.next() {
        let last = u32::from(blocks.peek().is_none());
        let size = u32::try_from(block.len()).unwrap_or(0) << 3;
        let first = block.first().copied().unwrap_or(0);
        if block.len() > 1 && block.iter().all(|&byte| byte == first) {
            let header = size | (1 << 1) | last;
            out.extend_from_slice(&header.to_le_bytes()[..3]);
            out.push(first);
        } else {
            let header = size | last;
            out.extend_from_slice(&header.to_le_bytes()[..3]);
            out.extend_from_slice(block);
        }
    }
    if params.checksum {
        let checksum = u32::try_from(xxh64(input, 0) & 0xFFFF_FFFF).unwrap_or(0);
        out.extend_from_slice(&checksum.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodeParams, Level, encode_all};
    use crate::frame::{DecodeLimits, decode_all};

    const STORED: &str = include_str!("../tests/vectors/store_frames.txt");

    fn lcg(seed: u64, len: usize) -> Vec<u8> {
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

    fn input(name: &str) -> Vec<u8> {
        match name {
            "empty" => Vec::new(),
            "one-x" => b"x".to_vec(),
            "two-a" => b"aa".to_vec(),
            "lcg1x255" => lcg(1, 255),
            "lcg2x256" => lcg(2, 256),
            "zeros300" => vec![0; 300],
            "zeros128k+lcg5x1000" => {
                let mut data = vec![0; 128 * 1024];
                data.extend(lcg(5, 1000));
                data
            }
            other => panic!("unknown vector {other}"),
        }
    }

    #[test]
    fn matches_the_reference_checked_frames_byte_for_byte() {
        let mut seen = 0;
        for line in STORED.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let data = input(fields[0]);
            let params = EncodeParams {
                checksum: fields[1] == "1",
                ..EncodeParams::new(Level::Store)
            };
            let expected: Vec<u8> = (0..fields[2].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[2][i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(encode_all(&data, &params), expected, "{line}");
            seen += 1;
        }
        assert_eq!(seen, 14, "the stored-frame file must keep all 14 vectors");
    }

    #[test]
    fn round_trips_through_the_decoder_at_block_and_size_boundaries() {
        for len in [
            0,
            1,
            2,
            255,
            256,
            65_791,
            65_792,
            128 * 1024 - 1,
            128 * 1024,
            128 * 1024 + 1,
            300_000,
        ] {
            let data = lcg(len as u64 + 11, len);
            for checksum in [true, false] {
                let params = EncodeParams {
                    checksum,
                    ..EncodeParams::new(Level::Store)
                };
                let frame = encode_all(&data, &params);
                let limits = DecodeLimits {
                    require_content_size: true,
                    ..DecodeLimits::new(len)
                };
                assert_eq!(
                    decode_all(&frame, &limits).as_deref(),
                    Ok(&data[..]),
                    "len {len}"
                );
            }
        }
    }

    #[test]
    fn large_inputs_use_a_bounded_window() {
        let data = lcg(99, (8 << 20) + 1);
        let frame = encode_all(&data, &EncodeParams::new(Level::Store));
        assert_eq!(frame[4] & 0x20, 0, "not single segment");
        assert_eq!(
            decode_all(&frame, &DecodeLimits::new(data.len())).map(|out| out == data),
            Ok(true)
        );
    }
}
