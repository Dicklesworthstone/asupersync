//! Zstandard frame encoding: stored frames ([`Level::Store`], stage E0,
//! br-asupersync-t1fblr.15) and compressed ones ([`Level::Fast`], stage E1,
//! br-asupersync-t1fblr.19-.21).

use crate::literals::encode_literals;
use crate::matcher::{Match, MatchFinder};
use crate::sequences::{EncodedSequence, encode_sequences, offset_value};
use crate::xxhash64::xxh64;

/// The largest block (Block_Maximum_Size with a window of at least 128 KiB).
const MAX_BLOCK: usize = 128 * 1024;

/// Content up to this size is written as a single-segment frame (its window
/// is the content size, which the 8 MiB default decode limit accepts).
const SINGLE_SEGMENT_MAX: usize = 8 << 20;

/// Window descriptor for 2^17 bytes: every stored block fits it.
const WINDOW_128_KIB: u8 = 0x38;

/// Window descriptor for 2^20 bytes, the farthest [`Level::Fast`] reaches
/// back.
const WINDOW_1_MIB: u8 = 0x50;

/// How far back [`Level::Fast`] matches reach.
const FAST_WINDOW: usize = 1 << 20;

/// How hard the encoder works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// No compression: raw blocks, or RLE blocks for runs of one byte.
    Store,
    /// Greedy matching through one hash table over a 1 MiB window, Huffman
    /// literals and FSE-coded sequences. A block that does not shrink is
    /// stored raw.
    Fast,
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
    match params.level {
        Level::Store => {
            write_frame_header(input.len(), params.checksum, WINDOW_128_KIB, out);
            store_blocks(input, out);
        }
        Level::Fast => {
            write_frame_header(input.len(), params.checksum, WINDOW_1_MIB, out);
            fast_blocks(input, out);
        }
    }
    if params.checksum {
        let checksum = u32::try_from(xxh64(input, 0) & 0xFFFF_FFFF).unwrap_or(0);
        out.extend_from_slice(&checksum.to_le_bytes());
    }
}

/// The frame header for `len` bytes of content. Content up to
/// [`SINGLE_SEGMENT_MAX`] is a single segment; larger content declares
/// `window_descriptor`.
fn write_frame_header(len: usize, checksum: bool, window_descriptor: u8, out: &mut Vec<u8>) {
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
    let descriptor =
        (size_flag << 6) | if single_segment { 0x20 } else { 0 } | if checksum { 0x04 } else { 0 };
    out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, descriptor]);
    if !single_segment {
        out.push(window_descriptor);
    }
    out.extend_from_slice(&size_bytes);
}

/// A 3-byte block header.
fn write_block_header(size: usize, block_type: u32, last: bool, out: &mut Vec<u8>) {
    let header = (u32::try_from(size).unwrap_or(0) << 3) | (block_type << 1) | u32::from(last);
    out.extend_from_slice(&header.to_le_bytes()[..3]);
}

/// Raw blocks, or RLE blocks where a block is one repeated byte.
fn store_blocks(input: &[u8], out: &mut Vec<u8>) {
    let mut blocks = input.chunks(MAX_BLOCK).peekable();
    if blocks.peek().is_none() {
        // An empty frame still carries one (empty, last) raw block.
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
    }
    while let Some(block) = blocks.next() {
        let last = blocks.peek().is_none();
        let first = block.first().copied().unwrap_or(0);
        if block.len() > 1 && block.iter().all(|&byte| byte == first) {
            write_block_header(block.len(), 1, last, out);
            out.push(first);
        } else {
            write_block_header(block.len(), 0, last, out);
            out.extend_from_slice(block);
        }
    }
}

/// Compressed blocks of at most [`MAX_BLOCK`] bytes; a block whose
/// compressed form is not smaller is stored raw (and leaves the repeat
/// offsets as they were, as the decoder does).
fn fast_blocks(input: &[u8], out: &mut Vec<u8>) {
    let mut finder = MatchFinder::new(input.len());
    let mut matches = Vec::new();
    let mut body = Vec::new();
    let mut rep = [1, 4, 8];
    let mut pos = 0;
    loop {
        let end = (pos + MAX_BLOCK).min(input.len());
        let last = end >= input.len();
        let compressed = if end > pos {
            compress_block(input, pos, end, rep, &mut finder, &mut matches, &mut body)
        } else {
            None
        };
        match compressed {
            Some(next_rep) if body.len() < end - pos => {
                write_block_header(body.len(), 2, last, out);
                out.extend_from_slice(&body);
                rep = next_rep;
            }
            _ => {
                write_block_header(end - pos, 0, last, out);
                out.extend_from_slice(&input[pos..end]);
            }
        }
        pos = end;
        if last {
            break;
        }
    }
}

/// Writes the compressed form of `src[start..end]` into `body` and returns
/// the repeat offsets after it, or `None` if the block cannot be expressed.
fn compress_block(
    src: &[u8],
    start: usize,
    end: usize,
    mut rep: [usize; 3],
    finder: &mut MatchFinder,
    matches: &mut Vec<Match>,
    body: &mut Vec<u8>,
) -> Option<[usize; 3]> {
    body.clear();
    finder.find(src, start, end, end.saturating_sub(FAST_WINDOW), matches);
    let mut literals = Vec::with_capacity(end - start);
    let mut sequences = Vec::with_capacity(matches.len());
    let mut pos = start;
    for found in &*matches {
        literals.extend_from_slice(&src[pos..pos + found.literals_length]);
        pos += found.literals_length + found.length;
        let (value, next_rep) = offset_value(found.offset, found.literals_length, rep);
        rep = next_rep;
        sequences.push(EncodedSequence {
            literals_length: u32::try_from(found.literals_length).ok()?,
            offset_value: u32::try_from(value).ok()?,
            match_length: u32::try_from(found.length).ok()?,
        });
    }
    literals.extend_from_slice(&src[pos..end]);
    encode_literals(&literals, body);
    encode_sequences(&sequences, body)?;
    Some(rep)
}

#[cfg(test)]
mod tests {
    use super::{EncodeParams, Level, encode_all};
    use crate::frame::{DecodeLimits, decode_all};
    use crate::xxhash64::xxh64;

    const STORED: &str = include_str!("../tests/vectors/store_frames.txt");
    const FAST: &str = include_str!("../tests/vectors/fast_frames.txt");
    const CLI_FRAMES: &str = include_str!("../tests/vectors/frames_zstd_cli.txt");

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

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The content of the first reference frame cut from the corpus slice
    /// `slice` (labels in the CLI fixture are `slice:zstd-options`).
    fn corpus_slice(slice: &str) -> Vec<u8> {
        let line = CLI_FRAMES
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find(|line| line.split(':').next() == Some(slice))
            .unwrap_or_else(|| panic!("no reference frame for {slice}"));
        let fields: Vec<&str> = line.split_whitespace().collect();
        let length: usize = fields[1].parse().unwrap();
        decode_all(&hex(fields[3]), &DecodeLimits::new(length)).unwrap()
    }

    /// `fast_frames.txt` holds the frame length and XXH64 of the frame the
    /// scratch Python model of this encoder wrote for each input, and each of
    /// those frames was decoded to its input by reference zstd 1.5.7. Equal
    /// digests mean this encoder writes those same reference-checked bytes.
    #[test]
    fn fast_frames_match_the_reference_checked_model() {
        let mut seen = 0;
        for line in FAST.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let data = if fields[0] == "range256x40000" {
                (0..=255_u8).cycle().take(256 * 40_000).collect()
            } else {
                corpus_slice(fields[0])
            };
            assert_eq!(data.len(), fields[1].parse::<usize>().unwrap(), "{line}");
            let frame = encode_all(&data, &EncodeParams::new(Level::Fast));
            assert_eq!(
                (frame.len(), xxh64(&frame, 0)),
                (
                    fields[2].parse().unwrap(),
                    u64::from_str_radix(fields[3], 16).unwrap()
                ),
                "{line}"
            );
            assert_eq!(
                decode_all(&frame, &DecodeLimits::new(data.len())).as_deref(),
                Ok(&data[..]),
                "{line}"
            );
            seen += 1;
        }
        assert_eq!(seen, 39, "the model file must keep all 39 inputs");
    }

    /// Text-like data: words drawn from a small vocabulary, so there are
    /// repeats at many distances and a skewed byte distribution.
    fn words(seed: u64, len: usize) -> Vec<u8> {
        const VOCABULARY: [&str; 12] = [
            "region ",
            "task ",
            "cancel ",
            "obligation ",
            "scope ",
            "spawn ",
            "join ",
            "the ",
            "of ",
            "a ",
            "budget\n",
            "trace ",
        ];
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(
                VOCABULARY[usize::try_from(state >> 60).unwrap() % 12].as_bytes(),
            );
        }
        out.truncate(len);
        out
    }

    #[test]
    fn fast_frames_round_trip_and_compress() {
        let seven_bit: Vec<u8> = lcg(77, 20_000)
            .into_iter()
            .map(|byte| byte & 0x7F)
            .collect();
        let mut mixed = words(3, 150_000);
        mixed.extend(lcg(4, 40_000));
        mixed.extend(words(3, 150_000));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![7]),
            ("text 63", words(1, 63)),
            ("text 64", words(1, 64)),
            ("text 255", words(1, 255)),
            ("text 256", words(1, 256)),
            ("text 16 KiB - 1", words(2, 16 * 1024 - 1)),
            ("text 16 KiB", words(2, 16 * 1024)),
            ("text 128 KiB", words(2, 128 * 1024)),
            ("text 128 KiB + 1", words(2, 128 * 1024 + 1)),
            ("text 1 MiB", words(5, 1 << 20)),
            ("zeros 300000", vec![0; 300_000]),
            ("random 70000", lcg(9, 70_000)),
            // Equal Huffman weights for all 128 symbols (see huffman.rs).
            ("random 7-bit", seven_bit),
            ("text, noise, the same text", mixed),
        ];
        for (name, data) in &cases {
            for checksum in [true, false] {
                let params = EncodeParams {
                    checksum,
                    ..EncodeParams::new(Level::Fast)
                };
                let frame = encode_all(data, &params);
                let limits = DecodeLimits {
                    require_content_size: true,
                    ..DecodeLimits::new(data.len())
                };
                assert_eq!(
                    decode_all(&frame, &limits).as_deref(),
                    Ok(&data[..]),
                    "{name}, checksum {checksum}"
                );
                // Incompressible data costs at most the headers.
                let blocks = data.len().div_ceil(128 * 1024).max(1);
                assert!(frame.len() <= data.len() + 3 * blocks + 18, "{name}");
            }
        }
        let size = |name: &str| {
            let (_, data) = cases.iter().find(|(case, _)| *case == name).unwrap();
            encode_all(data, &EncodeParams::new(Level::Fast)).len()
        };
        assert!(
            size("zeros 300000") < 300,
            "runs collapse to a few sequences"
        );
        assert!(
            size("text 1 MiB") < (1 << 20) / 4,
            "repetitive text compresses"
        );
        assert!(
            size("random 7-bit") < 18_500,
            "7-bit literals use Huffman coding"
        );
        // The second copy of the text matches the first, 190 000 bytes back.
        assert!(size("text, noise, the same text") < size("text 128 KiB") + 70_000);
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
