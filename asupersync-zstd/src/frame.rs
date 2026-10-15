//! Zstandard frames and blocks, RFC 8878 §3.1, with explicit decode limits.

use crate::huffman::HuffmanTable;
use crate::literals::decode_literals;
use crate::sequences::{BlockBounds, MAX_BLOCK_OUTPUT, SequenceState, decode_sequences, reserve};
use crate::xxhash64::Xxh64;

const FRAME_MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

/// Why a Zstandard input was refused. Every variant is a clean refusal; the
/// decoder never panics on malformed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended inside a frame.
    Truncated,
    /// The input does not start with a Zstandard (or allowed skippable) frame.
    BadMagic,
    /// The frame needs a dictionary; dictionaries are not supported.
    DictionaryUnsupported,
    /// The frame's window exceeds [`DecodeLimits::max_window`].
    WindowTooLarge,
    /// Decoding would exceed [`DecodeLimits::max_output`].
    OutputTooLarge,
    /// [`DecodeLimits::require_content_size`] is set and the frame does not
    /// declare its content size.
    ContentSizeMissing,
    /// The decoded size differs from the frame's declared content size.
    ContentSizeMismatch,
    /// The content checksum does not match the decoded bytes.
    ChecksumMismatch,
    /// The frame violates RFC 8878; the text names the rule.
    Malformed(&'static str),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("zstd: input truncated"),
            Self::BadMagic => f.write_str("zstd: not a Zstandard frame"),
            Self::DictionaryUnsupported => f.write_str("zstd: dictionaries are not supported"),
            Self::WindowTooLarge => f.write_str("zstd: window exceeds the decode limit"),
            Self::OutputTooLarge => f.write_str("zstd: output exceeds the decode limit"),
            Self::ContentSizeMissing => {
                f.write_str("zstd: frame does not declare its content size")
            }
            Self::ContentSizeMismatch => f.write_str("zstd: content size mismatch"),
            Self::ChecksumMismatch => f.write_str("zstd: content checksum mismatch"),
            Self::Malformed(rule) => write!(f, "zstd: malformed input: {rule}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Resource limits for decoding untrusted input. There is no unbounded
/// decode entry point.
///
/// Build them with [`Self::new`] and the `with_*` methods. The struct is
/// `#[non_exhaustive]`, so later limits can be added without breaking
/// callers, and a struct literal does not compile outside this crate:
///
/// ```compile_fail,E0639
/// let limits = asupersync_zstd::DecodeLimits {
///     max_output: 1 << 20,
///     max_window: 1 << 20,
///     require_content_size: true,
///     allow_skippable_frames: false,
/// };
/// ```
///
/// ```
/// let limits = asupersync_zstd::DecodeLimits::new(1 << 20)
///     .with_max_window(1 << 20)
///     .with_require_content_size(true)
///     .with_allow_skippable_frames(false);
/// assert_eq!(limits.max_window, 1 << 20);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeLimits {
    /// The most bytes decoding may produce in total.
    pub max_output: usize,
    /// The largest frame window accepted. Defaults to 8 MiB, which RFC 9659
    /// requires HTTP `zstd` decoders to support and encoders not to exceed.
    pub max_window: usize,
    /// Refuse frames that do not declare their content size.
    pub require_content_size: bool,
    /// Skip skippable frames instead of refusing them.
    pub allow_skippable_frames: bool,
}

impl DecodeLimits {
    /// The default 8 MiB window limit.
    pub const DEFAULT_MAX_WINDOW: usize = 8 << 20;

    /// Limits allowing at most `max_output` bytes, with an 8 MiB window,
    /// optional content size and skippable frames allowed.
    #[must_use]
    pub const fn new(max_output: usize) -> Self {
        Self {
            max_output,
            max_window: Self::DEFAULT_MAX_WINDOW,
            require_content_size: false,
            allow_skippable_frames: true,
        }
    }

    /// These limits with the largest accepted frame window set to
    /// `max_window` bytes.
    #[must_use]
    pub const fn with_max_window(mut self, max_window: usize) -> Self {
        self.max_window = max_window;
        self
    }

    /// These limits refusing (`true`) or accepting frames that do not declare
    /// their content size.
    #[must_use]
    pub const fn with_require_content_size(mut self, require: bool) -> Self {
        self.require_content_size = require;
        self
    }

    /// These limits skipping (`true`) or refusing skippable frames.
    #[must_use]
    pub const fn with_allow_skippable_frames(mut self, allow: bool) -> Self {
        self.allow_skippable_frames = allow;
        self
    }
}

fn read_le(input: &[u8], pos: usize, width: usize) -> Result<u64, DecodeError> {
    let bytes = input.get(pos..pos + width).ok_or(DecodeError::Truncated)?;
    let mut word = [0_u8; 8];
    word.get_mut(..width)
        .ok_or(DecodeError::Truncated)?
        .copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
}

/// Decodes every frame in `input` (concatenated frames are allowed) within
/// `limits`.
pub fn decode_all(input: &[u8], limits: &DecodeLimits) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    decode_frames(input, limits, &mut out)?;
    Ok(out)
}

/// Decodes every frame in `input` and appends the output to `out`.
///
/// It reuses `out`'s capacity, so a buffer kept across calls stops
/// allocating once it is large enough. `limits.max_output` bounds the bytes
/// appended, and no frame reaches back into what `out` held before. Returns
/// the bytes appended; on error, `out` is truncated back to its previous
/// length.
pub fn decode_append(
    input: &[u8],
    out: &mut Vec<u8>,
    limits: &DecodeLimits,
) -> Result<usize, DecodeError> {
    let start = out.len();
    let absolute = DecodeLimits {
        max_output: start.saturating_add(limits.max_output),
        ..*limits
    };
    let decoded = decode_frames(input, &absolute, out);
    if decoded.is_err() {
        out.truncate(start);
    }
    decoded.map(|()| out.len() - start)
}

/// Decodes every frame in `input`, appending to `out`, whose final length
/// `limits.max_output` bounds.
fn decode_frames(
    input: &[u8],
    limits: &DecodeLimits,
    out: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Truncated);
    }
    let mut pos = 0;
    while pos < input.len() {
        pos += decode_frame(&input[pos..], limits, out)?;
    }
    Ok(())
}

/// Decodes every frame in `input` into `out`, which also bounds the output:
/// `max_output` is `min(limits.max_output, out.len())`. Returns the bytes
/// written.
pub fn decode_into(
    input: &[u8],
    out: &mut [u8],
    limits: &DecodeLimits,
) -> Result<usize, DecodeError> {
    let bounded = DecodeLimits {
        max_output: limits.max_output.min(out.len()),
        ..*limits
    };
    let decoded = decode_all(input, &bounded)?;
    let target = out
        .get_mut(..decoded.len())
        .ok_or(DecodeError::OutputTooLarge)?;
    target.copy_from_slice(&decoded);
    Ok(decoded.len())
}

/// Decodes one frame (or skips one skippable frame) at the start of
/// `input`, appending to `out`. Returns the bytes consumed.
fn decode_frame(
    input: &[u8],
    limits: &DecodeLimits,
    out: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    let magic = u32::try_from(read_le(input, 0, 4)?).map_err(|_| DecodeError::BadMagic)?;
    if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC {
        if !limits.allow_skippable_frames {
            return Err(DecodeError::BadMagic);
        }
        let size = usize::try_from(read_le(input, 4, 4)?).map_err(|_| DecodeError::Truncated)?;
        let end = 8_usize.checked_add(size).ok_or(DecodeError::Truncated)?;
        if end > input.len() {
            return Err(DecodeError::Truncated);
        }
        return Ok(end);
    }
    if magic != FRAME_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let descriptor = *input.get(4).ok_or(DecodeError::Truncated)?;
    let content_size_flag = descriptor >> 6;
    let single_segment = descriptor & 0x20 != 0;
    if descriptor & 0x08 != 0 {
        return Err(DecodeError::Malformed("reserved frame header bit"));
    }
    let has_checksum = descriptor & 0x04 != 0;
    let dictionary_id_size = [0, 1, 2, 4][usize::from(descriptor & 3)];
    let content_size_width = match content_size_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    // A header cut short is truncated input, whatever its fields say. The
    // stream decoder buffers the whole header before reading any field.
    if input.len() < 5 + usize::from(!single_segment) + dictionary_id_size + content_size_width {
        return Err(DecodeError::Truncated);
    }
    let mut pos = 5;
    let descriptor_window = if single_segment {
        None
    } else {
        let window_descriptor = *input.get(pos).ok_or(DecodeError::Truncated)?;
        pos += 1;
        let log = 10 + u32::from(window_descriptor >> 3);
        let base = 1_u64 << log;
        let size = base + (base / 8) * u64::from(window_descriptor & 7);
        Some(usize::try_from(size).unwrap_or(usize::MAX))
    };
    if dictionary_id_size > 0 && read_le(input, pos, dictionary_id_size)? != 0 {
        return Err(DecodeError::DictionaryUnsupported);
    }
    pos += dictionary_id_size;
    let content_size = if content_size_width == 0 {
        None
    } else {
        let value = read_le(input, pos, content_size_width)?;
        pos += content_size_width;
        let value = if content_size_width == 2 {
            value + 256
        } else {
            value
        };
        Some(usize::try_from(value).unwrap_or(usize::MAX))
    };
    let window = if single_segment {
        content_size
    } else {
        descriptor_window
    }
    .ok_or(DecodeError::Malformed("frame without a window"))?;
    if window > limits.max_window {
        return Err(DecodeError::WindowTooLarge);
    }
    if limits.require_content_size && content_size.is_none() {
        return Err(DecodeError::ContentSizeMissing);
    }
    if let Some(declared) = content_size
        && out.len().saturating_add(declared) > limits.max_output
    {
        return Err(DecodeError::OutputTooLarge);
    }

    let frame_start = out.len();
    // A frame that declares its size may not produce more: it is refused as
    // soon as a block would pass the declared end, not after decoding up to
    // `max_output` (the check above keeps that end within `max_output`).
    let (limit, overflow) = content_size.map_or(
        (limits.max_output, DecodeError::OutputTooLarge),
        |declared| (frame_start + declared, DecodeError::ContentSizeMismatch),
    );
    let overflowed = |error: DecodeError| {
        if error == DecodeError::OutputTooLarge {
            overflow
        } else {
            error
        }
    };
    let bounds = BlockBounds {
        frame_start,
        window,
        block_maximum: window.min(MAX_BLOCK_OUTPUT),
        limit,
    };
    let mut huffman: Option<HuffmanTable> = None;
    let mut sequences = SequenceState::new()?;
    let mut literals = Vec::new();
    loop {
        let header = u32::try_from(read_le(input, pos, 3)?).map_err(|_| DecodeError::Truncated)?;
        pos += 3;
        let last = header & 1 != 0;
        let block_type = (header >> 1) & 3;
        let block_size = usize::try_from(header >> 3).map_err(|_| DecodeError::Truncated)?;
        if block_size > bounds.block_maximum {
            return Err(DecodeError::Malformed(
                "block larger than Block_Maximum_Size",
            ));
        }
        match block_type {
            0 => {
                let bytes = input
                    .get(pos..pos + block_size)
                    .ok_or(DecodeError::Truncated)?;
                reserve(out, block_size, limit).map_err(overflowed)?;
                out.extend_from_slice(bytes);
                pos += block_size;
            }
            1 => {
                let byte = *input.get(pos).ok_or(DecodeError::Truncated)?;
                reserve(out, block_size, limit).map_err(overflowed)?;
                out.resize(out.len() + block_size, byte);
                pos += 1;
            }
            2 => {
                let block = input
                    .get(pos..pos + block_size)
                    .ok_or(DecodeError::Truncated)?;
                // The block decodes to at most Block_Maximum_Size bytes:
                // make room for that much (within the frame's limit) once,
                // so the block never reallocates the output.
                let most = bounds.block_maximum.min(limit.saturating_sub(out.len()));
                reserve(out, most, limit).map_err(overflowed)?;
                decode_compressed_block(
                    block,
                    &mut huffman,
                    &mut literals,
                    &mut sequences,
                    out,
                    bounds,
                )
                .map_err(overflowed)?;
                pos += block_size;
            }
            _ => return Err(DecodeError::Malformed("reserved block type")),
        }
        if last {
            break;
        }
    }
    let produced = &out[frame_start..];
    if let Some(declared) = content_size
        && produced.len() != declared
    {
        return Err(DecodeError::ContentSizeMismatch);
    }
    if has_checksum {
        let stored = read_le(input, pos, 4)?;
        pos += 4;
        let mut hasher = Xxh64::new(0);
        hasher.update(produced);
        if hasher.digest() & 0xFFFF_FFFF != stored {
            return Err(DecodeError::ChecksumMismatch);
        }
    }
    Ok(pos)
}

/// Decodes one compressed block, all `Block_Size` bytes of it, appending its
/// output to `out` within `bounds`. Since the whole block is at hand, a
/// literals or sequences section that runs past its end is malformed, not
/// truncated input.
pub fn decode_compressed_block(
    block: &[u8],
    huffman: &mut Option<HuffmanTable>,
    literals: &mut Vec<u8>,
    sequences: &mut SequenceState,
    out: &mut Vec<u8>,
    bounds: BlockBounds,
) -> Result<(), DecodeError> {
    let used = decode_literals(block, bounds.block_maximum, huffman, literals).map_err(overrun)?;
    let section = block.get(used..).ok_or(OVERRUN)?;
    decode_sequences(section, literals, sequences, out, bounds).map_err(overrun)
}

const OVERRUN: DecodeError = DecodeError::Malformed("block sections run past Block_Size");

fn overrun(error: DecodeError) -> DecodeError {
    if error == DecodeError::Truncated {
        OVERRUN
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodeError, DecodeLimits, decode_all, decode_append, decode_into};
    use crate::xxhash64::xxh64;

    const FRAMES: &str = include_str!("../tests/vectors/frames_zstd_cli.txt");

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Vec<(String, usize, u64, Vec<u8>)> {
        FRAMES
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                (
                    fields[0].to_owned(),
                    fields[1].parse().unwrap(),
                    u64::from_str_radix(fields[2], 16).unwrap(),
                    hex(fields[3]),
                )
            })
            .collect()
    }

    #[test]
    fn decodes_every_reference_frame() {
        let all = vectors();
        assert_eq!(all.len(), 264, "the golden file must keep all 264 frames");
        for (label, length, digest, frame) in &all {
            let out = decode_all(frame, &DecodeLimits::new(*length)).unwrap_or_else(|error| {
                panic!("{label}: {error}");
            });
            assert_eq!(out.len(), *length, "{label}");
            assert_eq!(xxh64(&out, 0), *digest, "{label}");
            let mut exact = vec![0_u8; *length];
            assert_eq!(
                decode_into(frame, &mut exact, &DecodeLimits::new(usize::MAX)),
                Ok(*length),
                "{label}"
            );
            assert_eq!(exact, out, "{label}");
        }
    }

    #[test]
    fn output_limit_is_enforced() {
        for (label, length, _, frame) in vectors().iter().filter(|v| v.1 > 1) {
            assert_eq!(
                decode_all(frame, &DecodeLimits::new(length - 1)),
                Err(DecodeError::OutputTooLarge),
                "{label}"
            );
        }
    }

    /// Each builder sets exactly its own limit and keeps the others.
    #[test]
    fn builders_set_one_limit_each() {
        let base = DecodeLimits::new(10);
        assert_eq!(
            base,
            DecodeLimits {
                max_output: 10,
                max_window: DecodeLimits::DEFAULT_MAX_WINDOW,
                require_content_size: false,
                allow_skippable_frames: true,
            }
        );
        assert_eq!(
            base.with_max_window(1024),
            DecodeLimits {
                max_window: 1024,
                ..base
            }
        );
        assert_eq!(
            base.with_require_content_size(true),
            DecodeLimits {
                require_content_size: true,
                ..base
            }
        );
        assert_eq!(
            base.with_allow_skippable_frames(false),
            DecodeLimits {
                allow_skippable_frames: false,
                ..base
            }
        );
    }

    #[test]
    fn window_limit_is_enforced() {
        let (_, length, _, frame) = vectors()
            .into_iter()
            .find(|v| v.0.contains("--long=20") && v.1 > 30_000)
            .unwrap();
        let limits = DecodeLimits {
            max_window: 1024,
            ..DecodeLimits::new(length)
        };
        assert_eq!(
            decode_all(&frame, &limits),
            Err(DecodeError::WindowTooLarge)
        );
    }

    #[test]
    fn corrupted_frames_are_refused_without_panicking() {
        let mut state = 0x6A09_E667_F3BC_C908_u64;
        for (label, length, _, frame) in vectors().iter().take(120) {
            for _ in 0..8 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let mut damaged = frame.clone();
                let at = usize::try_from(state >> 33).unwrap() % damaged.len();
                damaged[at] ^= u8::try_from((state >> 8) & 0xFF).unwrap() | 1;
                let limits = DecodeLimits::new(length + 4096);
                // Either a clean error or (rarely) a different valid decode;
                // never a panic, never more than the limit.
                if let Ok(out) = decode_all(&damaged, &limits) {
                    assert!(out.len() <= limits.max_output, "{label}");
                }
            }
            for cut in [1, frame.len() / 2, frame.len().saturating_sub(1)] {
                if cut < frame.len() && cut > 0 {
                    assert!(
                        decode_all(&frame[..cut], &DecodeLimits::new(length + 1)).is_err(),
                        "{label} cut at {cut}"
                    );
                }
            }
        }
    }

    #[test]
    fn checksum_and_header_errors_are_reported() {
        let (label, length, _, frame) = vectors()
            .into_iter()
            .find(|v| v.0.ends_with(":-1") && v.1 == 700)
            .unwrap();
        let mut bad_checksum = frame.clone();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 0x01;
        assert_eq!(
            decode_all(&bad_checksum, &DecodeLimits::new(length)),
            Err(DecodeError::ChecksumMismatch),
            "{label}"
        );
        let mut bad_magic = frame.clone();
        bad_magic[0] ^= 0x01;
        assert_eq!(
            decode_all(&bad_magic, &DecodeLimits::new(length)),
            Err(DecodeError::BadMagic)
        );
        let mut reserved = frame;
        reserved[4] |= 0x08;
        assert_eq!(
            decode_all(&reserved, &DecodeLimits::new(length)),
            Err(DecodeError::Malformed("reserved frame header bit"))
        );
        assert_eq!(
            decode_all(&[], &DecodeLimits::new(1)),
            Err(DecodeError::Truncated)
        );
    }

    /// Block_Maximum_Size is min(window, 128 KiB) for the decoded size of
    /// compressed blocks too. Both frames have a 1 KiB window and a small
    /// compressed block that decodes to more than 1 KiB: RLE literals of 2000
    /// bytes, and one literal plus a 1027-byte match. Reference zstd 1.5.7
    /// refuses both ("Data corruption detected") and decodes the same blocks
    /// under a 128 KiB window (descriptor 0x38).
    #[test]
    fn small_windows_bound_compressed_blocks() {
        for (frame, expected) in [
            ("28B52FFD0000250000057D6100", 2000),
            ("28B52FFD00004D00000861015401002E0004", 1028),
        ] {
            let mut frame = hex(frame);
            assert!(
                matches!(
                    decode_all(&frame, &DecodeLimits::new(1 << 20)),
                    Err(DecodeError::Malformed(_))
                ),
                "{frame:02X?}"
            );
            frame[5] = 0x38;
            assert_eq!(
                decode_all(&frame, &DecodeLimits::new(1 << 20)),
                Ok(vec![b'a'; expected])
            );
        }
    }

    /// decode_append adds after what the buffer holds, bounds only the bytes
    /// it appends, reuses the buffer's capacity, and leaves the buffer as it
    /// was on error.
    #[test]
    fn decode_append_reuses_the_buffer_and_restores_it_on_error() {
        let (label, length, _, frame) = vectors().into_iter().find(|v| v.1 > 10_000).unwrap();
        let expected = decode_all(&frame, &DecodeLimits::new(length)).unwrap();
        let mut out = b"prefix".to_vec();
        out.reserve(length);
        let buffer = out.as_ptr();
        assert_eq!(
            decode_append(&frame, &mut out, &DecodeLimits::new(length)),
            Ok(length),
            "{label}"
        );
        assert_eq!(&out[..6], b"prefix");
        assert!(out[6..] == expected[..], "{label}");
        assert_eq!(out.as_ptr(), buffer, "{label}: no reallocation");

        out.truncate(6);
        assert_eq!(
            decode_append(&frame, &mut out, &DecodeLimits::new(length - 1)),
            Err(DecodeError::OutputTooLarge),
            "{label}: the limit counts appended bytes only"
        );
        assert_eq!(out, b"prefix");
        assert!(
            decode_append(
                &frame[..frame.len() / 2],
                &mut out,
                &DecodeLimits::new(length)
            )
            .is_err(),
            "{label}: truncated"
        );
        assert_eq!(out, b"prefix", "{label}: restored after an error");
    }

    /// A 3-byte block header.
    fn block_header(size: u32, block_type: u32, last: bool) -> [u8; 3] {
        let header = (size << 3) | (block_type << 1) | u32::from(last);
        let bytes = header.to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    }

    /// A frame that declares its size is refused as soon as a block passes
    /// the declared end, before decoding on toward `max_output`: here the
    /// first 128 KiB RLE block of a frame declaring 256 bytes, where
    /// decoding the second block would only then pass `max_output`.
    #[test]
    fn the_declared_size_bounds_decoding() {
        // Content-size flag 1 (2 bytes, plus 256), window 128 KiB, size 256.
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x40, 0x38, 0x00, 0x00];
        for last in [false, true] {
            frame.extend_from_slice(&block_header(128 * 1024, 1, last));
            frame.push(b'a');
        }
        assert_eq!(
            decode_all(&frame, &DecodeLimits::new(200_000)),
            Err(DecodeError::ContentSizeMismatch)
        );
    }

    /// Without a declared size, the output grows up to `max_output` and its
    /// capacity never doubles past it.
    #[test]
    fn output_capacity_stays_within_the_limit() {
        // No content size, window 128 KiB, RLE blocks of 40 000 and 30 000.
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
        frame.extend_from_slice(&block_header(40_000, 1, false));
        frame.push(b'x');
        frame.extend_from_slice(&block_header(30_000, 1, true));
        frame.push(b'y');
        let out = decode_all(&frame, &DecodeLimits::new(70_000)).unwrap();
        assert_eq!(out.len(), 70_000);
        assert!(out.capacity() < 80_000, "capacity {}", out.capacity());
        assert_eq!(
            decode_all(&frame, &DecodeLimits::new(69_999)),
            Err(DecodeError::OutputTooLarge)
        );
    }

    #[test]
    fn skippable_frames_follow_the_limits() {
        let (_, length, _, frame) = vectors()
            .into_iter()
            .find(|v| v.0.ends_with(":-3") && v.1 == 700)
            .unwrap();
        let mut input = vec![0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 9, 9, 9];
        input.extend_from_slice(&frame);
        assert_eq!(
            decode_all(&input, &DecodeLimits::new(length)).map(|out| out.len()),
            Ok(length)
        );
        let strict = DecodeLimits {
            allow_skippable_frames: false,
            ..DecodeLimits::new(length)
        };
        assert_eq!(decode_all(&input, &strict), Err(DecodeError::BadMagic));
    }
}
