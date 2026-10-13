//! Incremental frame parsing with bounded block and sliding-history storage.

use crate::huffman::HuffmanTable;
use crate::literals::decode_literals;
use crate::sequences::{MAX_BLOCK_OUTPUT, SequenceState, decode_sequences};
use crate::{DecodeError, DecodeLimits, StreamProgress, StreamStatus, Xxh64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Magic,
    Descriptor,
    Header(usize),
    SkipLength,
    Skip(usize),
    BlockHeader,
    Block { kind: u8, size: usize, last: bool },
    Checksum,
    Boundary,
}

struct FrameState {
    window: usize,
    content_size: Option<usize>,
    produced: usize,
    checksum: bool,
    hasher: Xxh64,
    huffman: Option<HuffmanTable>,
    sequences: SequenceState,
    literals: Vec<u8>,
    history: Vec<u8>,
    emitted: usize,
}

impl FrameState {
    fn parse(header: &[u8], limits: DecodeLimits, total: usize) -> Result<Self, DecodeError> {
        let descriptor = header[0];
        let single = descriptor & 0x20 != 0;
        let dictionary_width = [0, 1, 2, 4][usize::from(descriptor & 3)];
        let mut pos = 1;
        let descriptor_window = if single {
            0
        } else {
            let value = header[pos];
            pos += 1;
            let base = 1_u64 << (10 + u32::from(value >> 3));
            base + (base / 8) * u64::from(value & 7)
        };
        if little_endian(&header[pos..pos + dictionary_width]) != 0 {
            return Err(DecodeError::DictionaryUnsupported);
        }
        pos += dictionary_width;
        let width = header.len() - pos;
        let content_size = if width == 0 {
            None
        } else {
            let value = little_endian(&header[pos..]);
            let value = if width == 2 { value + 256 } else { value };
            Some(usize::try_from(value).map_err(|_| DecodeError::OutputTooLarge)?)
        };
        let window = if single {
            content_size.ok_or(DecodeError::ContentSizeMissing)?
        } else {
            usize::try_from(descriptor_window).map_err(|_| DecodeError::WindowTooLarge)?
        };
        if window > limits.max_window {
            return Err(DecodeError::WindowTooLarge);
        }
        if limits.require_content_size && content_size.is_none() {
            return Err(DecodeError::ContentSizeMissing);
        }
        if content_size.is_some_and(|size| size > limits.max_output.saturating_sub(total)) {
            return Err(DecodeError::OutputTooLarge);
        }
        Ok(Self {
            window,
            content_size,
            produced: 0,
            checksum: descriptor & 4 != 0,
            hasher: Xxh64::new(0),
            huffman: None,
            sequences: SequenceState::new()?,
            literals: Vec::new(),
            history: Vec::new(),
            emitted: 0,
        })
    }

    fn decode_block(
        &mut self,
        block: &[u8],
        kind: u8,
        size: usize,
        remaining: usize,
    ) -> Result<usize, DecodeError> {
        // Compact only once per window, not once per block. Offsets are still
        // limited to one window by decode_sequences. The extra retained window
        // amortizes the copy cost without retaining the entire frame.
        if self.history.len().saturating_sub(self.window) >= self.window {
            let keep = self.history.len().min(self.window);
            let start = self.history.len() - keep;
            self.history.copy_within(start.., 0);
            self.history.truncate(keep);
        }
        let start = self.history.len();
        self.emitted = start;
        let allowance = remaining.min(self.window.min(MAX_BLOCK_OUTPUT));
        let cap = start
            .checked_add(allowance)
            .ok_or(DecodeError::OutputTooLarge)?;
        match kind {
            0 => {
                if size > allowance {
                    return Err(DecodeError::OutputTooLarge);
                }
                self.history.extend_from_slice(block);
            }
            1 => {
                if size > allowance {
                    return Err(DecodeError::OutputTooLarge);
                }
                self.history.resize(start + size, block[0]);
            }
            2 => {
                let used = decode_literals(block, &mut self.huffman, &mut self.literals)?;
                let section = block.get(used..).ok_or(DecodeError::Truncated)?;
                decode_sequences(
                    section,
                    &self.literals,
                    &mut self.sequences,
                    &mut self.history,
                    0,
                    self.window,
                    cap,
                )?;
            }
            _ => return Err(DecodeError::Malformed("reserved block type")),
        }
        let produced = self.history.len() - start;
        self.produced = self
            .produced
            .checked_add(produced)
            .ok_or(DecodeError::OutputTooLarge)?;
        if self.content_size.is_some_and(|size| self.produced > size) {
            return Err(DecodeError::ContentSizeMismatch);
        }
        if self.checksum {
            self.hasher.update(&self.history[start..]);
        }
        Ok(produced)
    }
}

/// Incrementally decodes concatenated Zstandard frames without retaining an
/// entire encoded or decoded frame. Dictionaries are not supported.
///
/// Input and output are caller-owned slices. `decode` accepts a prefix, emits
/// a prefix, and reports both lengths. Preserve unconsumed input. Output
/// backpressure stops further input admission until the pending block drains.
/// Each call decodes at most one block, or skips at most 128 KiB of metadata;
/// the caller controls scheduling and I/O. No tasks or ambient effects exist.
///
/// The configured output limit is cumulative across all concatenated frames,
/// including decoded bytes not yet emitted. The window limit is checked before
/// constructing frame state. Buffer lengths are bounded by two windows plus
/// one decoded block, one encoded block, and the codec's bounded literals and
/// entropy-table workspace; allocation capacity may exceed buffer length.
/// Skippable frame payloads are discarded incrementally, never buffered.
///
/// **Output is provisional until `FrameFinished`.** A checksum, content-size,
/// or truncation error can be discovered after earlier output was delivered.
/// Callers requiring atomic publication must stage output themselves. A frame
/// boundary validates that frame, not subsequent frames or the whole stream.
/// Call `finish` at transport EOF to detect truncation, including an empty
/// input stream. Malformed-data and limit errors are terminal and sticky.
///
/// Retaining this object across a cancelled I/O wait retains its accepted
/// bytes and progress. Dropping it discards buffered bytes, does not finish
/// validation, and does not make the enclosing I/O operation cancel-safe.
///
/// # Example
///
/// ```
/// use asupersync_zstd::{DecodeLimits, StreamDecoder, StreamStatus};
///
/// let wire = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 2, 0x11, 0, 0, b'h', b'i'];
/// let mut decoder = StreamDecoder::new(DecodeLimits::new(1024));
/// let mut output = [0; 1];
/// let mut decoded = Vec::new();
/// let mut offset = 0;
/// while offset < wire.len() {
///     let step = decoder.decode(&wire[offset..], &mut output)?;
///     offset += step.input_read;
///     decoded.extend_from_slice(&output[..step.output_written]);
/// }
/// loop {
///     let step = decoder.finish(&mut output)?;
///     decoded.extend_from_slice(&output[..step.output_written]);
///     if step.status == StreamStatus::Finished {
///         break;
///     }
/// }
/// assert_eq!(decoded, b"hi");
/// # Ok::<(), asupersync_zstd::DecodeError>(())
/// ```
pub struct StreamDecoder {
    limits: DecodeLimits,
    stage: Stage,
    input: Vec<u8>,
    frame: Option<FrameState>,
    total: usize,
    saw_frame: bool,
    finishing: bool,
    error: Option<DecodeError>,
}

impl core::fmt::Debug for StreamDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamDecoder")
            .field("limits", &self.limits)
            .field("stage", &self.stage)
            .field("total", &self.total)
            .field("finishing", &self.finishing)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl StreamDecoder {
    /// Creates a decoder with explicit cumulative output and per-frame window
    /// limits. Storage is allocated lazily as input arrives.
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            stage: Stage::Magic,
            input: Vec::new(),
            frame: None,
            total: 0,
            saw_frame: false,
            finishing: false,
            error: None,
        }
    }

    /// Processes a prefix of `input`. Continue with the unconsumed suffix,
    /// even when `NeedInput` or `FrameFinished` is returned. `NeedInput` with
    /// all input consumed means more bytes are needed; it is not EOF.
    ///
    /// `NeedOutput` requires fresh output space. An empty input slice can
    /// drain pending output. An empty output slice can accept at most one
    /// block before admission stops. On error this call writes no output,
    /// although input and private state may already have advanced; no retry
    /// or recovery is permitted. Earlier calls' output remains provisional.
    /// Calling `decode` after finalization has started refuses new input.
    pub fn decode(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<StreamProgress, DecodeError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.finishing {
            return Err(DecodeError::Malformed("stream decoder is finishing or finished"));
        }
        let result = self.decode_inner(input, output);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    /// Declares transport EOF and drains a completely received final frame.
    /// Repeat while `NeedOutput` is returned. Successful completion is
    /// idempotent. Supply all unconsumed input to `decode` before calling.
    ///
    /// Any incomplete header, block, checksum, or skippable payload returns
    /// `Truncated`, as does an entirely empty stream. No output is written on
    /// that error. A failed decoder keeps returning its first error.
    pub fn finish(&mut self, output: &mut [u8]) -> Result<StreamProgress, DecodeError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.finishing = true;
        if self.stage != Stage::Boundary
            && !(self.stage == Stage::Magic && self.input.is_empty() && self.saw_frame)
        {
            self.error = Some(DecodeError::Truncated);
            return Err(DecodeError::Truncated);
        }
        let mut progress = self.emit(output, 0);
        if progress.status != StreamStatus::NeedOutput {
            progress.status = StreamStatus::Finished;
        }
        Ok(progress)
    }

    fn decode_inner(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<StreamProgress, DecodeError> {
        if self
            .frame
            .as_ref()
            .is_some_and(|frame| frame.emitted < frame.history.len())
        {
            return Ok(self.emit(output, 0));
        }
        let mut read = 0;
        loop {
            let needed = match self.stage {
                Stage::Magic | Stage::SkipLength | Stage::Checksum => 4,
                Stage::Descriptor | Stage::Block { kind: 1, .. } => 1,
                Stage::BlockHeader => 3,
                Stage::Header(size) | Stage::Block { size, .. } => size,
                Stage::Skip(remaining) => {
                    let skipped = remaining.min(input.len() - read).min(MAX_BLOCK_OUTPUT);
                    read += skipped;
                    if skipped == remaining {
                        self.stage = Stage::Boundary;
                        return Ok(self.emit(output, read));
                    }
                    self.stage = Stage::Skip(remaining - skipped);
                    return Ok(progress(read, 0, StreamStatus::NeedInput));
                }
                Stage::Boundary => return Ok(self.emit(output, read)),
            };
            let take = (needed - self.input.len()).min(input.len() - read);
            self.input.extend_from_slice(&input[read..read + take]);
            read += take;
            if self.input.len() < needed {
                return Ok(progress(read, 0, StreamStatus::NeedInput));
            }
            match self.stage {
                Stage::Magic => {
                    let magic = little_endian(&self.input);
                    self.stage = if magic == 0xFD2F_B528 {
                        Stage::Descriptor
                    } else if magic & 0xFFFF_FFF0 == 0x184D_2A50
                        && self.limits.allow_skippable_frames
                    {
                        Stage::SkipLength
                    } else {
                        return Err(DecodeError::BadMagic);
                    };
                    self.input.clear();
                }
                Stage::Descriptor => {
                    let descriptor = self.input[0];
                    if descriptor & 8 != 0 {
                        return Err(DecodeError::Malformed("reserved frame header bit"));
                    }
                    let single = descriptor & 0x20 != 0;
                    let content_width = match descriptor >> 6 {
                        0 => usize::from(single),
                        1 => 2,
                        2 => 4,
                        _ => 8,
                    };
                    let dictionary_width = [0, 1, 2, 4][usize::from(descriptor & 3)];
                    self.stage = Stage::Header(
                        1 + usize::from(!single) + dictionary_width + content_width,
                    );
                }
                Stage::Header(_) => {
                    self.frame = Some(FrameState::parse(&self.input, self.limits, self.total)?);
                    self.input.clear();
                    self.stage = Stage::BlockHeader;
                }
                Stage::SkipLength => {
                    let size = usize::try_from(little_endian(&self.input))
                        .map_err(|_| DecodeError::Truncated)?;
                    self.input.clear();
                    self.stage = Stage::Skip(size);
                }
                Stage::BlockHeader => {
                    let header = little_endian(&self.input);
                    let kind = u8::try_from((header >> 1) & 3).unwrap_or(3);
                    let size = usize::try_from(header >> 3).map_err(|_| DecodeError::Truncated)?;
                    let frame = self.frame.as_ref().ok_or(DecodeError::BadMagic)?;
                    if size > frame.window.min(MAX_BLOCK_OUTPUT) {
                        return Err(DecodeError::Malformed("block larger than Block_Maximum_Size"));
                    }
                    if kind == 3 {
                        return Err(DecodeError::Malformed("reserved block type"));
                    }
                    self.input.clear();
                    self.stage = Stage::Block {
                        kind,
                        size,
                        last: header & 1 != 0,
                    };
                }
                Stage::Block { kind, size, last } => {
                    let frame = self.frame.as_mut().ok_or(DecodeError::BadMagic)?;
                    let produced = frame.decode_block(
                        &self.input,
                        kind,
                        size,
                        self.limits.max_output - self.total,
                    )?;
                    self.total += produced;
                    if last && frame.content_size.is_some_and(|size| size != frame.produced) {
                        return Err(DecodeError::ContentSizeMismatch);
                    }
                    self.stage = if !last {
                        Stage::BlockHeader
                    } else if frame.checksum {
                        Stage::Checksum
                    } else {
                        Stage::Boundary
                    };
                    self.input.clear();
                    return Ok(self.emit(output, read));
                }
                Stage::Checksum => {
                    let frame = self.frame.as_ref().ok_or(DecodeError::BadMagic)?;
                    if frame.hasher.digest() & 0xFFFF_FFFF != little_endian(&self.input) {
                        return Err(DecodeError::ChecksumMismatch);
                    }
                    self.input.clear();
                    self.stage = Stage::Boundary;
                    return Ok(self.emit(output, read));
                }
                Stage::Skip(_) | Stage::Boundary => unreachable!("handled before buffering"),
            }
        }
    }

    fn emit(&mut self, output: &mut [u8], read: usize) -> StreamProgress {
        let mut written = 0;
        if let Some(frame) = &mut self.frame {
            written = output.len().min(frame.history.len() - frame.emitted);
            output[..written]
                .copy_from_slice(&frame.history[frame.emitted..frame.emitted + written]);
            frame.emitted += written;
            if frame.emitted < frame.history.len() {
                return progress(read, written, StreamStatus::NeedOutput);
            }
        }
        let status = if self.stage == Stage::Boundary {
            self.frame = None;
            self.stage = Stage::Magic;
            self.saw_frame = true;
            StreamStatus::FrameFinished
        } else {
            StreamStatus::NeedInput
        };
        progress(read, written, status)
    }
}

fn little_endian(bytes: &[u8]) -> u64 {
    let mut word = [0_u8; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

fn progress(input_read: usize, output_written: usize, status: StreamStatus) -> StreamProgress {
    StreamProgress {
        input_read,
        output_written,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BLOCK_OUTPUT, StreamDecoder};
    use crate::literals::encode_literals;
    use crate::sequences::{EncodedSequence, encode_sequences};
    use crate::{
        DecodeError, DecodeLimits, EncodeParams, Level, StreamStatus, decode_all, encode_all, xxh64,
    };

    const HI: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 2, 0x11, 0, 0, b'h', b'i'];

    fn decode_chunks(
        wire: &[u8],
        limits: DecodeLimits,
        input_chunk: usize,
        output_chunk: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let mut decoder = StreamDecoder::new(limits);
        let mut plain = Vec::new();
        let mut out = vec![0_u8; output_chunk];
        for chunk in wire.chunks(input_chunk) {
            let mut offset = 0;
            while offset < chunk.len() {
                let step = decoder.decode(&chunk[offset..], &mut out)?;
                assert!(step.input_read > 0 || step.output_written > 0);
                assert!(step.input_read <= chunk.len() - offset);
                assert!(step.output_written <= out.len());
                offset += step.input_read;
                plain.extend_from_slice(&out[..step.output_written]);
                assert!(plain.len() <= limits.max_output);
                if let Some(frame) = &decoder.frame {
                    assert!(frame.history.len() <= frame.window * 2 + MAX_BLOCK_OUTPUT);
                    assert!(frame.literals.len() <= MAX_BLOCK_OUTPUT);
                }
                assert!(decoder.input.len() <= MAX_BLOCK_OUTPUT);
            }
        }
        loop {
            let step = decoder.finish(&mut out)?;
            plain.extend_from_slice(&out[..step.output_written]);
            if step.status == StreamStatus::Finished {
                break;
            }
            assert_eq!(step.status, StreamStatus::NeedOutput);
            assert!(step.output_written > 0);
        }
        assert_eq!(decoder.finish(&mut []).unwrap().status, StreamStatus::Finished);
        Ok(plain)
    }

    fn block_header(size: usize, kind: u32, last: bool, out: &mut Vec<u8>) {
        let header = (u32::try_from(size).unwrap() << 3) | (kind << 1) | u32::from(last);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
    }

    #[test]
    fn every_header_and_body_split_with_single_byte_output() {
        let data = b"hello fragmented compression, hello fragmented compression";
        let mut frames = vec![HI.to_vec()];
        for level in [Level::Store, Level::Fast] {
            for checksum in [false, true] {
                frames.push(encode_all(data, &EncodeParams { level, checksum }));
            }
        }
        for frame in frames {
            let expected = decode_all(&frame, &DecodeLimits::new(1024)).unwrap();
            for chunk in 1..=frame.len() {
                for output in [1, 3, 128] {
                    assert_eq!(
                        decode_chunks(&frame, DecodeLimits::new(1024), chunk, output).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn all_reference_cli_frames_decode_incrementally() {
        let vectors = include_str!("../tests/vectors/frames_zstd_cli.txt");
        let mut count = 0;
        for line in vectors
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
        {
            let fields: Vec<_> = line.split_whitespace().collect();
            let length: usize = fields[1].parse().unwrap();
            let digest = u64::from_str_radix(fields[2], 16).unwrap();
            let wire: Vec<u8> = (0..fields[3].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).unwrap())
                .collect();
            let decoded = decode_chunks(&wire, DecodeLimits::new(length), 17, 257)
                .unwrap_or_else(|error| panic!("{}: {error}", fields[0]));
            assert_eq!(decoded.len(), length, "{}", fields[0]);
            assert_eq!(xxh64(&decoded, 0), digest, "{}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 264, "exercise the complete existing independent corpus");
    }

    #[test]
    fn compressed_matches_survive_repeated_history_compaction() {
        // No content-size field, 1 KiB window, checksum. First block seeds the
        // history; subsequent compressed blocks copy it at the window edge.
        let mut wire = vec![0x28, 0xb5, 0x2f, 0xfd, 4, 0];
        let seed: Vec<u8> = (0..1024).map(|i| u8::try_from(i % 251).unwrap()).collect();
        block_header(seed.len(), 0, false, &mut wire);
        wire.extend_from_slice(&seed);
        let mut body = Vec::new();
        encode_literals(&[], &mut body);
        encode_sequences(
            &[EncodedSequence {
                literals_length: 0,
                offset_value: 1027,
                match_length: 1024,
            }],
            &mut body,
        )
        .unwrap();
        for block in 0..20 {
            block_header(body.len(), 2, block == 19, &mut wire);
            wire.extend_from_slice(&body);
        }
        let expected = seed.repeat(21);
        wire.extend_from_slice(&xxh64(&expected, 0).to_le_bytes()[..4]);
        assert_eq!(decode_all(&wire, &DecodeLimits::new(expected.len())).unwrap(), expected);
        for output in [1, 13, 2048] {
            assert_eq!(
                decode_chunks(&wire, DecodeLimits::new(expected.len()), 7, output).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn output_pressure_preserves_input_and_finish_drains_final_block() {
        let mut decoder = StreamDecoder::new(DecodeLimits::new(2));
        let step = decoder.decode(HI, &mut []).unwrap();
        assert_eq!(step.input_read, HI.len());
        assert_eq!(step.status, StreamStatus::NeedOutput);
        assert_eq!(decoder.decode(b"not accepted", &mut []).unwrap().input_read, 0);
        let mut byte = [0_u8; 1];
        assert_eq!(decoder.finish(&mut byte).unwrap().status, StreamStatus::NeedOutput);
        assert_eq!(byte, [b'h']);
        assert!(decoder.decode(&[], &mut byte).is_err());
        assert_eq!(decoder.finish(&mut byte).unwrap().status, StreamStatus::Finished);
        assert_eq!(byte, [b'i']);
        assert_eq!(decoder.finish(&mut byte).unwrap().output_written, 0);
    }

    #[test]
    fn concatenated_and_skippable_frames_keep_exact_boundaries_and_total_limit() {
        let skip = [0x5f, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        let mut wire = HI.to_vec();
        wire.extend_from_slice(&skip);
        wire.extend_from_slice(HI);
        let mut decoder = StreamDecoder::new(DecodeLimits::new(4));
        let mut output = [0_u8; 8];
        let first = decoder.decode(&wire, &mut output).unwrap();
        assert_eq!(first.input_read, HI.len());
        assert_eq!(first.output_written, 2);
        assert_eq!(first.status, StreamStatus::FrameFinished);
        let skipped = decoder.decode(&wire[first.input_read..], &mut output).unwrap();
        assert_eq!(skipped.input_read, skip.len());
        assert_eq!(skipped.output_written, 0);
        assert_eq!(skipped.status, StreamStatus::FrameFinished);
        assert_eq!(decode_chunks(&wire, DecodeLimits::new(4), 1, 1).unwrap(), b"hihi");
        assert_eq!(
            decode_chunks(&wire, DecodeLimits::new(3), 1, 1),
            Err(DecodeError::OutputTooLarge)
        );
        let strict = DecodeLimits {
            allow_skippable_frames: false,
            ..DecodeLimits::new(4)
        };
        assert_eq!(decode_chunks(&skip, strict, 1, 1), Err(DecodeError::BadMagic));
        assert_eq!(
            decode_chunks(&skip, DecodeLimits::new(0), 1, 1),
            Ok(Vec::new())
        );
    }

    #[test]
    fn huge_skippable_lengths_never_allocate_the_payload() {
        let mut decoder = StreamDecoder::new(DecodeLimits::new(0));
        let header = [0x50, 0x2a, 0x4d, 0x18, 0xff, 0xff, 0xff, 0xff];
        let step = decoder.decode(&header, &mut []).unwrap();
        assert_eq!(step.input_read, header.len());
        assert_eq!(step.status, StreamStatus::NeedInput);
        assert!(decoder.input.capacity() <= 16);
        assert!(decoder.frame.is_none());
        let payload = vec![0_u8; MAX_BLOCK_OUTPUT + 1];
        let step = decoder.decode(&payload, &mut []).unwrap();
        assert_eq!(step.input_read, MAX_BLOCK_OUTPUT);
        assert_eq!(decoder.input, Vec::<u8>::new());
        assert_eq!(decoder.finish(&mut []).unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn every_truncated_prefix_fails_at_eof() {
        let frame = encode_all(b"checksum and truncation", &EncodeParams::new(Level::Store));
        for end in 0..frame.len() {
            assert_eq!(
                decode_chunks(&frame[..end], DecodeLimits::new(1024), 1, 1),
                Err(DecodeError::Truncated),
                "prefix {end}"
            );
        }
        let mut garbage_tail = HI.to_vec();
        garbage_tail.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode_chunks(&garbage_tail, DecodeLimits::new(8), 1, 1),
            Err(DecodeError::BadMagic)
        );
        let mut partial_tail = HI.to_vec();
        partial_tail.push(0x28);
        assert_eq!(
            decode_chunks(&partial_tail, DecodeLimits::new(8), 1, 1),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn checksum_failure_is_late_sticky_and_writes_no_output_on_error() {
        let mut frame = encode_all(b"hi", &EncodeParams::new(Level::Store));
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let mut decoder = StreamDecoder::new(DecodeLimits::new(2));
        let mut output = [0_u8; 16];
        let first = decoder.decode(&frame, &mut output).unwrap();
        assert_eq!(&output[..first.output_written], b"hi");
        assert_eq!(first.status, StreamStatus::NeedInput);
        output.fill(0xab);
        let error = decoder.decode(&frame[first.input_read..], &mut output).unwrap_err();
        assert_eq!(error, DecodeError::ChecksumMismatch);
        assert_eq!(output, [0xab; 16]);
        assert_eq!(decoder.decode(HI, &mut output).unwrap_err(), error);
        assert_eq!(decoder.finish(&mut output).unwrap_err(), error);
        assert_eq!(output, [0xab; 16]);
    }

    #[test]
    fn window_dictionary_content_size_and_reserved_bits_fail_closed() {
        let limits = DecodeLimits::new(1024);
        let mut too_large = limits;
        too_large.max_window = 1;
        assert_eq!(decode_chunks(HI, too_large, 1, 1), Err(DecodeError::WindowTooLarge));
        let mut mismatch = HI.to_vec();
        mismatch[5] = 3;
        assert_eq!(decode_chunks(&mismatch, limits, 1, 1), Err(DecodeError::ContentSizeMismatch));
        let dictionary = [0x28, 0xb5, 0x2f, 0xfd, 0x21, 1, 2];
        assert_eq!(
            decode_chunks(&dictionary, limits, 1, 1),
            Err(DecodeError::DictionaryUnsupported)
        );
        let mut reserved = HI.to_vec();
        reserved[4] |= 8;
        assert_eq!(
            decode_chunks(&reserved, limits, 1, 1),
            Err(DecodeError::Malformed("reserved frame header bit"))
        );
        let missing_size = [0x28, 0xb5, 0x2f, 0xfd, 0, 0];
        let strict = DecodeLimits {
            require_content_size: true,
            ..limits
        };
        assert_eq!(
            decode_chunks(&missing_size, strict, 1, 1),
            Err(DecodeError::ContentSizeMissing)
        );
    }

    #[test]
    fn rle_expansion_is_bounded_without_a_declared_content_size() {
        let mut wire = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0];
        block_header(1024, 1, true, &mut wire);
        wire.push(b'x');
        assert_eq!(
            decode_chunks(&wire, DecodeLimits::new(1023), 1, 1),
            Err(DecodeError::OutputTooLarge)
        );
        assert_eq!(decode_chunks(&wire, DecodeLimits::new(1024), 1, 7).unwrap(), vec![b'x'; 1024]);
        for level in [Level::Store, Level::Fast] {
            let empty = encode_all(&[], &EncodeParams::new(level));
            assert_eq!(
                decode_chunks(&empty, DecodeLimits::new(0), 1, 1),
                Ok(Vec::new())
            );
        }
    }

    #[test]
    fn matches_cannot_reach_a_previous_frame() {
        let params = EncodeParams {
            level: Level::Store,
            checksum: false,
        };
        let mut wire = encode_all(&[b'x'; 1024], &params);
        wire.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0]);
        let mut body = Vec::new();
        encode_literals(&[], &mut body);
        encode_sequences(
            &[EncodedSequence {
                literals_length: 0,
                offset_value: 1027,
                match_length: 1024,
            }],
            &mut body,
        )
        .unwrap();
        block_header(body.len(), 2, true, &mut wire);
        wire.extend_from_slice(&body);
        assert_eq!(
            decode_chunks(&wire, DecodeLimits::new(2048), 7, 19),
            Err(DecodeError::Malformed("offset beyond the available history"))
        );
    }
}
