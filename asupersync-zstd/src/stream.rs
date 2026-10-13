//! Bounded, caller-driven Zstandard streaming.
//!
//! These adapters perform no I/O and create no tasks. Input and output slices
//! belong to the caller; retain the adapter across a cancelled I/O wait to
//! retain any bytes it has already accepted. Discarding the adapter discards
//! its buffered bytes and does not finalize a stream.

use crate::{EncodeParams, encode_into};

/// Why a streaming operation stopped. Inspect the byte counts even when the
/// status indicates a boundary: a call can consume input and produce output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamStatus {
    /// Supply more input, or explicitly finish the stream at end of input.
    NeedInput,
    /// Supply output space and call again, retaining the unconsumed input.
    NeedOutput,
    /// One complete frame was emitted. Continue with the unconsumed input.
    FrameFinished,
    /// Explicit finalization completed; no further input is accepted.
    Finished,
}

/// Progress made by one streaming call. Only the reported input prefix has
/// been accepted, and only the reported output prefix has been initialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamProgress {
    /// Bytes accepted from the supplied input slice.
    pub input_read: usize,
    /// Bytes written to the supplied output slice.
    pub output_written: usize,
    /// The next action the caller should take.
    pub status: StreamStatus,
}

/// Invalid configuration or use of a finalized streaming encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEncodeError {
    /// Frame size must be in `1..=StreamEncoder::MAX_FRAME_SIZE`.
    FrameSizeOutOfRange,
    /// Finalization has started; only further `finish` calls are allowed.
    Finished,
}

impl core::fmt::Display for StreamEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FrameSizeOutOfRange => {
                f.write_str("zstd: streaming frame size must be 1..=8 MiB")
            }
            Self::Finished => f.write_str("zstd: streaming encoder is finishing or finished"),
        }
    }
}

impl std::error::Error for StreamEncodeError {}

/// Encodes arbitrarily long input with a bounded amount of buffered data.
///
/// Input is divided into independent, concatenated Zstandard frames of at
/// most `frame_size` bytes. Every frame declares its content size and uses
/// the supplied checksum policy. Matching does not cross frame boundaries;
/// this trades compression ratio for bounded buffering and independently
/// verifiable frames. The wire format needs no private envelope and is
/// accepted by [`crate::decode_all`].
///
/// At most one plain frame and one encoded frame are retained, in addition
/// to the existing encoder's bounded per-frame workspace. Output pressure
/// stops input admission: `encode` does not accept another frame until the
/// previous frame has been completely emitted. It emits at most one frame
/// per call. No allocation is proportional to the total stream length.
///
/// `flush` seals a partial frame without ending the stream. `finish` seals
/// the last frame, emits a valid empty frame for empty input, and must be
/// called until it reports [`StreamStatus::Finished`]. Neither dropping the
/// encoder nor an empty input slice implicitly flushes or finishes it.
#[derive(Debug)]
pub struct StreamEncoder {
    params: EncodeParams,
    frame_size: usize,
    plain: Vec<u8>,
    encoded: Vec<u8>,
    position: usize,
    emitted_frame: bool,
    finishing: bool,
}

impl StreamEncoder {
    /// The largest permitted plain frame (and single-segment window).
    pub const MAX_FRAME_SIZE: usize = 8 << 20;
    /// A default-sized frame preserves the fast encoder's 1 MiB match window.
    pub const DEFAULT_FRAME_SIZE: usize = 1 << 20;

    /// Creates an encoder with explicit frame and memory bounds.
    ///
    /// # Errors
    /// Returns [`StreamEncodeError::FrameSizeOutOfRange`] for zero or more
    /// than 8 MiB. The default decoder window accepts every permitted frame.
    pub fn new(params: EncodeParams, frame_size: usize) -> Result<Self, StreamEncodeError> {
        if !(1..=Self::MAX_FRAME_SIZE).contains(&frame_size) {
            return Err(StreamEncodeError::FrameSizeOutOfRange);
        }
        Ok(Self {
            params,
            frame_size,
            plain: Vec::new(),
            encoded: Vec::new(),
            position: 0,
            emitted_frame: false,
            finishing: false,
        })
    }

    /// Accepts an input prefix and emits an output prefix. Repeat with the
    /// unconsumed input; a `FrameFinished` result is not end of the stream.
    ///
    /// An empty output slice may accept at most one frame, then returns
    /// `NeedOutput`. An empty input slice drains already encoded output but
    /// does not seal a partial frame. Finalization permanently refuses input.
    pub fn encode(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<StreamProgress, StreamEncodeError> {
        if self.finishing {
            return Err(StreamEncodeError::Finished);
        }
        if self.position < self.encoded.len() {
            return Ok(self.emit(output, 0));
        }
        let accepted = input.len().min(self.frame_size - self.plain.len());
        self.plain.extend_from_slice(&input[..accepted]);
        if self.plain.len() == self.frame_size {
            self.seal();
            return Ok(self.emit(output, accepted));
        }
        Ok(StreamProgress {
            input_read: accepted,
            output_written: 0,
            status: StreamStatus::NeedInput,
        })
    }

    /// Seals a partial frame and drains pending output without ending the
    /// stream. Repeat while `NeedOutput` is returned. Flushing an empty
    /// encoder emits nothing; `finish` is required for an empty stream.
    pub fn flush(&mut self, output: &mut [u8]) -> Result<StreamProgress, StreamEncodeError> {
        if self.finishing {
            return Err(StreamEncodeError::Finished);
        }
        if self.position == self.encoded.len() && !self.plain.is_empty() {
            self.seal();
        }
        if self.position < self.encoded.len() {
            return Ok(self.emit(output, 0));
        }
        Ok(StreamProgress {
            input_read: 0,
            output_written: 0,
            status: StreamStatus::NeedInput,
        })
    }

    /// Permanently ends input and drains the final frame. Repeat with fresh
    /// output space until `Finished`. Subsequent `finish` calls are harmless
    /// and return `Finished` without producing bytes.
    ///
    /// Call only after all input has been accepted by `encode`. In particular,
    /// retain an input suffix refused because output space was exhausted.
    pub fn finish(&mut self, output: &mut [u8]) -> StreamProgress {
        if !self.finishing {
            self.finishing = true;
            if self.position == self.encoded.len()
                && (!self.plain.is_empty() || !self.emitted_frame)
            {
                self.seal();
            }
        }
        self.emit(output, 0)
    }

    fn seal(&mut self) {
        self.encoded.clear();
        encode_into(&self.plain, &self.params, &mut self.encoded);
        self.plain.clear();
        self.position = 0;
        self.emitted_frame = true;
    }

    fn emit(&mut self, output: &mut [u8], input_read: usize) -> StreamProgress {
        let written = output.len().min(self.encoded.len() - self.position);
        output[..written]
            .copy_from_slice(&self.encoded[self.position..self.position + written]);
        self.position += written;
        let status = if self.position < self.encoded.len() {
            StreamStatus::NeedOutput
        } else if self.finishing {
            StreamStatus::Finished
        } else {
            StreamStatus::FrameFinished
        };
        StreamProgress {
            input_read,
            output_written: written,
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamEncodeError, StreamEncoder, StreamStatus};
    use crate::{DecodeLimits, EncodeParams, Level, decode_all, encode_all};

    fn encode_chunks(
        data: &[u8],
        frame: usize,
        input_chunk: usize,
        output_chunk: usize,
        level: Level,
    ) -> Vec<u8> {
        let mut encoder = StreamEncoder::new(EncodeParams::new(level), frame).unwrap();
        let mut wire = Vec::new();
        let mut output = vec![0_u8; output_chunk];
        for chunk in data.chunks(input_chunk) {
            let mut offset = 0;
            while offset < chunk.len() {
                let progress = encoder.encode(&chunk[offset..], &mut output).unwrap();
                assert!(progress.input_read != 0 || progress.output_written != 0);
                assert!(progress.input_read <= chunk.len() - offset);
                offset += progress.input_read;
                wire.extend_from_slice(&output[..progress.output_written]);
            }
        }
        loop {
            let progress = encoder.finish(&mut output);
            wire.extend_from_slice(&output[..progress.output_written]);
            if progress.status == StreamStatus::Finished {
                break;
            }
            assert!(progress.output_written != 0);
        }
        assert_eq!(encoder.finish(&mut output).output_written, 0);
        wire
    }

    #[test]
    fn fragmented_input_and_output_match_independent_frames() {
        let input: Vec<u8> = (0..577).map(|i| u8::try_from(i % 31).unwrap()).collect();
        for level in [Level::Store, Level::Fast] {
            for frame in [1, 31, 128, 256, 1024] {
                let params = EncodeParams::new(level);
                let expected: Vec<u8> = input
                    .chunks(frame)
                    .flat_map(|part| encode_all(part, &params))
                    .collect();
                for input_chunk in [1, 17, 577] {
                    for output_chunk in [1, 7, 4096] {
                        let actual =
                            encode_chunks(&input, frame, input_chunk, output_chunk, level);
                        assert_eq!(actual, expected);
                        assert_eq!(
                            decode_all(&actual, &DecodeLimits::new(input.len())).unwrap(),
                            input
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn empty_stream_is_a_real_frame_and_finish_is_idempotent() {
        for level in [Level::Store, Level::Fast] {
            let actual = encode_chunks(&[], 1024, 1, 1, level);
            assert_eq!(actual, encode_all(&[], &EncodeParams::new(level)));
            assert_eq!(
                decode_all(&actual, &DecodeLimits::new(0)).unwrap(),
                Vec::<u8>::new()
            );
        }
    }

    #[test]
    fn output_pressure_stops_input_admission() {
        let mut encoder = StreamEncoder::new(EncodeParams::new(Level::Store), 3).unwrap();
        let progress = encoder.encode(b"abcdef", &mut []).unwrap();
        assert_eq!(progress.input_read, 3);
        assert_eq!(progress.status, StreamStatus::NeedOutput);
        assert_eq!(encoder.encode(b"def", &mut []).unwrap().input_read, 0);
        let mut output = [0_u8; 64];
        let first = encoder.encode(b"def", &mut output).unwrap();
        assert_eq!(first.input_read, 0);
        assert_eq!(first.status, StreamStatus::FrameFinished);
        assert_eq!(
            decode_all(&output[..first.output_written], &DecodeLimits::new(3)).unwrap(),
            b"abc"
        );
        assert_eq!(encoder.encode(b"def", &mut output).unwrap().input_read, 3);
    }

    #[test]
    fn flush_seals_partial_frames_but_does_not_end_input() {
        let params = EncodeParams::new(Level::Store);
        let mut encoder = StreamEncoder::new(params, 1024).unwrap();
        let mut output = [0_u8; 1024];
        assert_eq!(encoder.flush(&mut output).unwrap().output_written, 0);
        assert_eq!(
            encoder.encode(b"first", &mut output).unwrap().status,
            StreamStatus::NeedInput
        );
        assert_eq!(encoder.encode(&[], &mut output).unwrap().output_written, 0);
        assert_eq!(
            encoder.flush(&mut []).unwrap().status,
            StreamStatus::NeedOutput
        );
        let flushed = encoder.flush(&mut output).unwrap();
        assert_eq!(flushed.status, StreamStatus::FrameFinished);
        assert_eq!(
            &output[..flushed.output_written],
            encode_all(b"first", &params)
        );
        assert_eq!(encoder.flush(&mut output).unwrap().output_written, 0);
        encoder.encode(b"second", &mut output).unwrap();
        let finished = encoder.finish(&mut output);
        assert_eq!(finished.status, StreamStatus::Finished);
        assert_eq!(
            &output[..finished.output_written],
            encode_all(b"second", &params)
        );
    }

    #[test]
    fn finish_drains_a_full_frame_without_an_extra_empty_frame() {
        let params = EncodeParams::new(Level::Store);
        let mut encoder = StreamEncoder::new(params, 3).unwrap();
        encoder.encode(b"abc", &mut []).unwrap();
        assert_eq!(encoder.finish(&mut []).status, StreamStatus::NeedOutput);
        assert_eq!(
            encoder.encode(b"d", &mut []).unwrap_err(),
            StreamEncodeError::Finished
        );
        assert_eq!(encoder.flush(&mut []).unwrap_err(), StreamEncodeError::Finished);
        let mut output = [0_u8; 64];
        let finished = encoder.finish(&mut output);
        assert_eq!(finished.status, StreamStatus::Finished);
        assert_eq!(&output[..finished.output_written], encode_all(b"abc", &params));
        assert_eq!(encoder.finish(&mut output).output_written, 0);
    }

    #[test]
    fn explicit_frame_bounds_and_checksum_policy() {
        let params = EncodeParams {
            level: Level::Store,
            checksum: false,
        };
        assert_eq!(
            StreamEncoder::new(params, 0).unwrap_err(),
            StreamEncodeError::FrameSizeOutOfRange
        );
        assert_eq!(
            StreamEncoder::new(params, StreamEncoder::MAX_FRAME_SIZE + 1).unwrap_err(),
            StreamEncodeError::FrameSizeOutOfRange
        );
        assert!(StreamEncoder::new(params, StreamEncoder::MAX_FRAME_SIZE).is_ok());
        let mut encoder = StreamEncoder::new(params, 3).unwrap();
        let mut output = [0_u8; 64];
        let progress = encoder.encode(b"abc", &mut output).unwrap();
        assert_eq!(&output[..progress.output_written], encode_all(b"abc", &params));
        assert_eq!(encoder.finish(&mut output).output_written, 0);
    }

    #[test]
    fn stored_stream_matches_a_known_wire_frame() {
        let params = EncodeParams {
            level: Level::Store,
            checksum: false,
        };
        let mut encoder = StreamEncoder::new(params, 2).unwrap();
        let mut output = [0_u8; 64];
        let progress = encoder.encode(b"hi", &mut output).unwrap();
        assert_eq!(progress.status, StreamStatus::FrameFinished);
        assert_eq!(
            &output[..progress.output_written],
            &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x02, 0x11, 0, 0, b'h', b'i']
        );
        assert_eq!(encoder.finish(&mut output).output_written, 0);
    }
}
