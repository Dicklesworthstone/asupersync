//! Bounded salvage of trace files whose writer did not finish.
//!
//! The normal [`super::file::TraceReader`] deliberately rejects the zero event
//! digest left by an unfinished v3 writer. This module is the explicit forensic
//! alternative: metadata must still pass its checksum and schema checks, but
//! complete frames are recovered without trusting the unfinished event count.
//! A salvage result is **never** an authenticated, complete replay trace.

use super::file::{
    FLAG_CHECKSUMMED, FLAG_COMPRESSED, MAX_COMPRESSED_CHUNK_LEN, MAX_EVENT_LEN, MAX_META_LEN,
    TRACE_CHECKSUM_LEN, TRACE_MAGIC, TraceFileError, TraceFileResult,
};
use super::replay::{REPLAY_SCHEMA_VERSION, ReplayEvent, TraceMetadata};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Take};
use std::path::Path;

/// Independent resource budgets for crash-trace salvage.
///
/// Byte budgets count serialized bytes, not Rust object overhead. Each decoded
/// event also costs its Rust representation. Compressed input additionally needs
/// at most one bounded compressed chunk and one bounded decompressed chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashRecoveryLimits {
    /// Maximum events retained. No allocation is based on the header count.
    pub max_events: usize,
    /// Maximum cumulative `length prefix + MessagePack payload` bytes retained.
    pub max_decoded_bytes: usize,
    /// Maximum input bytes consumed, including the header (plus fixed I/O buffering).
    pub max_input_bytes: u64,
    /// Maximum compressed or decompressed chunk, also capped by the format limit.
    pub max_chunk_bytes: usize,
}

impl CrashRecoveryLimits {
    /// Set event and decoded-byte budgets, with a 1 GiB input budget and the
    /// format's 64 MiB per-chunk ceiling. Zero budgets are allowed.
    #[must_use]
    pub const fn new(max_events: usize, max_decoded_bytes: usize) -> Self {
        Self {
            max_events,
            max_decoded_bytes,
            max_input_bytes: 1024 * 1024 * 1024,
            max_chunk_bytes: MAX_COMPRESSED_CHUNK_LEN,
        }
    }
}

/// Why salvage stopped. There is intentionally no `Complete` variant.
#[derive(Debug)]
pub enum CrashRecoveryStop {
    /// Reached the available EOF at a frame boundary, without a final digest.
    EndOfAvailableData,
    /// Reached the caller's event budget without inspecting the next event.
    EventLimitReached,
    /// The next frame would exceed the cumulative decoded-byte budget.
    DecodedByteLimitReached,
    /// The parser reached its input budget. Even EOF at this boundary is not
    /// claimed, since inspecting another byte would exceed the budget.
    InputByteLimitReached,
    /// The next compressed or decompressed chunk exceeds the caller's budget.
    ChunkLimitReached {
        /// Advertised chunk length.
        declared: usize,
        /// Effective per-chunk limit.
        max: usize,
    },
    /// A malformed, truncated, or unreadable frame ended recovery. No later
    /// record is inspected and the offending record is not returned.
    CorruptFrame {
        /// Index of the first unrecovered event.
        next_event: usize,
        /// Underlying framing or I/O failure. Invalid MessagePack is reported
        /// without reflecting the event's contents into the diagnostic.
        error: TraceFileError,
    },
}

/// An unauthenticated contiguous event prefix from an unfinished v3 trace.
#[derive(Debug)]
pub struct CrashRecovery {
    /// Metadata checked against the v3 metadata digest (not a signature).
    pub metadata: TraceMetadata,
    /// Original count, retained for diagnostics only. An interrupted header
    /// update may leave a nonzero count with a zero event digest.
    pub declared_events: u64,
    /// Structurally decodable events in source order, never independently
    /// authenticated by an event-stream checksum.
    pub events: Vec<ReplayEvent>,
    /// Serialized frame bytes represented by `events`.
    pub decoded_bytes: usize,
    /// Input bytes consumed by the parser, including the header.
    pub input_bytes: u64,
    /// Terminal reason; never a complete-replay admission.
    pub stop: CrashRecoveryStop,
}

fn read_error(error: io::Error) -> TraceFileError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        TraceFileError::Truncated
    } else {
        TraceFileError::Io(error)
    }
}

fn read_array<const N: usize>(reader: &mut impl Read) -> TraceFileResult<[u8; N]> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(bytes)
}

fn read_length(reader: &mut impl Read) -> TraceFileResult<Option<usize>> {
    let mut bytes = [0; 4];
    match reader.read_exact(&mut bytes[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(TraceFileError::Io(error)),
    }
    reader.read_exact(&mut bytes[1..]).map_err(read_error)?;
    Ok(Some(u32::from_le_bytes(bytes) as usize))
}

fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> TraceFileResult<T> {
    let mut decoder = rmp_serde::Deserializer::new(Cursor::new(bytes));
    decoder.set_max_depth(128);
    let value = serde::Deserialize::deserialize(&mut decoder)
        .map_err(|_| TraceFileError::Deserialize("invalid crash-trace record".to_owned()))?;
    if decoder.position() != bytes.len() as u64 {
        return Err(TraceFileError::Deserialize(
            "trailing data inside crash-trace record".to_owned(),
        ));
    }
    Ok(value)
}

struct CrashFrames {
    reader: Take<BufReader<File>>,
    #[cfg(feature = "trace-compression")]
    limits: CrashRecoveryLimits,
    compressed: bool,
    #[cfg(feature = "trace-compression")]
    chunk: Vec<u8>,
    #[cfg(feature = "trace-compression")]
    position: usize,
}

impl CrashFrames {
    fn corrupt(next_event: usize, error: TraceFileError) -> CrashRecoveryStop {
        CrashRecoveryStop::CorruptFrame { next_event, error }
    }

    fn input_failure(&self, next_event: usize, error: TraceFileError) -> CrashRecoveryStop {
        if self.reader.limit() == 0 && matches!(error, TraceFileError::Truncated) {
            CrashRecoveryStop::InputByteLimitReached
        } else {
            Self::corrupt(next_event, error)
        }
    }

    fn next_input_length(&mut self, next_event: usize) -> Result<usize, CrashRecoveryStop> {
        if self.reader.limit() == 0 {
            return Err(CrashRecoveryStop::InputByteLimitReached);
        }
        match read_length(&mut self.reader) {
            Ok(Some(length)) => Ok(length),
            Ok(None) => Err(CrashRecoveryStop::EndOfAvailableData),
            Err(error) => Err(self.input_failure(next_event, error)),
        }
    }

    fn read_input(&mut self, length: usize, next_event: usize) -> Result<Vec<u8>, CrashRecoveryStop> {
        if length as u64 > self.reader.limit() {
            return Err(CrashRecoveryStop::InputByteLimitReached);
        }
        let mut bytes = vec![0; length];
        self.reader
            .read_exact(&mut bytes)
            .map_err(|error| self.input_failure(next_event, read_error(error)))?;
        Ok(bytes)
    }

    fn check_frame_length(
        length: usize,
        remaining: usize,
        next_event: usize,
    ) -> Result<(), CrashRecoveryStop> {
        if length > MAX_EVENT_LEN {
            return Err(Self::corrupt(
                next_event,
                TraceFileError::OversizedField {
                    field: "event_len",
                    actual: length as u64,
                    max: MAX_EVENT_LEN as u64,
                },
            ));
        }
        // Check before allocating the frame buffer or deserializing the event.
        if remaining < 4 || length > remaining - 4 {
            return Err(CrashRecoveryStop::DecodedByteLimitReached);
        }
        Ok(())
    }

    fn next_frame(
        &mut self,
        remaining: usize,
        next_event: usize,
    ) -> Result<Vec<u8>, CrashRecoveryStop> {
        if remaining < 4 {
            return Err(CrashRecoveryStop::DecodedByteLimitReached);
        }
        #[cfg(feature = "trace-compression")]
        if self.compressed {
            return self.next_compressed_frame(remaining, next_event);
        }
        #[cfg(not(feature = "trace-compression"))]
        debug_assert!(!self.compressed);
        let length = self.next_input_length(next_event)?;
        Self::check_frame_length(length, remaining, next_event)?;
        self.read_input(length, next_event)
    }

    #[cfg(feature = "trace-compression")]
    fn next_compressed_frame(
        &mut self,
        remaining: usize,
        next_event: usize,
    ) -> Result<Vec<u8>, CrashRecoveryStop> {
        if self.position == self.chunk.len() {
            let length = self.next_input_length(next_event)?;
            let max = self.limits.max_chunk_bytes.min(MAX_COMPRESSED_CHUNK_LEN);
            if length > max {
                return Err(CrashRecoveryStop::ChunkLimitReached { declared: length, max });
            }
            if length < 4 {
                return Err(Self::corrupt(next_event, TraceFileError::Truncated));
            }
            let compressed = self.read_input(length, next_event)?;
            let decoded_length = u32::from_le_bytes(
                compressed[..4].try_into().expect("validated chunk prefix"),
            ) as usize;
            if decoded_length > max {
                return Err(CrashRecoveryStop::ChunkLimitReached {
                    declared: decoded_length,
                    max,
                });
            }
            // Writer chunks contain complete frames; empty chunks are not a
            // progress marker and must not permit an unbounded empty-chunk loop.
            if decoded_length == 0 {
                return Err(Self::corrupt(next_event, TraceFileError::Truncated));
            }
            // Release the old chunk before allocating its replacement.
            self.chunk = Vec::new();
            self.chunk = lz4_flex::decompress_size_prepended(&compressed).map_err(|_| {
                Self::corrupt(
                    next_event,
                    TraceFileError::Decompression("invalid crash-trace chunk".to_owned()),
                )
            })?;
            self.position = 0;
        }
        let available = &self.chunk[self.position..];
        if available.len() < 4 {
            return Err(Self::corrupt(next_event, TraceFileError::Truncated));
        }
        let length = u32::from_le_bytes(available[..4].try_into().expect("validated frame prefix"))
            as usize;
        Self::check_frame_length(length, remaining, next_event)?;
        if length > available.len() - 4 {
            return Err(Self::corrupt(next_event, TraceFileError::Truncated));
        }
        let bytes = available[4..4 + length].to_vec();
        self.position += 4 + length;
        Ok(bytes)
    }
}

/// Recover a bounded prefix from a v3 trace with an unfinished event digest.
///
/// Works after process exit without destructors, including interrupted count
/// backpatching and partially written final frames/chunks. The source is opened
/// read-only and never rewritten or "repaired". Use `recover_trace_prefix` for
/// finalized or legacy files. An EOF result here still has no final event digest
/// and must not be promoted to deterministic replay proof.
///
/// # Errors
///
/// Returns a hard error for an unreadable or invalid header, corrupt metadata,
/// unsupported schema/compression, a finalized/legacy file, or an input budget
/// too small to read the metadata. Frame failures instead return the earlier
/// contiguous prefix and a typed stop reason. Compressed salvage requires
/// `trace-compression`; it does not switch the production LZ4 backend.
///
/// # Example
///
/// ```no_run
/// use asupersync::trace::{CrashRecoveryLimits, recover_crashed_trace_prefix};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let recovered = recover_crashed_trace_prefix(
///     "crashed.trace", CrashRecoveryLimits::new(10_000, 64 * 1024 * 1024),
/// )?;
/// // Inspect recovered.events as forensic evidence, not verified replay input.
/// # let _ = recovered;
/// # Ok(())
/// # }
/// ```
pub fn recover_crashed_trace_prefix(
    path: impl AsRef<Path>,
    limits: CrashRecoveryLimits,
) -> TraceFileResult<CrashRecovery> {
    let mut reader = BufReader::new(File::open(path)?).take(limits.max_input_bytes);
    if &read_array::<11>(&mut reader)? != TRACE_MAGIC {
        return Err(TraceFileError::InvalidMagic);
    }
    let version = u16::from_le_bytes(read_array(&mut reader)?);
    if version != 3 {
        return Err(TraceFileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "crash salvage requires a v3 container; use recover_trace_prefix for legacy files",
        )));
    }
    let flags = u16::from_le_bytes(read_array(&mut reader)?);
    if flags & !(FLAG_COMPRESSED | FLAG_CHECKSUMMED) != 0 || flags & FLAG_CHECKSUMMED == 0 {
        return Err(TraceFileError::UnsupportedFlags(flags));
    }
    let compression = read_array::<1>(&mut reader)?[0];
    let compressed = flags & FLAG_COMPRESSED != 0;
    if compression > 1 || (!compressed && compression != 0) {
        return Err(TraceFileError::UnsupportedCompression(compression));
    }
    if compressed && compression == 0 {
        return Err(TraceFileError::UnsupportedFlags(flags));
    }
    #[cfg(not(feature = "trace-compression"))]
    if compressed {
        return Err(TraceFileError::CompressionNotAvailable);
    }
    let metadata_length = u32::from_le_bytes(read_array(&mut reader)?) as usize;
    if metadata_length > MAX_META_LEN {
        return Err(TraceFileError::OversizedField {
            field: "meta_len",
            actual: metadata_length as u64,
            max: MAX_META_LEN as u64,
        });
    }
    let metadata_digest = read_array::<TRACE_CHECKSUM_LEN>(&mut reader)?;
    if metadata_length as u64 > reader.limit() {
        return Err(TraceFileError::Truncated);
    }
    let mut metadata_bytes = vec![0; metadata_length];
    reader.read_exact(&mut metadata_bytes).map_err(read_error)?;
    let actual_digest: [u8; TRACE_CHECKSUM_LEN] = Sha256::digest(&metadata_bytes).into();
    if metadata_digest != actual_digest {
        return Err(TraceFileError::ChecksumMismatch { section: "metadata" });
    }
    let metadata: TraceMetadata = decode_exact(&metadata_bytes)?;
    if metadata.version != REPLAY_SCHEMA_VERSION {
        return Err(TraceFileError::SchemaMismatch {
            expected: REPLAY_SCHEMA_VERSION,
            found: metadata.version,
        });
    }
    let declared_events = u64::from_le_bytes(read_array(&mut reader)?);
    if read_array::<TRACE_CHECKSUM_LEN>(&mut reader)? != [0; TRACE_CHECKSUM_LEN] {
        return Err(TraceFileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "event digest is not unfinished; use recover_trace_prefix for finalized files",
        )));
    }
    let mut frames = CrashFrames {
        reader,
        #[cfg(feature = "trace-compression")]
        limits,
        compressed,
        #[cfg(feature = "trace-compression")]
        chunk: Vec::new(),
        #[cfg(feature = "trace-compression")]
        position: 0,
    };
    let mut events = Vec::new();
    let mut decoded_bytes = 0;
    let stop = loop {
        if events.len() >= limits.max_events {
            break CrashRecoveryStop::EventLimitReached;
        }
        let frame = match frames.next_frame(limits.max_decoded_bytes - decoded_bytes, events.len()) {
            Ok(frame) => frame,
            Err(stop) => break stop,
        };
        match decode_exact(&frame) {
            Ok(event) => {
                decoded_bytes += 4 + frame.len();
                events.push(event);
            }
            Err(_) => {
                break CrashFrames::corrupt(
                    events.len(),
                    TraceFileError::Deserialize("invalid crash-trace event".to_owned()),
                );
            }
        }
    };
    Ok(CrashRecovery {
        metadata,
        declared_events,
        events,
        decoded_bytes,
        input_bytes: limits.max_input_bytes - frames.reader.limit(),
        stop,
    })
}

#[cfg(test)]
#[path = "recovery_inline_tests.rs"]
mod tests;
