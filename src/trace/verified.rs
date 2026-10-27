//! Bounded, pre-verified streaming replay and content-bound checkpoints.
//!
//! Unlike a lazy iterator that discovers corruption after consumers have already
//! acted on a prefix, [`VerifiedTraceReader::open`] verifies the entire declared
//! stream before exposing its first event. Verification retains one event at a
//! time. Checkpoints bind to the metadata and *all* events, including the suffix
//! not yet consumed, rather than just a seed and a declared count.
//!
//! Inputs must remain immutable while a reader is alive. An open file is not an
//! OS snapshot. Replay checks the content fingerprint again at its end, but that
//! cannot retract events already returned if another process rewrites the file.

use super::file::{MAX_EVENT_LEN, TraceFileError, TraceReader};
use super::replay::{ReplayEvent, TraceMetadata};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::iter::FusedIterator;
use std::path::Path;

const CHECKPOINT_MAGIC: &[u8; 8] = b"ASUPRC01";
const CHECKPOINT_LEN: usize = 56;
const HASH_DOMAIN: &[u8] = b"asupersync-verified-replay-content-v1\0";

/// Explicit verification and replay budgets.
///
/// These bound admitted events and their cumulative canonical MessagePack
/// payload size, not exact heap usage or raw input bytes. The underlying reader
/// additionally bounds metadata, individual input frames and LZ4 chunks. One
/// decoded event and codec buffers are needed even when its cumulative admission
/// fails. Use [`VerifiedTraceReader::open_with_frame_limit`] to additionally
/// reject large raw event frames before allocation or deserialization. No
/// collection is preallocated from the untrusted declared event count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceReadLimits {
    /// Maximum declared events admitted to verification.
    pub max_events: u64,
    /// Maximum sum of canonical MessagePack event payload lengths.
    pub max_event_bytes: u64,
}

impl TraceReadLimits {
    /// Create explicit event and canonical-payload budgets. Zero admits an empty trace.
    #[must_use]
    pub const fn new(max_events: u64, max_event_bytes: u64) -> Self {
        Self {
            max_events,
            max_event_bytes,
        }
    }
}

/// Failure to admit, read, or resume a verified trace.
#[derive(Debug, thiserror::Error)]
pub enum VerifiedTraceError {
    /// Container, codec or underlying I/O failure.
    #[error("trace validation failed: {0}")]
    Trace(#[from] TraceFileError),
    /// The untrusted declared event count exceeds the caller's budget.
    #[error("trace declares {declared} events, exceeding limit {limit}")]
    EventLimit {
        /// Count in the file header.
        declared: u64,
        /// Caller-provided event limit.
        limit: u64,
    },
    /// The next event cannot be admitted within the cumulative payload budget.
    #[error("trace event {event_index} exceeds cumulative canonical byte limit {limit}")]
    ByteLimit {
        /// Zero-based event position that failed admission.
        event_index: u64,
        /// Caller-provided cumulative byte limit.
        limit: u64,
    },
    /// Wrong length, version or inconsistent position in a checkpoint.
    #[error("invalid verified replay checkpoint")]
    InvalidCheckpoint,
    /// Metadata, total count, or any event differs from the checkpoint's source.
    #[error("verified replay checkpoint belongs to different trace content")]
    CheckpointMismatch,
    /// The same open file changed between verification and replay.
    #[error("trace content changed after verification")]
    ContentChanged,
    /// Reading already failed; the reader cannot resume or create checkpoints.
    #[error("verified trace reader is terminal after a prior error")]
    ReaderFailed,
}

/// Portable position bound to the entire verified semantic trace content.
///
/// The fixed-size encoding is versioned and length-checked. Its SHA-256 digest
/// is an identity check, not a signature or authorization token. Identical
/// metadata and events can resume across compressed/uncompressed containers;
/// changing the unread suffix, ordering, metadata or total count is rejected.
/// Fields are private so invalid positions cannot be constructed accidentally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedReplayCheckpoint {
    position: u64,
    total_events: u64,
    content_digest: [u8; 32],
}

impl VerifiedReplayCheckpoint {
    /// Number of events already consumed.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Total events in the verified source.
    #[must_use]
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Encode a versioned, fixed-size checkpoint without allocation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CHECKPOINT_LEN] {
        let mut bytes = [0; CHECKPOINT_LEN];
        bytes[..8].copy_from_slice(CHECKPOINT_MAGIC);
        bytes[8..16].copy_from_slice(&self.position.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.total_events.to_le_bytes());
        bytes[24..].copy_from_slice(&self.content_digest);
        bytes
    }

    /// Decode exactly one checkpoint. Trailing bytes are not ignored.
    ///
    /// # Errors
    /// Returns [`VerifiedTraceError::InvalidCheckpoint`] for an unsupported
    /// version, wrong length or a position beyond the declared end.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifiedTraceError> {
        if bytes.len() != CHECKPOINT_LEN || &bytes[..8] != CHECKPOINT_MAGIC {
            return Err(VerifiedTraceError::InvalidCheckpoint);
        }
        let mut position = [0; 8];
        position.copy_from_slice(&bytes[8..16]);
        let position = u64::from_le_bytes(position);
        let mut total = [0; 8];
        total.copy_from_slice(&bytes[16..24]);
        let total_events = u64::from_le_bytes(total);
        if position > total_events {
            return Err(VerifiedTraceError::InvalidCheckpoint);
        }
        let mut content_digest = [0; 32];
        content_digest.copy_from_slice(&bytes[24..]);
        Ok(Self {
            position,
            total_events,
            content_digest,
        })
    }
}

struct SizeWriter {
    bytes: u64,
    limit: u64,
    exceeded: bool,
}

impl Write for SizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(total) = self.bytes.checked_add(bytes.len() as u64) else {
            self.exceeded = true;
            return Err(io::Error::other("canonical event size overflow"));
        };
        if total > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("canonical event byte budget exceeded"));
        }
        self.bytes = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn header_hasher(metadata: &TraceMetadata, total: u64) -> Result<Sha256, VerifiedTraceError> {
    let metadata = rmp_serde::to_vec(metadata).map_err(TraceFileError::from)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update((metadata.len() as u64).to_le_bytes());
    hasher.update(metadata);
    hasher.update(total.to_le_bytes());
    Ok(hasher)
}

fn admit_event(
    event: &ReplayEvent,
    index: u64,
    used: &mut u64,
    hasher: &mut Sha256,
    limits: TraceReadLimits,
) -> Result<(), VerifiedTraceError> {
    let mut size = SizeWriter {
        bytes: 0,
        limit: limits.max_event_bytes.saturating_sub(*used),
        exceeded: false,
    };
    let result = event.serialize(&mut rmp_serde::Serializer::new(&mut size));
    if size.exceeded {
        return Err(VerifiedTraceError::ByteLimit {
            event_index: index,
            limit: limits.max_event_bytes,
        });
    }
    result.map_err(TraceFileError::from)?;
    // Length framing prevents concatenation ambiguity. Serialize directly into
    // the hash, avoiding a second event-sized temporary allocation.
    hasher.update(size.bytes.to_le_bytes());
    event
        .serialize(&mut rmp_serde::Serializer::new(HashWriter(hasher)))
        .map_err(TraceFileError::from)?;
    *used += size.bytes;
    Ok(())
}

/// Streaming reader that verifies before publishing and fuses on the first error.
///
/// Opening scans the entire declared stream once, under explicit limits, then
/// rewinds the same file handle. Memory is independent of event count except
/// for the individual event and bounded codec buffers. Replay is a second pass;
/// resuming also re-verifies the complete source before skipping the consumed
/// prefix. There is deliberately no unchecked or metadata-only resume shortcut.
///
/// V3 checksums are verified by the existing container reader. Legacy v1/v2
/// files get structural validation and a newly computed content fingerprint,
/// not a retroactive persisted-checksum guarantee. Framing, trailing-container
/// bytes and schema support retain the underlying [`TraceReader`] contracts.
/// Keep the input immutable for the whole reader lifetime.
///
/// As an iterator, this emits at most one error and has a zero lower size hint;
/// it never promises an exact size derived from an untrusted header. Successful
/// completion validates the replayed content fingerprint again. Stopping early
/// does not establish immutability or validate mutations after opening.
///
/// # Example
///
/// ```no_run
/// use asupersync::trace::{TraceReadLimits, VerifiedTraceReader};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let limits = TraceReadLimits::new(1_000_000, 128 * 1024 * 1024);
/// let mut replay = VerifiedTraceReader::open("run.trace", limits)?;
/// let _first = replay.next_event()?;
/// let checkpoint = replay.checkpoint()?;
/// let resumed = VerifiedTraceReader::resume("run.trace", checkpoint, limits)?;
/// for event in resumed {
///     let _event = event?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VerifiedTraceReader {
    reader: TraceReader,
    limits: TraceReadLimits,
    content_digest: [u8; 32],
    hasher: Sha256,
    event_bytes: u64,
    events_consumed: u64,
    failed: bool,
    complete: bool,
}

impl VerifiedTraceReader {
    /// Verify a trace, then position the reader before its first event.
    ///
    /// # Errors
    /// Rejects malformed/truncated files, checksum failures and exceeded limits
    /// before exposing any replay event.
    pub fn open(
        path: impl AsRef<Path>,
        limits: TraceReadLimits,
    ) -> Result<Self, VerifiedTraceError> {
        Self::open_with_frame_limit(path, limits, MAX_EVENT_LEN)
    }

    /// Verify with an additional bound on each raw MessagePack event frame.
    ///
    /// This limit is checked before allocating an uncompressed payload or
    /// deserializing a compressed payload, on both verification and replay.
    /// Metadata and compressed chunk buffers retain their separate container
    /// limits. Raw encodings can be larger than canonical encodings, so this
    /// additive admission policy is separate from [`TraceReadLimits`].
    ///
    /// # Errors
    /// Returns the usual verification errors and [`TraceFileError::OversizedField`]
    /// when an encoded event exceeds `max_frame_bytes` or [`MAX_EVENT_LEN`].
    pub fn open_with_frame_limit(
        path: impl AsRef<Path>,
        limits: TraceReadLimits,
        max_frame_bytes: usize,
    ) -> Result<Self, VerifiedTraceError> {
        let mut reader = TraceReader::open(path)?.with_max_event_len(max_frame_bytes);
        if reader.event_count() > limits.max_events {
            return Err(VerifiedTraceError::EventLimit {
                declared: reader.event_count(),
                limit: limits.max_events,
            });
        }
        let initial = header_hasher(reader.metadata(), reader.event_count())?;
        let mut hasher = initial.clone();
        let mut used = 0;
        while let Some(event) = reader.read_event()? {
            admit_event(&event, reader.events_read() - 1, &mut used, &mut hasher, limits)?;
        }
        let content_digest = hasher.finalize().into();
        reader.rewind()?;
        let complete = reader.event_count() == 0;
        Ok(Self {
            reader,
            limits,
            content_digest,
            hasher: initial,
            event_bytes: 0,
            events_consumed: 0,
            failed: false,
            complete,
        })
    }

    /// Re-verify the entire trace against a checkpoint, then skip its prefix.
    ///
    /// # Errors
    /// Rejects different metadata or any different event (including an unread
    /// suffix), invalid input, exceeded limits, and read failures during skip.
    pub fn resume(
        path: impl AsRef<Path>,
        checkpoint: VerifiedReplayCheckpoint,
        limits: TraceReadLimits,
    ) -> Result<Self, VerifiedTraceError> {
        Self::resume_with_frame_limit(path, checkpoint, limits, MAX_EVENT_LEN)
    }

    /// Resume with a raw-frame limit enforced while re-verifying and skipping.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::open_with_frame_limit`] and
    /// [`Self::resume`]. A checkpoint cannot bypass the caller's current limit.
    pub fn resume_with_frame_limit(
        path: impl AsRef<Path>,
        checkpoint: VerifiedReplayCheckpoint,
        limits: TraceReadLimits,
        max_frame_bytes: usize,
    ) -> Result<Self, VerifiedTraceError> {
        let mut reader = Self::open_with_frame_limit(path, limits, max_frame_bytes)?;
        if reader.total_events() != checkpoint.total_events
            || reader.content_digest != checkpoint.content_digest
            || checkpoint.position > checkpoint.total_events
        {
            return Err(VerifiedTraceError::CheckpointMismatch);
        }
        for _ in 0..checkpoint.position {
            if reader.next_event()?.is_none() {
                return Err(VerifiedTraceError::CheckpointMismatch);
            }
        }
        Ok(reader)
    }

    /// Verified trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        self.reader.metadata()
    }

    /// Number of declared and verified events.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.reader.event_count()
    }

    /// Events successfully consumed during the replay pass.
    #[must_use]
    pub const fn events_consumed(&self) -> u64 {
        self.events_consumed
    }

    /// Whether the replay pass completed without a read or fingerprint error.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete && !self.failed
    }

    /// Whether reading has entered a terminal failure state.
    #[must_use]
    pub const fn has_failed(&self) -> bool {
        self.failed
    }

    /// Make a content-bound checkpoint at the current replay position.
    ///
    /// # Errors
    /// Rejects checkpoint creation after any replay failure.
    pub fn checkpoint(&self) -> Result<VerifiedReplayCheckpoint, VerifiedTraceError> {
        if self.failed {
            return Err(VerifiedTraceError::ReaderFailed);
        }
        Ok(VerifiedReplayCheckpoint {
            position: self.events_consumed,
            total_events: self.total_events(),
            content_digest: self.content_digest,
        })
    }

    /// Read the next event, preserving the original failure and then refusing retries.
    ///
    /// # Errors
    /// A read, size or fingerprint error makes the reader permanently failed.
    /// Later calls return [`VerifiedTraceError::ReaderFailed`]. The iterator
    /// interface instead ends after yielding the original error once.
    pub fn next_event(&mut self) -> Result<Option<ReplayEvent>, VerifiedTraceError> {
        if self.failed {
            return Err(VerifiedTraceError::ReaderFailed);
        }
        if self.complete {
            return Ok(None);
        }
        let result = self.read_next();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn read_next(&mut self) -> Result<Option<ReplayEvent>, VerifiedTraceError> {
        let event = self.reader.read_event()?.ok_or(TraceFileError::Truncated)?;
        admit_event(
            &event,
            self.events_consumed,
            &mut self.event_bytes,
            &mut self.hasher,
            self.limits,
        )?;
        if self.events_consumed + 1 == self.total_events() {
            let actual: [u8; 32] = self.hasher.clone().finalize().into();
            if actual != self.content_digest {
                return Err(VerifiedTraceError::ContentChanged);
            }
            self.complete = true;
        }
        self.events_consumed += 1;
        Ok(Some(event))
    }
}

impl Iterator for VerifiedTraceReader {
    type Item = Result<ReplayEvent, VerifiedTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.complete {
            return None;
        }
        self.next_event().transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.failed || self.complete {
            return (0, Some(0));
        }
        let remaining = self.total_events().saturating_sub(self.events_consumed);
        (0, usize::try_from(remaining).ok())
    }
}

impl FusedIterator for VerifiedTraceReader {}

#[cfg(test)]
#[path = "verified_inline_tests.rs"]
mod tests;
