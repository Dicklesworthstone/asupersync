//! Streaming replay for large traces.
//!
//! This module provides streaming support for processing traces that are too large
//! to fit in memory. The key types are:
//!
//! - [`StreamingReplayer`]: Replays traces directly from file with O(1) memory
//! - [`ReplayCheckpoint`]: Saves replay state for resumption
//! - [`ReplayProgress`]: Progress tracking during replay
//!
//! # Memory Guarantees
//!
//! - [`StreamingReplayer`]: O(1) memory - only buffers current event
//! - Reading: Uses [`TraceReader`] with streaming reads
//! - Writing: Uses `TraceWriter` with streaming writes
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::streaming::{StreamingReplayer, ReplayProgress};
//! use std::path::Path;
//!
//! // Open a large trace file for streaming replay
//! let mut replayer = StreamingReplayer::open("large_trace.bin")?;
//!
//! // Process events one at a time
//! while let Some(event) = replayer.next_event()? {
//!     println!("Event: {:?}", event);
//!
//!     // Check progress
//!     if replayer.progress().percent() > 50.0 {
//!         println!("Halfway done!");
//!     }
//! }
//!
//! // For very long replays, checkpoint and resume later
//! let checkpoint = replayer.checkpoint()?;
//! std::fs::write("checkpoint.bin", checkpoint.to_bytes()?)?;
//!
//! // Later: resume from checkpoint
//! let checkpoint = ReplayCheckpoint::from_bytes(&std::fs::read("checkpoint.bin")?)?;
//! let mut resumed = StreamingReplayer::resume("large_trace.bin", checkpoint)?;
//! ```

use super::file::{TraceFileError, TraceReader};
use super::replay::{ReplayEvent, TraceMetadata};
use super::replayer::{Breakpoint, DivergenceError, EventSource, ReplayMode};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

// =============================================================================
// Errors
// =============================================================================

/// Errors specific to streaming replay operations.
#[derive(Debug, thiserror::Error)]
pub enum StreamingReplayError {
    /// File operation error.
    #[error("file error: {0}")]
    File(#[from] TraceFileError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Checkpoint is invalid or corrupt.
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),

    /// Checkpoint doesn't match trace file.
    #[error("checkpoint mismatch: {0}")]
    CheckpointMismatch(String),

    /// Divergence detected during replay.
    #[error("{0}")]
    Divergence(#[from] DivergenceError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialize(String),

    /// A serialized evidence record does not fit in the configured chunk size.
    #[error("evidence record too large: {actual} bytes exceeds max chunk size {max}")]
    EvidenceRecordTooLarge {
        /// Serialized record length, including the length prefix.
        actual: usize,
        /// Configured maximum chunk size.
        max: usize,
    },

    /// The configured sink reported backpressure and the policy requires an error.
    #[error("evidence sink backpressure at sequence {sequence}")]
    EvidenceBackpressure {
        /// First record sequence in the backpressured chunk.
        sequence: u64,
    },
}

/// Result type for streaming replay operations.
pub type StreamingReplayResult<T> = Result<T, StreamingReplayError>;

// =============================================================================
// Trace Evidence Streaming
// =============================================================================

/// Policy applied when an evidence record cannot be emitted immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceOverflowPolicy {
    /// Stop streaming and return the stats gathered so far.
    Stop,
    /// Drop the record or chunk that could not be emitted.
    DropNewest,
    /// Return an explicit error.
    Error,
}

/// Decision returned by a trace evidence sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSinkDecision {
    /// The sink accepted the chunk.
    Accepted,
    /// The sink is applying backpressure.
    Backpressured,
    /// The sink is closed and no further chunks should be sent.
    Closed,
}

/// Bounded-copy streaming configuration for trace evidence records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceEvidenceStreamConfig {
    /// Maximum bytes per emitted evidence chunk.
    pub max_chunk_bytes: usize,
    /// Policy for oversized records and backpressured sinks.
    pub overflow_policy: EvidenceOverflowPolicy,
}

impl TraceEvidenceStreamConfig {
    /// Default maximum evidence chunk size: 64 KiB.
    pub const DEFAULT_MAX_CHUNK_BYTES: usize = 64 * 1024;

    /// Creates a new config with defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_chunk_bytes: Self::DEFAULT_MAX_CHUNK_BYTES,
            overflow_policy: EvidenceOverflowPolicy::Stop,
        }
    }

    /// Sets the maximum chunk size in bytes.
    #[must_use]
    pub const fn with_max_chunk_bytes(mut self, max_chunk_bytes: usize) -> Self {
        self.max_chunk_bytes = max_chunk_bytes;
        self
    }

    /// Sets the overflow and backpressure policy.
    #[must_use]
    pub const fn with_overflow_policy(mut self, policy: EvidenceOverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }
}

impl Default for TraceEvidenceStreamConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed evidence chunk handed to a sink.
///
/// The payload is a sequence of length-prefixed MessagePack [`ReplayEvent`]
/// records. The slice is valid only for the duration of the sink call, allowing
/// callers to stream from the reusable internal buffer without allocating a new
/// chunk per sink write.
#[derive(Debug, Clone, Copy)]
pub struct TraceEvidenceChunk<'a> {
    /// First record sequence in this chunk.
    pub first_sequence: u64,
    /// Number of records in this chunk.
    pub records: u64,
    /// Length-prefixed MessagePack records.
    pub payload: &'a [u8],
}

impl TraceEvidenceChunk<'_> {
    /// Returns the payload length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.payload.len()
    }

    /// Returns true when the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Sink for bounded-copy trace evidence chunks.
pub trait TraceEvidenceSink {
    /// Pushes one borrowed evidence chunk to the sink.
    ///
    /// Implementations must copy or consume the payload before returning if
    /// they need to retain it.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink fails while accepting the chunk.
    fn push_trace_evidence(
        &mut self,
        chunk: TraceEvidenceChunk<'_>,
    ) -> StreamingReplayResult<EvidenceSinkDecision>;
}

/// Streaming counters emitted by [`TraceEvidenceStreamer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TraceEvidenceStreamStats {
    /// Records presented to the streamer.
    pub records_seen: u64,
    /// Records accepted by the sink.
    pub records_emitted: u64,
    /// Records not emitted because of overflow, backpressure, or sink closure.
    pub records_dropped: u64,
    /// Bytes accepted by the sink.
    pub bytes_emitted: u64,
    /// Number of oversized-record decisions.
    pub overflow_events: u64,
    /// Number of sink backpressure decisions.
    pub backpressure_events: u64,
    /// Largest combined scratch-buffer footprint observed.
    pub max_buffered_bytes: usize,
}

/// Bounded-copy evidence streamer for replay events.
///
/// Events are encoded into a reusable scratch buffer, framed with a 4-byte
/// little-endian length prefix, and packed into bounded chunks. The sink sees a
/// borrowed slice into the streamer's chunk buffer, so the hot path avoids
/// allocating one owned `Vec<u8>` per emitted chunk.
pub struct TraceEvidenceStreamer {
    config: TraceEvidenceStreamConfig,
    chunk: Vec<u8>,
    event: Vec<u8>,
    first_sequence_in_chunk: u64,
    pending_records: u64,
    halted: bool,
    stats: TraceEvidenceStreamStats,
}

impl TraceEvidenceStreamer {
    /// Creates a new evidence streamer.
    #[must_use]
    pub fn new(config: TraceEvidenceStreamConfig) -> Self {
        let capacity = config
            .max_chunk_bytes
            .min(TraceEvidenceStreamConfig::DEFAULT_MAX_CHUNK_BYTES);
        Self {
            config,
            chunk: Vec::with_capacity(capacity),
            event: Vec::new(),
            first_sequence_in_chunk: 0,
            pending_records: 0,
            halted: false,
            stats: TraceEvidenceStreamStats::default(),
        }
    }

    /// Returns the configured stream policy.
    #[must_use]
    pub const fn config(&self) -> TraceEvidenceStreamConfig {
        self.config
    }

    /// Returns the current streaming counters.
    #[must_use]
    pub const fn stats(&self) -> TraceEvidenceStreamStats {
        self.stats
    }

    fn update_buffer_watermark(&mut self) {
        let buffered = self.chunk.len().saturating_add(self.event.len());
        self.stats.max_buffered_bytes = self.stats.max_buffered_bytes.max(buffered);
    }

    fn encode_event(&mut self, event: &ReplayEvent) -> StreamingReplayResult<usize> {
        self.event.clear();
        let mut serializer = rmp_serde::Serializer::new(&mut self.event);
        event
            .serialize(&mut serializer)
            .map_err(|err| StreamingReplayError::Serialize(err.to_string()))?;
        self.update_buffer_watermark();
        Ok(4usize.saturating_add(self.event.len()))
    }

    fn handle_record_overflow(&mut self, record_len: usize) -> StreamingReplayResult<bool> {
        self.stats.overflow_events = self.stats.overflow_events.saturating_add(1);
        match self.config.overflow_policy {
            EvidenceOverflowPolicy::Stop => {
                self.halted = true;
                self.drop_current_record();
                Ok(false)
            }
            EvidenceOverflowPolicy::DropNewest => {
                self.drop_current_record();
                Ok(true)
            }
            EvidenceOverflowPolicy::Error => Err(StreamingReplayError::EvidenceRecordTooLarge {
                actual: record_len,
                max: self.config.max_chunk_bytes,
            }),
        }
    }

    fn append_encoded_event(&mut self) -> StreamingReplayResult<()> {
        let len = u32::try_from(self.event.len()).map_err(|_| {
            StreamingReplayError::EvidenceRecordTooLarge {
                actual: self.event.len(),
                max: u32::MAX as usize,
            }
        })?;
        self.chunk.extend_from_slice(&len.to_le_bytes());
        self.chunk.extend_from_slice(&self.event);
        self.pending_records = self.pending_records.saturating_add(1);
        self.update_buffer_watermark();
        Ok(())
    }

    fn drop_current_record(&mut self) {
        self.stats.records_dropped = self.stats.records_dropped.saturating_add(1);
        self.event.clear();
    }

    fn discard_pending_chunk(&mut self) {
        self.stats.records_dropped = self
            .stats
            .records_dropped
            .saturating_add(self.pending_records);
        self.chunk.clear();
        self.pending_records = 0;
    }

    fn flush_pending<S>(&mut self, sink: &mut S) -> StreamingReplayResult<bool>
    where
        S: TraceEvidenceSink,
    {
        if self.chunk.is_empty() {
            return Ok(true);
        }

        let first_sequence = self.first_sequence_in_chunk;
        let records = self.pending_records;
        let len = self.chunk.len();
        let chunk = TraceEvidenceChunk {
            first_sequence,
            records,
            payload: &self.chunk,
        };

        match sink.push_trace_evidence(chunk)? {
            EvidenceSinkDecision::Accepted => {
                self.stats.records_emitted = self.stats.records_emitted.saturating_add(records);
                self.stats.bytes_emitted = self.stats.bytes_emitted.saturating_add(len as u64);
                self.chunk.clear();
                self.pending_records = 0;
                Ok(true)
            }
            EvidenceSinkDecision::Backpressured => {
                self.stats.backpressure_events = self.stats.backpressure_events.saturating_add(1);
                match self.config.overflow_policy {
                    EvidenceOverflowPolicy::Stop => {
                        self.halted = true;
                        self.discard_pending_chunk();
                        Ok(false)
                    }
                    EvidenceOverflowPolicy::DropNewest => {
                        self.discard_pending_chunk();
                        Ok(true)
                    }
                    EvidenceOverflowPolicy::Error => {
                        Err(StreamingReplayError::EvidenceBackpressure {
                            sequence: first_sequence,
                        })
                    }
                }
            }
            EvidenceSinkDecision::Closed => {
                self.halted = true;
                self.discard_pending_chunk();
                Ok(false)
            }
        }
    }

    /// Streams replay events from an iterator to a sink.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or if the configured policy
    /// treats overflow/backpressure as an error.
    pub fn stream_events<'a, I, S>(
        &mut self,
        events: I,
        sink: &mut S,
    ) -> StreamingReplayResult<TraceEvidenceStreamStats>
    where
        I: IntoIterator<Item = &'a ReplayEvent>,
        S: TraceEvidenceSink,
    {
        if self.halted {
            return Ok(self.stats);
        }

        for event in events {
            let sequence = self.stats.records_seen;
            self.stats.records_seen = self.stats.records_seen.saturating_add(1);

            let record_len = self.encode_event(event)?;
            if record_len > self.config.max_chunk_bytes {
                if !self.handle_record_overflow(record_len)? {
                    return Ok(self.stats);
                }
                continue;
            }

            if !self.chunk.is_empty()
                && self.chunk.len().saturating_add(record_len) > self.config.max_chunk_bytes
                && !self.flush_pending(sink)?
            {
                self.drop_current_record();
                return Ok(self.stats);
            }

            if self.chunk.is_empty() {
                self.first_sequence_in_chunk = sequence;
            }
            self.append_encoded_event()?;
        }

        self.finish(sink)
    }

    /// Streams all remaining events from a [`StreamingReplayer`] to a sink.
    ///
    /// # Errors
    ///
    /// Returns an error if the replayer, serialization, or sink fails.
    pub fn stream_replayer<S>(
        &mut self,
        replayer: &mut StreamingReplayer,
        sink: &mut S,
    ) -> StreamingReplayResult<TraceEvidenceStreamStats>
    where
        S: TraceEvidenceSink,
    {
        if self.halted {
            return Ok(self.stats);
        }

        while let Some(event) = replayer.next_event()? {
            let sequence = self.stats.records_seen;
            self.stats.records_seen = self.stats.records_seen.saturating_add(1);

            let record_len = self.encode_event(&event)?;
            if record_len > self.config.max_chunk_bytes {
                if !self.handle_record_overflow(record_len)? {
                    return Ok(self.stats);
                }
                continue;
            }

            if !self.chunk.is_empty()
                && self.chunk.len().saturating_add(record_len) > self.config.max_chunk_bytes
                && !self.flush_pending(sink)?
            {
                self.drop_current_record();
                return Ok(self.stats);
            }

            if self.chunk.is_empty() {
                self.first_sequence_in_chunk = sequence;
            }
            self.append_encoded_event()?;
        }

        self.finish(sink)
    }

    /// Flushes the final pending chunk and returns stream stats.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured policy treats final sink
    /// backpressure as an error.
    pub fn finish<S>(&mut self, sink: &mut S) -> StreamingReplayResult<TraceEvidenceStreamStats>
    where
        S: TraceEvidenceSink,
    {
        if self.halted {
            return Ok(self.stats);
        }

        let _ = self.flush_pending(sink)?;
        Ok(self.stats)
    }
}

// =============================================================================
// Progress Tracking
// =============================================================================

/// Progress information during streaming replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayProgress {
    /// Number of events processed so far.
    pub events_processed: u64,
    /// Total number of events in the trace.
    pub total_events: u64,
}

impl ReplayProgress {
    /// Creates a new progress tracker.
    #[must_use]
    pub const fn new(events_processed: u64, total_events: u64) -> Self {
        Self {
            events_processed,
            total_events,
        }
    }

    /// Returns progress as a percentage (0.0 to 100.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss is acceptable for progress display
    pub fn percent(&self) -> f64 {
        if self.total_events == 0 {
            100.0
        } else {
            (self.events_processed as f64 / self.total_events as f64) * 100.0
        }
    }

    /// Returns progress as a fraction (0.0 to 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss is acceptable for progress display
    pub fn fraction(&self) -> f64 {
        if self.total_events == 0 {
            1.0
        } else {
            self.events_processed as f64 / self.total_events as f64
        }
    }

    /// Returns true if replay is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.events_processed >= self.total_events
    }

    /// Returns the number of remaining events.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.total_events.saturating_sub(self.events_processed)
    }
}

impl std::fmt::Display for ReplayProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} ({:.1}%)",
            self.events_processed,
            self.total_events,
            self.percent()
        )
    }
}

// =============================================================================
// Checkpoint
// =============================================================================

/// A checkpoint for resuming long replays.
///
/// Checkpoints capture the current position in the trace, allowing replay
/// to be suspended and resumed later without re-processing all events.
///
/// # Safety
///
/// Checkpoints are only valid for the specific trace file they were created from.
/// Attempting to resume with a checkpoint from a different trace will result in
/// an error.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReplayCheckpoint {
    /// Number of events that have been processed.
    pub events_processed: u64,

    /// Total number of events in the trace this checkpoint came from.
    pub total_events: u64,

    /// The seed from the trace metadata (for validation).
    pub seed: u64,

    /// Hash of the trace metadata (for validation).
    pub metadata_hash: u64,

    /// Deterministic checkpoint timestamp derived from trace metadata and position.
    pub created_at: u64,
}

impl ReplayCheckpoint {
    /// Creates a new checkpoint.
    fn new(events_processed: u64, total_events: u64, metadata: &TraceMetadata) -> Self {
        Self {
            events_processed,
            total_events,
            seed: metadata.seed,
            metadata_hash: Self::hash_metadata(metadata),
            // Keep checkpoint artifacts stable for identical replay state instead of
            // reintroducing ambient wall-clock time into the replay toolchain.
            created_at: metadata.recorded_at.saturating_add(events_processed),
        }
    }

    /// Validates that this checkpoint matches the given trace metadata.
    fn validate(&self, metadata: &TraceMetadata, total_events: u64) -> StreamingReplayResult<()> {
        if self.seed != metadata.seed {
            return Err(StreamingReplayError::CheckpointMismatch(format!(
                "seed mismatch: checkpoint has {}, trace has {}",
                self.seed, metadata.seed
            )));
        }

        let expected_hash = Self::hash_metadata(metadata);
        if self.metadata_hash != expected_hash {
            return Err(StreamingReplayError::CheckpointMismatch(
                "metadata hash mismatch".to_string(),
            ));
        }

        if self.total_events != total_events {
            return Err(StreamingReplayError::CheckpointMismatch(format!(
                "event count mismatch: checkpoint has {}, trace has {}",
                self.total_events, total_events
            )));
        }

        if self.events_processed > total_events {
            return Err(StreamingReplayError::CheckpointMismatch(format!(
                "checkpoint position {} exceeds trace length {}",
                self.events_processed, total_events
            )));
        }

        Ok(())
    }

    /// Computes a hash of the trace metadata for validation.
    fn hash_metadata(metadata: &TraceMetadata) -> u64 {
        use std::hash::{Hash, Hasher};

        struct SimpleHasher(u64);

        impl Hasher for SimpleHasher {
            fn finish(&self) -> u64 {
                self.0
            }

            fn write(&mut self, bytes: &[u8]) {
                for byte in bytes {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(*byte));
                }
            }
        }

        let mut hasher = SimpleHasher(0);
        metadata.seed.hash(&mut hasher);
        metadata.version.hash(&mut hasher);
        metadata.recorded_at.hash(&mut hasher);
        metadata.config_hash.hash(&mut hasher);
        metadata.description.hash(&mut hasher);
        hasher.finish()
    }

    /// Serializes the checkpoint to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> StreamingReplayResult<Vec<u8>> {
        rmp_serde::to_vec(self)
            .map_err(|e: rmp_serde::encode::Error| StreamingReplayError::Serialize(e.to_string()))
    }

    /// Deserializes a checkpoint from bytes.
    ///
    /// # Security
    ///
    /// This method validates input size and performs basic bounds checking
    /// before deserialization to prevent DoS attacks from malformed data.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails or if the data fails validation.
    pub fn from_bytes(bytes: &[u8]) -> StreamingReplayResult<Self> {
        // Size validation: prevent DoS from oversized input
        const MAX_CHECKPOINT_SIZE: usize = 1024; // Reasonable limit for MessagePack checkpoint
        if bytes.len() > MAX_CHECKPOINT_SIZE {
            return Err(StreamingReplayError::InvalidCheckpoint(format!(
                "checkpoint too large: {} bytes (max {})",
                bytes.len(),
                MAX_CHECKPOINT_SIZE
            )));
        }

        // Require minimum size for valid checkpoint
        const MIN_CHECKPOINT_SIZE: usize = 16; // Minimum for basic fields
        if bytes.len() < MIN_CHECKPOINT_SIZE {
            return Err(StreamingReplayError::InvalidCheckpoint(format!(
                "checkpoint too small: {} bytes (min {})",
                bytes.len(),
                MIN_CHECKPOINT_SIZE
            )));
        }

        // Deserialize with error handling
        let checkpoint = rmp_serde::from_slice(bytes).map_err(|e: rmp_serde::decode::Error| {
            StreamingReplayError::InvalidCheckpoint(format!("deserialization failed: {}", e))
        })?;

        // Basic bounds validation after deserialization
        Self::validate_bounds(&checkpoint)?;

        Ok(checkpoint)
    }

    /// Validates checkpoint field bounds to prevent logical inconsistencies.
    fn validate_bounds(checkpoint: &Self) -> StreamingReplayResult<()> {
        // Events processed cannot exceed total events
        if checkpoint.events_processed > checkpoint.total_events {
            return Err(StreamingReplayError::InvalidCheckpoint(format!(
                "events_processed ({}) exceeds total_events ({})",
                checkpoint.events_processed, checkpoint.total_events
            )));
        }

        // Sanity check for reasonable event counts (prevent overflow issues)
        const MAX_REASONABLE_EVENTS: u64 = u64::MAX / 2; // Leave headroom
        if checkpoint.total_events > MAX_REASONABLE_EVENTS {
            return Err(StreamingReplayError::InvalidCheckpoint(format!(
                "total_events too large: {} (max reasonable: {})",
                checkpoint.total_events, MAX_REASONABLE_EVENTS
            )));
        }

        Ok(())
    }
}

// =============================================================================
// Streaming Replayer
// =============================================================================

/// A streaming replayer that processes traces with O(1) memory.
///
/// Unlike [`TraceReplayer`][super::replayer::TraceReplayer] which loads all events
/// into memory, `StreamingReplayer` reads events one at a time from disk. This
/// enables replay of traces with millions of events that wouldn't fit in memory.
///
/// # Memory Usage
///
/// - File reader buffer: ~64 KB
/// - Current event: ~64 bytes
/// - Peeked event: ~64 bytes (optional)
/// - Total: O(1) regardless of trace size
///
/// # Example
///
/// ```ignore
/// let mut replayer = StreamingReplayer::open("trace.bin")?;
///
/// while let Some(event) = replayer.next_event()? {
///     process_event(&event);
/// }
/// ```
pub struct StreamingReplayer {
    /// The underlying file reader.
    reader: TraceReader,

    /// Cached metadata.
    metadata: TraceMetadata,

    /// Total number of events (from file header).
    total_events: u64,

    /// Number of events that have been consumed.
    events_consumed: u64,

    /// Peeked event (if any).
    peeked: Option<ReplayEvent>,

    /// Current replay mode.
    mode: ReplayMode,

    /// Whether we're at a breakpoint.
    at_breakpoint: bool,
    /// Last error observed via the [`EventSource`] adapter path.
    ///
    /// This preserves diagnosability for consumers that use the fallible-free
    /// trait surface.
    event_source_error: Option<StreamingReplayError>,
}

impl StreamingReplayer {
    /// Opens a trace file for streaming replay.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or has an invalid format.
    pub fn open(path: impl AsRef<Path>) -> StreamingReplayResult<Self> {
        let reader = TraceReader::open(path)?;
        let metadata = reader.metadata().clone();
        let total_events = reader.event_count();

        Ok(Self {
            reader,
            metadata,
            total_events,
            events_consumed: 0,
            peeked: None,
            mode: ReplayMode::Run,
            at_breakpoint: false,
            event_source_error: None,
        })
    }

    /// Resumes replay from a checkpoint.
    ///
    /// This skips forward to the checkpoint position without processing
    /// intermediate events.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened
    /// - The checkpoint is invalid
    /// - The checkpoint doesn't match the trace file
    pub fn resume(
        path: impl AsRef<Path>,
        checkpoint: ReplayCheckpoint,
    ) -> StreamingReplayResult<Self> {
        let mut reader = TraceReader::open(path)?;
        let metadata = reader.metadata().clone();
        let total_events = reader.event_count();

        // Validate checkpoint matches this trace
        checkpoint.validate(&metadata, total_events)?;

        // Skip to checkpoint position
        for _ in 0..checkpoint.events_processed {
            if reader.read_event()?.is_none() {
                return Err(StreamingReplayError::CheckpointMismatch(
                    "trace ended before checkpoint position".to_string(),
                ));
            }
        }

        Ok(Self {
            reader,
            metadata,
            total_events,
            events_consumed: checkpoint.events_processed,
            peeked: None,
            mode: ReplayMode::Run,
            at_breakpoint: false,
            event_source_error: None,
        })
    }

    /// Returns the trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        &self.metadata
    }

    /// Returns the total number of events in the trace.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Returns the number of events consumed so far.
    #[must_use]
    pub fn events_consumed(&self) -> u64 {
        self.events_consumed
    }

    /// Returns the current replay progress.
    #[must_use]
    pub fn progress(&self) -> ReplayProgress {
        ReplayProgress::new(self.events_consumed, self.total_events)
    }

    /// Returns true if all events have been consumed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.events_consumed >= self.total_events && self.peeked.is_none()
    }

    /// Returns true if we're at a breakpoint.
    #[must_use]
    pub fn at_breakpoint(&self) -> bool {
        self.at_breakpoint
    }

    /// Returns the most recent [`EventSource`] adapter error, if any.
    #[must_use]
    pub fn last_event_source_error(&self) -> Option<&StreamingReplayError> {
        self.event_source_error.as_ref()
    }

    /// Takes and clears the most recent [`EventSource`] adapter error.
    pub fn take_event_source_error(&mut self) -> Option<StreamingReplayError> {
        self.event_source_error.take()
    }

    /// Sets the replay mode.
    pub fn set_mode(&mut self, mode: ReplayMode) {
        self.mode = mode;
        self.at_breakpoint = false;
    }

    /// Returns the current replay mode.
    #[must_use]
    pub fn mode(&self) -> &ReplayMode {
        &self.mode
    }

    /// Peeks at the next event without consuming it.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn peek(&mut self) -> StreamingReplayResult<Option<&ReplayEvent>> {
        if self.peeked.is_none() {
            self.peeked = self.reader.read_event()?;
        }
        Ok(self.peeked.as_ref())
    }

    /// Reads and consumes the next event.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn next_event(&mut self) -> StreamingReplayResult<Option<ReplayEvent>> {
        let event = if let Some(peeked) = self.peeked.take() {
            Some(peeked)
        } else {
            self.reader.read_event()?
        };

        if event.is_some() {
            self.events_consumed += 1;

            // Check for breakpoint
            if let Some(ref e) = event {
                self.at_breakpoint = self.check_breakpoint(e);
            }
        }

        Ok(event)
    }

    /// Verifies that an actual event matches the next expected event.
    ///
    /// Does not consume the event - use `verify_and_advance` for that.
    ///
    /// # Errors
    ///
    /// Returns an error with divergence details if they don't match.
    pub fn verify(&mut self, actual: &ReplayEvent) -> StreamingReplayResult<()> {
        // Store position before borrowing self through peek()
        let current_position = self.events_consumed;

        let expected = self.peek()?;

        let Some(expected) = expected else {
            return Err(StreamingReplayError::Divergence(DivergenceError {
                index: current_position as usize,
                expected: None,
                actual: actual.clone(),
                context: "Trace ended but execution continued".to_string(),
            }));
        };

        if expected != actual {
            // Clone the expected event before the borrow ends
            let expected_clone = expected.clone();
            return Err(StreamingReplayError::Divergence(DivergenceError {
                index: current_position as usize,
                expected: Some(expected_clone),
                actual: actual.clone(),
                context: format!("Event mismatch at position {current_position}"),
            }));
        }

        Ok(())
    }

    /// Verifies and consumes the next event.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails or reading fails.
    pub fn verify_and_advance(
        &mut self,
        actual: &ReplayEvent,
    ) -> StreamingReplayResult<ReplayEvent> {
        self.verify(actual)?;
        self.next_event()
            .transpose()
            .expect("event was peeked so must exist")
    }

    /// Creates a checkpoint at the current position.
    ///
    /// The checkpoint can be used later with [`resume`][Self::resume] to
    /// continue replay from this point.
    #[must_use]
    pub fn checkpoint(&self) -> ReplayCheckpoint {
        ReplayCheckpoint::new(self.events_consumed, self.total_events, &self.metadata)
    }

    /// Steps forward according to the current mode.
    ///
    /// In Step mode, advances one event and stops.
    /// In Run mode, advances all events until completion.
    /// In RunTo mode, advances until the breakpoint is reached.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn step(&mut self) -> StreamingReplayResult<Option<ReplayEvent>> {
        self.at_breakpoint = false;
        self.next_event()
    }

    /// Runs until completion or breakpoint.
    ///
    /// Returns the number of events processed.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn run(&mut self) -> StreamingReplayResult<u64> {
        let mut count = 0u64;

        while !self.is_complete() && !self.at_breakpoint {
            if self.next_event()?.is_some() {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Runs with a callback for each event.
    ///
    /// This is useful for processing events as they're read without
    /// accumulating them in memory.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the callback returns an error.
    pub fn run_with<F, E>(&mut self, mut callback: F) -> Result<u64, E>
    where
        F: FnMut(ReplayEvent, ReplayProgress) -> Result<(), E>,
        E: From<StreamingReplayError>,
    {
        let mut count = 0u64;

        while !self.is_complete() && !self.at_breakpoint {
            if let Some(event) = self.next_event()? {
                let progress = self.progress();
                callback(event, progress)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Checks if the current event triggers a breakpoint.
    fn check_breakpoint(&self, event: &ReplayEvent) -> bool {
        match &self.mode {
            ReplayMode::Step => true,
            ReplayMode::Run => false,
            ReplayMode::RunTo(breakpoint) => match breakpoint {
                Breakpoint::EventIndex(idx) => self.events_consumed as usize == *idx + 1,
                Breakpoint::Tick(tick) => {
                    if let ReplayEvent::TaskScheduled { at_tick, .. } = event {
                        *at_tick >= *tick
                    } else {
                        false
                    }
                }
                Breakpoint::Task(task_id) => {
                    if let ReplayEvent::TaskScheduled { task, .. } = event {
                        task == task_id
                    } else {
                        false
                    }
                }
            },
        }
    }
}

impl EventSource for StreamingReplayer {
    fn next_event(&mut self) -> Option<ReplayEvent> {
        match Self::next_event(self) {
            Ok(event) => {
                self.event_source_error = None;
                event
            }
            Err(err) => {
                self.event_source_error = Some(err);
                None
            }
        }
    }

    fn metadata(&self) -> &TraceMetadata {
        &self.metadata
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::file::{HEADER_SIZE, TraceWriter, write_trace};
    use crate::trace::replay::CompactTaskId;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    fn sample_events(count: u64) -> Vec<ReplayEvent> {
        (0..count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect()
    }

    #[derive(Debug, Default)]
    struct CapturingEvidenceSink {
        chunks: Vec<(u64, u64, Vec<u8>)>,
        backpressure_after_chunks: Option<usize>,
    }

    impl CapturingEvidenceSink {
        fn with_backpressure_after_chunks(limit: usize) -> Self {
            Self {
                chunks: Vec::new(),
                backpressure_after_chunks: Some(limit),
            }
        }

        fn decoded_ticks(&self) -> Vec<u64> {
            let mut ticks = Vec::new();
            for (_, _, payload) in &self.chunks {
                let mut cursor = payload.as_slice();
                while !cursor.is_empty() {
                    let (len_bytes, rest) = cursor.split_at(4);
                    let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
                    let (event_bytes, remaining) = rest.split_at(len);
                    let event: ReplayEvent = rmp_serde::from_slice(event_bytes).unwrap();
                    if let ReplayEvent::TaskScheduled { at_tick, .. } = event {
                        ticks.push(at_tick);
                    }
                    cursor = remaining;
                }
            }
            ticks
        }
    }

    impl TraceEvidenceSink for CapturingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            if let Some(limit) = self.backpressure_after_chunks
                && self.chunks.len() >= limit
            {
                return Ok(EvidenceSinkDecision::Backpressured);
            }
            self.chunks
                .push((chunk.first_sequence, chunk.records, chunk.payload.to_vec()));
            Ok(EvidenceSinkDecision::Accepted)
        }
    }

    #[derive(Debug, Default)]
    struct CountingEvidenceSink {
        chunks: u64,
        max_chunk_len: usize,
    }

    impl TraceEvidenceSink for CountingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            assert!(!chunk.is_empty());
            self.chunks = self.chunks.saturating_add(1);
            self.max_chunk_len = self.max_chunk_len.max(chunk.len());
            Ok(EvidenceSinkDecision::Accepted)
        }
    }

    #[derive(Debug, Default)]
    struct ClosingEvidenceSink {
        calls: u64,
    }

    impl TraceEvidenceSink for ClosingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            assert!(!chunk.is_empty());
            self.calls = self.calls.saturating_add(1);
            Ok(EvidenceSinkDecision::Closed)
        }
    }

    #[test]
    fn evidence_stream_chunks_respect_capacity_and_ordering() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(48);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::default();

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(stats.records_seen, 8);
        assert_eq!(stats.records_emitted, 8);
        assert_eq!(stats.records_dropped, 0);
        assert_eq!(stats.overflow_events, 0);
        assert_eq!(stats.backpressure_events, 0);
        assert!(stats.bytes_emitted > 0);
        assert!(stats.max_buffered_bytes <= config.max_chunk_bytes * 2);
        assert!(!sink.chunks.is_empty());
        for (_, records, payload) in &sink.chunks {
            assert!(*records >= 1);
            assert!(payload.len() <= config.max_chunk_bytes);
        }
        assert_eq!(sink.decoded_ticks(), (0..8).collect::<Vec<_>>());
        assert_eq!(sink.chunks.first().unwrap().0, 0);
    }

    #[test]
    fn evidence_stream_backpressure_drop_newest_records_decision() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(48)
            .with_overflow_policy(EvidenceOverflowPolicy::DropNewest);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::with_backpressure_after_chunks(1);

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(stats.records_seen, 8);
        assert!(stats.records_emitted > 0);
        assert!(stats.records_emitted < stats.records_seen);
        assert_eq!(
            stats.records_seen,
            stats.records_emitted + stats.records_dropped
        );
        assert!(stats.backpressure_events > 0);
        assert_eq!(sink.chunks.len(), 1);
        let accepted_ticks = sink.decoded_ticks();
        assert_eq!(accepted_ticks.first(), Some(&0));
        assert_eq!(accepted_ticks.len() as u64, stats.records_emitted);
        assert!(accepted_ticks.len() < events.len());
    }

    #[test]
    fn evidence_stream_closed_sink_drops_pending_and_halts() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(256);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut closing_sink = ClosingEvidenceSink::default();

        let stats = streamer
            .stream_events(events.iter(), &mut closing_sink)
            .unwrap();

        assert_eq!(closing_sink.calls, 1);
        assert_eq!(stats.records_seen, 8);
        assert_eq!(stats.records_emitted, 0);
        assert_eq!(stats.records_dropped, 8);
        assert_eq!(stats.records_seen, stats.records_dropped);

        let mut accepting_sink = CapturingEvidenceSink::default();
        let after_halt = streamer.finish(&mut accepting_sink).unwrap();
        assert_eq!(after_halt, stats);
        assert!(accepting_sink.chunks.is_empty());
    }

    #[test]
    fn evidence_stream_stop_backpressure_drops_pending_and_current_record() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(48)
            .with_overflow_policy(EvidenceOverflowPolicy::Stop);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::with_backpressure_after_chunks(1);

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(sink.chunks.len(), 1);
        assert!(stats.records_seen > stats.records_emitted);
        assert_eq!(
            stats.records_seen,
            stats.records_emitted + stats.records_dropped
        );
        assert_eq!(stats.backpressure_events, 1);

        let emitted_before_retry = stats.records_emitted;
        let mut retry_sink = CapturingEvidenceSink::default();
        let retry_stats = streamer
            .stream_events(events.iter(), &mut retry_sink)
            .unwrap();
        assert_eq!(retry_stats, stats);
        assert_eq!(retry_stats.records_emitted, emitted_before_retry);
        assert!(retry_sink.chunks.is_empty());
    }

    #[test]
    fn evidence_stream_oversized_record_errors_when_policy_requires() {
        let events = sample_events(1);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(4)
            .with_overflow_policy(EvidenceOverflowPolicy::Error);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::default();

        let err = streamer
            .stream_events(events.iter(), &mut sink)
            .unwrap_err();
        assert!(matches!(
            err,
            StreamingReplayError::EvidenceRecordTooLarge { .. }
        ));
    }

    #[test]
    fn evidence_stream_large_trace_keeps_bounded_buffers() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let metadata = TraceMetadata::new(42);
        let event_count = 1_000u64;
        {
            let mut writer = TraceWriter::create(path).unwrap();
            writer.write_metadata(&metadata).unwrap();
            for event in sample_events(event_count) {
                writer.write_event(&event).unwrap();
            }
            writer.finish().unwrap();
        }

        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(256);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut replayer = StreamingReplayer::open(path).unwrap();
        let mut sink = CountingEvidenceSink::default();

        let stats = streamer.stream_replayer(&mut replayer, &mut sink).unwrap();

        assert_eq!(stats.records_seen, event_count);
        assert_eq!(stats.records_emitted, event_count);
        assert_eq!(stats.records_dropped, 0);
        assert_eq!(stats.overflow_events, 0);
        assert!(sink.chunks > 1);
        assert!(sink.max_chunk_len <= config.max_chunk_bytes);
        assert!(stats.max_buffered_bytes <= config.max_chunk_bytes * 2);
        assert!(replayer.is_complete());
    }

    #[test]
    fn basic_streaming_replay() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Stream replay
        let mut replayer = StreamingReplayer::open(path).unwrap();

        assert_eq!(replayer.total_events(), 100);
        assert_eq!(replayer.events_consumed(), 0);
        assert!(!replayer.is_complete());

        // Read all events
        let mut count = 0u64;
        while let Some(event) = replayer.next_event().unwrap() {
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                assert_eq!(task.0, count);
                assert_eq!(at_tick, count);
            } else {
                panic!("unexpected event type");
            }
            count += 1;
        }

        assert_eq!(count, 100);
        assert!(replayer.is_complete());
    }

    #[test]
    fn progress_tracking() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        // Check initial progress
        let progress = replayer.progress();
        assert_eq!(progress.events_processed, 0);
        assert_eq!(progress.total_events, 100);
        assert!((progress.percent() - 0.0).abs() < 0.01);

        // Read 50 events
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }

        // Check midpoint progress
        let progress = replayer.progress();
        assert_eq!(progress.events_processed, 50);
        assert!((progress.percent() - 50.0).abs() < 0.01);
        assert_eq!(progress.remaining(), 50);

        // Read rest
        while replayer.next_event().unwrap().is_some() {}

        // Check final progress
        let progress = replayer.progress();
        assert!(progress.is_complete());
        assert!((progress.percent() - 100.0).abs() < 0.01);
    }

    #[test]
    fn peek_without_consuming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(10);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        // Peek multiple times - should return same event
        let peeked1 = replayer.peek().unwrap().cloned();
        let peeked2 = replayer.peek().unwrap().cloned();
        assert_eq!(peeked1, peeked2);
        assert_eq!(replayer.events_consumed(), 0);

        // Now consume
        let consumed = replayer.next_event().unwrap();
        assert_eq!(consumed, peeked1);
        assert_eq!(replayer.events_consumed(), 1);

        // Next peek should be different
        let peeked3 = replayer.peek().unwrap().cloned();
        assert_ne!(peeked3, peeked1);
    }

    #[test]
    fn checkpoint_and_resume() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Replay partway and checkpoint
        let mut replayer = StreamingReplayer::open(path).unwrap();
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }

        let checkpoint = replayer.checkpoint();
        assert_eq!(checkpoint.events_processed, 50);
        assert_eq!(checkpoint.total_events, 100);

        // Serialize and deserialize checkpoint
        let checkpoint_bytes = checkpoint.to_bytes().unwrap();
        let restored_checkpoint = ReplayCheckpoint::from_bytes(&checkpoint_bytes).unwrap();

        // Resume from checkpoint
        let mut resumed = StreamingReplayer::resume(path, restored_checkpoint).unwrap();
        assert_eq!(resumed.events_consumed(), 50);

        // Continue reading
        let mut count = 50u64;
        while let Some(event) = resumed.next_event().unwrap() {
            if let ReplayEvent::TaskScheduled { task, .. } = event {
                assert_eq!(task.0, count);
            }
            count += 1;
        }

        assert_eq!(count, 100);
    }

    #[test]
    fn checkpoint_deserialization_accepts_initial_deterministic_checkpoint() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(3);
        write_trace(path, &metadata, &events).unwrap();

        let replayer = StreamingReplayer::open(path).unwrap();
        let checkpoint = replayer.checkpoint();

        assert_eq!(checkpoint.events_processed, 0);
        assert_eq!(checkpoint.total_events, 3);
        assert_eq!(
            checkpoint.created_at, 0,
            "recorded_at=0 is the deterministic no-wall-clock trace stamp"
        );

        let checkpoint_bytes = checkpoint.to_bytes().unwrap();
        let restored_checkpoint = ReplayCheckpoint::from_bytes(&checkpoint_bytes).unwrap();
        assert_eq!(restored_checkpoint.events_processed, 0);
        assert_eq!(restored_checkpoint.created_at, 0);

        let resumed = StreamingReplayer::resume(path, restored_checkpoint).unwrap();
        assert_eq!(resumed.events_consumed(), 0);
    }

    #[test]
    fn checkpoint_validation() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        // Write two different traces
        let metadata1 = TraceMetadata::new(42);
        let metadata2 = TraceMetadata::new(99);
        write_trace(temp1.path(), &metadata1, &sample_events(100)).unwrap();
        write_trace(temp2.path(), &metadata2, &sample_events(100)).unwrap();

        // Checkpoint from first trace
        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        // Try to resume with second trace - should fail
        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_validation_rejects_same_seed_metadata_drift() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        let metadata1 = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 100,
            config_hash: 0xCAFE,
            description: Some("trace-a".into()),
        };
        let metadata2 = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 200,
            config_hash: 0xCAFE,
            description: Some("trace-b".into()),
        };
        write_trace(temp1.path(), &metadata1, &sample_events(4)).unwrap();
        write_trace(temp2.path(), &metadata2, &sample_events(4)).unwrap();

        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..2 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_validation_rejects_event_count_drift() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 500,
            config_hash: 0xBEEF,
            description: Some("same-metadata".into()),
        };
        write_trace(temp1.path(), &metadata, &sample_events(4)).unwrap();
        write_trace(temp2.path(), &metadata, &sample_events(6)).unwrap();

        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..2 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_bytes_are_stable_for_same_position() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 1_000,
            config_hash: 0xCAFE,
            description: Some("stable checkpoint".into()),
        };
        write_trace(path, &metadata, &sample_events(5)).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        for _ in 0..3 {
            replayer.next_event().unwrap();
        }

        let checkpoint_a = replayer.checkpoint();
        let checkpoint_b = replayer.checkpoint();

        assert_eq!(checkpoint_a.events_processed, 3);
        assert_eq!(checkpoint_a.total_events, 5);
        assert_eq!(checkpoint_a.created_at, 1_003);
        assert_eq!(checkpoint_a.created_at, checkpoint_b.created_at);
        assert_eq!(
            checkpoint_a.to_bytes().unwrap(),
            checkpoint_b.to_bytes().unwrap()
        );
    }

    #[test]
    fn checkpoint_created_at_advances_with_position() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 500,
            config_hash: 0xBEEF,
            description: None,
        };
        write_trace(path, &metadata, &sample_events(4)).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        let first = replayer.checkpoint();
        assert_eq!(first.created_at, 500);

        replayer.next_event().unwrap();
        let second = replayer.checkpoint();
        assert_eq!(second.created_at, 501);
        assert_eq!(second.created_at, first.created_at + 1);

        replayer.next_event().unwrap();
        let third = replayer.checkpoint();
        assert_eq!(third.created_at, 502);
    }

    #[test]
    fn run_with_callback() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(50);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        let mut event_ids = Vec::new();
        let count = replayer
            .run_with(|event, progress| {
                if let ReplayEvent::TaskScheduled { task, .. } = event {
                    event_ids.push(task.0);
                }
                // Check progress is accurate
                assert!(!progress.is_complete() || progress.events_processed == 50);
                Ok::<_, StreamingReplayError>(())
            })
            .unwrap();

        assert_eq!(count, 50);
        assert_eq!(event_ids.len(), 50);
        for (i, id) in event_ids.iter().enumerate() {
            assert_eq!(*id, i as u64);
        }
    }

    #[test]
    fn large_trace_streaming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let event_count = 10_000u64;

        // Write large trace using streaming writer
        {
            let mut writer = TraceWriter::create(path).unwrap();
            writer.write_metadata(&metadata).unwrap();
            for i in 0..event_count {
                writer
                    .write_event(&ReplayEvent::TaskScheduled {
                        task: CompactTaskId(i),
                        at_tick: i,
                    })
                    .unwrap();
            }
            writer.finish().unwrap();
        }

        // Stream replay - should use constant memory
        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert_eq!(replayer.total_events(), event_count);

        let mut count = 0u64;
        while replayer.next_event().unwrap().is_some() {
            count += 1;
        }

        assert_eq!(count, event_count);
    }

    #[test]
    fn step_mode_streaming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(5);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::Step);

        // Each step should set breakpoint
        for _ in 0..5 {
            replayer.step().unwrap();
            assert!(replayer.at_breakpoint());
        }

        // Final step returns None
        let event = replayer.step().unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn breakpoint_at_tick() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 10, // Ticks: 0, 10, 20, 30, ...
            })
            .collect();
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(50)));

        let count = replayer.run().unwrap();
        // Should stop at tick >= 50 (which is at_tick=50, event index 5)
        assert!(replayer.at_breakpoint());
        assert_eq!(count, 6); // Events 0-5 (ticks 0, 10, 20, 30, 40, 50)
    }

    #[test]
    fn empty_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        write_trace(path, &metadata, &[]).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert_eq!(replayer.total_events(), 0);
        assert!(replayer.progress().is_complete());

        let event = replayer.next_event().unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn verify_past_end_of_trace_reports_trace_exhausted() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert!(replayer.next_event().unwrap().is_some());
        assert!(replayer.is_complete());

        let actual = ReplayEvent::RngSeed { seed: 99 };
        let err = replayer.verify(&actual).unwrap_err();
        match err {
            StreamingReplayError::Divergence(divergence) => {
                assert!(divergence.expected.is_none());
                assert_eq!(divergence.index, 1);
                assert!(divergence.context.contains("Trace ended"));
                assert!(format!("{divergence}").contains("<trace_exhausted>"));
            }
            other => panic!("expected divergence error, got {other:?}"),
        }
    }

    #[test]
    fn verify_mismatch_preserves_expected_event() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 10,
        }];
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        let actual = ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 10,
        };
        let err = replayer.verify(&actual).unwrap_err();
        match err {
            StreamingReplayError::Divergence(divergence) => {
                assert_eq!(
                    divergence.expected,
                    Some(ReplayEvent::TaskScheduled {
                        task: CompactTaskId(1),
                        at_tick: 10,
                    })
                );
                assert_eq!(divergence.actual, actual);
                assert_eq!(divergence.index, 0);
            }
            other => panic!("expected divergence error, got {other:?}"),
        }
    }

    #[test]
    fn progress_display() {
        let progress = ReplayProgress::new(250, 1000);
        let display = format!("{progress}");
        assert!(display.contains("250/1000"));
        assert!(display.contains("25.0%"));
    }

    #[test]
    fn run_with_respects_runto_breakpoint() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 10,
            })
            .collect();
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(50)));

        let count = replayer
            .run_with(|_, _| Ok::<_, StreamingReplayError>(()))
            .unwrap();
        assert_eq!(count, 6);
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn run_with_respects_step_mode() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(7);
        let events = sample_events(5);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::Step);

        let count = replayer
            .run_with(|_, _| Ok::<_, StreamingReplayError>(()))
            .unwrap();
        assert_eq!(count, 1);
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn event_source_adapter_captures_stream_error() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        write_trace(path, &metadata, &events).unwrap();

        // Corrupt the first event payload byte while preserving file structure.
        let meta_len = rmp_serde::to_vec(&metadata).unwrap().len() as u64;
        let first_event_payload = HEADER_SIZE as u64 + meta_len + 8 + 4;
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(first_event_payload)).unwrap();
        file.write_all(&[0xC1]).unwrap(); // MessagePack never-used marker => decode error.
        file.flush().unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        let event = <StreamingReplayer as EventSource>::next_event(&mut replayer);
        assert!(event.is_none());

        let err = replayer
            .take_event_source_error()
            .expect("expected captured event-source error");
        assert!(matches!(err, StreamingReplayError::File(_)));
        assert!(replayer.last_event_source_error().is_none());
    }

    #[test]
    fn checkpoint_deserialization_validates_input_size() {
        // Test oversized input rejection
        let large_input = vec![0u8; 2048]; // Exceeds MAX_CHECKPOINT_SIZE
        let result = ReplayCheckpoint::from_bytes(&large_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checkpoint too large")
        );

        // Test undersized input rejection
        let small_input = vec![0u8; 8]; // Below MIN_CHECKPOINT_SIZE
        let result = ReplayCheckpoint::from_bytes(&small_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checkpoint too small")
        );

        // Test malformed MessagePack rejection
        let malformed_input = vec![0xFF; 64]; // Invalid MessagePack
        let result = ReplayCheckpoint::from_bytes(&malformed_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("deserialization failed")
        );
    }

    #[test]
    fn checkpoint_deserialization_validates_field_bounds() {
        // Create a checkpoint with invalid bounds (events_processed > total_events)
        let bad_checkpoint = ReplayCheckpoint {
            events_processed: 100,
            total_events: 50, // Invalid: less than events_processed
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 1000,
        };

        // Serialize it (bypassing validation)
        let bytes = rmp_serde::to_vec(&bad_checkpoint).unwrap();

        // from_bytes should reject it due to bounds validation
        let result = ReplayCheckpoint::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exceeds total_events")
        );

        // Test excessive event count
        let excessive_checkpoint = ReplayCheckpoint {
            events_processed: 0,
            total_events: u64::MAX, // Too large
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 1000,
        };
        let bytes = rmp_serde::to_vec(&excessive_checkpoint).unwrap();
        let result = ReplayCheckpoint::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("total_events too large")
        );

        let deterministic_epoch_checkpoint = ReplayCheckpoint {
            events_processed: 0,
            total_events: 10,
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 0,
        };
        let bytes = rmp_serde::to_vec(&deterministic_epoch_checkpoint).unwrap();
        let restored = ReplayCheckpoint::from_bytes(&bytes).unwrap();
        assert_eq!(restored.created_at, 0);
    }
}
