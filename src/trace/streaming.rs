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
}

/// Result type for streaming replay operations.
pub type StreamingReplayResult<T> = Result<T, StreamingReplayError>;

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

    /// The seed from the trace metadata (for validation).
    pub seed: u64,

    /// Hash of the trace metadata (for validation).
    pub metadata_hash: u64,

    /// Timestamp when checkpoint was created.
    pub created_at: u64,
}

impl ReplayCheckpoint {
    /// Creates a new checkpoint.
    fn new(events_processed: u64, metadata: &TraceMetadata) -> Self {
        Self {
            events_processed,
            seed: metadata.seed,
            metadata_hash: Self::hash_metadata(metadata),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64),
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
        metadata.config_hash.hash(&mut hasher);
        hasher.finish()
    }

    /// Serializes the checkpoint to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> StreamingReplayResult<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| StreamingReplayError::Serialize(e.to_string()))
    }

    /// Deserializes a checkpoint from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> StreamingReplayResult<Self> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| StreamingReplayError::InvalidCheckpoint(e.to_string()))
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
                expected: ReplayEvent::RngSeed { seed: 0 }, // Placeholder
                actual: actual.clone(),
                context: "Trace ended but execution continued".to_string(),
            }));
        };

        if expected != actual {
            // Clone the expected event before the borrow ends
            let expected_clone = expected.clone();
            return Err(StreamingReplayError::Divergence(DivergenceError {
                index: current_position as usize,
                expected: expected_clone,
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
        ReplayCheckpoint::new(self.events_consumed, &self.metadata)
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

        while !self.is_complete() {
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
        Self::next_event(self).ok().flatten()
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
    use super::*;
    use crate::trace::file::{write_trace, TraceWriter};
    use crate::trace::replay::CompactTaskId;
    use tempfile::NamedTempFile;

    fn sample_events(count: u64) -> Vec<ReplayEvent> {
        (0..count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect()
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
    fn progress_display() {
        let progress = ReplayProgress::new(250, 1000);
        let display = format!("{progress}");
        assert!(display.contains("250/1000"));
        assert!(display.contains("25.0%"));
    }
}
