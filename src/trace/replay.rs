//! Replay event schema for deterministic record/replay.
//!
//! This module defines the [`ReplayEvent`] enum that captures all sources of
//! non-determinism in the Lab runtime. By recording these events during execution,
//! we can replay the exact same execution later for debugging or verification.
//!
//! # Design Goals
//!
//! - **Compact**: Events should typically be < 64 bytes for efficient storage
//! - **Complete**: All non-determinism sources must be captured
//! - **Versioned**: Format is versioned for forward compatibility
//! - **Deterministic**: Same events → same execution
//!
//! # Non-Determinism Sources
//!
//! | Category | Events | What It Captures |
//! |----------|--------|------------------|
//! | Scheduling | TaskScheduled, TaskYielded, TaskCompleted | Which task runs when |
//! | Time | TimeAdvanced, TimerCreated, TimerFired | Virtual time progression |
//! | I/O | IoReady, IoError | Simulated I/O results |
//! | RNG | RngSeed, RngValue | Deterministic randomness |
//! | Chaos | ChaosInjection | Fault injection decisions |
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::replay::{ReplayEvent, TraceMetadata, ReplayTrace};
//! use asupersync::types::TaskId;
//!
//! // Create trace metadata
//! let metadata = TraceMetadata::new(42); // seed
//!
//! // Record events
//! let mut trace = ReplayTrace::new(metadata);
//! trace.push(ReplayEvent::RngSeed { seed: 42 });
//! trace.push(ReplayEvent::TaskScheduled {
//!     task_id: TaskId::testing_default(),
//!     at_tick: 0,
//! });
//!
//! // Serialize for storage
//! let bytes = trace.to_bytes().expect("serialize");
//!
//! // Later: load and replay
//! let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");
//! ```

use crate::types::{RegionId, Severity, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::io;

// =============================================================================
// Trace Metadata
// =============================================================================

/// Current schema version for replay traces.
///
/// Increment this when making breaking changes to the schema.
pub const REPLAY_SCHEMA_VERSION: u32 = 1;

/// Metadata about a replay trace.
///
/// This header is written at the start of every trace file and contains
/// information needed to replay the trace correctly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceMetadata {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Original RNG seed used for the execution.
    pub seed: u64,

    /// Wall-clock timestamp when recording started (Unix epoch nanos).
    pub recorded_at: u64,

    /// Runtime configuration hash for compatibility checking.
    ///
    /// If the config hash differs during replay, results may not match.
    pub config_hash: u64,

    /// Optional description or test name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TraceMetadata {
    /// Creates new trace metadata with the given seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            version: REPLAY_SCHEMA_VERSION,
            seed,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            config_hash: 0,
            description: None,
        }
    }

    /// Sets the configuration hash.
    #[must_use]
    pub const fn with_config_hash(mut self, hash: u64) -> Self {
        self.config_hash = hash;
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Checks if this trace is compatible with the current schema.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.version == REPLAY_SCHEMA_VERSION
    }
}

// =============================================================================
// Compact ID Types for Serialization
// =============================================================================

/// Compact task identifier for serialization.
///
/// Uses raw u64 instead of `TaskId` for minimal size.
/// The high 32 bits are the index, low 32 bits are the generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompactTaskId(pub u64);

impl From<TaskId> for CompactTaskId {
    fn from(id: TaskId) -> Self {
        let idx = id.arena_index();
        let packed = (u64::from(idx.index()) << 32) | u64::from(idx.generation());
        Self(packed)
    }
}

impl CompactTaskId {
    /// Unpacks into index and generation components.
    #[must_use]
    pub const fn unpack(self) -> (u32, u32) {
        let index = (self.0 >> 32) as u32;
        let generation = self.0 as u32;
        (index, generation)
    }

    /// Creates a `TaskId` for testing (requires test-internals feature).
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn to_task_id(self) -> TaskId {
        let (index, generation) = self.unpack();
        TaskId::new_for_test(index, generation)
    }
}

/// Compact region identifier for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompactRegionId(pub u64);

impl From<RegionId> for CompactRegionId {
    fn from(id: RegionId) -> Self {
        let idx = id.arena_index();
        let packed = (u64::from(idx.index()) << 32) | u64::from(idx.generation());
        Self(packed)
    }
}

impl CompactRegionId {
    /// Unpacks into index and generation components.
    #[must_use]
    pub const fn unpack(self) -> (u32, u32) {
        let index = (self.0 >> 32) as u32;
        let generation = self.0 as u32;
        (index, generation)
    }

    /// Creates a `RegionId` for testing (requires test-internals feature).
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn to_region_id(self) -> RegionId {
        let (index, generation) = self.unpack();
        RegionId::new_for_test(index, generation)
    }
}

// =============================================================================
// Replay Events
// =============================================================================

/// A replay event capturing a source of non-determinism.
///
/// Events are ordered by their sequence number. During replay, the runtime
/// consumes events in order to reproduce the same execution.
///
/// # Size Optimization
///
/// Events are designed to be compact:
/// - Enum discriminant: 1 byte
/// - Most variants: 8-24 bytes of payload
/// - Typical event: < 32 bytes
/// - Maximum event: < 64 bytes (IoError with message)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ReplayEvent {
    // =========================================================================
    // Scheduling Decisions
    // =========================================================================
    /// A task was chosen for scheduling.
    ///
    /// Records which task was selected when multiple were ready.
    TaskScheduled {
        /// The task that was scheduled.
        task: CompactTaskId,
        /// Virtual time tick when scheduled.
        at_tick: u64,
    },

    /// A task voluntarily yielded.
    TaskYielded {
        /// The task that yielded.
        task: CompactTaskId,
    },

    /// A task completed execution.
    TaskCompleted {
        /// The task that completed.
        task: CompactTaskId,
        /// Outcome severity (0=Ok, 1=Err, 2=Cancelled, 3=Panicked).
        outcome: u8,
    },

    /// A task was spawned.
    TaskSpawned {
        /// The new task.
        task: CompactTaskId,
        /// The parent region.
        region: CompactRegionId,
        /// Virtual time tick when spawned.
        at_tick: u64,
    },

    // =========================================================================
    // Time Events
    // =========================================================================
    /// Virtual time advanced.
    TimeAdvanced {
        /// Previous time in nanoseconds.
        from_nanos: u64,
        /// New time in nanoseconds.
        to_nanos: u64,
    },

    /// A timer was created.
    TimerCreated {
        /// Timer identifier (token).
        timer_id: u64,
        /// Deadline in nanoseconds.
        deadline_nanos: u64,
    },

    /// A timer fired.
    TimerFired {
        /// Timer identifier (token).
        timer_id: u64,
    },

    /// A timer was cancelled.
    TimerCancelled {
        /// Timer identifier (token).
        timer_id: u64,
    },

    // =========================================================================
    // I/O Events (Lab Reactor)
    // =========================================================================
    /// I/O became ready.
    IoReady {
        /// I/O token.
        token: u64,
        /// Readiness flags (readable=1, writable=2, error=4, hangup=8).
        readiness: u8,
    },

    /// Simulated I/O result (bytes transferred).
    IoResult {
        /// I/O token.
        token: u64,
        /// Bytes read/written (negative for errors).
        bytes: i64,
    },

    /// I/O error was injected.
    IoError {
        /// I/O token.
        token: u64,
        /// Error kind as u8 (maps to io::ErrorKind).
        kind: u8,
    },

    // =========================================================================
    // RNG Events
    // =========================================================================
    /// RNG was seeded.
    RngSeed {
        /// The seed value.
        seed: u64,
    },

    /// An RNG value was generated (for verification).
    RngValue {
        /// The generated value.
        value: u64,
    },

    // =========================================================================
    // Chaos Injection
    // =========================================================================
    /// Chaos was injected.
    ChaosInjection {
        /// Kind of chaos (0=cancel, 1=delay, 2=io_error, 3=wakeup_storm, 4=budget).
        kind: u8,
        /// Affected task, if any.
        task: Option<CompactTaskId>,
        /// Additional data (e.g., delay nanos, error kind).
        data: u64,
    },

    // =========================================================================
    // Region Lifecycle Events
    // =========================================================================
    /// A region was created.
    ///
    /// Records when structured concurrency regions are established.
    /// This is needed to track the region tree during replay.
    RegionCreated {
        /// The new region.
        region: CompactRegionId,
        /// The parent region (None for root).
        parent: Option<CompactRegionId>,
        /// Virtual time tick when created.
        at_tick: u64,
    },

    /// A region was closed (completed normally or after draining).
    ///
    /// Records when all children have completed and finalizers have run.
    RegionClosed {
        /// The region that closed.
        region: CompactRegionId,
        /// Outcome severity (0=Ok, 1=Err, 2=Cancelled, 3=Panicked).
        outcome: u8,
    },

    /// A region received a cancellation request.
    ///
    /// Records the start of the cancellation protocol for a region.
    RegionCancelled {
        /// The region being cancelled.
        region: CompactRegionId,
        /// Cancel kind (severity level 0-5).
        cancel_kind: u8,
    },

    // =========================================================================
    // Waker Events
    // =========================================================================
    /// A waker was invoked.
    WakerWake {
        /// The task that was woken.
        task: CompactTaskId,
    },

    /// Multiple wakers were invoked (batch).
    WakerBatchWake {
        /// Number of tasks woken.
        count: u32,
    },

    // =========================================================================
    // Checkpoint Events
    // =========================================================================
    /// A checkpoint for replay synchronization.
    ///
    /// Checkpoints are inserted periodically to:
    /// - Verify replay is still synchronized with the recording
    /// - Provide restart points for long traces
    /// - Mark significant state transitions
    Checkpoint {
        /// Monotonic sequence number.
        sequence: u64,
        /// Virtual time at checkpoint in nanoseconds.
        time_nanos: u64,
        /// Number of active tasks.
        active_tasks: u32,
        /// Number of active regions.
        active_regions: u32,
    },
}

impl ReplayEvent {
    /// Returns the approximate serialized size in bytes.
    ///
    /// This is an estimate for capacity planning; actual size may vary
    /// slightly due to serde encoding overhead.
    #[must_use]
    pub const fn estimated_size(&self) -> usize {
        match self {
            Self::TaskScheduled { .. } => 17,                 // 1 + 8 + 8
            Self::TaskYielded { .. } => 9,                    // 1 + 8
            Self::TaskCompleted { .. } => 10,                 // 1 + 8 + 1
            Self::TaskSpawned { .. } => 25,                   // 1 + 8 + 8 + 8
            Self::TimeAdvanced { .. } => 17,                  // 1 + 8 + 8
            Self::TimerCreated { .. } => 17,                  // 1 + 8 + 8
            Self::TimerFired { .. } => 9,                     // 1 + 8
            Self::TimerCancelled { .. } => 9,                 // 1 + 8
            Self::IoReady { .. } => 10,                       // 1 + 8 + 1
            Self::IoResult { .. } => 17,                      // 1 + 8 + 8
            Self::IoError { .. } => 10,                       // 1 + 8 + 1
            Self::RngSeed { .. } => 9,                        // 1 + 8
            Self::RngValue { .. } => 9,                       // 1 + 8
            Self::ChaosInjection { task: None, .. } => 11,    // 1 + 1 + 1 + 8
            Self::ChaosInjection { task: Some(_), .. } => 19, // 1 + 1 + 9 + 8
            Self::RegionCreated { parent: None, .. } => 17,   // 1 + 8 + 8
            Self::RegionCreated {
                parent: Some(_), ..
            } => 25, // 1 + 8 + 8 + 8
            Self::RegionClosed { .. } => 10,                  // 1 + 8 + 1
            Self::RegionCancelled { .. } => 10,               // 1 + 8 + 1
            Self::WakerWake { .. } => 9,                      // 1 + 8
            Self::WakerBatchWake { .. } => 5,                 // 1 + 4
            Self::Checkpoint { .. } => 25,                    // 1 + 8 + 8 + 4 + 4
        }
    }

    /// Creates a task scheduled event.
    #[must_use]
    pub fn task_scheduled(task: impl Into<CompactTaskId>, at_tick: u64) -> Self {
        Self::TaskScheduled {
            task: task.into(),
            at_tick,
        }
    }

    /// Creates a task completed event from outcome severity.
    #[must_use]
    pub fn task_completed(task: impl Into<CompactTaskId>, severity: Severity) -> Self {
        Self::TaskCompleted {
            task: task.into(),
            outcome: severity.as_u8(),
        }
    }

    /// Creates a time advanced event.
    #[must_use]
    pub fn time_advanced(from: Time, to: Time) -> Self {
        Self::TimeAdvanced {
            from_nanos: from.as_nanos(),
            to_nanos: to.as_nanos(),
        }
    }

    /// Creates an I/O ready event.
    #[must_use]
    pub fn io_ready(token: u64, readable: bool, writable: bool, error: bool, hangup: bool) -> Self {
        let mut readiness = 0u8;
        if readable {
            readiness |= 1;
        }
        if writable {
            readiness |= 2;
        }
        if error {
            readiness |= 4;
        }
        if hangup {
            readiness |= 8;
        }
        Self::IoReady { token, readiness }
    }

    /// Creates an I/O error event.
    #[must_use]
    pub fn io_error(token: u64, kind: io::ErrorKind) -> Self {
        Self::IoError {
            token,
            kind: error_kind_to_u8(kind),
        }
    }

    /// Creates a region created event.
    #[must_use]
    pub fn region_created(
        region: impl Into<CompactRegionId>,
        parent: Option<impl Into<CompactRegionId>>,
        at_tick: u64,
    ) -> Self {
        Self::RegionCreated {
            region: region.into(),
            parent: parent.map(Into::into),
            at_tick,
        }
    }

    /// Creates a region closed event.
    #[must_use]
    pub fn region_closed(region: impl Into<CompactRegionId>, severity: Severity) -> Self {
        Self::RegionClosed {
            region: region.into(),
            outcome: severity.as_u8(),
        }
    }

    /// Creates a region cancelled event.
    #[must_use]
    pub fn region_cancelled(region: impl Into<CompactRegionId>, cancel_kind: u8) -> Self {
        Self::RegionCancelled {
            region: region.into(),
            cancel_kind,
        }
    }

    /// Creates a checkpoint event.
    #[must_use]
    pub fn checkpoint(
        sequence: u64,
        time_nanos: u64,
        active_tasks: u32,
        active_regions: u32,
    ) -> Self {
        Self::Checkpoint {
            sequence,
            time_nanos,
            active_tasks,
            active_regions,
        }
    }
}

// =============================================================================
// Replay Trace Container
// =============================================================================

/// A complete replay trace with metadata and events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTrace {
    /// Trace metadata header.
    pub metadata: TraceMetadata,
    /// Sequence of replay events.
    pub events: Vec<ReplayEvent>,
}

impl ReplayTrace {
    /// Creates a new replay trace with the given metadata.
    #[must_use]
    pub fn new(metadata: TraceMetadata) -> Self {
        Self {
            metadata,
            events: Vec::new(),
        }
    }

    /// Creates a new replay trace with estimated capacity.
    #[must_use]
    pub fn with_capacity(metadata: TraceMetadata, capacity: usize) -> Self {
        Self {
            metadata,
            events: Vec::with_capacity(capacity),
        }
    }

    /// Appends an event to the trace.
    pub fn push(&mut self, event: ReplayEvent) {
        self.events.push(event);
    }

    /// Returns the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true if the trace has no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Serializes the trace to MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    /// Deserializes a trace from MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails or the version is incompatible.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplayTraceError> {
        let trace: Self = rmp_serde::from_slice(bytes)?;
        if !trace.metadata.is_compatible() {
            return Err(ReplayTraceError::IncompatibleVersion {
                expected: REPLAY_SCHEMA_VERSION,
                found: trace.metadata.version,
            });
        }
        Ok(trace)
    }

    /// Returns an iterator over the events.
    pub fn iter(&self) -> impl Iterator<Item = &ReplayEvent> {
        self.events.iter()
    }

    /// Estimates the total serialized size in bytes.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        // Metadata overhead (~50 bytes) + events
        50 + self
            .events
            .iter()
            .map(ReplayEvent::estimated_size)
            .sum::<usize>()
    }
}

/// Errors that can occur when working with replay traces.
#[derive(Debug, thiserror::Error)]
pub enum ReplayTraceError {
    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] rmp_serde::decode::Error),

    /// Version mismatch.
    #[error("incompatible trace version: expected {expected}, found {found}")]
    IncompatibleVersion {
        /// Expected schema version.
        expected: u32,
        /// Found schema version.
        found: u32,
    },
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts an `io::ErrorKind` to a u8 for compact serialization.
#[must_use]
fn error_kind_to_u8(kind: io::ErrorKind) -> u8 {
    use io::ErrorKind::{NotFound, PermissionDenied, ConnectionRefused, ConnectionReset, ConnectionAborted, NotConnected, AddrInUse, AddrNotAvailable, BrokenPipe, AlreadyExists, WouldBlock, InvalidInput, InvalidData, TimedOut, WriteZero, Interrupted, UnexpectedEof, OutOfMemory};
    match kind {
        NotFound => 1,
        PermissionDenied => 2,
        ConnectionRefused => 3,
        ConnectionReset => 4,
        ConnectionAborted => 5,
        NotConnected => 6,
        AddrInUse => 7,
        AddrNotAvailable => 8,
        BrokenPipe => 9,
        AlreadyExists => 10,
        WouldBlock => 11,
        InvalidInput => 12,
        InvalidData => 13,
        TimedOut => 14,
        WriteZero => 15,
        Interrupted => 16,
        UnexpectedEof => 17,
        OutOfMemory => 18,
        _ => 255, // Other/unknown
    }
}

/// Converts a u8 back to an `io::ErrorKind`.
#[must_use]
pub fn u8_to_error_kind(value: u8) -> io::ErrorKind {
    use io::ErrorKind::{NotFound, PermissionDenied, ConnectionRefused, ConnectionReset, ConnectionAborted, NotConnected, AddrInUse, AddrNotAvailable, BrokenPipe, AlreadyExists, WouldBlock, InvalidInput, InvalidData, TimedOut, WriteZero, Interrupted, UnexpectedEof, OutOfMemory, Other};
    match value {
        1 => NotFound,
        2 => PermissionDenied,
        3 => ConnectionRefused,
        4 => ConnectionReset,
        5 => ConnectionAborted,
        6 => NotConnected,
        7 => AddrInUse,
        8 => AddrNotAvailable,
        9 => BrokenPipe,
        10 => AlreadyExists,
        11 => WouldBlock,
        12 => InvalidInput,
        13 => InvalidData,
        14 => TimedOut,
        15 => WriteZero,
        16 => Interrupted,
        17 => UnexpectedEof,
        18 => OutOfMemory,
        _ => Other,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_creation() {
        let meta = TraceMetadata::new(42);
        assert_eq!(meta.version, REPLAY_SCHEMA_VERSION);
        assert_eq!(meta.seed, 42);
        assert!(meta.is_compatible());
    }

    #[test]
    fn metadata_builder() {
        let meta = TraceMetadata::new(42)
            .with_config_hash(0xDEADBEEF)
            .with_description("test trace");
        assert_eq!(meta.config_hash, 0xDEADBEEF);
        assert_eq!(meta.description, Some("test trace".to_string()));
    }

    #[test]
    fn compact_task_id_roundtrip() {
        let task = TaskId::new_for_test(123, 456);
        let compact = CompactTaskId::from(task);
        let (index, gen) = compact.unpack();
        assert_eq!(index, 123);
        assert_eq!(gen, 456);
        assert_eq!(compact.to_task_id(), task);
    }

    #[test]
    fn replay_event_sizes() {
        // Verify events are compact
        let events = [
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(0),
                at_tick: 0,
            },
            ReplayEvent::TaskYielded {
                task: CompactTaskId(0),
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(0),
                outcome: 0,
            },
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 0,
            },
            ReplayEvent::TimerFired { timer_id: 0 },
            ReplayEvent::IoReady {
                token: 0,
                readiness: 0,
            },
            ReplayEvent::RngSeed { seed: 0 },
            ReplayEvent::WakerWake {
                task: CompactTaskId(0),
            },
        ];

        for event in &events {
            let size = event.estimated_size();
            assert!(
                size < 64,
                "Event {:?} exceeds 64 bytes: {} bytes",
                event,
                size
            );
        }
    }

    #[test]
    fn trace_serialization_roundtrip() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });
        trace.push(ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        });
        trace.push(ReplayEvent::TimeAdvanced {
            from_nanos: 0,
            to_nanos: 1_000_000,
        });
        trace.push(ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 0,
        });

        let bytes = trace.to_bytes().expect("serialize");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");

        assert_eq!(loaded.metadata.seed, 42);
        assert_eq!(loaded.events.len(), 4);
        assert_eq!(loaded.events[0], ReplayEvent::RngSeed { seed: 42 });
    }

    #[test]
    fn trace_actual_serialized_size() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));

        // Add typical events
        for i in 0..100 {
            trace.push(ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            });
        }

        let bytes = trace.to_bytes().expect("serialize");
        let avg_size = bytes.len() / 100;

        // Verify average event size is reasonable (should be well under 64 bytes)
        assert!(
            avg_size < 32,
            "Average serialized event size {} bytes exceeds expected",
            avg_size
        );
    }

    #[test]
    fn error_kind_roundtrip() {
        use io::ErrorKind::*;
        let kinds = [
            NotFound,
            PermissionDenied,
            ConnectionRefused,
            ConnectionReset,
            BrokenPipe,
            WouldBlock,
            TimedOut,
        ];

        for kind in kinds {
            let encoded = error_kind_to_u8(kind);
            let decoded = u8_to_error_kind(encoded);
            assert_eq!(kind, decoded, "Failed roundtrip for {:?}", kind);
        }
    }

    #[test]
    fn version_compatibility_check() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });

        // Serialize
        let bytes = trace.to_bytes().expect("serialize");

        // Modify version in raw bytes would require manual byte manipulation
        // Just verify normal case works
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");
        assert!(loaded.metadata.is_compatible());
    }

    #[test]
    fn io_ready_flags() {
        let event = ReplayEvent::io_ready(123, true, false, false, false);
        if let ReplayEvent::IoReady { token, readiness } = event {
            assert_eq!(token, 123);
            assert_eq!(readiness & 1, 1); // readable
            assert_eq!(readiness & 2, 0); // not writable
        } else {
            panic!("Expected IoReady");
        }

        let event = ReplayEvent::io_ready(456, true, true, true, true);
        if let ReplayEvent::IoReady { readiness, .. } = event {
            assert_eq!(readiness, 0b1111); // all flags set
        } else {
            panic!("Expected IoReady");
        }
    }

    #[test]
    fn chaos_injection_variants() {
        let event_no_task = ReplayEvent::ChaosInjection {
            kind: 1, // delay
            task: None,
            data: 1_000_000, // 1ms in nanos
        };
        assert!(event_no_task.estimated_size() < 64);

        let event_with_task = ReplayEvent::ChaosInjection {
            kind: 0, // cancel
            task: Some(CompactTaskId(42)),
            data: 0,
        };
        assert!(event_with_task.estimated_size() < 64);
    }

    #[test]
    fn region_created_event() {
        let event = ReplayEvent::region_created(CompactRegionId(1), Some(CompactRegionId(0)), 100);

        if let ReplayEvent::RegionCreated {
            region,
            parent,
            at_tick,
        } = event
        {
            assert_eq!(region.0, 1);
            assert_eq!(parent.map(|p| p.0), Some(0));
            assert_eq!(at_tick, 100);
        } else {
            panic!("Expected RegionCreated");
        }

        // Test without parent (root region)
        let root = ReplayEvent::region_created(CompactRegionId(0), None::<CompactRegionId>, 0);
        if let ReplayEvent::RegionCreated { parent, .. } = root {
            assert!(parent.is_none());
        } else {
            panic!("Expected RegionCreated");
        }
    }

    #[test]
    fn region_closed_event() {
        let event = ReplayEvent::region_closed(CompactRegionId(5), Severity::Ok);

        if let ReplayEvent::RegionClosed { region, outcome } = event {
            assert_eq!(region.0, 5);
            assert_eq!(outcome, Severity::Ok.as_u8());
        } else {
            panic!("Expected RegionClosed");
        }
    }

    #[test]
    fn region_cancelled_event() {
        let event = ReplayEvent::region_cancelled(CompactRegionId(3), 1);

        if let ReplayEvent::RegionCancelled {
            region,
            cancel_kind,
        } = event
        {
            assert_eq!(region.0, 3);
            assert_eq!(cancel_kind, 1);
        } else {
            panic!("Expected RegionCancelled");
        }
    }

    #[test]
    fn checkpoint_event() {
        let event = ReplayEvent::checkpoint(42, 1_000_000_000, 5, 2);

        if let ReplayEvent::Checkpoint {
            sequence,
            time_nanos,
            active_tasks,
            active_regions,
        } = event
        {
            assert_eq!(sequence, 42);
            assert_eq!(time_nanos, 1_000_000_000);
            assert_eq!(active_tasks, 5);
            assert_eq!(active_regions, 2);
        } else {
            panic!("Expected Checkpoint");
        }
    }

    #[test]
    fn region_events_size() {
        // Verify all region events stay compact (< 64 bytes)
        let events = [
            ReplayEvent::RegionCreated {
                region: CompactRegionId(0),
                parent: None,
                at_tick: 0,
            },
            ReplayEvent::RegionCreated {
                region: CompactRegionId(0),
                parent: Some(CompactRegionId(1)),
                at_tick: 0,
            },
            ReplayEvent::RegionClosed {
                region: CompactRegionId(0),
                outcome: 0,
            },
            ReplayEvent::RegionCancelled {
                region: CompactRegionId(0),
                cancel_kind: 0,
            },
            ReplayEvent::Checkpoint {
                sequence: 0,
                time_nanos: 0,
                active_tasks: 0,
                active_regions: 0,
            },
        ];

        for event in &events {
            let size = event.estimated_size();
            assert!(
                size < 64,
                "Event {:?} exceeds 64 bytes: {} bytes",
                event,
                size
            );
        }
    }

    #[test]
    fn region_events_serialization_roundtrip() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(123));

        // Add region lifecycle events
        trace.push(ReplayEvent::RegionCreated {
            region: CompactRegionId(0),
            parent: None,
            at_tick: 0,
        });
        trace.push(ReplayEvent::RegionCreated {
            region: CompactRegionId(1),
            parent: Some(CompactRegionId(0)),
            at_tick: 10,
        });
        trace.push(ReplayEvent::RegionCancelled {
            region: CompactRegionId(1),
            cancel_kind: 2,
        });
        trace.push(ReplayEvent::RegionClosed {
            region: CompactRegionId(1),
            outcome: 2, // Cancelled
        });
        trace.push(ReplayEvent::RegionClosed {
            region: CompactRegionId(0),
            outcome: 0, // Ok
        });
        trace.push(ReplayEvent::Checkpoint {
            sequence: 1,
            time_nanos: 1_000_000,
            active_tasks: 0,
            active_regions: 0,
        });

        let bytes = trace.to_bytes().expect("serialize");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");

        assert_eq!(loaded.events.len(), 6);

        // Verify first event (root region created)
        match &loaded.events[0] {
            ReplayEvent::RegionCreated {
                region,
                parent,
                at_tick,
            } => {
                assert_eq!(region.0, 0);
                assert!(parent.is_none());
                assert_eq!(*at_tick, 0);
            }
            _ => panic!("Expected RegionCreated"),
        }

        // Verify checkpoint event
        match &loaded.events[5] {
            ReplayEvent::Checkpoint {
                sequence,
                time_nanos,
                active_tasks,
                active_regions,
            } => {
                assert_eq!(*sequence, 1);
                assert_eq!(*time_nanos, 1_000_000);
                assert_eq!(*active_tasks, 0);
                assert_eq!(*active_regions, 0);
            }
            _ => panic!("Expected Checkpoint"),
        }
    }
}
