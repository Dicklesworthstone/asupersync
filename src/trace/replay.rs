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

use crate::types::{Budget, CancelReason, RegionId, Severity, TaskId, Time};
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

    /// Deterministic recording stamp for this trace.
    ///
    /// `0` means no wall-clock timestamp was attached. Deterministic runtime
    /// paths use `0` by default so identical runs produce identical metadata.
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
            recorded_at: 0,
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
            Self::TaskYielded { .. }
            | Self::TimerFired { .. }
            | Self::TimerCancelled { .. }
            | Self::RngSeed { .. }
            | Self::RngValue { .. }
            | Self::WakerWake { .. } => 9, // 1 + 8
            Self::TaskCompleted { .. }
            | Self::IoReady { .. }
            | Self::IoError { .. }
            | Self::RegionClosed { .. }
            | Self::RegionCancelled { .. } => 10, // 1 + 8 + 1
            Self::TaskScheduled { .. }
            | Self::TimeAdvanced { .. }
            | Self::TimerCreated { .. }
            | Self::IoResult { .. }
            | Self::RegionCreated { parent: None, .. } => 17, // 1 + 8 + 8
            Self::TaskSpawned { .. }
            | Self::RegionCreated {
                parent: Some(_), ..
            }
            | Self::Checkpoint { .. } => 25, // 1 + 8 + 8 + 8
            Self::ChaosInjection { task: None, .. } => 11, // 1 + 1 + 1 + 8
            Self::ChaosInjection { task: Some(_), .. } => 19, // 1 + 1 + 9 + 8
            Self::WakerBatchWake { .. } => 5,              // 1 + 4
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
    #[allow(clippy::fn_params_excessive_bools)]
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
    /// Cursor for O(1) event consumption via [`EventSource`](super::replayer::EventSource).
    #[serde(skip)]
    pub cursor: usize,
}

impl ReplayTrace {
    /// Creates a new replay trace with the given metadata.
    #[must_use]
    pub fn new(metadata: TraceMetadata) -> Self {
        Self {
            metadata,
            events: Vec::new(),
            cursor: 0,
        }
    }

    /// Creates a new replay trace with estimated capacity.
    #[must_use]
    pub fn with_capacity(metadata: TraceMetadata, capacity: usize) -> Self {
        Self {
            metadata,
            events: Vec::with_capacity(capacity),
            cursor: 0,
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
    use io::ErrorKind::{
        AddrInUse, AddrNotAvailable, AlreadyExists, BrokenPipe, ConnectionAborted,
        ConnectionRefused, ConnectionReset, Interrupted, InvalidData, InvalidInput, NotConnected,
        NotFound, OutOfMemory, PermissionDenied, TimedOut, UnexpectedEof, WouldBlock, WriteZero,
    };
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
    use io::ErrorKind::{
        AddrInUse, AddrNotAvailable, AlreadyExists, BrokenPipe, ConnectionAborted,
        ConnectionRefused, ConnectionReset, Interrupted, InvalidData, InvalidInput, NotConnected,
        NotFound, Other, OutOfMemory, PermissionDenied, TimedOut, UnexpectedEof, WouldBlock,
        WriteZero,
    };
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

// =============================================================================
// Production schedule projection (br-asupersync-bi2462.6)
// =============================================================================

/// Why a production trace could not be projected into a replayable schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    /// The trace carried no schedule-defining events at all.
    Empty,
    /// A task acted (`Schedule`/`Poll`/`Yield`/`Complete`) before any `Spawn`
    /// for it was seen.
    ///
    /// The ring buffer truncated the trace before that task's birth, or the
    /// trace was filtered. Strict projection refuses rather than silently
    /// replaying a partial history; see
    /// [`ProjectionOptions::allow_orphans`].
    MissingSpawn {
        /// The task without a recorded spawn.
        task: CompactTaskId,
        /// Sequence number of the offending event.
        seq: u64,
        /// Kind of the offending event.
        kind: crate::trace::event::TraceEventKind,
    },
    /// The same task id was spawned twice inside one trace.
    DuplicateSpawn {
        /// The task spawned again.
        task: CompactTaskId,
        /// Sequence number of the second spawn.
        seq: u64,
    },
}

impl core::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "production trace carries no schedule events"),
            Self::MissingSpawn { task, seq, kind } => write!(
                f,
                "event {kind:?} at seq {seq} names task {task:?} whose spawn is outside the trace window"
            ),
            Self::DuplicateSpawn { task, seq } => {
                write!(f, "task {task:?} spawned twice (second at seq {seq})")
            }
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Options for [`ProductionSchedule::from_runtime_trace_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProjectionOptions {
    /// Accept tasks whose `Spawn` lies before the trace window: they receive
    /// a spawn ordinal at first appearance and are listed in
    /// [`ProjectionSummary::orphans`]. Off by default (strict).
    pub allow_orphans: bool,
}

/// What a projection kept and dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectionSummary {
    /// `Spawn` events projected to [`ReplayEvent::TaskSpawned`].
    pub spawned: usize,
    /// Scheduling steps projected to [`ReplayEvent::TaskScheduled`].
    pub steps: usize,
    /// `Yield` events projected.
    pub yielded: usize,
    /// `Complete` events projected. The trace events carry no outcome, so
    /// [`ProductionSchedule::from_runtime_trace`] projects 0; a schedule from
    /// a native capture carries the captured outcomes instead
    /// ([`ProductionSchedule::carries_outcomes`]).
    pub completed: usize,
    /// `TimeAdvance` events projected.
    pub time_advances: usize,
    /// Timer events projected.
    pub timers: usize,
    /// Tasks admitted without a recorded spawn (only with
    /// [`ProjectionOptions::allow_orphans`]).
    pub orphans: Vec<CompactTaskId>,
    /// Events of kinds the projection does not carry (I/O, obligations,
    /// regions, cancellation, ...) plus `Schedule` events when `Poll`
    /// events define the steps.
    pub skipped: usize,
    /// Sequence number of the first and last event in the input.
    pub first_seq: u64,
    /// See `first_seq`.
    pub last_seq: u64,
    /// True when the input had no `Poll` events and `Schedule` events were
    /// used as steps instead.
    pub steps_from_schedule_events: bool,
}

/// One recorded phase of a task's cooperative cancellation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductionCancellationPhase {
    /// A witnessed cancellation publication between native task polls.
    Request,
    /// The scheduler consumed a checkpoint acknowledgement after a task poll.
    Acknowledgement,
}

/// Cancellation evidence carried beside the existing replay wire schema.
///
/// Only [`crate::trace::capture::ScheduleCaptureSnapshot::production_schedule_with_cancellation`]
/// constructs this evidence, after checking publication spans and poll ordering.
/// Source identities in the full reason remain provenance; replay injects that
/// exact reason into the task selected by its captured spawn ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCancellationEvent {
    source_sequence: u64,
    after_dispatches: usize,
    task: CompactTaskId,
    region: CompactRegionId,
    reason: CancelReason,
    phase: ProductionCancellationPhase,
    task_poll_ordinal: usize,
    cleanup_budget: Budget,
}

impl ProductionCancellationEvent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source_sequence: u64,
        after_dispatches: usize,
        task: CompactTaskId,
        region: CompactRegionId,
        reason: CancelReason,
        phase: ProductionCancellationPhase,
        task_poll_ordinal: usize,
        cleanup_budget: Budget,
    ) -> Self {
        Self {
            source_sequence,
            after_dispatches,
            task,
            region,
            reason,
            phase,
            task_poll_ordinal,
            cleanup_budget,
        }
    }

    /// Canonical source Request or Ack sequence, retained for diagnostics.
    #[must_use]
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// Number of captured task Poll entries preceding this observation.
    #[must_use]
    pub const fn after_dispatches(&self) -> usize {
        self.after_dispatches
    }

    /// Captured target task, bound to a reconstructed task by spawn ordinal.
    #[must_use]
    pub const fn task(&self) -> CompactTaskId {
        self.task
    }

    /// Captured owner region of the target task.
    #[must_use]
    pub const fn region(&self) -> CompactRegionId {
        self.region
    }

    /// Complete recorded cancellation reason, including its source provenance.
    #[must_use]
    pub fn reason(&self) -> &CancelReason {
        &self.reason
    }

    /// Whether this observation requests cancellation or acknowledges it.
    #[must_use]
    pub const fn phase(&self) -> ProductionCancellationPhase {
        self.phase
    }

    /// Task-poll boundary associated with this cancellation observation.
    ///
    /// For an acknowledgement this is the one-based ordinal of the poll that
    /// produced it, identified by the source worker even when the same task
    /// has already been polled again on another worker. For a request it is the
    /// number of already completed polls of the target task and may be zero.
    #[must_use]
    pub const fn task_poll_ordinal(&self) -> usize {
        self.task_poll_ordinal
    }

    /// Effective cleanup budget of the witnessed request. An acknowledgement
    /// repeats its matching request's budget; this is not a fresh budget sample
    /// taken at acknowledgement time.
    #[must_use]
    pub const fn cleanup_budget(&self) -> Budget {
        self.cleanup_budget
    }
}

/// A production runtime trace reduced to the decisions the lab can re-drive.
///
/// The production runtime records the lab's [`crate::trace::event::TraceEvent`]
/// schema (`Runtime::trace_snapshot`); its task ids are arena slots with
/// generations that a fresh lab run will never reproduce. This projection
/// keeps the interleaving — spawn order, the order of `Poll` steps, yields,
/// completions, virtual-time and timer hints — as a [`ReplayTrace`], and
/// pairs every task with its spawn ordinal so a replay can bind the lab's
/// own ids to the recorded ones as tasks are created.
///
/// Semantics:
/// - a step is a `Poll` event (one per poll of a task); when the input has
///   no `Poll` events at all, `Schedule` events are used instead and
///   [`ProjectionSummary::steps_from_schedule_events`] is set;
/// - the tick recorded on every projected event is the production sequence
///   number, monotone within the trace;
/// - I/O, obligation, region and cancellation events are not carried by the
///   replay wire schema and are counted in [`ProjectionSummary::skipped`];
///   checked native captures can separately retain witnessed task cancellation
///   through [`Self::cancellation_events`];
/// - a task that acts before its `Spawn` is a truncated ring buffer: strict
///   projection returns [`ProjectionError::MissingSpawn`]; with
///   [`ProjectionOptions::allow_orphans`] it is admitted and listed.
#[derive(Debug, Clone)]
pub struct ProductionSchedule {
    trace: ReplayTrace,
    spawn_order: Vec<CompactTaskId>,
    summary: ProjectionSummary,
    source_sequence_disorder: Option<(u64, u64)>,
    /// Whether the projected completions carry captured terminal outcomes.
    outcomes_captured: bool,
    /// `None` preserves legacy task-order projection. `Some`, including an
    /// empty vector, opts into request injection and acknowledgement checking.
    cancellation_events: Option<Vec<ProductionCancellationEvent>>,
}

impl ProductionSchedule {
    /// Strict projection: refuses truncated histories.
    pub fn from_runtime_trace(
        events: &[crate::trace::event::TraceEvent],
    ) -> Result<Self, ProjectionError> {
        Self::from_runtime_trace_with(events, ProjectionOptions::default())
    }

    /// Projection with explicit options.
    pub fn from_runtime_trace_with(
        events: &[crate::trace::event::TraceEvent],
        options: ProjectionOptions,
    ) -> Result<Self, ProjectionError> {
        use crate::trace::event::{TraceData, TraceEventKind};

        let (Some(first), Some(last)) = (events.first(), events.last()) else {
            return Err(ProjectionError::Empty);
        };
        let use_polls = events
            .iter()
            .any(|event| matches!(event.kind, TraceEventKind::Poll));

        let mut trace = ReplayTrace::new(
            TraceMetadata::new(0).with_description("production schedule projection"),
        );
        let mut spawn_order: Vec<CompactTaskId> = Vec::new();
        // Keyed by the packed id: `CompactTaskId` is not `Ord`/`Hash`.
        let mut ordinal: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        let mut summary = ProjectionSummary {
            first_seq: first.seq,
            last_seq: last.seq,
            steps_from_schedule_events: !use_polls,
            ..ProjectionSummary::default()
        };

        // A task that acts before its spawn was seen: admit it as an orphan
        // (tolerant mode) or refuse (strict mode).
        fn admit(
            ordinal: &mut std::collections::BTreeMap<u64, usize>,
            spawn_order: &mut Vec<CompactTaskId>,
            summary: &mut ProjectionSummary,
            options: ProjectionOptions,
            task: CompactTaskId,
            seq: u64,
            kind: TraceEventKind,
        ) -> Result<(), ProjectionError> {
            if ordinal.contains_key(&task.0) {
                return Ok(());
            }
            if options.allow_orphans {
                ordinal.insert(task.0, spawn_order.len());
                spawn_order.push(task);
                summary.orphans.push(task);
                Ok(())
            } else {
                Err(ProjectionError::MissingSpawn { task, seq, kind })
            }
        }

        for event in events {
            match (&event.kind, &event.data) {
                (TraceEventKind::Spawn, TraceData::Task { task, region }) => {
                    let task = CompactTaskId::from(*task);
                    if ordinal.contains_key(&task.0) {
                        return Err(ProjectionError::DuplicateSpawn {
                            task,
                            seq: event.seq,
                        });
                    }
                    ordinal.insert(task.0, spawn_order.len());
                    spawn_order.push(task);
                    trace.push(ReplayEvent::TaskSpawned {
                        task,
                        region: CompactRegionId::from(*region),
                        at_tick: event.seq,
                    });
                    summary.spawned += 1;
                }
                (
                    kind @ (TraceEventKind::Poll | TraceEventKind::Schedule),
                    TraceData::Task { task, .. },
                ) => {
                    let is_step = if use_polls {
                        matches!(kind, TraceEventKind::Poll)
                    } else {
                        matches!(kind, TraceEventKind::Schedule)
                    };
                    if !is_step {
                        summary.skipped += 1;
                        continue;
                    }
                    let task = CompactTaskId::from(*task);
                    admit(
                        &mut ordinal,
                        &mut spawn_order,
                        &mut summary,
                        options,
                        task,
                        event.seq,
                        *kind,
                    )?;
                    trace.push(ReplayEvent::TaskScheduled {
                        task,
                        at_tick: event.seq,
                    });
                    summary.steps += 1;
                }
                (TraceEventKind::Yield, TraceData::Task { task, .. }) => {
                    let task = CompactTaskId::from(*task);
                    admit(
                        &mut ordinal,
                        &mut spawn_order,
                        &mut summary,
                        options,
                        task,
                        event.seq,
                        event.kind,
                    )?;
                    trace.push(ReplayEvent::TaskYielded { task });
                    summary.yielded += 1;
                }
                (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                    let task = CompactTaskId::from(*task);
                    admit(
                        &mut ordinal,
                        &mut spawn_order,
                        &mut summary,
                        options,
                        task,
                        event.seq,
                        event.kind,
                    )?;
                    trace.push(ReplayEvent::TaskCompleted { task, outcome: 0 });
                    summary.completed += 1;
                }
                (TraceEventKind::TimeAdvance, TraceData::Time { old, new }) => {
                    trace.push(ReplayEvent::TimeAdvanced {
                        from_nanos: old.as_nanos(),
                        to_nanos: new.as_nanos(),
                    });
                    summary.time_advances += 1;
                }
                (TraceEventKind::TimerScheduled, TraceData::Timer { timer_id, deadline }) => {
                    trace.push(ReplayEvent::TimerCreated {
                        timer_id: *timer_id,
                        deadline_nanos: deadline.map_or(0, |deadline| deadline.as_nanos()),
                    });
                    summary.timers += 1;
                }
                (TraceEventKind::TimerFired, TraceData::Timer { timer_id, .. }) => {
                    trace.push(ReplayEvent::TimerFired {
                        timer_id: *timer_id,
                    });
                    summary.timers += 1;
                }
                (TraceEventKind::TimerCancelled, TraceData::Timer { timer_id, .. }) => {
                    trace.push(ReplayEvent::TimerCancelled {
                        timer_id: *timer_id,
                    });
                    summary.timers += 1;
                }
                _ => summary.skipped += 1,
            }
        }

        if summary.spawned == 0 && summary.steps == 0 {
            return Err(ProjectionError::Empty);
        }
        Ok(Self {
            trace,
            spawn_order,
            summary,
            source_sequence_disorder: events
                .windows(2)
                .find(|pair| pair[1].seq <= pair[0].seq)
                .map(|pair| (pair[0].seq, pair[1].seq)),
            outcomes_captured: false,
            cancellation_events: None,
        })
    }

    /// Replace each projected completion's outcome with the captured one,
    /// keyed by the raw compact task id (br-asupersync-bi2462.8). The caller
    /// guarantees an outcome for every projected completion.
    pub(crate) fn with_completion_outcomes(
        mut self,
        outcomes: &std::collections::BTreeMap<u64, Severity>,
    ) -> Self {
        for event in &mut self.trace.events {
            if let ReplayEvent::TaskCompleted { task, outcome } = event
                && let Some(captured) = outcomes.get(&task.0)
            {
                *outcome = captured.as_u8();
            }
        }
        self.outcomes_captured = true;
        self
    }

    /// Whether the projected completions carry outcomes captured beside the
    /// production trace. A projection made from trace events alone carries
    /// none: its completions all read as outcome 0.
    #[must_use]
    pub const fn carries_outcomes(&self) -> bool {
        self.outcomes_captured
    }

    pub(crate) fn with_cancellation_events(
        mut self,
        events: Vec<ProductionCancellationEvent>,
    ) -> Self {
        self.cancellation_events = Some(events);
        self
    }

    /// Witnessed task cancellation observations, when explicitly requested
    /// from a checked native capture. `Some(&[])` also requires the replay to
    /// observe no unexpected cancellation acknowledgements; `None` retains
    /// legacy task-order-only replay behavior.
    #[must_use]
    pub fn cancellation_events(&self) -> Option<&[ProductionCancellationEvent]> {
        self.cancellation_events.as_deref()
    }

    /// The captured terminal outcome of a recorded task, or `None` when the
    /// projection carries no outcomes or the task has no completion.
    #[must_use]
    pub fn captured_outcome(&self, task: CompactTaskId) -> Option<Severity> {
        if !self.outcomes_captured {
            return None;
        }
        self.trace.events.iter().find_map(|event| match event {
            ReplayEvent::TaskCompleted {
                task: completed,
                outcome,
            } if *completed == task => Severity::from_u8(*outcome),
            _ => None,
        })
    }

    /// The first duplicate or reversed source sequence, if any.
    ///
    /// Sequence numbers are ordering keys, not dense indices: abandoned
    /// event reservations may leave legitimate gaps. This detects disorder,
    /// not arbitrary missing observations or capture completeness.
    #[must_use]
    pub const fn source_sequence_disorder(&self) -> Option<(u64, u64)> {
        self.source_sequence_disorder
    }

    /// The projected replay trace (spawns, steps, yields, completions, time
    /// and timer hints), ready for [`crate::trace::replayer::TraceReplayer`].
    #[must_use]
    pub fn trace(&self) -> &ReplayTrace {
        &self.trace
    }

    /// Consume the projection, keeping only the replay trace. Cancellation
    /// evidence is separate from that wire schema and is discarded here.
    #[must_use]
    pub fn into_trace(self) -> ReplayTrace {
        self.trace
    }

    /// Recorded tasks in spawn order (orphans, if admitted, at first sight).
    #[must_use]
    pub fn spawn_order(&self) -> &[CompactTaskId] {
        &self.spawn_order
    }

    /// Spawn ordinal of a recorded task id.
    #[must_use]
    pub fn spawn_ordinal(&self, task: CompactTaskId) -> Option<usize> {
        self.spawn_order
            .iter()
            .position(|candidate| *candidate == task)
    }

    /// The interleaving as `(spawn ordinal, tick)` pairs, one per step.
    pub fn steps(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.trace.events.iter().filter_map(|event| {
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                Some((self.spawn_ordinal(*task)?, *at_tick))
            } else {
                None
            }
        })
    }

    /// Counts of what was kept and dropped.
    #[must_use]
    pub fn summary(&self) -> &ProjectionSummary {
        &self.summary
    }
}

#[cfg(test)]
#[path = "replay_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "replay_production_schedule_tests_inline_tests.rs"]
mod production_schedule_tests;
