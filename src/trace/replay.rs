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
    /// `Complete` events projected (outcome is not recorded by the
    /// production trace and is projected as 0).
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
/// - I/O, obligation, region and cancellation events are not carried (they
///   are outcomes to re-inject, not decisions to re-drive) and are counted
///   in [`ProjectionSummary::skipped`];
/// - a task that acts before its `Spawn` is a truncated ring buffer: strict
///   projection returns [`ProjectionError::MissingSpawn`]; with
///   [`ProjectionOptions::allow_orphans`] it is admitted and listed.
#[derive(Debug, Clone)]
pub struct ProductionSchedule {
    trace: ReplayTrace,
    spawn_order: Vec<CompactTaskId>,
    summary: ProjectionSummary,
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
        })
    }

    /// The projected replay trace (spawns, steps, yields, completions, time
    /// and timer hints), ready for [`crate::trace::replayer::TraceReplayer`].
    #[must_use]
    pub fn trace(&self) -> &ReplayTrace {
        &self.trace
    }

    /// Consume the projection, keeping only the replay trace.
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

    #[test]
    fn metadata_creation() {
        let meta = TraceMetadata::new(42);
        assert_eq!(meta.version, REPLAY_SCHEMA_VERSION);
        assert_eq!(meta.seed, 42);
        assert_eq!(meta.recorded_at, 0);
        assert!(meta.is_compatible());
    }

    #[test]
    fn metadata_creation_is_deterministic_for_same_seed() {
        let first = TraceMetadata::new(42);
        let second = TraceMetadata::new(42);

        assert_eq!(first, second);
        assert_eq!(first.recorded_at, 0);
    }

    #[test]
    fn metadata_builder() {
        let meta = TraceMetadata::new(42)
            .with_config_hash(0xDEAD_BEEF)
            .with_description("test trace");
        assert_eq!(meta.config_hash, 0xDEAD_BEEF);
        assert_eq!(meta.description, Some("test trace".to_string()));
    }

    #[test]
    fn compact_task_id_roundtrip() {
        let task = TaskId::new_for_test(123, 456);
        let compact = CompactTaskId::from(task);
        let (index, generation) = compact.unpack();
        assert_eq!(index, 123);
        assert_eq!(generation, 456);
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
            assert!(size < 64, "Event {event:?} exceeds 64 bytes: {size} bytes");
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
            "Average serialized event size {avg_size} bytes exceeds expected"
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
            assert_eq!(kind, decoded, "Failed roundtrip for {kind:?}");
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
            assert!(size < 64, "Event {event:?} exceeds 64 bytes: {size} bytes");
        }
    }

    #[test]
    fn empty_trace_serialization_roundtrip() {
        let trace = ReplayTrace::new(TraceMetadata::new(0));
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);

        let bytes = trace.to_bytes().expect("serialize empty");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize empty");

        assert_eq!(loaded.metadata.seed, 0);
        assert!(loaded.is_empty());
    }

    #[test]
    fn incompatible_version_rejected() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });

        let _bytes = trace.to_bytes().expect("serialize");

        // Manually tamper with the version in the serialized bytes
        // TraceMetadata is serialized via msgpack, version is the first field
        // Instead, create a trace with wrong version directly
        let meta = TraceMetadata {
            version: 999,
            seed: 42,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        };
        let bad_trace = ReplayTrace {
            metadata: meta,
            events: vec![ReplayEvent::RngSeed { seed: 42 }],
            cursor: 0,
        };
        let bad_bytes = bad_trace.to_bytes().expect("serialize bad version");
        let err = ReplayTrace::from_bytes(&bad_bytes).unwrap_err();
        assert!(matches!(
            err,
            ReplayTraceError::IncompatibleVersion {
                expected: REPLAY_SCHEMA_VERSION,
                found: 999
            }
        ));
    }

    #[test]
    fn trace_with_capacity_preallocates() {
        let trace = ReplayTrace::with_capacity(TraceMetadata::new(1), 100);
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);
    }

    #[test]
    fn estimated_size_increases_with_events() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        let base_size = trace.estimated_size();

        trace.push(ReplayEvent::RngSeed { seed: 42 });
        let one_event_size = trace.estimated_size();
        assert!(one_event_size > base_size);

        trace.push(ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        });
        let two_event_size = trace.estimated_size();
        assert!(two_event_size > one_event_size);
    }

    #[test]
    fn compact_region_id_roundtrip() {
        let region = RegionId::new_for_test(456, 789);
        let compact = CompactRegionId::from(region);
        let (index, generation) = compact.unpack();
        assert_eq!(index, 456);
        assert_eq!(generation, 789);
        assert_eq!(compact.to_region_id(), region);
    }

    #[test]
    fn metadata_compatibility_flag() {
        let meta = TraceMetadata::new(42);
        assert!(meta.is_compatible());

        let old_meta = TraceMetadata {
            version: 0,
            seed: 42,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        };
        assert!(!old_meta.is_compatible());
    }

    #[test]
    fn io_error_roundtrip_all_known_kinds() {
        use io::ErrorKind::*;
        let all_known = [
            NotFound,
            PermissionDenied,
            ConnectionRefused,
            ConnectionReset,
            ConnectionAborted,
            NotConnected,
            AddrInUse,
            AddrNotAvailable,
            BrokenPipe,
            AlreadyExists,
            WouldBlock,
            InvalidInput,
            InvalidData,
            TimedOut,
            WriteZero,
            Interrupted,
            UnexpectedEof,
            OutOfMemory,
        ];

        for kind in all_known {
            let encoded = error_kind_to_u8(kind);
            let decoded = u8_to_error_kind(encoded);
            assert_eq!(kind, decoded, "Roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn unknown_error_kind_maps_to_other() {
        let decoded = u8_to_error_kind(255);
        assert_eq!(decoded, io::ErrorKind::Other);
        let decoded = u8_to_error_kind(200);
        assert_eq!(decoded, io::ErrorKind::Other);
    }

    #[test]
    fn trace_iter_yields_all_events() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 1 });
        trace.push(ReplayEvent::RngSeed { seed: 2 });
        trace.push(ReplayEvent::RngSeed { seed: 3 });

        assert_eq!(trace.iter().count(), 3);
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

    // --- wave 77 trait coverage ---

    #[test]
    fn trace_metadata_debug_clone_eq() {
        let m = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 0,
            config_hash: 0xABC,
            description: Some("test".into()),
        };
        let m2 = m.clone();
        assert_eq!(m, m2);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("TraceMetadata"));
    }

    #[test]
    fn compact_task_id_debug_clone_copy_eq() {
        let id = CompactTaskId(42);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, CompactTaskId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"));
    }

    #[test]
    fn compact_region_id_debug_clone_copy_eq() {
        let id = CompactRegionId(7);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, CompactRegionId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains('7'));
    }

    #[test]
    fn replay_event_debug_clone_eq() {
        let e = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 100,
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_ne!(
            e,
            ReplayEvent::TaskYielded {
                task: CompactTaskId(1),
            }
        );
        let dbg = format!("{e:?}");
        assert!(dbg.contains("TaskScheduled"));
    }
}

#[cfg(test)]
mod production_schedule_tests {
    use super::{
        CompactTaskId, ProductionSchedule, ProjectionError, ProjectionOptions, ReplayEvent,
    };
    use crate::trace::event::{TraceEvent, TraceEventKind};
    use crate::types::{RegionId, TaskId, Time};

    fn task(n: u32) -> TaskId {
        TaskId::new_for_test(n, 1)
    }

    fn region() -> RegionId {
        RegionId::new_for_test(1, 1)
    }

    fn at(seq: u64) -> Time {
        Time::from_nanos(seq * 10)
    }

    #[test]
    fn interleaved_polls_project_in_order() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::spawn(2, at(2), task(2), region()),
            TraceEvent::schedule(3, at(3), task(1), region()),
            TraceEvent::poll(4, at(4), task(1), region()),
            TraceEvent::poll(5, at(5), task(2), region()),
            TraceEvent::poll(6, at(6), task(1), region()),
            TraceEvent::complete(7, at(7), task(1), region()),
            TraceEvent::complete(8, at(8), task(2), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(
            schedule.steps().collect::<Vec<_>>(),
            vec![(0, 4), (1, 5), (0, 6)],
            "steps are the Poll events in order, keyed by spawn ordinal"
        );
        let summary = schedule.summary();
        assert_eq!(summary.spawned, 2);
        assert_eq!(summary.steps, 3);
        assert_eq!(summary.completed, 2);
        assert_eq!(
            summary.skipped, 1,
            "the Schedule event is dropped when Polls exist"
        );
        assert!(!summary.steps_from_schedule_events);
        assert_eq!((summary.first_seq, summary.last_seq), (1, 8));
        assert_eq!(
            schedule.spawn_order(),
            &[CompactTaskId::from(task(1)), CompactTaskId::from(task(2))]
        );
        assert!(matches!(
            schedule.trace().events.first(),
            Some(ReplayEvent::TaskSpawned { at_tick: 1, .. })
        ));
    }

    #[test]
    fn poll_before_spawn_is_refused_strictly_and_tolerated_as_orphan() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::poll(2, at(2), task(2), region()),
        ];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&events).err(),
            Some(ProjectionError::MissingSpawn {
                task: CompactTaskId::from(task(2)),
                seq: 2,
                kind: TraceEventKind::Poll,
            })
        );
        let tolerant = ProductionSchedule::from_runtime_trace_with(
            &events,
            ProjectionOptions {
                allow_orphans: true,
            },
        )
        .expect("orphans admitted");
        assert_eq!(
            tolerant.summary().orphans,
            vec![CompactTaskId::from(task(2))]
        );
        assert_eq!(
            tolerant.spawn_ordinal(CompactTaskId::from(task(2))),
            Some(1)
        );
        assert_eq!(tolerant.steps().collect::<Vec<_>>(), vec![(1, 2)]);
    }

    #[test]
    fn schedule_events_are_steps_only_when_no_polls_exist() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::schedule(2, at(2), task(1), region()),
            TraceEvent::schedule(3, at(3), task(1), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(schedule.steps().collect::<Vec<_>>(), vec![(0, 2), (0, 3)]);
        assert!(schedule.summary().steps_from_schedule_events);
        assert_eq!(schedule.summary().skipped, 0);
    }

    #[test]
    fn empty_and_duplicate_spawn_are_errors() {
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&[]).err(),
            Some(ProjectionError::Empty)
        );
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::spawn(2, at(2), task(1), region()),
        ];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&events).err(),
            Some(ProjectionError::DuplicateSpawn {
                task: CompactTaskId::from(task(1)),
                seq: 2,
            })
        );
        // Events of kinds the projection does not carry alone are "empty".
        let only_region = vec![TraceEvent::time_advance(
            1,
            Time::ZERO,
            Time::from_nanos(0),
            Time::from_nanos(100),
        )];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&only_region).err(),
            Some(ProjectionError::Empty)
        );
    }

    #[test]
    fn time_and_timer_hints_are_carried_and_others_counted() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::time_advance(2, at(2), Time::from_nanos(0), Time::from_nanos(100)),
            TraceEvent::timer_scheduled(3, at(3), 7, Time::from_nanos(500)),
            TraceEvent::timer_fired(4, at(4), 7),
            TraceEvent::wake(5, at(5), task(1), region()),
            TraceEvent::poll(6, at(6), task(1), region()),
            TraceEvent::yield_task(7, at(7), task(1), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        let summary = schedule.summary();
        assert_eq!(summary.time_advances, 1);
        assert_eq!(summary.timers, 2);
        assert_eq!(summary.yielded, 1);
        assert_eq!(
            summary.skipped, 1,
            "Wake is not a decision the lab re-drives"
        );
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 100
            }
        )));
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TimerCreated {
                timer_id: 7,
                deadline_nanos: 500
            }
        )));
        assert_eq!(schedule.into_trace().len(), 6);
    }
}
