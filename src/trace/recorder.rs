//! Trace recorder for deterministic replay.
//!
//! The [`TraceRecorder`] captures all sources of non-determinism in the Lab runtime,
//! enabling exact replay of executions for debugging and verification.
//!
//! # Usage
//!
//! The recorder is designed to be opt-in and low-overhead:
//!
//! ```ignore
//! use asupersync::trace::recorder::TraceRecorder;
//! use asupersync::trace::replay::TraceMetadata;
//!
//! // Create a recorder
//! let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
//!
//! // Record events during execution
//! recorder.record_task_scheduled(task_id, tick);
//! recorder.record_time_advanced(old_time, new_time);
//! recorder.record_rng_value(value);
//!
//! // Finish and extract the trace
//! let trace = recorder.finish();
//! ```
//!
//! # Design
//!
//! The recorder is designed for minimal overhead:
//! - Events are stored in a pre-allocated vector
//! - All operations are inline-friendly
//! - Disabled recorders have zero allocation overhead

use crate::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};
use crate::tracing_compat::{error, warn};
use crate::types::{RegionId, Severity, TaskId, Time};
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Arc;

// =============================================================================
// Trace Recorder Configuration
// =============================================================================

/// Default maximum memory for buffered events (100MB).
pub const DEFAULT_MAX_MEMORY: usize = 100 * 1024 * 1024;
/// Default maximum trace file size (1GB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// The kind of limit that was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Maximum event count reached.
    MaxEvents,
    /// Maximum in-memory bytes reached.
    MaxMemory,
    /// Maximum file size reached.
    MaxFileSize,
}

/// Context provided when a recording limit is reached.
#[derive(Debug, Clone)]
pub struct LimitReached {
    /// Which limit was hit.
    pub kind: LimitKind,
    /// Current number of events recorded.
    pub current_events: u64,
    /// Maximum allowed events (if applicable).
    pub max_events: Option<u64>,
    /// Current bytes (memory or file size depending on limit kind).
    pub current_bytes: u64,
    /// Maximum allowed bytes (memory or file size depending on limit kind).
    pub max_bytes: u64,
    /// Additional bytes required to record the next event.
    pub needed_bytes: u64,
}

/// Action to take when a recording limit is reached.
#[derive(Clone, Default)]
pub enum LimitAction {
    /// Stop recording, keep what we have.
    #[default]
    StopRecording,
    /// Drop oldest events (ring buffer mode).
    DropOldest,
    /// Fail loudly (panic in debug, log error in release).
    Fail,
    /// Call user callback for decision.
    Callback(Arc<dyn Fn(LimitReached) -> Self + Send + Sync>),
}

impl fmt::Debug for LimitAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StopRecording => f.write_str("StopRecording"),
            Self::DropOldest => f.write_str("DropOldest"),
            Self::Fail => f.write_str("Fail"),
            Self::Callback(_) => f.write_str("Callback(..)"),
        }
    }
}

/// Configuration for trace recording.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    /// Whether recording is enabled.
    pub enabled: bool,
    /// Initial capacity for the event buffer.
    pub initial_capacity: usize,
    /// Whether to record RNG values (can be verbose).
    pub record_rng: bool,
    /// Whether to record waker events.
    pub record_wakers: bool,
    /// Maximum events to record before stopping.
    /// Default: None (unlimited).
    pub max_events: Option<u64>,
    /// Maximum memory for buffered events (streaming writer bypasses this).
    /// Default: 100MB.
    pub max_memory: usize,
    /// Maximum file size for trace file.
    /// Default: 1GB.
    /// Not enforced by the recorder; the trace file writer enforces its own
    /// `TraceFileConfig::max_file_size`.
    pub max_file_size: u64,
    /// Action when limit reached.
    pub on_limit: LimitAction,
}

impl RecorderConfig {
    /// Creates a new configuration with recording enabled.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            initial_capacity: 1024,
            record_rng: true,
            record_wakers: true,
            max_events: None,
            max_memory: DEFAULT_MAX_MEMORY,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            on_limit: LimitAction::StopRecording,
        }
    }

    /// Creates a disabled configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Sets the initial capacity.
    #[must_use]
    pub const fn with_capacity(mut self, capacity: usize) -> Self {
        self.initial_capacity = capacity;
        self
    }

    /// Sets whether to record RNG values.
    #[must_use]
    pub const fn with_rng(mut self, record: bool) -> Self {
        self.record_rng = record;
        self
    }

    /// Sets whether to record waker events.
    #[must_use]
    pub const fn with_wakers(mut self, record: bool) -> Self {
        self.record_wakers = record;
        self
    }

    /// Sets a maximum number of events to record.
    #[must_use]
    pub const fn with_max_events(mut self, max_events: Option<u64>) -> Self {
        self.max_events = max_events;
        self
    }

    /// Sets a maximum memory budget for buffered events.
    #[must_use]
    pub const fn with_max_memory(mut self, max_memory: usize) -> Self {
        self.max_memory = max_memory;
        self
    }

    /// Sets a maximum file size for trace files.
    #[must_use]
    pub const fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    /// Sets the limit action policy.
    #[must_use]
    pub fn on_limit(mut self, action: LimitAction) -> Self {
        self.on_limit = action;
        self
    }
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_capacity: 1024,
            record_rng: true,
            record_wakers: true,
            max_events: None,
            max_memory: DEFAULT_MAX_MEMORY,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            on_limit: LimitAction::StopRecording,
        }
    }
}

// =============================================================================
// Chaos Injection Kinds
// =============================================================================

/// Chaos injection kind constants for replay events.
pub mod chaos_kind {
    /// Cancellation injection.
    pub const CANCEL: u8 = 0;
    /// Delay injection.
    pub const DELAY: u8 = 1;
    /// I/O error injection.
    pub const IO_ERROR: u8 = 2;
    /// Wakeup storm injection.
    pub const WAKEUP_STORM: u8 = 3;
    /// Budget exhaustion injection.
    pub const BUDGET_EXHAUST: u8 = 4;
}

// =============================================================================
// Recording Retention
// =============================================================================

/// Retention evidence for the events submitted to one enabled recorder.
///
/// Counters cover the recorder's lifetime, including earlier calls to
/// [`TraceRecorder::take`]. Events excluded by `record_rng` or `record_wakers`,
/// duplicate seeds, and unchanged time observations are not submissions. This
/// describes storage loss, not whether every source of nondeterminism was
/// instrumented or the workload reached quiescence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceRecordingStatus {
    submitted_events: u64,
    retained_events: usize,
    first_event_index: u64,
    dropped_oldest: u64,
    rejected_events: u64,
    stopped: bool,
    finished: bool,
    last_limit: Option<LimitKind>,
    record_rng: bool,
    record_wakers: bool,
}

impl TraceRecordingStatus {
    /// Events submitted since the recorder was created, including rejected ones.
    #[must_use]
    pub const fn submitted_events(&self) -> u64 {
        self.submitted_events
    }

    /// Events retained in this snapshot or segment.
    #[must_use]
    pub const fn retained_events(&self) -> usize {
        self.retained_events
    }

    /// Source submission index at which the retained segment starts.
    ///
    /// Eviction and rotation advance this offset. A nonzero offset means this
    /// segment cannot independently replay the recorder's original prefix.
    #[must_use]
    pub const fn first_event_index(&self) -> u64 {
        self.first_event_index
    }

    /// Events evicted by `DropOldest` across all recording segments.
    #[must_use]
    pub const fn dropped_oldest(&self) -> u64 {
        self.dropped_oldest
    }

    /// Submissions rejected at a limit or while the recorder was stopped.
    ///
    /// This also counts a limit callback or failure policy that unwound before
    /// the submission could be retained. Rotation does not erase this history.
    #[must_use]
    pub const fn rejected_events(&self) -> u64 {
        self.rejected_events
    }

    /// Whether a limit stopped this segment from accepting further events.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Whether this receipt finalized a segment rather than observing it live.
    ///
    /// Finalization does not establish that the recorded workload has ended.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Whether this is a snapshot of a recorder still accepting events.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.finished && !self.stopped
    }

    /// Most recent limit encountered, retained across segment rotation.
    #[must_use]
    pub const fn last_limit(&self) -> Option<LimitKind> {
        self.last_limit
    }

    /// Whether RNG value submissions were enabled. The initial seed is separate.
    #[must_use]
    pub const fn records_rng(&self) -> bool {
        self.record_rng
    }

    /// Whether waker submissions were enabled.
    #[must_use]
    pub const fn records_wakers(&self) -> bool {
        self.record_wakers
    }

    /// Whether every submitted event since recorder creation is retained here.
    ///
    /// An active snapshot can satisfy this and still be only a run prefix.
    /// Use [`TraceRecording::into_replay_trace`] to additionally require an
    /// explicitly finalized segment.
    #[must_use]
    pub const fn is_lossless_from_start(&self) -> bool {
        self.first_event_index == 0 && self.dropped_oldest == 0 && self.rejected_events == 0
    }
}

/// A retained trace together with immutable storage-loss evidence.
///
/// The existing [`ReplayTrace`] and [`TraceMetadata`] wire representations are
/// unchanged. Extracting or serializing the bare trace discards this evidence;
/// keep the receipt when deciding whether a recording can authorize replay.
#[derive(Debug, Clone)]
pub struct TraceRecording {
    trace: ReplayTrace,
    status: TraceRecordingStatus,
}

impl TraceRecording {
    /// Borrow the retained events for analysis, even if the recording lost data.
    #[must_use]
    pub fn trace(&self) -> &ReplayTrace {
        &self.trace
    }

    /// Storage retention, lifetime loss counters, and recorder policy.
    #[must_use]
    pub const fn status(&self) -> TraceRecordingStatus {
        self.status
    }

    /// Extract a finalized trace with every submitted event retained from origin.
    ///
    /// This proves retention only. Disabled event categories, missing producer
    /// instrumentation, arbitrary external effects, and workload termination
    /// remain outside this receipt's scope.
    ///
    /// # Errors
    /// Refuses live snapshots, evicted or rejected events, and rotated suffixes.
    pub fn into_replay_trace(self) -> Result<ReplayTrace, TraceRecordingError> {
        if !self.status.finished || !self.status.is_lossless_from_start() {
            return Err(TraceRecordingError {
                status: self.status,
            });
        }
        Ok(self.trace)
    }

    /// Extract the retained prefix or suffix, explicitly discarding its receipt.
    ///
    /// This is useful for partial-trace analysis and legacy consumers. It does
    /// not authorize lossless replay.
    #[must_use]
    pub fn into_retained_trace(self) -> ReplayTrace {
        self.trace
    }
}

/// A recording cannot supply a finalized, lossless trace from its origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceRecordingError {
    status: TraceRecordingStatus,
}

impl TraceRecordingError {
    /// The retention evidence that caused replay admission to fail.
    #[must_use]
    pub const fn status(&self) -> TraceRecordingStatus {
        self.status
    }
}

impl fmt::Display for TraceRecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "replay recording is incomplete: finished={}, first_event_index={}, dropped_oldest={}, rejected_events={}",
            self.status.finished,
            self.status.first_event_index,
            self.status.dropped_oldest,
            self.status.rejected_events
        )
    }
}

impl std::error::Error for TraceRecordingError {}

// =============================================================================
// Trace Recorder
// =============================================================================

/// Records replay events during Lab runtime execution.
///
/// The recorder captures all sources of non-determinism to enable exact replay:
/// - Scheduling decisions (which task runs when)
/// - Time advancement
/// - I/O results
/// - RNG values
/// - Chaos injections
/// - Waker invocations
#[derive(Debug)]
pub struct TraceRecorder {
    /// Metadata for the trace being built.
    metadata: Option<TraceMetadata>,
    /// Buffer of recorded events.
    ///
    /// Uses `VecDeque` for efficient O(1) removal from front when `DropOldest`
    /// limit action is active.
    events: Option<VecDeque<ReplayEvent>>,
    /// Configuration.
    config: RecorderConfig,
    /// Whether the initial RNG seed has been recorded.
    seed_recorded: bool,
    /// Whether recording has been stopped due to limits or errors.
    stopped: bool,
    /// Estimated bytes for recorded events (metadata excluded).
    estimated_event_bytes: u64,
    /// Lifetime retention counters, deliberately preserved across rotation.
    submitted_events: u64,
    first_event_index: u64,
    dropped_oldest: u64,
    rejected_events: u64,
    last_limit: Option<LimitKind>,
}

impl TraceRecorder {
    /// Creates a new trace recorder with the given metadata.
    #[must_use]
    pub fn new(metadata: TraceMetadata) -> Self {
        Self::with_config(metadata, RecorderConfig::enabled())
    }

    /// Creates a new trace recorder with custom configuration.
    #[must_use]
    pub fn with_config(metadata: TraceMetadata, config: RecorderConfig) -> Self {
        let (metadata, events) = if config.enabled {
            (
                Some(metadata),
                Some(VecDeque::with_capacity(config.initial_capacity)),
            )
        } else {
            (None, None)
        };
        Self {
            metadata,
            events,
            config,
            seed_recorded: false,
            stopped: false,
            estimated_event_bytes: 0,
            submitted_events: 0,
            first_event_index: 0,
            dropped_oldest: 0,
            rejected_events: 0,
            last_limit: None,
        }
    }

    /// Creates a disabled recorder (no-op).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            metadata: None,
            events: None,
            config: RecorderConfig::disabled(),
            seed_recorded: false,
            stopped: true,
            estimated_event_bytes: 0,
            submitted_events: 0,
            first_event_index: 0,
            dropped_oldest: 0,
            rejected_events: 0,
            last_limit: None,
        }
    }

    /// Returns true if recording is enabled.
    #[must_use]
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.events.is_some()
    }

    /// Returns the number of recorded events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.as_ref().map_or(0, VecDeque::len)
    }

    /// Returns the estimated size of the trace in bytes.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        // Metadata overhead (~50 bytes) + events
        50 + self.estimated_event_bytes as usize
    }

    /// Inspect retention without cloning the event buffer.
    ///
    /// Returns `None` when recording is disabled. A stopped recorder continues
    /// reporting subsequent rejected submissions and earlier segments' loss.
    #[must_use]
    pub fn status(&self) -> Option<TraceRecordingStatus> {
        self.events.as_ref().map(|_| self.recording_status(false))
    }

    fn recording_status(&self, finished: bool) -> TraceRecordingStatus {
        TraceRecordingStatus {
            submitted_events: self.submitted_events,
            retained_events: self.event_count(),
            first_event_index: self.first_event_index,
            dropped_oldest: self.dropped_oldest,
            rejected_events: self.rejected_events,
            stopped: self.stopped,
            finished,
            last_limit: self.last_limit,
            record_rng: self.config.record_rng,
            record_wakers: self.config.record_wakers,
        }
    }

    fn resolve_limit_action(&self, info: &LimitReached) -> LimitAction {
        match &self.config.on_limit {
            LimitAction::Callback(cb) => (cb)(info.clone()),
            other => other.clone(),
        }
    }

    fn handle_limit(&mut self, info: &LimitReached) -> bool {
        // Publish terminal/loss evidence before user callbacks or debug failure
        // policies can unwind. Only a successful eviction reopens admission.
        self.stopped = true;
        self.last_limit = Some(info.kind);
        let mut action = self.resolve_limit_action(info);
        if matches!(action, LimitAction::Callback(_)) {
            action = LimitAction::StopRecording;
        }

        match action {
            LimitAction::StopRecording => {
                warn!(
                    kind = ?info.kind,
                    current_events = info.current_events,
                    max_events = ?info.max_events,
                    current_bytes = info.current_bytes,
                    max_bytes = info.max_bytes,
                    "trace recording stopped: limit reached"
                );
                self.stopped = true;
                false
            }
            LimitAction::DropOldest => {
                if self.drop_oldest_event() {
                    self.stopped = false;
                    true
                } else {
                    warn!(
                        kind = ?info.kind,
                        "trace recording stopped: unable to drop oldest event"
                    );
                    self.stopped = true;
                    false
                }
            }
            LimitAction::Fail => {
                if cfg!(debug_assertions) {
                    panic!("trace recording limit exceeded: {info:?}");
                } else {
                    error!(
                        kind = ?info.kind,
                        current_events = info.current_events,
                        max_events = ?info.max_events,
                        current_bytes = info.current_bytes,
                        max_bytes = info.max_bytes,
                        "trace recording failed: limit exceeded"
                    );
                }
                self.stopped = true;
                false
            }
            LimitAction::Callback(_) => {
                self.stopped = true;
                false
            }
        }
    }

    fn drop_oldest_event(&mut self) -> bool {
        let Some(events) = self.events.as_mut() else {
            return false;
        };
        if events.is_empty() {
            return false;
        }
        let dropped = events.pop_front().expect("events not empty");
        self.first_event_index = self.first_event_index.saturating_add(1);
        self.dropped_oldest = self.dropped_oldest.saturating_add(1);
        self.estimated_event_bytes = self
            .estimated_event_bytes
            .saturating_sub(dropped.estimated_size() as u64);
        true
    }

    fn ensure_capacity(&mut self, event_size: u64) -> bool {
        loop {
            if let Some(max_events) = self.config.max_events {
                let current = self.event_count() as u64;
                if current.saturating_add(1) > max_events {
                    let info = LimitReached {
                        kind: LimitKind::MaxEvents,
                        current_events: current,
                        max_events: Some(max_events),
                        current_bytes: self.estimated_event_bytes,
                        max_bytes: self.config.max_memory as u64,
                        needed_bytes: event_size,
                    };
                    if !self.handle_limit(&info) {
                        return false;
                    }
                    continue;
                }
            }

            let max_memory = self.config.max_memory as u64;
            if max_memory > 0 && self.estimated_event_bytes.saturating_add(event_size) > max_memory
            {
                let info = LimitReached {
                    kind: LimitKind::MaxMemory,
                    current_events: self.event_count() as u64,
                    max_events: self.config.max_events,
                    current_bytes: self.estimated_event_bytes,
                    max_bytes: max_memory,
                    needed_bytes: event_size,
                };
                if !self.handle_limit(&info) {
                    return false;
                }
                continue;
            }

            break;
        }
        true
    }

    fn record_event(&mut self, event: ReplayEvent) {
        if self.events.is_none() {
            return;
        }
        self.submitted_events = self.submitted_events.saturating_add(1);
        // Count the event as rejected until retention succeeds. If a limit
        // callback panics, the next receipt must still report the missing event.
        let previous_rejections = self.rejected_events;
        self.rejected_events = self.rejected_events.saturating_add(1);
        if self.stopped {
            return;
        }
        let event_size = event.estimated_size() as u64;
        if !self.ensure_capacity(event_size) {
            return;
        }
        if let Some(ref mut events) = self.events {
            events.push_back(event);
            self.estimated_event_bytes = self.estimated_event_bytes.saturating_add(event_size);
            self.rejected_events = previous_rejections;
        }
    }

    // =========================================================================
    // Recording Methods - Scheduling
    // =========================================================================

    /// Records that a task was scheduled.
    #[inline]
    pub fn record_task_scheduled(&mut self, task: TaskId, at_tick: u64) {
        self.record_event(ReplayEvent::TaskScheduled {
            task: task.into(),
            at_tick,
        });
    }

    /// Records that a task yielded.
    #[inline]
    pub fn record_task_yielded(&mut self, task: TaskId) {
        self.record_event(ReplayEvent::TaskYielded { task: task.into() });
    }

    /// Records that a task completed.
    #[inline]
    pub fn record_task_completed(&mut self, task: TaskId, severity: Severity) {
        self.record_event(ReplayEvent::TaskCompleted {
            task: task.into(),
            outcome: severity.as_u8(),
        });
    }

    /// Records that a task was spawned.
    #[inline]
    pub fn record_task_spawned(&mut self, task: TaskId, region: RegionId, at_tick: u64) {
        self.record_event(ReplayEvent::TaskSpawned {
            task: task.into(),
            region: region.into(),
            at_tick,
        });
    }

    // =========================================================================
    // Recording Methods - Time
    // =========================================================================

    /// Records that virtual time advanced.
    #[inline]
    pub fn record_time_advanced(&mut self, from: Time, to: Time) {
        if from != to {
            self.record_event(ReplayEvent::TimeAdvanced {
                from_nanos: from.as_nanos(),
                to_nanos: to.as_nanos(),
            });
        }
    }

    /// Records that a timer was created.
    #[inline]
    pub fn record_timer_created(&mut self, timer_id: u64, deadline: Time) {
        self.record_event(ReplayEvent::TimerCreated {
            timer_id,
            deadline_nanos: deadline.as_nanos(),
        });
    }

    /// Records that a timer fired.
    #[inline]
    pub fn record_timer_fired(&mut self, timer_id: u64) {
        self.record_event(ReplayEvent::TimerFired { timer_id });
    }

    /// Records that a timer was cancelled.
    #[inline]
    pub fn record_timer_cancelled(&mut self, timer_id: u64) {
        self.record_event(ReplayEvent::TimerCancelled { timer_id });
    }

    // =========================================================================
    // Recording Methods - I/O
    // =========================================================================

    /// Records that I/O became ready.
    #[inline]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn record_io_ready(
        &mut self,
        token: u64,
        readable: bool,
        writable: bool,
        error: bool,
        hangup: bool,
    ) {
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
        self.record_event(ReplayEvent::IoReady { token, readiness });
    }

    /// Records an I/O result (bytes transferred).
    #[inline]
    pub fn record_io_result(&mut self, token: u64, bytes: i64) {
        self.record_event(ReplayEvent::IoResult { token, bytes });
    }

    /// Records an I/O error.
    #[inline]
    pub fn record_io_error(&mut self, token: u64, kind: io::ErrorKind) {
        self.record_event(ReplayEvent::io_error(token, kind));
    }

    // =========================================================================
    // Recording Methods - RNG
    // =========================================================================

    /// Records the RNG seed.
    ///
    /// This should be called once at the start of execution.
    #[inline]
    pub fn record_rng_seed(&mut self, seed: u64) {
        if !self.seed_recorded {
            self.record_event(ReplayEvent::RngSeed { seed });
            self.seed_recorded = true;
        }
    }

    /// Records an RNG value.
    ///
    /// This is only recorded if `record_rng` is enabled in the config.
    #[inline]
    pub fn record_rng_value(&mut self, value: u64) {
        if self.config.record_rng {
            self.record_event(ReplayEvent::RngValue { value });
        }
    }

    // =========================================================================
    // Recording Methods - Chaos
    // =========================================================================

    /// Records a chaos injection.
    #[inline]
    pub fn record_chaos_injection(&mut self, kind: u8, task: Option<TaskId>, data: u64) {
        self.record_event(ReplayEvent::ChaosInjection {
            kind,
            task: task.map(std::convert::Into::into),
            data,
        });
    }

    /// Records a cancellation injection.
    #[inline]
    pub fn record_cancel_injection(&mut self, task: TaskId) {
        self.record_chaos_injection(chaos_kind::CANCEL, Some(task), 0);
    }

    /// Records a delay injection.
    #[inline]
    pub fn record_delay_injection(&mut self, task: Option<TaskId>, delay_nanos: u64) {
        self.record_chaos_injection(chaos_kind::DELAY, task, delay_nanos);
    }

    /// Records an I/O error injection.
    #[inline]
    pub fn record_io_error_injection(&mut self, task: Option<TaskId>, error_kind: u8) {
        self.record_chaos_injection(chaos_kind::IO_ERROR, task, u64::from(error_kind));
    }

    /// Records a wakeup storm injection.
    #[inline]
    pub fn record_wakeup_storm_injection(&mut self, task: TaskId, count: u32) {
        self.record_chaos_injection(chaos_kind::WAKEUP_STORM, Some(task), u64::from(count));
    }

    /// Records a budget exhaustion injection.
    #[inline]
    pub fn record_budget_exhaust_injection(&mut self, task: TaskId) {
        self.record_chaos_injection(chaos_kind::BUDGET_EXHAUST, Some(task), 0);
    }

    // =========================================================================
    // Recording Methods - Wakers
    // =========================================================================

    /// Records that a waker was invoked.
    #[inline]
    pub fn record_waker_wake(&mut self, task: TaskId) {
        if self.config.record_wakers {
            self.record_event(ReplayEvent::WakerWake { task: task.into() });
        }
    }

    /// Records a batch waker invocation.
    #[inline]
    pub fn record_waker_batch_wake(&mut self, count: u32) {
        if self.config.record_wakers {
            self.record_event(ReplayEvent::WakerBatchWake { count });
        }
    }

    // =========================================================================
    // Completion
    // =========================================================================

    /// Finishes recording and returns the completed trace.
    ///
    /// Returns `None` if recording was disabled.
    /// This legacy view omits retention evidence. Use [`Self::finish_recording`]
    /// when the consumer must distinguish loss from an intentionally short run.
    #[must_use]
    pub fn finish(self) -> Option<ReplayTrace> {
        if let (Some(metadata), Some(events)) = (self.metadata, self.events) {
            Some(ReplayTrace {
                metadata,
                events: events.into(),
                cursor: 0,
            })
        } else {
            None
        }
    }

    /// Finalizes the recorder and preserves its retention evidence.
    ///
    /// Returns `None` if recording was disabled. The receipt can be passed to
    /// [`super::replayer::TraceReplayer::from_recording`] for checked admission.
    #[must_use]
    pub fn finish_recording(self) -> Option<TraceRecording> {
        let status = self.recording_status(true);
        self.finish().map(|trace| TraceRecording { trace, status })
    }

    /// Takes the trace without consuming the recorder.
    ///
    /// This resets the recorder to a new empty trace with the same config.
    /// This legacy view omits retention evidence; [`Self::take_recording`]
    /// preserves it. Later segments keep their source offset and lifetime loss
    /// history even when rotation goes through this legacy method.
    pub fn take(&mut self) -> Option<ReplayTrace> {
        if self.metadata.is_none() || self.events.is_none() {
            return None;
        }

        let metadata = self.metadata.clone().expect("metadata must exist");
        let events = self
            .events
            .replace(VecDeque::with_capacity(self.config.initial_capacity))
            .expect("events must exist");

        let trace = ReplayTrace {
            metadata: metadata.clone(),
            events: events.into(),
            cursor: 0,
        };

        // Re-initialize with same metadata but fresh events. Keep rotation
        // deterministic by advancing from the caller-supplied timestamp instead
        // of consulting wall clock time again.
        let mut new_meta = metadata;
        new_meta.recorded_at = new_meta.recorded_at.saturating_add(1);
        self.metadata = Some(new_meta);
        self.seed_recorded = false;
        self.stopped = false;
        self.estimated_event_bytes = 0;
        self.first_event_index = self.submitted_events;

        Some(trace)
    }

    /// Finalizes the current segment and begins another without erasing loss.
    ///
    /// A later segment carries a nonzero source offset and cannot independently
    /// authorize replay from the original recorder's start.
    pub fn take_recording(&mut self) -> Option<TraceRecording> {
        let status = self.recording_status(true);
        self.take().map(|trace| TraceRecording { trace, status })
    }

    /// Returns a snapshot of the current trace, if recording.
    ///
    /// This clones the events, so it can be expensive for large traces.
    /// This legacy view omits retention evidence; use
    /// [`Self::snapshot_recording`] to retain it.
    #[must_use]
    pub fn snapshot(&self) -> Option<ReplayTrace> {
        if let (Some(metadata), Some(events)) = (&self.metadata, &self.events) {
            Some(ReplayTrace {
                metadata: metadata.clone(),
                events: events.clone().into(),
                cursor: 0,
            })
        } else {
            None
        }
    }

    /// Snapshots retained events and storage loss without finalizing the recorder.
    ///
    /// Even a lossless live snapshot is a prefix. Checked replay admission
    /// requires [`Self::finish_recording`] or [`Self::take_recording`].
    #[must_use]
    pub fn snapshot_recording(&self) -> Option<TraceRecording> {
        let status = self.recording_status(false);
        self.snapshot()
            .map(|trace| TraceRecording { trace, status })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "recorder_inline_tests.rs"]
mod tests;
