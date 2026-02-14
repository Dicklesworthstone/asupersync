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

    fn should_record(&self) -> bool {
        self.events.is_some() && !self.stopped
    }

    fn resolve_limit_action(&self, info: &LimitReached) -> LimitAction {
        match &self.config.on_limit {
            LimitAction::Callback(cb) => (cb)(info.clone()),
            other => other.clone(),
        }
    }

    fn handle_limit(&mut self, info: &LimitReached) -> bool {
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
        if !self.should_record() {
            return;
        }
        let event_size = event.estimated_size() as u64;
        if !self.ensure_capacity(event_size) {
            return;
        }
        if let Some(ref mut events) = self.events {
            events.push_back(event);
            self.estimated_event_bytes = self.estimated_event_bytes.saturating_add(event_size);
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

    /// Takes the trace without consuming the recorder.
    ///
    /// This resets the recorder to a new empty trace with the same config.
    pub fn take(&mut self) -> Option<ReplayTrace> {
        if self.metadata.is_none() || self.events.is_none() {
            return None;
        }

        let metadata = self.metadata.clone().unwrap();
        let events = self
            .events
            .replace(VecDeque::with_capacity(self.config.initial_capacity))
            .unwrap();

        let trace = ReplayTrace {
            metadata: metadata.clone(),
            events: events.into(),
            cursor: 0,
        };

        // Re-initialize with same metadata but fresh events
        let mut new_meta = metadata;
        new_meta.recorded_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        self.metadata = Some(new_meta);
        self.seed_recorded = false;
        self.stopped = false;
        self.estimated_event_bytes = 0;

        Some(trace)
    }

    /// Returns a snapshot of the current trace, if recording.
    ///
    /// This clones the events, so it can be expensive for large traces.
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
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_task_id(index: u32, gen: u32) -> TaskId {
        TaskId::new_for_test(index, gen)
    }

    fn make_region_id(index: u32, gen: u32) -> RegionId {
        RegionId::new_for_test(index, gen)
    }

    #[test]
    fn disabled_recorder_is_noop() {
        let mut recorder = TraceRecorder::disabled();
        assert!(!recorder.is_enabled());
        assert_eq!(recorder.event_count(), 0);

        // These should all be no-ops
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_rng_seed(42);
        recorder.record_rng_value(123);

        assert_eq!(recorder.event_count(), 0);
        assert!(recorder.finish().is_none());
    }

    #[test]
    fn enabled_recorder_captures_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        assert!(recorder.is_enabled());

        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_task_completed(make_task_id(1, 0), Severity::Ok);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("should have trace");
        assert_eq!(trace.events.len(), 4);
        assert_eq!(trace.metadata.seed, 42);
    }

    #[test]
    fn rng_recording_can_be_disabled() {
        let config = RecorderConfig::enabled().with_rng(false);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        // Seed is always recorded
        recorder.record_rng_seed(42);
        // But values are not
        recorder.record_rng_value(123);
        recorder.record_rng_value(456);

        assert_eq!(recorder.event_count(), 1); // Only the seed
    }

    #[test]
    fn waker_recording_can_be_disabled() {
        let config = RecorderConfig::enabled().with_wakers(false);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_waker_wake(make_task_id(1, 0));
        recorder.record_waker_batch_wake(5);

        assert_eq!(recorder.event_count(), 0);
    }

    #[test]
    fn time_advancement_deduplication() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        // Same time should not be recorded
        recorder.record_time_advanced(Time::ZERO, Time::ZERO);
        assert_eq!(recorder.event_count(), 0);

        // Different time should be recorded
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn seed_only_recorded_once() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_rng_seed(42);
        recorder.record_rng_seed(42); // Duplicate should be ignored
        recorder.record_rng_seed(99); // Different value also ignored

        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn take_resets_recorder() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        assert_eq!(recorder.event_count(), 2);

        let trace1 = recorder.take().expect("should have trace");
        assert_eq!(trace1.events.len(), 2);

        // Recorder should be reset but still enabled
        assert!(recorder.is_enabled());
        assert_eq!(recorder.event_count(), 0);

        // Can record new events
        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        assert_eq!(recorder.event_count(), 2);
    }

    #[test]
    fn chaos_injections() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        let task = make_task_id(1, 0);
        recorder.record_cancel_injection(task);
        recorder.record_delay_injection(Some(task), 1_000_000);
        recorder.record_wakeup_storm_injection(task, 10);
        recorder.record_budget_exhaust_injection(task);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("trace");

        // Verify the chaos events
        match &trace.events[0] {
            ReplayEvent::ChaosInjection { kind, .. } => {
                assert_eq!(*kind, chaos_kind::CANCEL);
            }
            _ => panic!("expected ChaosInjection"),
        }
    }

    #[test]
    fn io_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_io_ready(1, true, false, false, false);
        recorder.record_io_result(1, 100);
        recorder.record_io_error(2, io::ErrorKind::ConnectionRefused);

        assert_eq!(recorder.event_count(), 3);

        let trace = recorder.finish().expect("trace");

        match &trace.events[0] {
            ReplayEvent::IoReady { token, readiness } => {
                assert_eq!(*token, 1);
                assert_eq!(*readiness & 1, 1); // readable
            }
            _ => panic!("expected IoReady"),
        }

        match &trace.events[1] {
            ReplayEvent::IoResult { token, bytes } => {
                assert_eq!(*token, 1);
                assert_eq!(*bytes, 100);
            }
            _ => panic!("expected IoResult"),
        }
    }

    #[test]
    fn task_lifecycle() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        let task = make_task_id(1, 0);
        let region = make_region_id(0, 0);

        recorder.record_task_spawned(task, region, 0);
        recorder.record_task_scheduled(task, 0);
        recorder.record_task_yielded(task);
        recorder.record_task_scheduled(task, 1);
        recorder.record_task_completed(task, Severity::Ok);

        assert_eq!(recorder.event_count(), 5);

        let trace = recorder.finish().expect("trace");

        // Verify sequence
        assert!(matches!(trace.events[0], ReplayEvent::TaskSpawned { .. }));
        assert!(matches!(trace.events[1], ReplayEvent::TaskScheduled { .. }));
        assert!(matches!(trace.events[2], ReplayEvent::TaskYielded { .. }));
        assert!(matches!(trace.events[3], ReplayEvent::TaskScheduled { .. }));
        assert!(matches!(trace.events[4], ReplayEvent::TaskCompleted { .. }));
    }

    #[test]
    fn timer_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_timer_created(1, Time::from_millis(100));
        recorder.record_timer_fired(1);
        recorder.record_timer_created(2, Time::from_millis(200));
        recorder.record_timer_cancelled(2);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("trace");

        assert!(matches!(
            trace.events[0],
            ReplayEvent::TimerCreated { timer_id: 1, .. }
        ));
        assert!(matches!(
            trace.events[1],
            ReplayEvent::TimerFired { timer_id: 1 }
        ));
        assert!(matches!(
            trace.events[2],
            ReplayEvent::TimerCreated { timer_id: 2, .. }
        ));
        assert!(matches!(
            trace.events[3],
            ReplayEvent::TimerCancelled { timer_id: 2 }
        ));
    }

    #[test]
    fn estimated_size() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        // Empty trace has some overhead
        let base_size = recorder.estimated_size();
        assert!(base_size > 0);

        // Add events and size should grow
        for i in 0..100 {
            recorder.record_task_scheduled(make_task_id(i, 0), u64::from(i));
        }

        let with_events = recorder.estimated_size();
        assert!(with_events > base_size);
        assert!(with_events < 5000); // Should be compact
    }

    #[test]
    fn max_events_stop_recording() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        assert_eq!(recorder.event_count(), 2);
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
    }

    #[test]
    fn max_events_drop_oldest() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(LimitAction::DropOldest);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
        match (&trace.events[0], &trace.events[1]) {
            (
                ReplayEvent::TaskScheduled { at_tick: first, .. },
                ReplayEvent::TaskScheduled {
                    at_tick: second, ..
                },
            ) => {
                assert_eq!(*first, 1);
                assert_eq!(*second, 2);
            }
            _ => panic!("unexpected events for drop-oldest"),
        }
    }

    #[test]
    fn max_memory_stop_recording() {
        let config = RecorderConfig::enabled()
            .with_max_memory(20)
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);

        assert_eq!(recorder.event_count(), 1);
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 1);
    }

    #[test]
    fn limit_callback_invoked() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hit_ref = Arc::clone(&hits);
        let action = LimitAction::Callback(Arc::new(move |_info| {
            hit_ref.fetch_add(1, Ordering::SeqCst);
            LimitAction::StopRecording
        }));

        let config = RecorderConfig::enabled()
            .with_max_events(Some(1))
            .on_limit(action);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(recorder.event_count(), 1);
    }

    // ── snapshot ───────────────────────────────────────────────────

    #[test]
    fn snapshot_returns_clone_of_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);

        let snap = recorder.snapshot().expect("should have snapshot");
        assert_eq!(snap.events.len(), 2);

        // Recording more events doesn't affect snapshot
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(recorder.event_count(), 3);
    }

    #[test]
    fn snapshot_on_disabled_returns_none() {
        let recorder = TraceRecorder::disabled();
        assert!(recorder.snapshot().is_none());
    }

    // ── take on disabled ───────────────────────────────────────────

    #[test]
    fn take_on_disabled_returns_none() {
        let mut recorder = TraceRecorder::disabled();
        assert!(recorder.take().is_none());
    }

    // ── io_ready bitflags ──────────────────────────────────────────

    #[test]
    fn io_ready_writable_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, true, false, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { token, readiness } => {
                assert_eq!(*token, 10);
                assert_eq!(*readiness, 2); // writable = bit 1
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_error_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, true, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 4); // error = bit 2
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_hangup_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, false, true);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 8); // hangup = bit 3
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_all_flags() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, true, true, true, true);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 0x0F); // all bits set
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_no_flags() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, false, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 0);
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    // ── chaos injection variants ───────────────────────────────────

    #[test]
    fn delay_injection_without_task() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_delay_injection(None, 5_000_000);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::ChaosInjection {
                kind, task, data, ..
            } => {
                assert_eq!(*kind, chaos_kind::DELAY);
                assert!(task.is_none());
                assert_eq!(*data, 5_000_000);
            }
            other => panic!("expected ChaosInjection, got {other:?}"),
        }
    }

    #[test]
    fn io_error_injection() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_error_injection(Some(make_task_id(5, 0)), 7);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::ChaosInjection { kind, data, .. } => {
                assert_eq!(*kind, chaos_kind::IO_ERROR);
                assert_eq!(*data, 7);
            }
            other => panic!("expected ChaosInjection, got {other:?}"),
        }
    }

    // ── waker events when enabled ──────────────────────────────────

    #[test]
    fn waker_events_when_enabled() {
        let config = RecorderConfig::enabled().with_wakers(true);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_waker_wake(make_task_id(1, 0));
        recorder.record_waker_batch_wake(5);

        assert_eq!(recorder.event_count(), 2);
        let trace = recorder.finish().expect("trace");
        assert!(matches!(trace.events[0], ReplayEvent::WakerWake { .. }));
        assert!(matches!(
            trace.events[1],
            ReplayEvent::WakerBatchWake { count: 5 }
        ));
    }

    // ── config builders ────────────────────────────────────────────

    #[test]
    fn config_disabled_creates_disabled() {
        let config = RecorderConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn config_with_capacity() {
        let config = RecorderConfig::enabled().with_capacity(4096);
        assert_eq!(config.initial_capacity, 4096);
    }

    #[test]
    fn config_with_max_file_size() {
        let config = RecorderConfig::enabled().with_max_file_size(512 * 1024);
        assert_eq!(config.max_file_size, 512 * 1024);
    }

    #[test]
    fn config_with_max_memory() {
        let config = RecorderConfig::enabled().with_max_memory(50 * 1024 * 1024);
        assert_eq!(config.max_memory, 50 * 1024 * 1024);
    }

    // ── LimitAction Debug ──────────────────────────────────────────

    #[test]
    fn limit_action_debug_variants() {
        assert_eq!(format!("{:?}", LimitAction::StopRecording), "StopRecording");
        assert_eq!(format!("{:?}", LimitAction::DropOldest), "DropOldest");
        assert_eq!(format!("{:?}", LimitAction::Fail), "Fail");
        let cb = LimitAction::Callback(Arc::new(|_| LimitAction::StopRecording));
        assert_eq!(format!("{cb:?}"), "Callback(..)");
    }

    // ── LimitKind ──────────────────────────────────────────────────

    #[test]
    fn limit_kind_eq() {
        assert_eq!(LimitKind::MaxEvents, LimitKind::MaxEvents);
        assert_eq!(LimitKind::MaxMemory, LimitKind::MaxMemory);
        assert_eq!(LimitKind::MaxFileSize, LimitKind::MaxFileSize);
        assert_ne!(LimitKind::MaxEvents, LimitKind::MaxMemory);
    }

    // ── max_memory with drop_oldest ────────────────────────────────

    #[test]
    fn max_memory_drop_oldest() {
        let config = RecorderConfig::enabled()
            .with_max_memory(20)
            .on_limit(LimitAction::DropOldest);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        // Should have kept events but dropped oldest to fit memory
        let trace = recorder.finish().expect("trace");
        assert!(trace.events.len() <= 2);
    }

    // ── callback that returns DropOldest ────────────────────────────

    #[test]
    fn callback_returning_drop_oldest() {
        let action = LimitAction::Callback(Arc::new(|_| LimitAction::DropOldest));
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(action);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
        // Oldest should have been dropped
        match &trace.events[0] {
            ReplayEvent::TaskScheduled { at_tick, .. } => assert_eq!(*at_tick, 1),
            other => panic!("expected TaskScheduled, got {other:?}"),
        }
    }

    // ── estimated size tracks correctly ─────────────────────────────

    #[test]
    fn estimated_size_resets_after_take() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        for i in 0..50 {
            recorder.record_task_scheduled(make_task_id(i, 0), u64::from(i));
        }
        let size_before = recorder.estimated_size();
        assert!(size_before > 50);

        recorder.take();
        let size_after = recorder.estimated_size();
        assert!(size_after < size_before);
        assert_eq!(size_after, 50); // Just the base overhead
    }

    // ── chaos_kind constants ───────────────────────────────────────

    #[test]
    fn chaos_kind_constants_are_distinct() {
        let kinds = [
            chaos_kind::CANCEL,
            chaos_kind::DELAY,
            chaos_kind::IO_ERROR,
            chaos_kind::WAKEUP_STORM,
            chaos_kind::BUDGET_EXHAUST,
        ];
        let unique: std::collections::BTreeSet<_> = kinds.iter().collect();
        assert_eq!(unique.len(), kinds.len());
    }

    // ── finish metadata ────────────────────────────────────────────

    #[test]
    fn finish_preserves_metadata_seed() {
        let recorder = TraceRecorder::new(TraceMetadata::new(99));
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.metadata.seed, 99);
    }

    // ── stopped recorder ignores events ────────────────────────────

    #[test]
    fn stopped_recorder_ignores_events() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(1))
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        // This triggers stop
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        // These should all be ignored
        recorder.record_rng_seed(42);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_io_ready(1, true, false, false, false);

        assert_eq!(recorder.event_count(), 1);
    }

    // ── default config values ──────────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = RecorderConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.initial_capacity, 1024);
        assert!(config.record_rng);
        assert!(config.record_wakers);
        assert_eq!(config.max_events, None);
        assert_eq!(config.max_memory, DEFAULT_MAX_MEMORY);
        assert_eq!(config.max_file_size, DEFAULT_MAX_FILE_SIZE);
    }

    #[test]
    fn enabled_config_values() {
        let config = RecorderConfig::enabled();
        assert!(config.enabled);
        assert_eq!(config.initial_capacity, 1024);
        assert!(config.record_rng);
        assert!(config.record_wakers);
        assert_eq!(config.max_events, None);
        assert_eq!(config.max_memory, DEFAULT_MAX_MEMORY);
        assert_eq!(config.max_file_size, DEFAULT_MAX_FILE_SIZE);
    }
}
