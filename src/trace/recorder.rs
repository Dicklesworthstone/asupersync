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
use crate::types::{RegionId, Severity, TaskId, Time};
use std::io;

// =============================================================================
// Trace Recorder Configuration
// =============================================================================

/// Configuration for trace recording.
#[derive(Debug, Clone, Default)]
pub struct RecorderConfig {
    /// Whether recording is enabled.
    pub enabled: bool,
    /// Initial capacity for the event buffer.
    pub initial_capacity: usize,
    /// Whether to record RNG values (can be verbose).
    pub record_rng: bool,
    /// Whether to record waker events.
    pub record_wakers: bool,
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
    /// The underlying trace being built.
    trace: Option<ReplayTrace>,
    /// Configuration.
    config: RecorderConfig,
    /// Whether the initial RNG seed has been recorded.
    seed_recorded: bool,
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
        let trace = if config.enabled {
            Some(ReplayTrace::with_capacity(
                metadata,
                config.initial_capacity,
            ))
        } else {
            None
        };
        Self {
            trace,
            config,
            seed_recorded: false,
        }
    }

    /// Creates a disabled recorder (no-op).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            trace: None,
            config: RecorderConfig::disabled(),
            seed_recorded: false,
        }
    }

    /// Returns true if recording is enabled.
    #[must_use]
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.trace.is_some()
    }

    /// Returns the number of recorded events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.trace.as_ref().map_or(0, |t| t.len())
    }

    /// Returns the estimated size of the trace in bytes.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        self.trace.as_ref().map_or(0, |t| t.estimated_size())
    }

    // =========================================================================
    // Recording Methods - Scheduling
    // =========================================================================

    /// Records that a task was scheduled.
    #[inline]
    pub fn record_task_scheduled(&mut self, task: TaskId, at_tick: u64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TaskScheduled {
                task: task.into(),
                at_tick,
            });
        }
    }

    /// Records that a task yielded.
    #[inline]
    pub fn record_task_yielded(&mut self, task: TaskId) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TaskYielded { task: task.into() });
        }
    }

    /// Records that a task completed.
    #[inline]
    pub fn record_task_completed(&mut self, task: TaskId, severity: Severity) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TaskCompleted {
                task: task.into(),
                outcome: severity.as_u8(),
            });
        }
    }

    /// Records that a task was spawned.
    #[inline]
    pub fn record_task_spawned(&mut self, task: TaskId, region: RegionId, at_tick: u64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TaskSpawned {
                task: task.into(),
                region: region.into(),
                at_tick,
            });
        }
    }

    // =========================================================================
    // Recording Methods - Time
    // =========================================================================

    /// Records that virtual time advanced.
    #[inline]
    pub fn record_time_advanced(&mut self, from: Time, to: Time) {
        if let Some(ref mut trace) = self.trace {
            // Only record if time actually changed
            if from != to {
                trace.push(ReplayEvent::TimeAdvanced {
                    from_nanos: from.as_nanos(),
                    to_nanos: to.as_nanos(),
                });
            }
        }
    }

    /// Records that a timer was created.
    #[inline]
    pub fn record_timer_created(&mut self, timer_id: u64, deadline: Time) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TimerCreated {
                timer_id,
                deadline_nanos: deadline.as_nanos(),
            });
        }
    }

    /// Records that a timer fired.
    #[inline]
    pub fn record_timer_fired(&mut self, timer_id: u64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TimerFired { timer_id });
        }
    }

    /// Records that a timer was cancelled.
    #[inline]
    pub fn record_timer_cancelled(&mut self, timer_id: u64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::TimerCancelled { timer_id });
        }
    }

    // =========================================================================
    // Recording Methods - I/O
    // =========================================================================

    /// Records that I/O became ready.
    #[inline]
    pub fn record_io_ready(
        &mut self,
        token: u64,
        readable: bool,
        writable: bool,
        error: bool,
        hangup: bool,
    ) {
        if let Some(ref mut trace) = self.trace {
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
            trace.push(ReplayEvent::IoReady { token, readiness });
        }
    }

    /// Records an I/O result (bytes transferred).
    #[inline]
    pub fn record_io_result(&mut self, token: u64, bytes: i64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::IoResult { token, bytes });
        }
    }

    /// Records an I/O error.
    #[inline]
    pub fn record_io_error(&mut self, token: u64, kind: io::ErrorKind) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::io_error(token, kind));
        }
    }

    // =========================================================================
    // Recording Methods - RNG
    // =========================================================================

    /// Records the RNG seed.
    ///
    /// This should be called once at the start of execution.
    #[inline]
    pub fn record_rng_seed(&mut self, seed: u64) {
        if let Some(ref mut trace) = self.trace {
            if !self.seed_recorded {
                trace.push(ReplayEvent::RngSeed { seed });
                self.seed_recorded = true;
            }
        }
    }

    /// Records an RNG value.
    ///
    /// This is only recorded if `record_rng` is enabled in the config.
    #[inline]
    pub fn record_rng_value(&mut self, value: u64) {
        if self.config.record_rng {
            if let Some(ref mut trace) = self.trace {
                trace.push(ReplayEvent::RngValue { value });
            }
        }
    }

    // =========================================================================
    // Recording Methods - Chaos
    // =========================================================================

    /// Records a chaos injection.
    #[inline]
    pub fn record_chaos_injection(&mut self, kind: u8, task: Option<TaskId>, data: u64) {
        if let Some(ref mut trace) = self.trace {
            trace.push(ReplayEvent::ChaosInjection {
                kind,
                task: task.map(|t| t.into()),
                data,
            });
        }
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
        self.record_chaos_injection(chaos_kind::IO_ERROR, task, error_kind as u64);
    }

    /// Records a wakeup storm injection.
    #[inline]
    pub fn record_wakeup_storm_injection(&mut self, task: TaskId, count: u32) {
        self.record_chaos_injection(chaos_kind::WAKEUP_STORM, Some(task), count as u64);
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
            if let Some(ref mut trace) = self.trace {
                trace.push(ReplayEvent::WakerWake { task: task.into() });
            }
        }
    }

    /// Records a batch waker invocation.
    #[inline]
    pub fn record_waker_batch_wake(&mut self, count: u32) {
        if self.config.record_wakers {
            if let Some(ref mut trace) = self.trace {
                trace.push(ReplayEvent::WakerBatchWake { count });
            }
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
        self.trace
    }

    /// Takes the trace without consuming the recorder.
    ///
    /// This resets the recorder to a new empty trace with the same config.
    pub fn take(&mut self) -> Option<ReplayTrace> {
        let taken = self.trace.take();
        if let Some(ref t) = taken {
            // Re-initialize with same metadata but fresh events
            let mut new_meta = t.metadata.clone();
            new_meta.recorded_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            self.trace = Some(ReplayTrace::with_capacity(
                new_meta,
                self.config.initial_capacity,
            ));
            self.seed_recorded = false;
        }
        taken
    }

    /// Returns a reference to the current trace, if recording.
    #[must_use]
    pub fn trace(&self) -> Option<&ReplayTrace> {
        self.trace.as_ref()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
            recorder.record_task_scheduled(make_task_id(i, 0), i as u64);
        }

        let with_events = recorder.estimated_size();
        assert!(with_events > base_size);
        assert!(with_events < 5000); // Should be compact
    }
}
