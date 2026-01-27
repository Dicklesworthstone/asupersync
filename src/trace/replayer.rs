//! Trace replayer for deterministic replay.
//!
//! The [`TraceReplayer`] feeds recorded decisions back into the Lab runtime
//! to achieve exact execution replay. This is useful for:
//!
//! - Debugging non-deterministic issues
//! - Reproducing test failures
//! - Verifying execution determinism
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::trace::replayer::{TraceReplayer, ReplayMode};
//! use asupersync::trace::file::TraceReader;
//!
//! // Load a trace file
//! let reader = TraceReader::open("trace.bin")?;
//!
//! // Create a replayer
//! let mut replayer = TraceReplayer::new(reader)?;
//!
//! // Replay step by step
//! replayer.set_mode(ReplayMode::Step);
//! while let Some(event) = replayer.step()? {
//!     println!("Replayed: {:?}", event);
//! }
//! ```
//!
//! # Divergence Detection
//!
//! The replayer detects when actual execution diverges from the recorded trace.
//! This indicates either a bug in the code or trace corruption.

use crate::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};
use std::fmt;

// =============================================================================
// Replay Mode
// =============================================================================

/// The replay execution mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReplayMode {
    /// Run to completion without stopping.
    #[default]
    Run,
    /// Stop after each event.
    Step,
    /// Run until a specific breakpoint is reached.
    RunTo(Breakpoint),
}

/// A breakpoint that stops replay execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Breakpoint {
    /// Stop at a specific tick (step number).
    Tick(u64),
    /// Stop when a specific task is scheduled.
    Task(CompactTaskId),
    /// Stop at a specific event index.
    EventIndex(usize),
}

// =============================================================================
// Divergence Error
// =============================================================================

/// Error indicating that execution diverged from the recorded trace.
#[derive(Debug)]
pub struct DivergenceError {
    /// The event index where divergence occurred.
    pub index: usize,
    /// The expected event from the trace.
    pub expected: ReplayEvent,
    /// The actual event that occurred.
    pub actual: ReplayEvent,
    /// Additional context about the divergence.
    pub context: String,
}

impl fmt::Display for DivergenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Replay divergence at event {}: expected {:?}, got {:?}. {}",
            self.index, self.expected, self.actual, self.context
        )
    }
}

impl std::error::Error for DivergenceError {}

/// Errors that can occur during replay.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// Execution diverged from the trace.
    #[error("{0}")]
    Divergence(#[from] DivergenceError),

    /// Trace ended unexpectedly.
    #[error("trace ended unexpectedly at event {index}, expected more events")]
    UnexpectedEnd {
        /// The event index where the trace ended.
        index: usize,
    },

    /// Invalid trace metadata.
    #[error("invalid trace metadata: {0}")]
    InvalidMetadata(String),

    /// Version mismatch.
    #[error("trace version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Found version.
        found: u32,
    },
}

// =============================================================================
// Trace Replayer
// =============================================================================

/// Replays a recorded trace, feeding decisions back to the runtime.
///
/// The replayer maintains a cursor into the trace and provides the next
/// expected event for each replay step. It can detect divergence when
/// actual execution doesn't match the recorded trace.
#[derive(Debug)]
pub struct TraceReplayer {
    /// The trace being replayed.
    trace: ReplayTrace,
    /// Current position in the trace.
    current_index: usize,
    /// Current replay mode.
    mode: ReplayMode,
    /// Whether we've hit a breakpoint.
    at_breakpoint: bool,
    /// Whether replay has completed.
    completed: bool,
}

impl TraceReplayer {
    /// Creates a new replayer from a trace.
    #[must_use]
    pub fn new(trace: ReplayTrace) -> Self {
        Self {
            trace,
            current_index: 0,
            mode: ReplayMode::Run,
            at_breakpoint: false,
            completed: false,
        }
    }

    /// Returns the trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        &self.trace.metadata
    }

    /// Returns the total number of events in the trace.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.trace.len()
    }

    /// Returns the current event index.
    #[must_use]
    pub fn current_index(&self) -> usize {
        self.current_index
    }

    /// Returns true if replay has completed.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.completed
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

    /// Returns the next expected event without advancing.
    #[must_use]
    pub fn peek(&self) -> Option<&ReplayEvent> {
        self.trace.events.get(self.current_index)
    }

    /// Advances to the next event and returns it.
    ///
    /// Returns `None` if the trace has been fully replayed.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&ReplayEvent> {
        if self.completed {
            return None;
        }

        let event_index = self.current_index;
        let should_break = {
            let event = self.trace.events.get(event_index)?;
            self.check_breakpoint(event, event_index + 1)
        };

        self.current_index = event_index + 1;

        if self.current_index >= self.trace.len() {
            self.completed = true;
        }

        // Check for breakpoint
        self.at_breakpoint = should_break;

        self.trace.events.get(event_index)
    }

    /// Resets the replayer to the beginning of the trace.
    pub fn reset(&mut self) {
        self.current_index = 0;
        self.completed = false;
        self.at_breakpoint = false;
    }

    /// Seeks to a specific event index.
    ///
    /// Returns an error if the index is out of bounds.
    pub fn seek(&mut self, index: usize) -> Result<(), ReplayError> {
        if index >= self.trace.len() {
            return Err(ReplayError::UnexpectedEnd { index });
        }
        self.current_index = index;
        self.completed = false;
        self.at_breakpoint = false;
        Ok(())
    }

    /// Verifies that an actual event matches the expected recorded event.
    ///
    /// Returns an error with divergence details if they don't match.
    pub fn verify(&self, actual: &ReplayEvent) -> Result<(), DivergenceError> {
        let Some(expected) = self.peek() else {
            return Err(DivergenceError {
                index: self.current_index,
                expected: ReplayEvent::RngSeed { seed: 0 }, // Placeholder
                actual: actual.clone(),
                context: "Trace ended but execution continued".to_string(),
            });
        };

        if !events_match(expected, actual) {
            return Err(DivergenceError {
                index: self.current_index,
                expected: expected.clone(),
                actual: actual.clone(),
                context: divergence_context(expected, actual),
            });
        }

        Ok(())
    }

    /// Verifies and advances to the next event.
    ///
    /// This is the main replay loop method: verify the actual event matches,
    /// then advance.
    pub fn verify_and_advance(&mut self, actual: &ReplayEvent) -> Result<(), ReplayError> {
        self.verify(actual)?;
        self.next();
        Ok(())
    }

    /// Checks if we should stop at a breakpoint.
    fn check_breakpoint(&self, event: &ReplayEvent, next_index: usize) -> bool {
        if let ReplayMode::RunTo(ref breakpoint) = self.mode {
            match breakpoint {
                Breakpoint::EventIndex(idx) => next_index == *idx + 1,
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
            }
        } else {
            matches!(self.mode, ReplayMode::Step)
        }
    }

    /// Steps forward, respecting the current mode.
    ///
    /// In Step mode, advances one event and stops.
    /// In Run mode, advances all events until completion.
    /// In RunTo mode, advances until the breakpoint is reached.
    pub fn step(&mut self) -> Result<Option<&ReplayEvent>, ReplayError> {
        if self.completed {
            return Ok(None);
        }

        self.at_breakpoint = false;
        let event = self.next();

        Ok(event)
    }

    /// Continues execution until completion or breakpoint.
    ///
    /// Returns the number of events processed.
    pub fn run(&mut self) -> Result<usize, ReplayError> {
        let mut count = 0;

        while !self.completed && !self.at_breakpoint {
            if self.next().is_some() {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Returns all remaining events without consuming them.
    #[must_use]
    pub fn remaining_events(&self) -> &[ReplayEvent] {
        if self.current_index >= self.trace.len() {
            &[]
        } else {
            &self.trace.events[self.current_index..]
        }
    }

    /// Consumes the replayer and returns the underlying trace.
    #[must_use]
    pub fn into_trace(self) -> ReplayTrace {
        self.trace
    }
}

// =============================================================================
// Event Matching
// =============================================================================

/// Checks if two replay events match (allowing for minor differences).
///
/// Some fields may vary slightly between recording and replay due to
/// timing or other factors. This function defines what constitutes a "match".
fn events_match(expected: &ReplayEvent, actual: &ReplayEvent) -> bool {
    use std::mem::discriminant;

    // First check if they're the same variant
    if discriminant(expected) != discriminant(actual) {
        return false;
    }

    // For most events, exact equality is required
    // In the future, we might want to be more lenient for certain fields
    expected == actual
}

/// Generates helpful context for a divergence error.
fn divergence_context(expected: &ReplayEvent, actual: &ReplayEvent) -> String {
    match (expected, actual) {
        (
            ReplayEvent::TaskScheduled {
                task: expected_task,
                at_tick: expected_tick,
            },
            ReplayEvent::TaskScheduled {
                task: actual_task,
                at_tick: actual_tick,
            },
        ) => {
            if expected_task == actual_task {
                format!(
                    "Task scheduled at different tick: expected {expected_tick}, got {actual_tick}"
                )
            } else {
                format!(
                    "Different task scheduled: expected {expected_task:?}, got {actual_task:?} (at tick {actual_tick})"
                )
            }
        }
        (
            ReplayEvent::TimeAdvanced {
                from_nanos: e_from,
                to_nanos: e_to,
            },
            ReplayEvent::TimeAdvanced {
                from_nanos: a_from,
                to_nanos: a_to,
            },
        ) => {
            format!(
                "Time advanced differently: expected {e_from}ns -> {e_to}ns, got {a_from}ns -> {a_to}ns"
            )
        }
        (
            ReplayEvent::TaskCompleted {
                task: e_task,
                outcome: e_out,
            },
            ReplayEvent::TaskCompleted {
                task: a_task,
                outcome: a_out,
            },
        ) => {
            if e_task == a_task {
                format!("Different outcome: expected {e_out}, got {a_out}")
            } else {
                format!("Different task completed: expected {e_task:?}, got {a_task:?}")
            }
        }
        _ => "Events have same type but different values".to_string(),
    }
}

// =============================================================================
// Event Source Trait
// =============================================================================

/// Trait for types that can provide replay events.
///
/// This allows the replayer to work with different event sources:
/// - In-memory traces (`ReplayTrace`)
/// - Streaming file readers (`TraceReader`)
pub trait EventSource {
    /// Returns the next event, or `None` if exhausted.
    fn next_event(&mut self) -> Option<ReplayEvent>;

    /// Returns the metadata for this trace.
    fn metadata(&self) -> &TraceMetadata;
}

impl EventSource for ReplayTrace {
    fn next_event(&mut self) -> Option<ReplayEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
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
    use super::*;
    use crate::trace::replay::TraceMetadata;

    fn make_trace(events: Vec<ReplayEvent>) -> ReplayTrace {
        ReplayTrace {
            metadata: TraceMetadata::new(42),
            events,
        }
    }

    #[test]
    fn basic_replay() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        assert_eq!(replayer.event_count(), 3);
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());

        // Advance through events
        let e1 = replayer.next().cloned();
        assert!(matches!(e1, Some(ReplayEvent::RngSeed { seed: 42 })));

        let e2 = replayer.next().cloned();
        assert!(matches!(e2, Some(ReplayEvent::TaskScheduled { .. })));

        let e3 = replayer.next().cloned();
        assert!(matches!(e3, Some(ReplayEvent::TaskCompleted { .. })));

        assert!(replayer.is_completed());
        assert!(replayer.next().is_none());
    }

    #[test]
    fn step_mode() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::Step);

        // Each step should stop
        replayer.step().unwrap();
        assert!(replayer.at_breakpoint());

        replayer.step().unwrap();
        assert!(replayer.at_breakpoint());
        assert!(replayer.is_completed());
    }

    #[test]
    fn breakpoint_at_tick() {
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 5,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 10,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(5)));

        // Run should stop at tick 5
        let count = replayer.run().unwrap();
        assert_eq!(count, 2);
        assert!(replayer.at_breakpoint());
        assert!(!replayer.is_completed());
    }

    #[test]
    fn breakpoint_at_event_index() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::EventIndex(1)));

        // Run should stop at event index 1
        let count = replayer.run().unwrap();
        assert_eq!(count, 2); // Processed events 0 and 1
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn verify_matching_events() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let replayer = TraceReplayer::new(make_trace(events));

        // Matching event should succeed
        let actual = ReplayEvent::RngSeed { seed: 42 };
        assert!(replayer.verify(&actual).is_ok());
    }

    #[test]
    fn verify_mismatching_events() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let replayer = TraceReplayer::new(make_trace(events));

        // Different event should fail
        let actual = ReplayEvent::RngSeed { seed: 99 };
        let err = replayer.verify(&actual).unwrap_err();
        assert_eq!(err.index, 0);
    }

    #[test]
    fn seek_and_reset() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        // Advance partway
        replayer.next();
        replayer.next();
        assert_eq!(replayer.current_index(), 2);

        // Seek to beginning
        replayer.seek(0).unwrap();
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());

        // Advance to end
        replayer.next();
        replayer.next();
        replayer.next();
        assert!(replayer.is_completed());

        // Reset
        replayer.reset();
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());
    }

    #[test]
    fn verify_and_advance() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        // Verify and advance with matching events
        let actual1 = ReplayEvent::RngSeed { seed: 42 };
        assert!(replayer.verify_and_advance(&actual1).is_ok());
        assert_eq!(replayer.current_index(), 1);

        let actual2 = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        };
        assert!(replayer.verify_and_advance(&actual2).is_ok());
        assert!(replayer.is_completed());
    }

    #[test]
    fn divergence_error_formatting() {
        let expected = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        };
        let actual = ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 0,
        };

        let err = DivergenceError {
            index: 5,
            expected: expected.clone(),
            actual: actual.clone(),
            context: divergence_context(&expected, &actual),
        };

        let msg = format!("{err}");
        assert!(msg.contains("event 5"));
        assert!(msg.contains("Different task scheduled"));
    }

    #[test]
    fn remaining_events() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        assert_eq!(replayer.remaining_events().len(), 3);

        replayer.next();
        assert_eq!(replayer.remaining_events().len(), 2);

        replayer.next();
        replayer.next();
        assert_eq!(replayer.remaining_events().len(), 0);
    }
}
