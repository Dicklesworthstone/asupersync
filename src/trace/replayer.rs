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
//! ```no_run
//! use asupersync::trace::{ReplayMode, ReplayTrace, TraceReplayer, read_trace};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load a trace file
//! let (metadata, events) = read_trace("trace.bin")?;
//! let mut trace = ReplayTrace::new(metadata);
//! for event in events {
//!     trace.push(event);
//! }
//!
//! // Create a replayer
//! let mut replayer = TraceReplayer::new(trace);
//!
//! // Replay step by step
//! replayer.set_mode(ReplayMode::Step);
//! while let Some(event) = replayer.step()? {
//!     println!("Replayed: {:?}", event);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Divergence Detection
//!
//! The replayer detects when actual execution diverges from the recorded trace.
//! This indicates either a bug in the code or trace corruption.

use crate::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};
use serde::Serialize;
use std::fmt;

const REPLAY_DIVERGENCE_CODE: &str = "ASUP-E401";

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
    /// The expected event from the trace, or `None` when the trace is exhausted.
    pub expected: Option<ReplayEvent>,
    /// The actual event that occurred.
    pub actual: ReplayEvent,
    /// Additional context about the divergence.
    pub context: String,
}

impl fmt::Display for DivergenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expected = self.expected.as_ref().map_or_else(
            || "<trace_exhausted>".to_string(),
            |event| format!("{event:?}"),
        );
        write!(
            f,
            "[{REPLAY_DIVERGENCE_CODE}] replay divergence at event {}: expected {}, got {:?}. {}",
            self.index, expected, self.actual, self.context
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

/// Structured replay report for browser-incident and CI repro workflows.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserReplayReport {
    /// Trace identifier used by diagnostics and artifacts.
    pub trace_id: String,
    /// Replay schema version.
    pub schema_version: u32,
    /// Recording seed.
    pub seed: u64,
    /// Total events in trace.
    pub event_count: usize,
    /// Events consumed by replayer.
    pub replayed_events: usize,
    /// True when replay consumed all events.
    pub completed: bool,
    /// Optional divergence index.
    pub divergence_index: Option<usize>,
    /// Optional divergence summary.
    pub divergence_context: Option<String>,
    /// Minimal replay prefix length for divergence reproduction.
    pub minimization_prefix_len: Option<usize>,
    /// Percentage reduction from full trace size for the minimal prefix.
    pub minimization_reduction_pct: Option<u64>,
    /// Optional artifact pointer for persisted report/replay payload.
    pub artifact_pointer: Option<String>,
    /// Deterministic rerun command bundle.
    pub rerun_commands: Vec<String>,
}

impl BrowserReplayReport {
    /// Serializes report to pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
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
        let Some(event) = self.trace.events.get(event_index) else {
            self.completed = true;
            return None;
        };
        let should_break = self.check_breakpoint(event, event_index + 1);

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
    /// Returns an error if the index is beyond the end of the trace.
    ///
    /// Seeking to `event_count()` is allowed and positions the cursor at EOF.
    pub fn seek(&mut self, index: usize) -> Result<(), ReplayError> {
        if index > self.trace.len() {
            return Err(ReplayError::UnexpectedEnd { index });
        }
        self.current_index = index;
        self.completed = index == self.trace.len();
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
                expected: None,
                actual: actual.clone(),
                context: "Trace ended but execution continued".to_string(),
            });
        };

        if !events_match(expected, actual) {
            return Err(DivergenceError {
                index: self.current_index,
                expected: Some(expected.clone()),
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

    /// Builds a structured replay report for CI/browser incident artifacts.
    #[must_use]
    pub fn browser_replay_report(
        &self,
        trace_id: impl Into<String>,
        artifact_pointer: Option<impl Into<String>>,
        rerun_commands: Vec<String>,
        divergence: Option<&DivergenceError>,
    ) -> BrowserReplayReport {
        let (
            divergence_index,
            divergence_context,
            minimization_prefix_len,
            minimization_reduction_pct,
        ) = divergence.map_or((None, None, None, None), |divergence| {
            let prefix =
                crate::trace::divergence::minimal_divergent_prefix(&self.trace, divergence.index);
            let reduction_pct = minimization_reduction_pct(self.trace.len(), prefix.len());
            let diagnostic = self.diagnose_divergence(
                divergence,
                &crate::trace::divergence::DiagnosticConfig::default(),
            );
            (
                Some(divergence.index),
                Some(diagnostic.to_text()),
                Some(prefix.len()),
                Some(reduction_pct),
            )
        });

        BrowserReplayReport {
            trace_id: trace_id.into(),
            schema_version: self.trace.metadata.version,
            seed: self.trace.metadata.seed,
            event_count: self.trace.len(),
            replayed_events: self.current_index,
            completed: self.completed,
            divergence_index,
            divergence_context,
            minimization_prefix_len,
            minimization_reduction_pct,
            artifact_pointer: artifact_pointer.map(Into::into),
            rerun_commands,
        }
    }

    /// Builds a structured diagnostic report for a replay divergence.
    ///
    /// The replayer only observes one actual event at the failure boundary, so
    /// this uses the single-divergence diagnostic path. Call
    /// [`crate::trace::divergence::diagnose_replay_trace_divergence`] when a
    /// complete actual replay trace is available and actual after-context is
    /// needed.
    #[must_use]
    pub fn diagnose_divergence(
        &self,
        divergence: &DivergenceError,
        config: &crate::trace::divergence::DiagnosticConfig,
    ) -> crate::trace::divergence::DivergenceReport {
        crate::trace::divergence::diagnose_divergence(&self.trace, divergence, config)
    }
}

fn minimization_reduction_pct(total: usize, prefix: usize) -> u64 {
    if total == 0 || prefix >= total {
        return 0;
    }
    let reduced = total - prefix;
    ((reduced * 100) / total) as u64
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
        if self.cursor < self.events.len() {
            let event = self.events[self.cursor].clone();
            self.cursor += 1;
            Some(event)
        } else {
            None
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
#[path = "replayer_inline_tests.rs"]
mod tests;
