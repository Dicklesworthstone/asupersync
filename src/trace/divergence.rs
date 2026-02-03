//! Replay divergence diagnostics for actionable debugging.
//!
//! When a replay diverges from the recorded trace, this module provides
//! structured diagnostics to help identify the root cause:
//!
//! - **Minimal divergent prefix**: the smallest trace prefix that reproduces the issue
//! - **First-violation isolation**: pinpoints the exact event where divergence begins
//! - **Affected entity analysis**: identifies tasks, regions, and timers involved
//! - **Context window**: surrounding events for before/after comparison
//! - **Structured output**: JSON-serializable for CI integration
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::trace::divergence::{DivergenceReport, diagnose_divergence};
//! use asupersync::trace::replayer::DivergenceError;
//!
//! // After catching a divergence error during replay:
//! let report = diagnose_divergence(&trace, &divergence_error, DiagnosticConfig::default());
//! println!("{}", report.to_text());
//! println!("{}", report.to_json().unwrap());
//! ```

use crate::trace::replay::{ReplayEvent, ReplayTrace};
use crate::trace::replayer::DivergenceError;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for divergence diagnostics.
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    /// Number of events to include before the divergence point.
    pub context_before: usize,
    /// Number of expected events to include after the divergence point.
    pub context_after: usize,
    /// Maximum length of the minimal prefix (0 = no limit).
    pub max_prefix_len: usize,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            context_before: 10,
            context_after: 5,
            max_prefix_len: 0,
        }
    }
}

// =============================================================================
// Event Summary (compact, serializable representation)
// =============================================================================

/// A compact, human-readable summary of a replay event.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EventSummary {
    /// Event index in the trace.
    pub index: usize,
    /// Event type name.
    pub event_type: String,
    /// Key details as human-readable string.
    pub details: String,
    /// Task ID involved, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<u64>,
    /// Region ID involved, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_id: Option<u64>,
}

impl EventSummary {
    /// Create a summary from a replay event at a given index.
    #[must_use]
    pub fn from_event(index: usize, event: &ReplayEvent) -> Self {
        let (event_type, details, task_id, region_id) = summarize_event(event);
        Self {
            index,
            event_type,
            details,
            task_id,
            region_id,
        }
    }
}

// =============================================================================
// Affected Entities
// =============================================================================

/// Entities involved in or affected by the divergence.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AffectedEntities {
    /// Task IDs directly referenced at the divergence point.
    pub tasks: Vec<u64>,
    /// Region IDs directly referenced at the divergence point.
    pub regions: Vec<u64>,
    /// Timer IDs directly referenced at the divergence point.
    pub timers: Vec<u64>,
    /// Scheduler lane affected (if identifiable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler_lane: Option<String>,
}

// =============================================================================
// Divergence Category
// =============================================================================

/// High-level category of the divergence.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum DivergenceCategory {
    /// A different task was scheduled than expected.
    SchedulingOrder,
    /// A task completed with a different outcome.
    OutcomeMismatch,
    /// Virtual time advanced differently.
    TimeDivergence,
    /// Timer events differ.
    TimerMismatch,
    /// I/O events differ.
    IoMismatch,
    /// RNG values differ (seed or generated value).
    RngMismatch,
    /// Region lifecycle events differ.
    RegionMismatch,
    /// Different event types entirely.
    EventTypeMismatch,
    /// Trace ended but execution continued (or vice versa).
    LengthMismatch,
    /// Waker events differ.
    WakerMismatch,
    /// Chaos injection events differ.
    ChaosMismatch,
    /// Checkpoint mismatch (state drift).
    CheckpointMismatch,
}

impl fmt::Display for DivergenceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchedulingOrder => write!(f, "scheduling-order"),
            Self::OutcomeMismatch => write!(f, "outcome-mismatch"),
            Self::TimeDivergence => write!(f, "time-divergence"),
            Self::TimerMismatch => write!(f, "timer-mismatch"),
            Self::IoMismatch => write!(f, "io-mismatch"),
            Self::RngMismatch => write!(f, "rng-mismatch"),
            Self::RegionMismatch => write!(f, "region-mismatch"),
            Self::EventTypeMismatch => write!(f, "event-type-mismatch"),
            Self::LengthMismatch => write!(f, "length-mismatch"),
            Self::WakerMismatch => write!(f, "waker-mismatch"),
            Self::ChaosMismatch => write!(f, "chaos-mismatch"),
            Self::CheckpointMismatch => write!(f, "checkpoint-mismatch"),
        }
    }
}

// =============================================================================
// Divergence Report
// =============================================================================

/// Structured diagnostics report for a replay divergence.
///
/// Contains all information needed to understand and debug a divergence:
/// the exact divergence point, surrounding context, affected entities,
/// category, and actionable guidance.
#[derive(Debug, Clone, Serialize)]
pub struct DivergenceReport {
    /// High-level category of the divergence.
    pub category: DivergenceCategory,

    /// Event index where divergence was detected.
    pub divergence_index: usize,

    /// Total events in the recorded trace.
    pub trace_length: usize,

    /// Percentage of trace that replayed successfully before divergence.
    pub replay_progress_pct: f64,

    /// Summary of the expected event.
    pub expected: EventSummary,

    /// Summary of the actual event.
    pub actual: EventSummary,

    /// Human-readable explanation of what went wrong.
    pub explanation: String,

    /// Actionable suggestion for debugging.
    pub suggestion: String,

    /// Context window: events immediately before the divergence.
    pub context_before: Vec<EventSummary>,

    /// Context window: expected events immediately after the divergence.
    pub context_after: Vec<EventSummary>,

    /// Entities affected by the divergence.
    pub affected: AffectedEntities,

    /// Length of the minimal divergent prefix (events 0..=divergence_index).
    pub minimal_prefix_len: usize,

    /// Seed from the trace metadata.
    pub seed: u64,
}

impl DivergenceReport {
    /// Serialize the report to a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render a human-readable text report.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        out.push_str("=== Replay Divergence Report ===\n\n");

        let _ = writeln!(out, "Category:   {}", self.category);
        let _ = writeln!(
            out,
            "Event:      {} of {} ({:.1}% replayed)",
            self.divergence_index, self.trace_length, self.replay_progress_pct
        );
        let _ = writeln!(out, "Seed:       0x{:016x}", self.seed);
        let _ = writeln!(out, "Min prefix: {} events\n", self.minimal_prefix_len);

        let _ = writeln!(
            out,
            "Expected: [{}] {}",
            self.expected.event_type, self.expected.details
        );
        let _ = writeln!(
            out,
            "Actual:   [{}] {}\n",
            self.actual.event_type, self.actual.details
        );

        let _ = writeln!(out, "Explanation: {}", self.explanation);
        let _ = writeln!(out, "Suggestion:  {}\n", self.suggestion);

        if !self.affected.tasks.is_empty() {
            let _ = writeln!(out, "Affected tasks:   {:?}", self.affected.tasks);
        }
        if !self.affected.regions.is_empty() {
            let _ = writeln!(out, "Affected regions: {:?}", self.affected.regions);
        }
        if !self.affected.timers.is_empty() {
            let _ = writeln!(out, "Affected timers:  {:?}", self.affected.timers);
        }

        if !self.context_before.is_empty() {
            out.push_str("\n--- Context (before) ---\n");
            for ev in &self.context_before {
                let _ = writeln!(out, "  [{}] {} {}", ev.index, ev.event_type, ev.details);
            }
        }

        let _ = writeln!(out, "  [{}] >>> DIVERGENCE <<<", self.divergence_index);

        if !self.context_after.is_empty() {
            out.push_str("--- Context (expected after) ---\n");
            for ev in &self.context_after {
                let _ = writeln!(out, "  [{}] {} {}", ev.index, ev.event_type, ev.details);
            }
        }

        out
    }
}

// =============================================================================
// Diagnosis Entry Point
// =============================================================================

/// Produce a structured [`DivergenceReport`] from a divergence error and its trace.
///
/// This is the main entry point for divergence diagnostics. Given the recorded
/// trace and the error from the replayer, it analyzes the divergence and
/// produces a rich, actionable report.
#[must_use]
pub fn diagnose_divergence(
    trace: &ReplayTrace,
    error: &DivergenceError,
    config: &DiagnosticConfig,
) -> DivergenceReport {
    let idx = error.index;
    let trace_len = trace.events.len();

    // Category
    let category = classify_divergence(&error.expected, &error.actual);

    // Summaries
    let expected = EventSummary::from_event(idx, &error.expected);
    let actual = EventSummary::from_event(idx, &error.actual);

    // Context windows
    let context_before = build_context_before(&trace.events, idx, config.context_before);
    let context_after = build_context_after(&trace.events, idx, config.context_after);

    // Affected entities
    let affected = extract_affected_entities(&error.expected, &error.actual);

    // Explanation and suggestion
    let explanation = build_explanation(category, &error.expected, &error.actual);
    let suggestion = build_suggestion(category, &affected);

    // Minimal prefix length
    let minimal_prefix_len = if config.max_prefix_len > 0 {
        (idx + 1).min(config.max_prefix_len)
    } else {
        idx + 1
    };

    // Progress
    let replay_progress_pct = if trace_len == 0 {
        0.0
    } else {
        (idx as f64 / trace_len as f64) * 100.0
    };

    DivergenceReport {
        category,
        divergence_index: idx,
        trace_length: trace_len,
        replay_progress_pct,
        expected,
        actual,
        explanation,
        suggestion,
        context_before,
        context_after,
        affected,
        minimal_prefix_len,
        seed: trace.metadata.seed,
    }
}

/// Extract the minimal divergent prefix: the shortest sub-trace that still
/// demonstrates the divergence.
///
/// Returns the prefix as a new `ReplayTrace` containing events `0..=divergence_index`.
#[must_use]
pub fn minimal_divergent_prefix(trace: &ReplayTrace, divergence_index: usize) -> ReplayTrace {
    let end = (divergence_index + 1).min(trace.events.len());
    ReplayTrace {
        metadata: trace.metadata.clone(),
        events: trace.events[..end].to_vec(),
        cursor: 0,
    }
}

// =============================================================================
// Classification
// =============================================================================

/// Classify a divergence by comparing expected and actual events.
fn classify_divergence(expected: &ReplayEvent, actual: &ReplayEvent) -> DivergenceCategory {
    use std::mem::discriminant;

    if discriminant(expected) != discriminant(actual) {
        return DivergenceCategory::EventTypeMismatch;
    }

    match (expected, actual) {
        (ReplayEvent::TaskScheduled { .. }, ReplayEvent::TaskScheduled { .. }) => {
            DivergenceCategory::SchedulingOrder
        }
        (ReplayEvent::TaskCompleted { .. }, ReplayEvent::TaskCompleted { .. }) => {
            DivergenceCategory::OutcomeMismatch
        }
        (ReplayEvent::TimeAdvanced { .. }, ReplayEvent::TimeAdvanced { .. }) => {
            DivergenceCategory::TimeDivergence
        }
        (ReplayEvent::TimerCreated { .. }, ReplayEvent::TimerCreated { .. })
        | (ReplayEvent::TimerFired { .. }, ReplayEvent::TimerFired { .. })
        | (ReplayEvent::TimerCancelled { .. }, ReplayEvent::TimerCancelled { .. }) => {
            DivergenceCategory::TimerMismatch
        }
        (ReplayEvent::IoReady { .. }, ReplayEvent::IoReady { .. })
        | (ReplayEvent::IoResult { .. }, ReplayEvent::IoResult { .. })
        | (ReplayEvent::IoError { .. }, ReplayEvent::IoError { .. }) => {
            DivergenceCategory::IoMismatch
        }
        (ReplayEvent::RngSeed { .. }, ReplayEvent::RngSeed { .. })
        | (ReplayEvent::RngValue { .. }, ReplayEvent::RngValue { .. }) => {
            DivergenceCategory::RngMismatch
        }
        (ReplayEvent::RegionCreated { .. }, ReplayEvent::RegionCreated { .. })
        | (ReplayEvent::RegionClosed { .. }, ReplayEvent::RegionClosed { .. })
        | (ReplayEvent::RegionCancelled { .. }, ReplayEvent::RegionCancelled { .. }) => {
            DivergenceCategory::RegionMismatch
        }
        (ReplayEvent::WakerWake { .. }, ReplayEvent::WakerWake { .. })
        | (ReplayEvent::WakerBatchWake { .. }, ReplayEvent::WakerBatchWake { .. }) => {
            DivergenceCategory::WakerMismatch
        }
        (ReplayEvent::ChaosInjection { .. }, ReplayEvent::ChaosInjection { .. }) => {
            DivergenceCategory::ChaosMismatch
        }
        (ReplayEvent::Checkpoint { .. }, ReplayEvent::Checkpoint { .. }) => {
            DivergenceCategory::CheckpointMismatch
        }
        _ => DivergenceCategory::EventTypeMismatch,
    }
}

// =============================================================================
// Context Windows
// =============================================================================

fn build_context_before(events: &[ReplayEvent], idx: usize, count: usize) -> Vec<EventSummary> {
    let start = idx.saturating_sub(count);
    events[start..idx]
        .iter()
        .enumerate()
        .map(|(i, ev)| EventSummary::from_event(start + i, ev))
        .collect()
}

fn build_context_after(events: &[ReplayEvent], idx: usize, count: usize) -> Vec<EventSummary> {
    let after_start = idx + 1;
    if after_start >= events.len() {
        return Vec::new();
    }
    let end = (after_start + count).min(events.len());
    events[after_start..end]
        .iter()
        .enumerate()
        .map(|(i, ev)| EventSummary::from_event(after_start + i, ev))
        .collect()
}

// =============================================================================
// Entity Extraction
// =============================================================================

fn extract_affected_entities(expected: &ReplayEvent, actual: &ReplayEvent) -> AffectedEntities {
    let mut tasks = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut timers = BTreeSet::new();
    let mut lane = None;

    collect_event_entities(expected, &mut tasks, &mut regions, &mut timers);
    collect_event_entities(actual, &mut tasks, &mut regions, &mut timers);

    // Determine scheduler lane from scheduling events
    match (expected, actual) {
        (
            ReplayEvent::TaskScheduled { task: e, .. },
            ReplayEvent::TaskScheduled { task: a, .. },
        ) => {
            if e != a {
                lane = Some(format!("ready (expected task {:?}, got {:?})", e, a));
            }
        }
        _ => {}
    }

    AffectedEntities {
        tasks: tasks.into_iter().collect(),
        regions: regions.into_iter().collect(),
        timers: timers.into_iter().collect(),
        scheduler_lane: lane,
    }
}

fn collect_event_entities(
    event: &ReplayEvent,
    tasks: &mut BTreeSet<u64>,
    regions: &mut BTreeSet<u64>,
    timers: &mut BTreeSet<u64>,
) {
    match event {
        ReplayEvent::TaskScheduled { task, .. }
        | ReplayEvent::TaskYielded { task }
        | ReplayEvent::TaskCompleted { task, .. }
        | ReplayEvent::WakerWake { task } => {
            tasks.insert(task.0);
        }
        ReplayEvent::TaskSpawned { task, region, .. } => {
            tasks.insert(task.0);
            regions.insert(region.0);
        }
        ReplayEvent::TimerCreated { timer_id, .. }
        | ReplayEvent::TimerFired { timer_id }
        | ReplayEvent::TimerCancelled { timer_id } => {
            timers.insert(*timer_id);
        }
        ReplayEvent::RegionCreated { region, parent, .. } => {
            regions.insert(region.0);
            if let Some(p) = parent {
                regions.insert(p.0);
            }
        }
        ReplayEvent::RegionClosed { region, .. } | ReplayEvent::RegionCancelled { region, .. } => {
            regions.insert(region.0);
        }
        ReplayEvent::ChaosInjection { task, .. } => {
            if let Some(t) = task {
                tasks.insert(t.0);
            }
        }
        ReplayEvent::IoReady { .. }
        | ReplayEvent::IoResult { .. }
        | ReplayEvent::IoError { .. }
        | ReplayEvent::RngSeed { .. }
        | ReplayEvent::RngValue { .. }
        | ReplayEvent::TimeAdvanced { .. }
        | ReplayEvent::WakerBatchWake { .. }
        | ReplayEvent::Checkpoint { .. } => {}
    }
}

// =============================================================================
// Explanations and Suggestions
// =============================================================================

fn build_explanation(
    category: DivergenceCategory,
    expected: &ReplayEvent,
    actual: &ReplayEvent,
) -> String {
    match category {
        DivergenceCategory::SchedulingOrder => {
            if let (
                ReplayEvent::TaskScheduled {
                    task: e,
                    at_tick: et,
                    ..
                },
                ReplayEvent::TaskScheduled {
                    task: a,
                    at_tick: at,
                    ..
                },
            ) = (expected, actual)
            {
                if e == a {
                    format!(
                        "Task {:?} was scheduled at tick {} instead of expected tick {}. \
                         The scheduler made the same choice but at a different time.",
                        e, at, et
                    )
                } else {
                    format!(
                        "Scheduler chose task {:?} at tick {} instead of expected task {:?} at tick {}. \
                         The ready queue ordering diverged.",
                        a, at, e, et
                    )
                }
            } else {
                "Scheduling order diverged from recorded trace.".to_string()
            }
        }
        DivergenceCategory::OutcomeMismatch => {
            if let (
                ReplayEvent::TaskCompleted {
                    task: e,
                    outcome: eo,
                },
                ReplayEvent::TaskCompleted {
                    task: a,
                    outcome: ao,
                },
            ) = (expected, actual)
            {
                let outcome_name = |o: u8| match o {
                    0 => "Ok",
                    1 => "Err",
                    2 => "Cancelled",
                    3 => "Panicked",
                    _ => "Unknown",
                };
                if e == a {
                    format!(
                        "Task {:?} completed with {} (expected {}). \
                         The task's internal logic took a different path.",
                        e,
                        outcome_name(*ao),
                        outcome_name(*eo)
                    )
                } else {
                    format!(
                        "Different task completed: got {:?} ({}) instead of {:?} ({}).",
                        a,
                        outcome_name(*ao),
                        e,
                        outcome_name(*eo)
                    )
                }
            } else {
                "Task completion outcome diverged.".to_string()
            }
        }
        DivergenceCategory::TimeDivergence => {
            "Virtual time advanced to a different value. This usually indicates \
             a timer or sleep duration changed between record and replay."
                .to_string()
        }
        DivergenceCategory::TimerMismatch => {
            "Timer event (create/fire/cancel) diverged. Check if timer registration \
             order or deadlines changed."
                .to_string()
        }
        DivergenceCategory::IoMismatch => {
            "I/O event diverged. The simulated I/O layer returned different results. \
             This may indicate a Lab reactor configuration change."
                .to_string()
        }
        DivergenceCategory::RngMismatch => {
            "RNG seed or value mismatch. The deterministic RNG produced different output. \
             Verify the seed is identical and no additional RNG calls were inserted."
                .to_string()
        }
        DivergenceCategory::RegionMismatch => {
            "Region lifecycle event diverged. A region was created, closed, or cancelled \
             differently than recorded."
                .to_string()
        }
        DivergenceCategory::EventTypeMismatch => {
            format!(
                "Completely different event types: expected {} but got {}. \
                 The execution path diverged significantly.",
                event_type_name(expected),
                event_type_name(actual)
            )
        }
        DivergenceCategory::LengthMismatch => {
            "Trace ended but execution continued (or vice versa).".to_string()
        }
        DivergenceCategory::WakerMismatch => {
            "Waker event diverged. A different task was woken or batch count differs.".to_string()
        }
        DivergenceCategory::ChaosMismatch => {
            "Chaos injection event diverged. The fault injection decisions differ.".to_string()
        }
        DivergenceCategory::CheckpointMismatch => {
            "Checkpoint state mismatch. The runtime state at a synchronization point \
             differs from the recording, indicating accumulated drift."
                .to_string()
        }
    }
}

fn build_suggestion(category: DivergenceCategory, affected: &AffectedEntities) -> String {
    let mut suggestion = match category {
        DivergenceCategory::SchedulingOrder => {
            "Check for non-deterministic task readiness (e.g., I/O completion order, \
             timer resolution). Use a fixed seed and verify the scheduler configuration \
             matches the recording."
                .to_string()
        }
        DivergenceCategory::OutcomeMismatch => {
            "The task produced a different result. Check for external state dependencies, \
             non-deterministic error paths, or changed business logic."
                .to_string()
        }
        DivergenceCategory::TimeDivergence => {
            "Verify the Lab runtime clock configuration matches. Check for changed \
             sleep/timeout durations in the code under test."
                .to_string()
        }
        DivergenceCategory::RngMismatch => {
            "Ensure the same seed is used. If new RNG calls were added between record \
             and replay, the sequence will shift. Use derive_entropy_seed() for \
             subsystem-specific RNG isolation."
                .to_string()
        }
        DivergenceCategory::EventTypeMismatch => {
            "The execution diverged so significantly that a completely different event \
             was produced. Look for code changes that alter the control flow, such as \
             added/removed spawns, new I/O operations, or changed cancellation paths."
                .to_string()
        }
        DivergenceCategory::CheckpointMismatch => {
            "State accumulated drift before this checkpoint. Examine the events between \
             the previous checkpoint and this one for subtle differences."
                .to_string()
        }
        _ => "Compare the expected and actual events above. Check for code changes, \
             configuration differences, or non-deterministic external dependencies."
            .to_string(),
    };

    if !affected.tasks.is_empty() {
        use std::fmt::Write;
        let _ = write!(suggestion, " Focus on task(s): {:?}.", affected.tasks);
    }

    suggestion
}

// =============================================================================
// Event Summarization
// =============================================================================

/// Returns (event_type, details, optional_task_id, optional_region_id).
fn summarize_event(event: &ReplayEvent) -> (String, String, Option<u64>, Option<u64>) {
    match event {
        ReplayEvent::TaskScheduled { task, at_tick } => (
            "TaskScheduled".into(),
            format!("task={:?} tick={at_tick}", task),
            Some(task.0),
            None,
        ),
        ReplayEvent::TaskYielded { task } => (
            "TaskYielded".into(),
            format!("task={:?}", task),
            Some(task.0),
            None,
        ),
        ReplayEvent::TaskCompleted { task, outcome } => {
            let outcome_str = match outcome {
                0 => "Ok",
                1 => "Err",
                2 => "Cancelled",
                3 => "Panicked",
                _ => "Unknown",
            };
            (
                "TaskCompleted".into(),
                format!("task={:?} outcome={outcome_str}", task),
                Some(task.0),
                None,
            )
        }
        ReplayEvent::TaskSpawned {
            task,
            region,
            at_tick,
        } => (
            "TaskSpawned".into(),
            format!("task={:?} region={:?} tick={at_tick}", task, region),
            Some(task.0),
            Some(region.0),
        ),
        ReplayEvent::TimeAdvanced {
            from_nanos,
            to_nanos,
        } => (
            "TimeAdvanced".into(),
            format!("{from_nanos}ns -> {to_nanos}ns"),
            None,
            None,
        ),
        ReplayEvent::TimerCreated {
            timer_id,
            deadline_nanos,
        } => (
            "TimerCreated".into(),
            format!("timer={timer_id} deadline={deadline_nanos}ns"),
            None,
            None,
        ),
        ReplayEvent::TimerFired { timer_id } => {
            ("TimerFired".into(), format!("timer={timer_id}"), None, None)
        }
        ReplayEvent::TimerCancelled { timer_id } => (
            "TimerCancelled".into(),
            format!("timer={timer_id}"),
            None,
            None,
        ),
        ReplayEvent::IoReady { token, readiness } => (
            "IoReady".into(),
            format!("token={token} readiness=0x{readiness:02x}"),
            None,
            None,
        ),
        ReplayEvent::IoResult { token, bytes } => (
            "IoResult".into(),
            format!("token={token} bytes={bytes}"),
            None,
            None,
        ),
        ReplayEvent::IoError { token, kind } => (
            "IoError".into(),
            format!("token={token} kind={kind}"),
            None,
            None,
        ),
        ReplayEvent::RngSeed { seed } => ("RngSeed".into(), format!("0x{seed:016x}"), None, None),
        ReplayEvent::RngValue { value } => {
            ("RngValue".into(), format!("0x{value:016x}"), None, None)
        }
        ReplayEvent::ChaosInjection { kind, task, data } => {
            let kind_str = match kind {
                0 => "cancel",
                1 => "delay",
                2 => "io_error",
                3 => "wakeup_storm",
                4 => "budget",
                _ => "unknown",
            };
            (
                "ChaosInjection".into(),
                format!("kind={kind_str} task={task:?} data={data}"),
                task.map(|t| t.0),
                None,
            )
        }
        ReplayEvent::RegionCreated {
            region,
            parent,
            at_tick,
        } => (
            "RegionCreated".into(),
            format!("region={:?} parent={parent:?} tick={at_tick}", region),
            None,
            Some(region.0),
        ),
        ReplayEvent::RegionClosed { region, outcome } => {
            let outcome_str = match outcome {
                0 => "Ok",
                1 => "Err",
                2 => "Cancelled",
                3 => "Panicked",
                _ => "Unknown",
            };
            (
                "RegionClosed".into(),
                format!("region={:?} outcome={outcome_str}", region),
                None,
                Some(region.0),
            )
        }
        ReplayEvent::RegionCancelled {
            region,
            cancel_kind,
        } => (
            "RegionCancelled".into(),
            format!("region={:?} cancel_kind={cancel_kind}", region),
            None,
            Some(region.0),
        ),
        ReplayEvent::WakerWake { task } => (
            "WakerWake".into(),
            format!("task={:?}", task),
            Some(task.0),
            None,
        ),
        ReplayEvent::WakerBatchWake { count } => (
            "WakerBatchWake".into(),
            format!("count={count}"),
            None,
            None,
        ),
        ReplayEvent::Checkpoint {
            sequence,
            time_nanos,
            active_tasks,
            active_regions,
        } => (
            "Checkpoint".into(),
            format!(
                "seq={sequence} time={time_nanos}ns tasks={active_tasks} regions={active_regions}"
            ),
            None,
            None,
        ),
    }
}

fn event_type_name(event: &ReplayEvent) -> &'static str {
    match event {
        ReplayEvent::TaskScheduled { .. } => "TaskScheduled",
        ReplayEvent::TaskYielded { .. } => "TaskYielded",
        ReplayEvent::TaskCompleted { .. } => "TaskCompleted",
        ReplayEvent::TaskSpawned { .. } => "TaskSpawned",
        ReplayEvent::TimeAdvanced { .. } => "TimeAdvanced",
        ReplayEvent::TimerCreated { .. } => "TimerCreated",
        ReplayEvent::TimerFired { .. } => "TimerFired",
        ReplayEvent::TimerCancelled { .. } => "TimerCancelled",
        ReplayEvent::IoReady { .. } => "IoReady",
        ReplayEvent::IoResult { .. } => "IoResult",
        ReplayEvent::IoError { .. } => "IoError",
        ReplayEvent::RngSeed { .. } => "RngSeed",
        ReplayEvent::RngValue { .. } => "RngValue",
        ReplayEvent::ChaosInjection { .. } => "ChaosInjection",
        ReplayEvent::RegionCreated { .. } => "RegionCreated",
        ReplayEvent::RegionClosed { .. } => "RegionClosed",
        ReplayEvent::RegionCancelled { .. } => "RegionCancelled",
        ReplayEvent::WakerWake { .. } => "WakerWake",
        ReplayEvent::WakerBatchWake { .. } => "WakerBatchWake",
        ReplayEvent::Checkpoint { .. } => "Checkpoint",
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::replay::TraceMetadata;

    fn make_trace(seed: u64, events: Vec<ReplayEvent>) -> ReplayTrace {
        ReplayTrace {
            metadata: TraceMetadata::new(seed),
            events,
            cursor: 0,
        }
    }

    fn make_error(index: usize, expected: ReplayEvent, actual: ReplayEvent) -> DivergenceError {
        DivergenceError {
            index,
            expected,
            actual,
            context: String::new(),
        }
    }

    // -------------------------------------------------------------------------
    // Classification tests
    // -------------------------------------------------------------------------

    #[test]
    fn classify_scheduling_order() {
        let cat = classify_divergence(
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );
        assert_eq!(cat, DivergenceCategory::SchedulingOrder);
    }

    #[test]
    fn classify_outcome_mismatch() {
        let cat = classify_divergence(
            &ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
            &ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 2,
            },
        );
        assert_eq!(cat, DivergenceCategory::OutcomeMismatch);
    }

    #[test]
    fn classify_event_type_mismatch() {
        let cat = classify_divergence(
            &ReplayEvent::RngSeed { seed: 42 },
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        );
        assert_eq!(cat, DivergenceCategory::EventTypeMismatch);
    }

    #[test]
    fn classify_time_divergence() {
        let cat = classify_divergence(
            &ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1000,
            },
            &ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 2000,
            },
        );
        assert_eq!(cat, DivergenceCategory::TimeDivergence);
    }

    #[test]
    fn classify_rng_mismatch() {
        let cat = classify_divergence(
            &ReplayEvent::RngSeed { seed: 42 },
            &ReplayEvent::RngSeed { seed: 99 },
        );
        assert_eq!(cat, DivergenceCategory::RngMismatch);
    }

    #[test]
    fn classify_checkpoint_mismatch() {
        let cat = classify_divergence(
            &ReplayEvent::Checkpoint {
                sequence: 1,
                time_nanos: 100,
                active_tasks: 3,
                active_regions: 1,
            },
            &ReplayEvent::Checkpoint {
                sequence: 1,
                time_nanos: 100,
                active_tasks: 5,
                active_regions: 1,
            },
        );
        assert_eq!(cat, DivergenceCategory::CheckpointMismatch);
    }

    // -------------------------------------------------------------------------
    // Full report tests
    // -------------------------------------------------------------------------

    #[test]
    fn diagnose_scheduling_divergence() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(1),
                region: CompactRegionId(100),
                at_tick: 0,
            },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(2),
                region: CompactRegionId(100),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 2,
            },
        ];
        let trace = make_trace(0xDEAD, events);

        let error = make_error(
            3,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::SchedulingOrder);
        assert_eq!(report.divergence_index, 3);
        assert_eq!(report.trace_length, 5);
        assert_eq!(report.minimal_prefix_len, 4);
        assert_eq!(report.seed, 0xDEAD);
        assert!(report.replay_progress_pct > 50.0);
        assert!(report.affected.tasks.contains(&1));
        assert!(report.affected.tasks.contains(&2));
        assert!(report.explanation.contains("Scheduler chose"));
        assert!(!report.context_before.is_empty());
    }

    #[test]
    fn diagnose_outcome_divergence() {
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 3,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::OutcomeMismatch);
        assert!(report.explanation.contains("Panicked"));
        assert!(report.explanation.contains("Ok"));
    }

    #[test]
    fn diagnose_event_type_mismatch() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TimerFired { timer_id: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::EventTypeMismatch);
        assert!(report.explanation.contains("TaskScheduled"));
        assert!(report.explanation.contains("TimerFired"));
    }

    // -------------------------------------------------------------------------
    // Context window tests
    // -------------------------------------------------------------------------

    #[test]
    fn context_window_bounds() {
        let events: Vec<_> = (0..20)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let error = make_error(
            10,
            ReplayEvent::RngValue { value: 10 },
            ReplayEvent::RngValue { value: 99 },
        );

        let config = DiagnosticConfig {
            context_before: 3,
            context_after: 2,
            ..DiagnosticConfig::default()
        };

        let report = diagnose_divergence(&trace, &error, &config);

        assert_eq!(report.context_before.len(), 3);
        assert_eq!(report.context_after.len(), 2);
        assert_eq!(report.context_before[0].index, 7);
        assert_eq!(report.context_before[2].index, 9);
        assert_eq!(report.context_after[0].index, 11);
    }

    #[test]
    fn context_window_at_start() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 43 },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            0,
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert!(report.context_before.is_empty());
        assert_eq!(report.context_after.len(), 1);
    }

    #[test]
    fn context_window_at_end() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 43 },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::RngSeed { seed: 43 },
            ReplayEvent::RngSeed { seed: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.context_before.len(), 1);
        assert!(report.context_after.is_empty());
    }

    // -------------------------------------------------------------------------
    // Minimal prefix tests
    // -------------------------------------------------------------------------

    #[test]
    fn minimal_prefix_extraction() {
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 5);
        assert_eq!(prefix.events.len(), 6); // 0..=5
        assert_eq!(prefix.metadata.seed, 42);
    }

    #[test]
    fn minimal_prefix_at_zero() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 0);
        assert_eq!(prefix.events.len(), 1);
    }

    #[test]
    fn minimal_prefix_beyond_trace() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 100);
        assert_eq!(prefix.events.len(), 1); // clamped to trace length
    }

    // -------------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------------

    #[test]
    fn report_serializes_to_json() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
        let json = report.to_json().expect("serialize");

        // Verify JSON is valid and contains key fields
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["category"], "SchedulingOrder");
        assert_eq!(parsed["divergence_index"], 1);
        assert_eq!(parsed["seed"], 42);
    }

    #[test]
    fn report_renders_text() {
        let events = vec![ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        }];
        let trace = make_trace(0xBEEF, events);

        let error = make_error(
            0,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
        let text = report.to_text();

        assert!(text.contains("Replay Divergence Report"));
        assert!(text.contains("scheduling-order"));
        assert!(text.contains("0x000000000000beef"));
        assert!(text.contains("DIVERGENCE"));
    }

    // -------------------------------------------------------------------------
    // Entity extraction tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_task_entities() {
        let affected = extract_affected_entities(
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        assert_eq!(affected.tasks, vec![1, 2]);
        assert!(affected.regions.is_empty());
        assert!(affected.scheduler_lane.is_some());
    }

    #[test]
    fn extract_region_entities() {
        let affected = extract_affected_entities(
            &ReplayEvent::RegionCreated {
                region: CompactRegionId(10),
                parent: Some(CompactRegionId(5)),
                at_tick: 0,
            },
            &ReplayEvent::RegionCreated {
                region: CompactRegionId(10),
                parent: None,
                at_tick: 0,
            },
        );

        assert!(affected.tasks.is_empty());
        assert!(affected.regions.contains(&10));
        assert!(affected.regions.contains(&5));
    }

    #[test]
    fn extract_timer_entities() {
        let affected = extract_affected_entities(
            &ReplayEvent::TimerFired { timer_id: 42 },
            &ReplayEvent::TimerFired { timer_id: 99 },
        );

        assert!(affected.tasks.is_empty());
        assert_eq!(affected.timers, vec![42, 99]);
    }

    // -------------------------------------------------------------------------
    // Event summary tests
    // -------------------------------------------------------------------------

    #[test]
    fn event_summary_from_task_scheduled() {
        let summary = EventSummary::from_event(
            5,
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(42),
                at_tick: 10,
            },
        );

        assert_eq!(summary.index, 5);
        assert_eq!(summary.event_type, "TaskScheduled");
        assert!(summary.details.contains("tick=10"));
        assert_eq!(summary.task_id, Some(42));
        assert_eq!(summary.region_id, None);
    }

    #[test]
    fn event_summary_from_region_created() {
        let summary = EventSummary::from_event(
            0,
            &ReplayEvent::RegionCreated {
                region: CompactRegionId(7),
                parent: None,
                at_tick: 0,
            },
        );

        assert_eq!(summary.event_type, "RegionCreated");
        assert_eq!(summary.region_id, Some(7));
        assert_eq!(summary.task_id, None);
    }
}
