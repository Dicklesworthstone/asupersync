//! Determinism oracle for verifying identical trace reproduction.
//!
//! This oracle verifies the non-negotiable invariant:
//! > Given the same lab configuration (including seed) and the same user program,
//! > the runtime produces the same observable trace.
//!
//! # Usage
//!
//! ```rust
//! use asupersync::lab::{LabConfig, LabRuntime};
//! use asupersync::lab::oracle::determinism::DeterminismOracle;
//!
//! let config = LabConfig::new(42);
//!
//! // Run a program twice with the same config and verify identical traces
//! let result = DeterminismOracle::new().verify(config, |runtime: &mut LabRuntime| {
//!     // Your test scenario here
//!     runtime.run_until_quiescent();
//! });
//!
//! assert!(result.is_ok(), "Traces should be identical");
//! ```
//!
//! [`assert_deterministic`] does the same and panics with the first divergence.

use crate::lab::{LabConfig, LabRuntime};
use crate::trace::event::TraceEventKind;
use crate::trace::{TraceData, TraceEvent};
use core::fmt;

/// A violation of the determinism invariant.
///
/// This is produced when two executions with identical configuration
/// produce different traces.
#[derive(Debug, Clone)]
pub struct DeterminismViolation {
    /// Index of the first diverging event.
    pub divergence_index: usize,
    /// The event from the first run (or None if trace1 was shorter).
    pub expected: Option<TraceEventSummary>,
    /// The event from the second run (or None if trace2 was shorter).
    pub actual: Option<TraceEventSummary>,
    /// Context: events before divergence from the first trace.
    pub context_before: Vec<TraceEventSummary>,
    /// Expected events immediately after the divergence point.
    pub context_after_expected: Vec<TraceEventSummary>,
    /// Actual events immediately after the divergence point.
    pub context_after_actual: Vec<TraceEventSummary>,
    /// Best-effort source hint for the nondeterminism checklist.
    pub source_hint: DeterminismSourceHint,
    /// Length of the first trace.
    pub trace1_len: usize,
    /// Length of the second trace.
    pub trace2_len: usize,
}

/// Best-effort source hint for a same-seed determinism failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeterminismSourceHint {
    /// A virtual-time or timer event diverged.
    AmbientClock,
    /// A deterministic RNG event diverged.
    AmbientEntropy,
    /// A scheduling, wakeup, I/O, or chaos event changed ordering.
    SchedulerOrdering,
    /// User trace payloads differ; inspect the code that emitted them.
    UserTrace,
    /// One run ended before the other.
    TraceLength,
    /// The event shape is not specific enough for a narrower hint.
    Unknown,
}

impl DeterminismSourceHint {
    /// Stable diagnostic code for same-seed lab nondeterminism.
    pub const ERROR_CODE: &'static str = "ASUP-E403";

    /// Checklist token agents can search for in docs and closeout notes.
    #[must_use]
    pub const fn checklist_item(self) -> &'static str {
        match self {
            Self::AmbientClock => "determinism.checklist.ambient-clock",
            Self::AmbientEntropy => "determinism.checklist.ambient-entropy",
            Self::SchedulerOrdering => "determinism.checklist.scheduler-ordering",
            Self::UserTrace => "determinism.checklist.user-trace",
            Self::TraceLength => "determinism.checklist.trace-length",
            Self::Unknown => "determinism.checklist.inspect-first-divergence",
        }
    }

    /// Human-readable explanation for the hint.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::AmbientClock => {
                "virtual time or timer behavior changed; check wall-clock reads and deadlines"
            }
            Self::AmbientEntropy => {
                "deterministic RNG behavior changed; check ambient entropy and extra RNG calls"
            }
            Self::SchedulerOrdering => {
                "scheduler-visible ordering changed; check readiness, wakeups, I/O, and chaos paths"
            }
            Self::UserTrace => {
                "user trace payloads changed; inspect the code that emitted the trace event"
            }
            Self::TraceLength => "one trace ended early; check leaked or extra runtime activity",
            Self::Unknown => "inspect the first divergent event and surrounding context",
        }
    }

    fn for_divergence(
        expected: Option<&TraceEventSummary>,
        actual: Option<&TraceEventSummary>,
    ) -> Self {
        let Some(expected) = expected else {
            return Self::TraceLength;
        };
        let Some(actual) = actual else {
            return Self::TraceLength;
        };

        match (expected.kind, actual.kind) {
            (
                TraceEventKind::TimeAdvance
                | TraceEventKind::TimerScheduled
                | TraceEventKind::TimerFired
                | TraceEventKind::TimerCancelled,
                _,
            )
            | (
                _,
                TraceEventKind::TimeAdvance
                | TraceEventKind::TimerScheduled
                | TraceEventKind::TimerFired
                | TraceEventKind::TimerCancelled,
            ) => Self::AmbientClock,

            (TraceEventKind::RngSeed | TraceEventKind::RngValue, _)
            | (_, TraceEventKind::RngSeed | TraceEventKind::RngValue) => Self::AmbientEntropy,

            (
                TraceEventKind::Schedule
                | TraceEventKind::Wake
                | TraceEventKind::IoRequested
                | TraceEventKind::IoReady
                | TraceEventKind::IoResult
                | TraceEventKind::IoError
                | TraceEventKind::ChaosInjection,
                _,
            )
            | (
                _,
                TraceEventKind::Schedule
                | TraceEventKind::Wake
                | TraceEventKind::IoRequested
                | TraceEventKind::IoReady
                | TraceEventKind::IoResult
                | TraceEventKind::IoError
                | TraceEventKind::ChaosInjection,
            ) => Self::SchedulerOrdering,

            (TraceEventKind::UserTrace, TraceEventKind::UserTrace) => Self::UserTrace,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for DeterminismViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "[{}] Determinism violation at index {}",
            DeterminismSourceHint::ERROR_CODE,
            self.divergence_index
        )?;
        writeln!(f, "  First trace length:  {}", self.trace1_len)?;
        writeln!(f, "  Second trace length: {}", self.trace2_len)?;
        writeln!(
            f,
            "  Likely source: {} ({})",
            self.source_hint.checklist_item(),
            self.source_hint.description()
        )?;

        if let Some(ref expected) = self.expected {
            writeln!(f, "  Expected: {expected}")?;
        } else {
            writeln!(f, "  Expected: <end of trace>")?;
        }

        if let Some(ref actual) = self.actual {
            writeln!(f, "  Actual:   {actual}")?;
        } else {
            writeln!(f, "  Actual:   <end of trace>")?;
        }

        if !self.context_before.is_empty() {
            writeln!(
                f,
                "\n  Context (last {} events before divergence):",
                self.context_before.len()
            )?;
            for (i, event) in self.context_before.iter().enumerate() {
                let idx = self
                    .divergence_index
                    .saturating_sub(self.context_before.len() - i);
                writeln!(f, "    [{idx:04}] {event}")?;
            }
        }

        if !self.context_after_expected.is_empty() {
            writeln!(
                f,
                "\n  Expected context after divergence (next {} events):",
                self.context_after_expected.len()
            )?;
            for (i, event) in self.context_after_expected.iter().enumerate() {
                let idx = self.divergence_index + 1 + i;
                writeln!(f, "    [{idx:04}] {event}")?;
            }
        }

        if !self.context_after_actual.is_empty() {
            writeln!(
                f,
                "\n  Actual context after divergence (next {} events):",
                self.context_after_actual.len()
            )?;
            for (i, event) in self.context_after_actual.iter().enumerate() {
                let idx = self.divergence_index + 1 + i;
                writeln!(f, "    [{idx:04}] {event}")?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for DeterminismViolation {}

/// A summary of a trace event for comparison and display.
///
/// This captures the essential aspects of an event that should be
/// deterministic across runs.
#[derive(Debug, Clone)]
pub struct TraceEventSummary {
    /// Sequence number.
    pub seq: u64,
    /// Time in nanoseconds (for display only, not comparison).
    pub time_nanos: u64,
    /// Kind of event.
    pub kind: TraceEventKind,
    /// Summarized data (for comparison).
    pub data_summary: String,
}

/// Custom equality implementation that excludes timing for determinism.
///
/// Time is excluded from comparison because nanosecond-precision timing
/// can vary under chaos injection, making deterministic oracles flaky.
/// Only logical sequence (seq), event kind, and data matter for determinism.
impl PartialEq for TraceEventSummary {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.kind == other.kind && self.data_summary == other.data_summary
    }
}

impl Eq for TraceEventSummary {}

impl TraceEventSummary {
    /// Creates a summary from a trace event.
    #[must_use]
    pub fn from_event(event: &TraceEvent) -> Self {
        Self {
            seq: event.seq,
            time_nanos: event.time.as_nanos(),
            kind: event.kind,
            data_summary: Self::summarize_data(&event.data),
        }
    }

    /// Summarizes trace data for comparison.
    #[allow(clippy::too_many_lines)]
    fn summarize_data(data: &TraceData) -> String {
        use std::fmt::Write;

        match data {
            TraceData::None => String::new(),
            TraceData::Task { task, region } => {
                format!("task={task} region={region}")
            }
            TraceData::Budget {
                task,
                region,
                protocol,
                source,
                outcome,
                ..
            } => {
                format!(
                    "budget task={task} region={region} protocol={protocol} source={source:?} outcome={outcome:?}"
                )
            }
            TraceData::Region { region, parent } => parent.as_ref().map_or_else(
                || format!("region={region} parent=None"),
                |p| format!("region={region} parent={p}"),
            ),
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                let mut summary = format!(
                    "obligation={obligation} task={task} region={region} kind={kind:?} state={state:?}"
                );
                if let Some(duration) = duration_ns {
                    let _ = write!(summary, " duration_ns={duration}");
                }
                if let Some(reason) = abort_reason {
                    let _ = write!(summary, " abort_reason={reason}");
                }
                summary
            }
            TraceData::Cancel {
                task,
                region,
                reason,
            } => {
                format!("task={task} region={region} reason={reason}")
            }
            TraceData::Time { old, new } => {
                format!("old={old} new={new}")
            }
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                format!(
                    "task={task} region={region} idle={idle_steps} held_count={}",
                    held.len()
                )
            }
            // The whole message: a prefix compared runs that differed after
            // it as equal, and cutting at a byte offset panicked inside a
            // multi-byte character.
            TraceData::Message(msg) => format!("msg={msg}"),
            TraceData::Chaos { kind, task, detail } => {
                let mut summary = format!("chaos={kind}");
                if let Some(t) = task {
                    let _ = write!(summary, " task={t}");
                }
                if !detail.is_empty() {
                    let _ = write!(summary, " detail={detail}");
                }
                summary
            }
            TraceData::RegionCancel { region, reason } => {
                format!("region={region} reason={reason}")
            }
            TraceData::Timer { timer_id, deadline } => deadline.map_or_else(
                || format!("timer={timer_id}"),
                |d| format!("timer={timer_id} deadline={d}"),
            ),
            TraceData::IoRequested { token, interest } => {
                format!("io_token={token} interest={interest:#x}")
            }
            TraceData::IoReady { token, readiness } => {
                format!("io_token={token} readiness={readiness:#x}")
            }
            TraceData::IoResult { token, bytes } => {
                format!("io_token={token} bytes={bytes}")
            }
            TraceData::IoError { token, kind } => {
                format!("io_token={token} error_kind={kind}")
            }
            TraceData::RngSeed { seed } => {
                format!("seed={seed}")
            }
            TraceData::RngValue { value } => {
                format!("rng_value={value}")
            }
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            } => {
                format!("seq={sequence} tasks={active_tasks} regions={active_regions}")
            }
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            } => format!(
                "monitor_ref={monitor_ref} watcher={watcher} watcher_region={watcher_region} monitored={monitored}"
            ),
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            } => format!(
                "down monitor_ref={monitor_ref} watcher={watcher} monitored={monitored} completion_vt={completion_vt} reason={reason}"
            ),
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            } => format!(
                "link_ref={link_ref} a={task_a} region_a={region_a} b={task_b} region_b={region_b}"
            ),
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            } => format!(
                "exit link_ref={link_ref} from={from} to={to} failure_vt={failure_vt} reason={reason}"
            ),
            TraceData::Worker {
                worker_id,
                job_id,
                decision_seq,
                replay_hash,
                task,
                region,
                obligation,
            } => format!(
                "worker={worker_id} job_id={job_id} decision_seq={decision_seq} replay_hash={replay_hash} task={task} region={region} obligation={obligation}"
            ),
        }
    }
}

impl fmt::Display for TraceEventSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seq={} time={} kind={:?}",
            self.seq, self.time_nanos, self.kind
        )?;
        if !self.data_summary.is_empty() {
            write!(f, " {}", self.data_summary)?;
        }
        Ok(())
    }
}

/// Oracle for verifying deterministic execution.
///
/// This oracle runs a program twice with identical configuration and
/// verifies that the traces are identical. When the first run records more
/// events than the configured trace buffer keeps, the program runs once more
/// with a buffer that holds them all, so the comparison covers the whole
/// trace and not only the buffer's newest events.
#[derive(Debug, Default)]
pub struct DeterminismOracle {
    /// Number of context events to include before divergence.
    context_window: usize,
}

impl DeterminismOracle {
    /// Creates a new determinism oracle with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self { context_window: 5 }
    }

    /// Sets the context window size (events shown before divergence).
    #[must_use]
    pub fn context_window(mut self, size: usize) -> Self {
        self.context_window = size;
        self
    }

    /// Verifies that a program produces identical traces when run twice.
    ///
    /// # Arguments
    ///
    /// * `config` - The lab configuration (includes seed).
    /// * `program` - A closure that runs the program on the provided runtime.
    ///
    /// # Returns
    ///
    /// `Ok(())` if traces are identical, `Err(DeterminismViolation)` otherwise.
    pub fn verify<F>(&self, config: LabConfig, program: F) -> Result<(), Box<DeterminismViolation>>
    where
        F: Fn(&mut LabRuntime),
    {
        let (config, trace1) = capture_reference(config, &program);
        // Second run with the config the reference was captured under
        let (trace2, _) = run_and_summarize(&config, &program);
        self.compare_traces(&trace1, &trace2)
    }

    /// Compares two trace summaries and returns a violation if they differ.
    fn compare_traces(
        &self,
        trace1: &[TraceEventSummary],
        trace2: &[TraceEventSummary],
    ) -> Result<(), Box<DeterminismViolation>> {
        let max_len = trace1.len().max(trace2.len());

        for i in 0..max_len {
            let e1 = trace1.get(i);
            let e2 = trace2.get(i);

            match (e1, e2) {
                (Some(ev1), Some(ev2)) if ev1 == ev2 => {}
                (e1, e2) => {
                    // Divergence found
                    let context_start = i.saturating_sub(self.context_window);
                    let context_before = trace1[context_start..i].to_vec();
                    let after_start1 = i.saturating_add(1).min(trace1.len());
                    let after_start2 = i.saturating_add(1).min(trace2.len());
                    let context_end1 = after_start1
                        .saturating_add(self.context_window)
                        .min(trace1.len());
                    let context_end2 = after_start2
                        .saturating_add(self.context_window)
                        .min(trace2.len());

                    return Err(Box::new(DeterminismViolation {
                        divergence_index: i,
                        expected: e1.cloned(),
                        actual: e2.cloned(),
                        context_before,
                        context_after_expected: trace1[after_start1..context_end1].to_vec(),
                        context_after_actual: trace2[after_start2..context_end2].to_vec(),
                        source_hint: DeterminismSourceHint::for_divergence(e1, e2),
                        trace1_len: trace1.len(),
                        trace2_len: trace2.len(),
                    }));
                }
            }
        }

        Ok(())
    }
}

/// The most events a re-run keeps when a program's trace overflows the
/// configured buffer (see [`capture_reference`]).
const FULL_TRACE_EVENT_LIMIT: u64 = 1 << 20;

/// Runs `program` on a fresh runtime built from `config`. Returns the
/// summaries of the events its trace buffer kept and the number of events it
/// recorded, kept or evicted.
fn run_and_summarize<F>(config: &LabConfig, program: &F) -> (Vec<TraceEventSummary>, u64)
where
    F: Fn(&mut LabRuntime),
{
    let mut runtime = LabRuntime::new(config.clone());
    program(&mut runtime);
    let trace = runtime.trace();
    let summaries = trace
        .snapshot()
        .into_iter()
        .map(|e| TraceEventSummary::from_event(&e))
        .collect();
    (summaries, trace.total_pushed())
}

/// Runs `program` once for the reference trace. Returns the config the runs
/// compared against it must use, and the trace.
///
/// The trace buffer keeps only the newest `trace_capacity` events, so two
/// overflowed buffers compared only their newest events: runs that diverged
/// and converged again passed. A first run that overflowed is repeated with a
/// buffer that holds every event it recorded (up to
/// [`FULL_TRACE_EVENT_LIMIT`]), and that config is returned.
fn capture_reference<F>(config: LabConfig, program: &F) -> (LabConfig, Vec<TraceEventSummary>)
where
    F: Fn(&mut LabRuntime),
{
    let (trace, recorded) = run_and_summarize(&config, program);
    let kept = u64::try_from(trace.len()).unwrap_or(u64::MAX);
    if recorded <= kept || recorded > FULL_TRACE_EVENT_LIMIT {
        return (config, trace);
    }
    let Ok(capacity) = usize::try_from(recorded) else {
        return (config, trace);
    };
    let config = config.trace_capacity(capacity);
    let (trace, _) = run_and_summarize(&config, program);
    (config, trace)
}

/// Convenience function to verify determinism with a simple program.
///
/// This is the easiest way to check if a program is deterministic:
///
/// ```rust
/// use asupersync::lab::oracle::determinism::assert_deterministic;
/// use asupersync::lab::LabConfig;
///
/// assert_deterministic(LabConfig::new(42), |runtime| {
///     // Your test scenario
///     runtime.run_until_quiescent();
/// });
/// ```
///
/// # Panics
///
/// Panics if the traces differ between runs.
pub fn assert_deterministic<F>(config: LabConfig, program: F)
where
    F: Fn(&mut LabRuntime),
{
    let oracle = DeterminismOracle::new();
    if let Err(violation) = oracle.verify(config, program) {
        panic!(
            "Determinism check failed:\n{violation}\n\n\
             This indicates non-deterministic behavior in the runtime or program.",
        );
    }
}

/// Convenience function to verify determinism with multiple runs.
///
/// Runs the program `runs` times and verifies all traces are identical. As
/// in [`DeterminismOracle::verify`], a first run that overflows the trace
/// buffer is repeated with a buffer that holds every event.
///
/// # Panics
///
/// Panics if any trace differs from the first.
pub fn assert_deterministic_multi<F>(config: &LabConfig, runs: usize, program: F)
where
    F: Fn(&mut LabRuntime),
{
    assert!(runs >= 2, "Need at least 2 runs to verify determinism");

    // Capture the reference trace from the first run
    let (config, reference_trace) = capture_reference(config.clone(), &program);

    let oracle = DeterminismOracle::new();

    // Compare each subsequent run
    for run in 2..=runs {
        let (trace, _) = run_and_summarize(&config, &program);

        if let Err(violation) = oracle.compare_traces(&reference_trace, &trace) {
            panic!(
                "Determinism check failed on run {run} of {runs}:\n{violation}\n\n\
                 This indicates non-deterministic behavior in the runtime or program.",
            );
        }
    }
}

/// Verifies determinism across a set of fixed seeds.
///
/// Each seed is run twice with [`LabConfig::new`]. The helper panics on
/// the first divergent seed and includes the seed plus the first-divergence
/// report in the panic text.
///
/// # Panics
///
/// Panics when `seeds` is empty or any seed produces divergent traces.
pub fn assert_deterministic_for_seeds<I, F>(seeds: I, program: F)
where
    I: IntoIterator<Item = u64>,
    F: Fn(&mut LabRuntime),
{
    let oracle = DeterminismOracle::new();
    let mut saw_seed = false;

    for seed in seeds {
        saw_seed = true;
        let config = LabConfig::new(seed);
        if let Err(violation) = oracle.verify(config, &program) {
            panic!(
                "Determinism check failed for seed {seed}:\n{violation}\n\n\
                 This indicates same-seed nondeterminism in the runtime or program.",
            );
        }
    }

    assert!(saw_seed, "Need at least one seed to verify determinism");
}

#[cfg(test)]
#[path = "determinism_inline_tests.rs"]
mod tests;
