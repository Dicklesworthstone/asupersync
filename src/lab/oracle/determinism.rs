//! Determinism oracle for verifying identical trace reproduction.
//!
//! This oracle verifies the non-negotiable invariant:
//! > Given the same lab configuration (including seed) and the same user program,
//! > the runtime produces the same observable trace.
//!
//! # Usage
//!
//! ```rust,ignore
//! use asupersync::lab::{LabConfig, LabRuntime};
//! use asupersync::lab::oracle::determinism::DeterminismOracle;
//!
//! let config = LabConfig::new(42);
//!
//! // Run a program twice with the same config and verify identical traces
//! let result = DeterminismOracle::verify(config, |runtime| {
//!     // Your test scenario here
//!     runtime.run_until_quiescent();
//! });
//!
//! assert!(result.is_ok(), "Traces should be identical");
//! ```

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
    /// Length of the first trace.
    pub trace1_len: usize,
    /// Length of the second trace.
    pub trace2_len: usize,
}

impl fmt::Display for DeterminismViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Determinism violation at index {}",
            self.divergence_index
        )?;
        writeln!(f, "  First trace length:  {}", self.trace1_len)?;
        writeln!(f, "  Second trace length: {}", self.trace2_len)?;

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

        Ok(())
    }
}

impl std::error::Error for DeterminismViolation {}

/// A summary of a trace event for comparison and display.
///
/// This captures the essential aspects of an event that should be
/// deterministic across runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEventSummary {
    /// Sequence number.
    pub seq: u64,
    /// Time in nanoseconds.
    pub time_nanos: u64,
    /// Kind of event.
    pub kind: TraceEventKind,
    /// Summarized data (for comparison).
    pub data_summary: String,
}

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
    fn summarize_data(data: &TraceData) -> String {
        match data {
            TraceData::None => String::new(),
            TraceData::Task { task, region } => {
                format!("task={task} region={region}")
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
                    summary.push_str(&format!(" duration_ns={duration}"));
                }
                if let Some(reason) = abort_reason {
                    summary.push_str(&format!(" abort_reason={reason}"));
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
            TraceData::Message(msg) => {
                // Truncate long messages for comparison
                if msg.len() > 100 {
                    format!("msg={}...", &msg[..100])
                } else {
                    format!("msg={msg}")
                }
            }
            TraceData::Chaos { kind, task, detail } => {
                let mut summary = format!("chaos={kind}");
                if let Some(t) = task {
                    summary.push_str(&format!(" task={t}"));
                }
                if !detail.is_empty() {
                    summary.push_str(&format!(" detail={detail}"));
                }
                summary
            }
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
/// verifies that the traces are identical.
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
        // First run
        let mut runtime1 = LabRuntime::new(config.clone());
        program(&mut runtime1);
        let trace1: Vec<_> = runtime1
            .trace()
            .iter()
            .map(TraceEventSummary::from_event)
            .collect();

        // Second run with identical config
        let mut runtime2 = LabRuntime::new(config);
        program(&mut runtime2);
        let trace2: Vec<_> = runtime2
            .trace()
            .iter()
            .map(TraceEventSummary::from_event)
            .collect();

        // Compare traces
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

                    return Err(Box::new(DeterminismViolation {
                        divergence_index: i,
                        expected: e1.cloned(),
                        actual: e2.cloned(),
                        context_before,
                        trace1_len: trace1.len(),
                        trace2_len: trace2.len(),
                    }));
                }
            }
        }

        Ok(())
    }
}

/// Convenience function to verify determinism with a simple program.
///
/// This is the easiest way to check if a program is deterministic:
///
/// ```rust,ignore
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
/// Runs the program `runs` times and verifies all traces are identical.
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
    let mut reference = LabRuntime::new(config.clone());
    program(&mut reference);
    let reference_trace: Vec<_> = reference
        .trace()
        .iter()
        .map(TraceEventSummary::from_event)
        .collect();

    let oracle = DeterminismOracle::new();

    // Compare each subsequent run
    for run in 2..=runs {
        let mut runtime = LabRuntime::new(config.clone());
        program(&mut runtime);
        let trace: Vec<_> = runtime
            .trace()
            .iter()
            .map(TraceEventSummary::from_event)
            .collect();

        if let Err(violation) = oracle.compare_traces(&reference_trace, &trace) {
            panic!(
                "Determinism check failed on run {run} of {runs}:\n{violation}\n\n\
                 This indicates non-deterministic behavior in the runtime or program.",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn empty_runtime_is_deterministic() {
        init_test("empty_runtime_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |_runtime| {
            // Do nothing
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_runtime_is_deterministic");
    }

    #[test]
    fn time_advance_is_deterministic() {
        init_test("time_advance_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            runtime.advance_time(1_000_000);
            runtime.advance_time(2_000_000);
            runtime.advance_time(3_000_000);
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("time_advance_is_deterministic");
    }

    #[test]
    fn region_creation_is_deterministic() {
        init_test("region_creation_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            let _root = runtime.state.create_root_region(Budget::INFINITE);
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("region_creation_is_deterministic");
    }

    #[test]
    fn run_until_quiescent_is_deterministic() {
        init_test("run_until_quiescent_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            runtime.run_until_quiescent();
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("run_until_quiescent_is_deterministic");
    }

    #[test]
    fn rng_seeded_deterministically() {
        init_test("rng_seeded_deterministically");
        // Verify that the RNG produces identical sequences
        let config = LabConfig::new(12345);

        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        // Run some steps which consume RNG state
        for _ in 0..100 {
            r1.step_for_test();
        }
        for _ in 0..100 {
            r2.step_for_test();
        }

        // Traces should be identical
        let trace1: Vec<_> = r1
            .trace()
            .iter()
            .map(TraceEventSummary::from_event)
            .collect();
        let trace2: Vec<_> = r2
            .trace()
            .iter()
            .map(TraceEventSummary::from_event)
            .collect();

        let oracle = DeterminismOracle::new();
        let ok = oracle.compare_traces(&trace1, &trace2).is_ok();
        crate::assert_with_log!(ok, "traces ok", true, ok);
        crate::test_complete!("rng_seeded_deterministically");
    }

    #[test]
    fn multi_run_determinism() {
        init_test("multi_run_determinism");
        let config = LabConfig::new(999);
        assert_deterministic_multi(&config, 5, |runtime| {
            runtime.advance_time(1_000);
            runtime.run_until_quiescent();
        });
        crate::test_complete!("multi_run_determinism");
    }

    #[test]
    fn violation_reports_divergence_correctly() {
        init_test("violation_reports_divergence_correctly");
        let oracle = DeterminismOracle::new().context_window(3);

        // Create two traces that diverge
        let trace1 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=hello".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=world".to_string(),
            },
            TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=foo".to_string(),
            },
        ];

        let trace2 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=hello".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=world".to_string(),
            },
            TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=bar".to_string(), // Different!
            },
        ];

        let result = oracle.compare_traces(&trace1, &trace2);
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.divergence_index == 2,
            "divergence_index",
            2,
            violation.divergence_index
        );
        let expected = violation.expected.unwrap().data_summary;
        crate::assert_with_log!(expected == "msg=foo", "expected", "msg=foo", expected);
        let actual = violation.actual.unwrap().data_summary;
        crate::assert_with_log!(actual == "msg=bar", "actual", "msg=bar", actual);
        let ctx_len = violation.context_before.len();
        crate::assert_with_log!(ctx_len == 2, "context len", 2, ctx_len); // Events 0 and 1
        crate::test_complete!("violation_reports_divergence_correctly");
    }

    #[test]
    fn violation_handles_different_lengths() {
        init_test("violation_handles_different_lengths");
        let oracle = DeterminismOracle::new();

        let trace1 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=a".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=b".to_string(),
            },
        ];

        let trace2 = vec![TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=a".to_string(),
        }];

        let result = oracle.compare_traces(&trace1, &trace2);
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.divergence_index == 1,
            "divergence_index",
            1,
            violation.divergence_index
        );
        let expected_some = violation.expected.is_some();
        crate::assert_with_log!(expected_some, "expected some", true, expected_some);
        let actual_none = violation.actual.is_none();
        crate::assert_with_log!(actual_none, "actual none", true, actual_none);
        crate::test_complete!("violation_handles_different_lengths");
    }

    #[test]
    fn trace_event_summary_equality() {
        init_test("trace_event_summary_equality");
        let s1 = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        let s2 = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        crate::assert_with_log!(s1 == s2, "equal", s2.clone(), s1.clone());

        let s3 = TraceEventSummary {
            seq: 1, // Different seq
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        let neq = s1 != s3;
        crate::assert_with_log!(neq, "not equal", true, neq);
        crate::test_complete!("trace_event_summary_equality");
    }
}
