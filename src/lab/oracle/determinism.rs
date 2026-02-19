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
    #[allow(clippy::too_many_lines)]
    fn summarize_data(data: &TraceData) -> String {
        use std::fmt::Write;

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
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
            .collect();

        // Second run with identical config
        let mut runtime2 = LabRuntime::new(config);
        program(&mut runtime2);
        let trace2: Vec<_> = runtime2
            .trace()
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
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
        .snapshot()
        .into_iter()
        .map(|e| TraceEventSummary::from_event(&e))
        .collect();

    let oracle = DeterminismOracle::new();

    // Compare each subsequent run
    for run in 2..=runs {
        let mut runtime = LabRuntime::new(config.clone());
        program(&mut runtime);
        let trace: Vec<_> = runtime
            .trace()
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
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
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
            .collect();
        let trace2: Vec<_> = r2
            .trace()
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
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

        crate::assert_with_log!(s1 == s2, "equal", s2, s1);

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

    #[test]
    fn determinism_violation_debug_clone() {
        init_test("determinism_violation_debug_clone");
        let v = DeterminismViolation {
            divergence_index: 5,
            expected: None,
            actual: None,
            context_before: vec![],
            trace1_len: 10,
            trace2_len: 8,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("DeterminismViolation"));
        let v2 = v.clone();
        assert_eq!(v2.divergence_index, 5);
        assert_eq!(v2.trace1_len, 10);
        assert_eq!(v2.trace2_len, 8);
        crate::test_complete!("determinism_violation_debug_clone");
    }

    #[test]
    fn determinism_violation_display_both_none() {
        init_test("determinism_violation_display_both_none");
        let v = DeterminismViolation {
            divergence_index: 0,
            expected: None,
            actual: None,
            context_before: vec![],
            trace1_len: 0,
            trace2_len: 0,
        };
        let display = format!("{v}");
        assert!(display.contains("Determinism violation at index 0"));
        assert!(display.contains("<end of trace>"));
        crate::test_complete!("determinism_violation_display_both_none");
    }

    #[test]
    fn determinism_violation_display_with_events() {
        init_test("determinism_violation_display_with_events");
        let v = DeterminismViolation {
            divergence_index: 3,
            expected: Some(TraceEventSummary {
                seq: 3,
                time_nanos: 300,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=expected".into(),
            }),
            actual: Some(TraceEventSummary {
                seq: 3,
                time_nanos: 300,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=actual".into(),
            }),
            context_before: vec![TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=context".into(),
            }],
            trace1_len: 5,
            trace2_len: 5,
        };
        let display = format!("{v}");
        assert!(display.contains("index 3"));
        assert!(display.contains("Expected:"));
        assert!(display.contains("Actual:"));
        assert!(display.contains("Context"));
        crate::test_complete!("determinism_violation_display_with_events");
    }

    #[test]
    fn determinism_violation_is_error() {
        init_test("determinism_violation_is_error");
        let v = DeterminismViolation {
            divergence_index: 0,
            expected: None,
            actual: None,
            context_before: vec![],
            trace1_len: 0,
            trace2_len: 0,
        };
        // Verify it implements std::error::Error
        let err: &dyn std::error::Error = &v;
        let display = format!("{err}");
        assert!(display.contains("Determinism violation"));
        crate::test_complete!("determinism_violation_is_error");
    }

    #[test]
    fn trace_event_summary_debug_clone() {
        init_test("trace_event_summary_debug_clone");
        let s = TraceEventSummary {
            seq: 42,
            time_nanos: 1000,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0)".into(),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TraceEventSummary"));
        let s2 = s.clone();
        assert_eq!(s2.seq, 42);
        assert_eq!(s2.time_nanos, 1000);
        assert_eq!(s2.data_summary, "task=Task(0)");
        crate::test_complete!("trace_event_summary_debug_clone");
    }

    #[test]
    fn trace_event_summary_display() {
        init_test("trace_event_summary_display");
        let s = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=hello".into(),
        };
        let display = format!("{s}");
        assert!(display.contains("seq=0"));
        assert!(display.contains("time=100"));
        assert!(display.contains("msg=hello"));
        crate::test_complete!("trace_event_summary_display");
    }

    #[test]
    fn trace_event_summary_display_empty_data() {
        init_test("trace_event_summary_display_empty_data");
        let s = TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: String::new(),
        };
        let display = format!("{s}");
        assert!(display.contains("seq=0"));
        // Empty data should not add extra content
        assert!(!display.contains("  "));
        crate::test_complete!("trace_event_summary_display_empty_data");
    }

    #[test]
    fn determinism_oracle_debug_default() {
        init_test("determinism_oracle_debug_default");
        let oracle = DeterminismOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("DeterminismOracle"));
        crate::test_complete!("determinism_oracle_debug_default");
    }

    #[test]
    fn determinism_oracle_context_window_builder() {
        init_test("determinism_oracle_context_window_builder");
        let oracle = DeterminismOracle::new().context_window(10);
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("10"));
        crate::test_complete!("determinism_oracle_context_window_builder");
    }

    #[test]
    fn determinism_oracle_identical_traces_ok() {
        init_test("determinism_oracle_identical_traces_ok");
        let oracle = DeterminismOracle::new();
        let trace = vec![TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=test".into(),
        }];
        let result = oracle.compare_traces(&trace, &trace);
        assert!(result.is_ok());
        crate::test_complete!("determinism_oracle_identical_traces_ok");
    }

    #[test]
    fn determinism_oracle_empty_traces_ok() {
        init_test("determinism_oracle_empty_traces_ok");
        let oracle = DeterminismOracle::new();
        let result = oracle.compare_traces(&[], &[]);
        assert!(result.is_ok());
        crate::test_complete!("determinism_oracle_empty_traces_ok");
    }
}
