//! Replay and diff utilities for trace analysis.
//!
//! This module provides utilities for:
//! - Replaying a trace to reproduce an execution
//! - Comparing two traces to find divergences
//! - Replay validation with certificate checking
//! - **Trace normalization** for canonical replay ordering
//!
//! # Trace Normalization
//!
//! Use [`normalize_for_replay`] to reorder trace events into a canonical form
//! that minimizes context switches while preserving all happens-before
//! relationships. This is useful for:
//!
//! - Deterministic comparison of equivalent traces
//! - Debugging with reduced interleaving noise
//! - Trace minimization and simplification
//!
//! ```ignore
//! use asupersync::lab::replay::{normalize_for_replay, traces_equivalent};
//!
//! // Normalize a trace
//! let result = normalize_for_replay(&events);
//! println!("{}", result); // Shows switch count reduction
//!
//! // Compare two traces for equivalence
//! if traces_equivalent(&trace_a, &trace_b) {
//!     println!("Traces are equivalent under normalization");
//! }
//! ```

use crate::lab::config::LabConfig;
use crate::lab::runtime::{CrashpackLink, LabRuntime, SporkHarnessReport};
use crate::lab::spork_harness::{ScenarioRunnerError, SporkScenarioConfig, SporkScenarioRunner};
use crate::trace::{TraceBuffer, TraceBufferHandle, TraceEvent};
use std::collections::BTreeMap;

/// Compares two traces and returns the first divergence point.
///
/// Returns `None` if the traces are equivalent.
#[must_use]
pub fn find_divergence(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let a_events = a;
    let b_events = b;

    for (i, (a_event, b_event)) in a_events.iter().zip(b_events.iter()).enumerate() {
        if !events_match(a_event, b_event) {
            return Some(TraceDivergence {
                position: i,
                event_a: (*a_event).clone(),
                event_b: (*b_event).clone(),
            });
        }
    }

    // Check for length mismatch
    if a_events.len() != b_events.len() {
        let position = a_events.len().min(b_events.len());
        #[allow(clippy::map_unwrap_or)]
        return Some(TraceDivergence {
            position,
            event_a: a_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace A>")
                }),
            event_b: b_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace B>")
                }),
        });
    }

    None
}

/// Checks if two events match (ignoring sequence numbers).
fn events_match(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.time == b.time && a.logical_time == b.logical_time && a.data == b.data
}

/// A divergence between two traces.
#[derive(Debug, Clone)]
pub struct TraceDivergence {
    /// Position in the trace where divergence occurred.
    pub position: usize,
    /// Event from trace A at the divergence point.
    pub event_a: TraceEvent,
    /// Event from trace B at the divergence point.
    pub event_b: TraceEvent,
}

impl std::fmt::Display for TraceDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Divergence at position {}:\n  A: {}\n  B: {}",
            self.position, self.event_a, self.event_b
        )
    }
}

/// Summary of a trace for quick comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSummary {
    /// Number of events.
    pub event_count: usize,
    /// Number of spawn events.
    pub spawn_count: usize,
    /// Number of complete events.
    pub complete_count: usize,
    /// Number of cancel events.
    pub cancel_count: usize,
}

impl TraceSummary {
    /// Creates a summary from a trace buffer.
    #[must_use]
    pub fn from_buffer(buffer: &TraceBuffer) -> Self {
        use crate::trace::event::TraceEventKind;

        let mut summary = Self {
            event_count: 0,
            spawn_count: 0,
            complete_count: 0,
            cancel_count: 0,
        };

        for event in buffer.iter() {
            summary.event_count += 1;
            match event.kind {
                TraceEventKind::Spawn => summary.spawn_count += 1,
                TraceEventKind::Complete => summary.complete_count += 1,
                TraceEventKind::CancelRequest | TraceEventKind::CancelAck => {
                    summary.cancel_count += 1;
                }
                _ => {}
            }
        }

        summary
    }
}

/// Result of a replay validation.
#[derive(Debug)]
pub struct ReplayValidation {
    /// Whether the replay matched the original.
    pub matched: bool,
    /// Certificate from the original run.
    pub original_certificate: u64,
    /// Certificate from the replay.
    pub replay_certificate: u64,
    /// First trace divergence (if any).
    pub divergence: Option<TraceDivergence>,
    /// Steps in original.
    pub original_steps: u64,
    /// Steps in replay.
    pub replay_steps: u64,
}

impl ReplayValidation {
    /// True if both certificate and trace matched.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.matched && self.divergence.is_none()
    }
}

impl std::fmt::Display for ReplayValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid() {
            write!(
                f,
                "Replay OK: {} steps, certificate {:#018x}",
                self.replay_steps, self.replay_certificate
            )
        } else {
            write!(f, "Replay DIVERGED:")?;
            if self.original_certificate != self.replay_certificate {
                write!(
                    f,
                    "\n  Certificate mismatch: original={:#018x} replay={:#018x}",
                    self.original_certificate, self.replay_certificate
                )?;
            }
            if let Some(ref div) = self.divergence {
                write!(f, "\n  {div}")?;
            }
            if self.original_steps != self.replay_steps {
                write!(
                    f,
                    "\n  Step count mismatch: original={} replay={}",
                    self.original_steps, self.replay_steps
                )?;
            }
            Ok(())
        }
    }
}

/// Replay a test with the same seed and validate determinism.
///
/// Runs the test twice with the same seed and checks:
/// 1. Schedule certificates match
/// 2. Traces match (no divergence)
/// 3. Step counts match
pub fn validate_replay<F>(seed: u64, worker_count: usize, test: F) -> ReplayValidation
where
    F: Fn(&mut LabRuntime),
{
    let run = |s: u64| -> (u64, u64, TraceBufferHandle) {
        let mut config = LabConfig::new(s);
        config = config.worker_count(worker_count);
        let mut runtime = LabRuntime::new(config);
        test(&mut runtime);
        let steps = runtime.steps();
        let cert = runtime.certificate().hash();
        let trace = runtime.trace().clone();
        (steps, cert, trace)
    };

    let (steps_a, cert_a, trace_a) = run(seed);
    let (steps_b, cert_b, trace_b) = run(seed);

    let events_a = trace_a.snapshot();
    let events_b = trace_b.snapshot();
    let divergence = find_divergence(&events_a, &events_b);
    let matched = cert_a == cert_b && steps_a == steps_b;

    ReplayValidation {
        matched,
        original_certificate: cert_a,
        replay_certificate: cert_b,
        divergence,
        original_steps: steps_a,
        replay_steps: steps_b,
    }
}

/// Validate replay across multiple seeds and report any failures.
pub fn validate_replay_multi<F>(
    seeds: &[u64],
    worker_count: usize,
    test: F,
) -> Vec<ReplayValidation>
where
    F: Fn(&mut LabRuntime),
{
    seeds
        .iter()
        .map(|&seed| validate_replay(seed, worker_count, &test))
        .collect()
}

/// Single seed-run summary for schedule exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical normalized-trace fingerprint for this run.
    pub trace_fingerprint: u64,
}

/// Deterministic fingerprint class produced by exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationFingerprintClass {
    /// Canonical normalized-trace fingerprint.
    pub trace_fingerprint: u64,
    /// Number of runs in this class.
    pub run_count: usize,
    /// Seeds observed in this class (sorted, deduplicated).
    pub seeds: Vec<u64>,
    /// Schedule hashes observed in this class (sorted, deduplicated).
    pub schedule_hashes: Vec<u64>,
}

/// Deterministic schedule-exploration report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationReport {
    /// Per-seed runs in stable order.
    pub runs: Vec<ExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl ExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }
}

/// Per-run deterministic summary for Spork app exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical trace fingerprint for this run.
    pub trace_fingerprint: u64,
    /// Whether all run invariants/oracles passed.
    pub passed: bool,
    /// Crashpack link metadata for failing runs when available.
    pub crashpack_link: Option<CrashpackLink>,
}

/// Deterministic DPOR-style report for Spork app seed exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationReport {
    /// Per-seed run summaries in stable order.
    pub runs: Vec<SporkExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl SporkExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }

    /// Number of failed runs.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.runs.iter().filter(|run| !run.passed).count()
    }

    /// True when every failed run includes crashpack linkage metadata.
    #[must_use]
    pub fn all_failures_linked_to_crashpacks(&self) -> bool {
        self.runs
            .iter()
            .filter(|run| !run.passed)
            .all(|run| run.crashpack_link.is_some())
    }
}

/// Classify run summaries by canonical fingerprint into deterministic classes.
#[must_use]
pub fn classify_fingerprint_classes(
    runs: &[ExplorationRunSummary],
) -> Vec<ExplorationFingerprintClass> {
    let mut grouped: BTreeMap<u64, (usize, Vec<u64>, Vec<u64>)> = BTreeMap::new();

    for run in runs {
        let entry = grouped
            .entry(run.trace_fingerprint)
            .or_insert_with(|| (0, Vec::new(), Vec::new()));
        entry.0 += 1;
        entry.1.push(run.seed);
        entry.2.push(run.schedule_hash);
    }

    grouped
        .into_iter()
        .map(
            |(trace_fingerprint, (run_count, mut seeds, mut schedule_hashes))| {
                seeds.sort_unstable();
                seeds.dedup();
                schedule_hashes.sort_unstable();
                schedule_hashes.dedup();
                ExplorationFingerprintClass {
                    trace_fingerprint,
                    run_count,
                    seeds,
                    schedule_hashes,
                }
            },
        )
        .collect()
}

/// Explore a seed-space and report deterministic canonical fingerprint classes.
///
/// This is a DPOR-style seed exploration helper: each seed produces one schedule
/// and one normalized-trace fingerprint; the report groups equivalent runs.
pub fn explore_seed_space<F>(seeds: &[u64], worker_count: usize, test: F) -> ExplorationReport
where
    F: Fn(&mut LabRuntime),
{
    let mut runs: Vec<ExplorationRunSummary> = seeds
        .iter()
        .map(|&seed| {
            let mut config = LabConfig::new(seed);
            config = config.worker_count(worker_count);
            let mut runtime = LabRuntime::new(config);
            test(&mut runtime);

            let trace_events = runtime.trace().snapshot();
            let normalized = normalize_for_replay(&trace_events);
            let trace_fingerprint =
                crate::trace::canonicalize::trace_fingerprint(&normalized.normalized);

            ExplorationRunSummary {
                seed,
                schedule_hash: runtime.certificate().hash(),
                trace_fingerprint,
            }
        })
        .collect();

    runs.sort_by_key(|run| run.seed);
    let fingerprint_classes = classify_fingerprint_classes(&runs);
    ExplorationReport {
        runs,
        fingerprint_classes,
    }
}

/// Build a deterministic Spork exploration report from completed harness reports.
#[must_use]
pub fn summarize_spork_reports(reports: &[SporkHarnessReport]) -> SporkExplorationReport {
    let mut runs: Vec<SporkExplorationRunSummary> = reports
        .iter()
        .map(|report| {
            let passed = report.passed();
            SporkExplorationRunSummary {
                seed: report.seed(),
                schedule_hash: report.run.trace_certificate.schedule_hash,
                trace_fingerprint: report.trace_fingerprint(),
                passed,
                crashpack_link: if passed {
                    None
                } else {
                    report.crashpack_link()
                },
            }
        })
        .collect();

    runs.sort_by_key(|run| (run.seed, run.schedule_hash, run.trace_fingerprint));

    let class_input: Vec<ExplorationRunSummary> = runs
        .iter()
        .map(|run| ExplorationRunSummary {
            seed: run.seed,
            schedule_hash: run.schedule_hash,
            trace_fingerprint: run.trace_fingerprint,
        })
        .collect();

    SporkExplorationReport {
        runs,
        fingerprint_classes: classify_fingerprint_classes(&class_input),
    }
}

/// Explore a Spork app seed-space and produce a deterministic DPOR-style report.
///
/// The caller provides one harness report per seed (typically by running
/// `SporkAppHarness`/`SporkScenarioRunner` with that seed). The result is
/// grouped by canonical fingerprint class and keeps failure-to-crashpack links.
pub fn explore_spork_seed_space<F>(seeds: &[u64], mut run_for_seed: F) -> SporkExplorationReport
where
    F: FnMut(u64) -> SporkHarnessReport,
{
    let reports: Vec<SporkHarnessReport> = seeds.iter().map(|&seed| run_for_seed(seed)).collect();
    summarize_spork_reports(&reports)
}

/// Run a registered Spork scenario across seeds and return deterministic
/// exploration classes with failure-to-crashpack linkage.
///
/// This is the glue between `SporkScenarioRunner` and DPOR-style exploration:
/// callers provide a scenario id and base config, and this helper handles
/// seed fan-out + deterministic report grouping.
pub fn explore_scenario_runner_seed_space(
    runner: &SporkScenarioRunner,
    scenario_id: &str,
    base_config: &SporkScenarioConfig,
    seeds: &[u64],
) -> Result<SporkExplorationReport, ScenarioRunnerError> {
    let mut reports = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        let mut config = base_config.clone();
        config.seed = seed;
        let result = runner.run_with_config(scenario_id, Some(config))?;
        reports.push(result.report);
    }
    Ok(summarize_spork_reports(&reports))
}

// ============================================================================
// Trace Normalization for Canonical Replay
// ============================================================================

/// Result of trace normalization.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// The normalized (reordered) trace events.
    pub normalized: Vec<TraceEvent>,
    /// Number of owner switches in the original trace.
    pub original_switches: usize,
    /// Number of owner switches after normalization.
    pub normalized_switches: usize,
    /// The algorithm used for normalization.
    pub algorithm: String,
}

impl NormalizationResult {
    /// Returns the reduction in switch count.
    #[must_use]
    pub fn switch_reduction(&self) -> usize {
        self.original_switches
            .saturating_sub(self.normalized_switches)
    }

    /// Returns the switch reduction as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn switch_reduction_pct(&self) -> f64 {
        if self.original_switches == 0 {
            0.0
        } else {
            (self.switch_reduction() as f64 / self.original_switches as f64) * 100.0
        }
    }
}

impl std::fmt::Display for NormalizationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Normalized {} events: {} → {} switches ({:.1}% reduction, {})",
            self.normalized.len(),
            self.original_switches,
            self.normalized_switches,
            self.switch_reduction_pct(),
            self.algorithm
        )
    }
}

/// Normalize a trace for canonical replay ordering.
///
/// This reorders trace events to minimize context switches while preserving
/// all happens-before relationships. The result is a canonical form suitable
/// for:
/// - Deterministic replay comparison
/// - Debugging (reduced noise from interleaving)
/// - Trace minimization
///
/// # Example
///
/// ```ignore
/// use asupersync::lab::replay::normalize_for_replay;
///
/// let events: Vec<TraceEvent> = /* captured trace */;
/// let result = normalize_for_replay(&events);
/// println!("{}", result); // Shows switch reduction
/// ```
#[must_use]
pub fn normalize_for_replay(events: &[TraceEvent]) -> NormalizationResult {
    normalize_for_replay_with_config(events, &crate::trace::GeodesicConfig::default())
}

/// Normalize a trace with custom configuration.
///
/// See [`GeodesicConfig`] for available options:
/// - `beam_threshold`: Trace size above which beam search is used
/// - `beam_width`: Width of beam search
/// - `step_budget`: Maximum search steps
#[must_use]
pub fn normalize_for_replay_with_config(
    events: &[TraceEvent],
    config: &crate::trace::GeodesicConfig,
) -> NormalizationResult {
    let original_switches = crate::trace::trace_switch_cost(events);
    let (normalized, geodesic_result) = crate::trace::normalize_trace(events, config);

    NormalizationResult {
        normalized,
        original_switches,
        normalized_switches: geodesic_result.switch_count,
        algorithm: format!("{:?}", geodesic_result.algorithm),
    }
}

/// Compare two traces for equivalence after normalization.
///
/// Two traces are considered equivalent if their normalized forms produce
/// the same sequence of events (respecting happens-before ordering).
///
/// Returns `None` if the traces are equivalent, or `Some(divergence)` if
/// they differ.
#[must_use]
pub fn compare_normalized(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let norm_a = normalize_for_replay(a);
    let norm_b = normalize_for_replay(b);
    find_divergence(&norm_a.normalized, &norm_b.normalized)
}

/// Check if two traces are equivalent under normalization.
///
/// This is a convenience wrapper around [`compare_normalized`].
#[must_use]
pub fn traces_equivalent(a: &[TraceEvent], b: &[TraceEvent]) -> bool {
    compare_normalized(a, b).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppSpec;
    use crate::lab::SporkScenarioSpec;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Budget;
    use crate::types::Time;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn identical_traces_no_divergence() {
        init_test("identical_traces_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "no divergence", true, ok);
        crate::test_complete!("identical_traces_no_divergence");
    }

    #[test]
    fn trace_seq_only_difference_no_divergence() {
        init_test("trace_seq_only_difference_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];
        let b = vec![TraceEvent::new(
            99,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "seq-only differences ignored", true, ok);
        crate::test_complete!("trace_seq_only_difference_no_divergence");
    }

    #[test]
    fn different_traces_find_divergence() {
        init_test("different_traces_find_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence");
    }

    #[test]
    fn different_traces_find_divergence_data() {
        init_test("different_traces_find_divergence_data");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("a".to_string()),
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("b".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence_data");
    }

    // ── Replay validation tests ─────────────────────────────────────────

    #[test]
    fn replay_single_task_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(42, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().unwrap().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
        assert_eq!(
            validation.original_certificate,
            validation.replay_certificate
        );
        assert_eq!(validation.original_steps, validation.replay_steps);
    }

    #[test]
    fn replay_two_tasks_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock().unwrap();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
    }

    #[test]
    fn replay_multi_seeds_all_deterministic() {
        use crate::types::Budget;
        let seeds: Vec<u64> = (0..10).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().unwrap().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(v.is_valid(), "Seed {} replay failed: {v}", seeds[i]);
        }
    }

    #[test]
    fn replay_validation_display_ok() {
        let v = ReplayValidation {
            matched: true,
            original_certificate: 0x1234,
            replay_certificate: 0x1234,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("Replay OK"));
    }

    #[test]
    fn replay_validation_display_diverged() {
        let v = ReplayValidation {
            matched: false,
            original_certificate: 0x1234,
            replay_certificate: 0x5678,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("DIVERGED"));
        assert!(s.contains("Certificate mismatch"));
    }

    // ── Normalization tests ─────────────────────────────────────────────

    #[test]
    fn normalization_single_owner_no_switches() {
        init_test("normalization_single_owner_no_switches");
        // All events from owner 1 - should have 0 switches
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(2),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];
        // All have seq numbers, but owner extraction uses seq % some_value or similar
        // The trace module should handle this; we're testing the wrapper

        let result = normalize_for_replay(&events);
        // Single-owner trace has no switches before or after
        assert_eq!(result.switch_reduction(), 0);
        crate::test_complete!("normalization_single_owner_no_switches");
    }

    #[test]
    fn normalization_result_display() {
        init_test("normalization_result_display");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 10,
            normalized_switches: 3,
            algorithm: "Greedy".to_string(),
        };

        let display = format!("{result}");
        assert!(display.contains("10 → 3 switches"));
        assert!(display.contains("70.0% reduction"));
        assert!(display.contains("Greedy"));
        crate::test_complete!("normalization_result_display");
    }

    #[test]
    fn normalization_result_zero_switches() {
        init_test("normalization_result_zero_switches");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 0,
            normalized_switches: 0,
            algorithm: "Trivial".to_string(),
        };

        // Avoid division by zero
        let pct = result.switch_reduction_pct();
        assert!((pct - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("normalization_result_zero_switches");
    }

    #[test]
    fn traces_equivalent_identical() {
        init_test("traces_equivalent_identical");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];

        let equivalent = traces_equivalent(&events, &events);
        crate::assert_with_log!(equivalent, "identical traces equivalent", true, equivalent);
        crate::test_complete!("traces_equivalent_identical");
    }

    #[test]
    fn traces_equivalent_ignores_sequence_numbers() {
        init_test("traces_equivalent_ignores_sequence_numbers");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            42,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            equivalent,
            "seq-only differences still equivalent",
            true,
            equivalent
        );
        crate::test_complete!("traces_equivalent_ignores_sequence_numbers");
    }

    #[test]
    fn traces_equivalent_different_kinds() {
        init_test("traces_equivalent_different_kinds");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            !equivalent,
            "different kinds not equivalent",
            false,
            equivalent
        );
        crate::test_complete!("traces_equivalent_different_kinds");
    }

    #[test]
    fn compare_normalized_returns_divergence() {
        init_test("compare_normalized_returns_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let divergence = compare_normalized(&a, &b);
        let has_div = divergence.is_some();
        crate::assert_with_log!(has_div, "divergence found", true, has_div);
        crate::test_complete!("compare_normalized_returns_divergence");
    }

    #[test]
    fn normalize_with_config_custom_beam() {
        use crate::trace::GeodesicConfig;

        init_test("normalize_with_config_custom_beam");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
        ];

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1,
            beam_width: 4,
            step_budget: 100,
        };

        let result = normalize_for_replay_with_config(&events, &config);
        // Just verify it runs without panic; algorithm choice depends on trace size
        assert!(!result.algorithm.is_empty());
        crate::test_complete!("normalize_with_config_custom_beam");
    }

    #[test]
    fn classify_fingerprint_classes_is_deterministic() {
        init_test("classify_fingerprint_classes_is_deterministic");

        let runs = vec![
            ExplorationRunSummary {
                seed: 9,
                schedule_hash: 0xB,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 3,
                schedule_hash: 0xA,
                trace_fingerprint: 0xBB,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
        ];

        let classes = classify_fingerprint_classes(&runs);
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].trace_fingerprint, 0xAA);
        assert_eq!(classes[0].run_count, 3);
        assert_eq!(classes[0].seeds, vec![7, 9]);
        assert_eq!(classes[0].schedule_hashes, vec![0xB, 0xC]);
        assert_eq!(classes[1].trace_fingerprint, 0xBB);
        assert_eq!(classes[1].run_count, 1);
        assert_eq!(classes[1].seeds, vec![3]);
        assert_eq!(classes[1].schedule_hashes, vec![0xA]);

        crate::test_complete!("classify_fingerprint_classes_is_deterministic");
    }

    #[test]
    fn explore_seed_space_is_deterministic_for_same_inputs() {
        init_test("explore_seed_space_is_deterministic_for_same_inputs");

        let seeds = [11_u64, 13_u64, 11_u64];
        let scenario = |runtime: &mut LabRuntime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().unwrap().schedule(task, 0);
            runtime.run_until_quiescent();
        };

        let a = explore_seed_space(&seeds, 1, scenario);
        let b = explore_seed_space(&seeds, 1, scenario);

        assert_eq!(a, b, "same seeds and scenario must produce same report");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        crate::test_complete!("explore_seed_space_is_deterministic_for_same_inputs");
    }

    fn make_spork_report(seed: u64, failing: bool) -> SporkHarnessReport {
        use crate::record::ObligationKind;

        let mut runtime = LabRuntime::with_seed(seed);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task, 0);
        runtime.run_until_quiescent();

        if failing {
            runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task,
                    region,
                    Some("intentional failure for exploration".to_string()),
                )
                .expect("create failing obligation");
        }

        runtime.spork_report("spork_exploration", Vec::new())
    }

    #[test]
    fn summarize_spork_reports_links_failures_to_crashpacks() {
        init_test("summarize_spork_reports_links_failures_to_crashpacks");

        let passing = make_spork_report(31, false);
        let failing = make_spork_report(32, true);

        let summary = summarize_spork_reports(&[failing, passing]);
        assert_eq!(summary.runs.len(), 2);
        assert_eq!(summary.failure_count(), 1);
        assert!(summary.unique_fingerprint_count() >= 1);
        assert!(
            summary.all_failures_linked_to_crashpacks(),
            "failed runs must include crashpack linkage metadata"
        );

        let failed_run = summary
            .runs
            .iter()
            .find(|run| !run.passed)
            .expect("one failing run expected");
        let crashpack = failed_run
            .crashpack_link
            .as_ref()
            .expect("failing run should have crashpack link");
        assert!(
            crashpack.path.starts_with("crashpack-"),
            "unexpected crashpack path: {}",
            crashpack.path
        );

        crate::test_complete!("summarize_spork_reports_links_failures_to_crashpacks");
    }

    #[test]
    fn explore_spork_seed_space_is_deterministic() {
        init_test("explore_spork_seed_space_is_deterministic");

        let seeds = [42_u64, 41_u64, 42_u64];

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let a = explore_spork_seed_space(&seeds, run_for_seed);

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let b = explore_spork_seed_space(&seeds, run_for_seed);

        assert_eq!(a, b, "same seeds must produce deterministic report");
        assert_eq!(a.runs.len(), seeds.len());
        assert_eq!(a.failure_count(), 2);
        assert!(a.unique_fingerprint_count() >= 1);
        assert!(a.all_failures_linked_to_crashpacks());

        crate::test_complete!("explore_spork_seed_space_is_deterministic");
    }

    #[test]
    fn scenario_runner_exploration_has_deterministic_fingerprints() {
        init_test("scenario_runner_exploration_has_deterministic_fingerprints");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("replay.scenario", |_| AppSpec::new("replay_app"))
                    .with_default_config(SporkScenarioConfig::default()),
            )
            .expect("register scenario");

        let base_config = SporkScenarioConfig::default();
        let seeds = [12_u64, 13_u64, 12_u64];

        let a =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration A");
        let b =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration B");

        assert_eq!(a, b, "scenario exploration must be deterministic");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        // Same seed should map to the same fingerprint.
        let seed_12: Vec<_> = a.runs.iter().filter(|run| run.seed == 12).collect();
        assert_eq!(seed_12.len(), 2);
        assert_eq!(seed_12[0].trace_fingerprint, seed_12[1].trace_fingerprint);

        crate::test_complete!("scenario_runner_exploration_has_deterministic_fingerprints");
    }
}
