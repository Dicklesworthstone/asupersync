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
use crate::lab::runtime::LabRuntime;
use crate::trace::{
    normalize_trace, trace_switch_cost, GeodesicConfig, TraceBuffer, TraceBufferHandle, TraceEvent,
};

/// Compares two traces and returns the first divergence point.
///
/// Returns `None` if the traces are equivalent.
#[must_use]
pub fn find_divergence(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let a_events = a;
    let b_events = b;

    for (i, (a_event, b_event)) in a_events.iter().zip(b_events.iter()).enumerate() {
        if a_event.seq != b_event.seq || !events_match(a_event, b_event) {
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
    a.kind == b.kind && a.time == b.time
    // In a full implementation, we'd also compare data
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
        self.original_switches.saturating_sub(self.normalized_switches)
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
    normalize_for_replay_with_config(events, &GeodesicConfig::default())
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
    config: &GeodesicConfig,
) -> NormalizationResult {
    let original_switches = trace_switch_cost(events);
    let (normalized, geodesic_result) = normalize_trace(events, config);

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
    use crate::trace::event::{TraceData, TraceEventKind};
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
            TraceEvent::new(1, Time::from_nanos(0), TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(2, Time::from_nanos(1), TraceEventKind::Poll, TraceData::None),
            TraceEvent::new(3, Time::from_nanos(2), TraceEventKind::Complete, TraceData::None),
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
            TraceEvent::new(1, Time::from_nanos(0), TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(2, Time::from_nanos(1), TraceEventKind::Complete, TraceData::None),
        ];

        let equivalent = traces_equivalent(&events, &events);
        crate::assert_with_log!(equivalent, "identical traces equivalent", true, equivalent);
        crate::test_complete!("traces_equivalent_identical");
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
        crate::assert_with_log!(!equivalent, "different kinds not equivalent", false, equivalent);
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
            TraceEvent::new(1, Time::from_nanos(0), TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(2, Time::from_nanos(1), TraceEventKind::Poll, TraceData::None),
        ];

        let config = GeodesicConfig {
            beam_threshold: 1,
            beam_width: 4,
            step_budget: 100,
        };

        let result = normalize_for_replay_with_config(&events, &config);
        // Just verify it runs without panic; algorithm choice depends on trace size
        assert!(!result.algorithm.is_empty());
        crate::test_complete!("normalize_with_config_custom_beam");
    }
}
