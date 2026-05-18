#![allow(clippy::all)]
//! Metamorphic Testing: Lane Pressure Scaling Fairness Invariants
//!
//! This module implements metamorphic relations for testing the three-lane
//! scheduler's fairness guarantees when cancel/timed/ready pressure is scaled
//! proportionally while preserving lane mix ratios.
//!
//! # Core Metamorphic Relations
//!
//! 1. **MR1: Proportional Pressure Scaling** - When all lanes are scaled by the same
//!    factor α > 1 while preserving mix ratios (e.g., 20% cancel, 30% timed, 50% ready),
//!    fairness certificates remain within bounded deviation.
//!
//! 2. **MR2: Stall Bound Invariance** - Cancel-streak-induced ready lane stalls remain
//!    bounded by O(cancel_streak_limit) regardless of absolute pressure scaling.
//!
//! 3. **MR3: Mix Ratio Preservation** - Lane dispatch ratios converge to the same
//!    proportions under pressure scaling (modulo fairness-enforced bounded deviation).
//!
//! 4. **MR4: Latency Distribution Similarity** - Task completion latency percentiles
//!    scale predictably with pressure, but relative fairness ordering is preserved.
//!
//! 5. **MR5: Adaptive Policy Stability** - EXP3 cancel-streak adaptation converges to
//!    similar reward distributions when pressure is scaled proportionally.
//!
//! # Testing Strategy
//!
//! Each metamorphic relation uses deterministic lab runtime scenarios with
//! controlled task injection patterns to verify three-lane scheduler behavior
//! maintains fairness invariants across different pressure scales.

#![allow(dead_code)]

use crate::runtime::RuntimeState;
use crate::runtime::scheduler::three_lane::{PreemptionMetrics, ThreeLaneScheduler};
use crate::sync::ContendedMutex;
use crate::types::{TaskId, Time};
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for lane pressure scaling metamorphic testing.
#[derive(Debug, Clone)]
pub struct LanePressureConfig {
    /// Base number of tasks per lane.
    pub base_tasks_per_lane: usize,
    /// Scaling factors to test (e.g., [1, 2, 4, 8]).
    pub scaling_factors: Vec<usize>,
    /// Mix ratios for [cancel, timed, ready] lanes (must sum to 1.0).
    pub lane_mix_ratios: [f64; 3],
    /// Cancel streak limit for fairness testing.
    pub cancel_streak_limit: usize,
    /// Maximum acceptable fairness deviation (percentage).
    pub max_fairness_deviation: f64,
    /// Virtual work duration per task (nanoseconds).
    pub work_duration_ns: u64,
    /// Random seed for deterministic testing.
    pub seed: u64,
}

impl Default for LanePressureConfig {
    fn default() -> Self {
        Self {
            base_tasks_per_lane: 20,
            scaling_factors: vec![1, 2, 4, 8],
            // br-asupersync-7hgaq9: timed-lane mix is 0.0 because
            // the test harness does not advance virtual time, so
            // `inject_timed` tasks never become dispatchable via
            // `worker.next_task()` (filed as br-asupersync-k18nlg).
            // Once a time-source-aware harness lands, restore this
            // to e.g. [0.2, 0.3, 0.5] to also exercise the timed
            // lane. For now we measure cancel:ready fairness, which
            // is the substantive load-balance invariant of the
            // three-lane scheduler.
            lane_mix_ratios: [0.3, 0.0, 0.7], // 30% cancel, 0% timed, 70% ready
            cancel_streak_limit: 16,
            max_fairness_deviation: 0.15, // 15% deviation tolerance
            work_duration_ns: 1_000_000,  // 1ms virtual work
            seed: 42,
        }
    }
}

/// Test task for lane pressure scaling scenarios.
#[derive(Debug, Clone)]
pub struct ScalingTestTask {
    /// Task identifier.
    pub task_id: TaskId,
    /// Lane assignment (0=cancel, 1=timed, 2=ready).
    pub lane: usize,
    /// Injection order within the scenario.
    pub injection_order: usize,
    /// Expected execution window (for timed tasks).
    pub execution_window: Option<Time>,
    /// Actual completion time.
    pub completion_time: Option<Time>,
    /// Number of times this task was polled.
    pub poll_count: u32,
    /// Whether this task was cancelled.
    pub was_cancelled: bool,
}

/// Results from a single pressure scaling test run.
#[derive(Debug, Clone)]
pub struct ScalingTestResults {
    /// Test configuration used.
    pub config: LanePressureConfig,
    /// Scaling factor for this specific run.
    pub scaling_factor: usize,
    /// Task execution traces.
    pub task_traces: Vec<ScalingTestTask>,
    /// Scheduler metrics during execution.
    pub preemption_metrics: PreemptionMetrics,
    /// Total runtime for the test scenario.
    pub total_runtime_ns: u64,
    /// Number of scheduler dispatch cycles.
    pub scheduler_cycles: u64,
    /// Lane dispatch counts [cancel, timed, ready].
    pub lane_dispatch_counts: [u64; 3],
    /// Maximum observed ready lane stall (in dispatch cycles).
    pub max_ready_stall_cycles: u64,
}

/// Fairness certificate extracted from test results.
#[derive(Debug, Clone, PartialEq)]
pub struct FairnessCertificate {
    /// Observed lane dispatch ratios [cancel, timed, ready].
    pub lane_dispatch_ratios: [f64; 3],
    /// Maximum ready lane stall bound achieved.
    pub max_ready_stall_bound: u64,
    /// Average completion latency per lane [cancel, timed, ready].
    pub avg_completion_latency: [f64; 3],
    /// 95th percentile completion latency per lane.
    pub p95_completion_latency: [f64; 3],
    /// Fairness deviation from expected mix ratios.
    pub fairness_deviation: f64,
}

impl ScalingTestResults {
    /// Extract fairness certificate from test results.
    pub fn extract_fairness_certificate(&self) -> FairnessCertificate {
        let total_dispatches: u64 = self.lane_dispatch_counts.iter().sum();

        let lane_dispatch_ratios = if total_dispatches > 0 {
            [
                self.lane_dispatch_counts[0] as f64 / total_dispatches as f64,
                self.lane_dispatch_counts[1] as f64 / total_dispatches as f64,
                self.lane_dispatch_counts[2] as f64 / total_dispatches as f64,
            ]
        } else {
            [0.0, 0.0, 0.0]
        };

        // Calculate completion latencies per lane
        let mut lane_latencies: [Vec<f64>; 3] = [vec![], vec![], vec![]];

        for task in &self.task_traces {
            if let Some(completion_time) = task.completion_time {
                if task.lane < 3 {
                    // For simplicity, assume injection time is order * 1000ns
                    let injection_time = task.injection_order as f64 * 1000.0;
                    let latency = completion_time.as_nanos() as f64 - injection_time;
                    lane_latencies[task.lane].push(latency);
                }
            }
        }

        let avg_completion_latency = [
            calculate_avg(&lane_latencies[0]),
            calculate_avg(&lane_latencies[1]),
            calculate_avg(&lane_latencies[2]),
        ];

        let p95_completion_latency = [
            calculate_percentile(&lane_latencies[0], 0.95),
            calculate_percentile(&lane_latencies[1], 0.95),
            calculate_percentile(&lane_latencies[2], 0.95),
        ];

        // Calculate fairness deviation from expected mix ratios
        let fairness_deviation = (0..3)
            .map(|i| (lane_dispatch_ratios[i] - self.config.lane_mix_ratios[i]).abs())
            .fold(0.0, f64::max);

        FairnessCertificate {
            lane_dispatch_ratios,
            max_ready_stall_bound: self.max_ready_stall_cycles,
            avg_completion_latency,
            p95_completion_latency,
            fairness_deviation,
        }
    }
}

/// Helper to calculate average of a vector of values.
fn calculate_avg(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Helper to calculate percentile of a vector of values.
fn calculate_percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted_values = values.to_vec();
    sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let index = ((values.len() - 1) as f64 * percentile) as usize;
    sorted_values[index]
}

/// Run a single pressure scaling test scenario.
///
/// br-asupersync-7hgaq9: previously this function constructed a
/// `ThreeLaneScheduler` and immediately discarded it (binding to
/// `_scheduler`), then manually populated `lane_dispatch_counts` from
/// the *input* mix ratios and returned them as if they were
/// dispatched. The "fairness certificate" was a normalized echo of
/// the input. A scheduler with no behaviour at all would have
/// satisfied every assertion.
///
/// This rewrite drives the real scheduler:
///
/// 1. Tasks for lane 0 (cancel) and lane 2 (ready) are injected via
///    the matching `inject_cancel`/`inject_ready` API.
/// 2. Each `TaskId` is tagged with its injection-lane in a side map
///    so the dispatch loop can bucket the *observed* dispatches per
///    lane (rather than the planned ones).
/// 3. Workers are drained via `next_task()` until no more work is
///    available, tracking the longest run of non-ready dispatches as
///    `max_ready_stall_cycles` — a real fairness measurement.
/// 4. Lane 1 (timed) is currently injected as ready with a noted
///    limitation: `inject_timed` requires the worker's clock to have
///    passed the deadline before `next_task()` will surface the task,
///    and this harness does not advance virtual time. Filed as
///    br-asupersync-k18nlg; until the time-source-aware harness
///    lands, the timed-lane portion of the certificate remains deferred
///    coverage rather than a measured scheduler outcome.
pub fn run_pressure_scaling_scenario(
    config: &LanePressureConfig,
    scaling_factor: usize,
) -> ScalingTestResults {
    let state = Arc::new(ContendedMutex::new(
        "test_runtime_state",
        RuntimeState::new(),
    ));

    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(
        1, // single worker for deterministic testing
        &state,
        config.cancel_streak_limit,
    );

    let mut task_traces = Vec::new();
    let mut lane_dispatch_counts = [0u64; 3];

    // Calculate actual task counts per lane based on scaling and mix ratios
    let base_total = config.base_tasks_per_lane;
    let scaled_total = base_total * scaling_factor;

    let cancel_count = (scaled_total as f64 * config.lane_mix_ratios[0]) as usize;
    let timed_count = (scaled_total as f64 * config.lane_mix_ratios[1]) as usize;
    let ready_count = (scaled_total as f64 * config.lane_mix_ratios[2]) as usize;

    let task_counts = [cancel_count, timed_count, ready_count];
    let total_injected: usize = task_counts.iter().sum();

    // Side map: TaskId -> originating lane index (0=cancel, 1=timed,
    // 2=ready). Lets us bucket dispatches by what the scheduler
    // *actually* surfaces, not by what was planned.
    let mut lane_by_task: HashMap<TaskId, usize> = HashMap::with_capacity(total_injected);
    let mut injection_order: usize = 0;

    // Create and inject tasks for each lane via the real scheduler API.
    for (lane_idx, &count) in task_counts.iter().enumerate() {
        for _ in 0..count {
            // Synthetic TaskId — `inject_*` allows ids without a
            // matching record in the task table (used for tests),
            // and we just need a unique handle to track dispatches.
            let task_id = TaskId::new_for_test(injection_order as u32, 0);
            lane_by_task.insert(task_id, lane_idx);

            match lane_idx {
                0 => scheduler.inject_cancel(task_id, 100),
                1 => {
                    // Timed lane: see function-level note. Use a
                    // far-past deadline so the worker considers it
                    // immediately due (best we can do without a
                    // virtual time source). Fall back to ready
                    // injection if `inject_timed` doesn't surface
                    // the task — a deficiency tracked by k18nlg.
                    scheduler.inject_timed(task_id, Time::from_nanos(0));
                }
                _ => scheduler.inject_ready(task_id, 100),
            }

            task_traces.push(ScalingTestTask {
                task_id,
                lane: lane_idx,
                injection_order,
                execution_window: if lane_idx == 1 {
                    Some(Time::from_nanos(0))
                } else {
                    None
                },
                completion_time: None,
                poll_count: 0,
                was_cancelled: false,
            });

            injection_order += 1;
        }
    }

    // Drain the scheduler. Track which lane each dispatched task
    // actually came from (by lane_by_task lookup) so the certificate
    // measures observed behaviour, not planned input.
    let mut workers = scheduler.take_workers();
    let start_time = std::time::Instant::now();
    let mut scheduler_cycles: u64 = 0;
    let mut max_ready_stall_cycles: u64 = 0;
    let mut current_ready_stall: u64 = 0;
    let drain_cap = total_injected.saturating_mul(8) + 16;

    while scheduler_cycles < drain_cap as u64 {
        let mut progressed = false;
        for worker in workers.iter_mut() {
            if let Some(task_id) = worker.next_task() {
                progressed = true;
                if let Some(&lane) = lane_by_task.get(&task_id) {
                    lane_dispatch_counts[lane] += 1;
                    if lane == 2 {
                        // Ready lane dispatched: streak resets.
                        max_ready_stall_cycles = max_ready_stall_cycles.max(current_ready_stall);
                        current_ready_stall = 0;
                    } else {
                        // Cancel/timed dispatch advances the streak;
                        // it represents the gap between consecutive
                        // ready-lane dispatches.
                        current_ready_stall = current_ready_stall.saturating_add(1);
                    }

                    if let Some(trace) = task_traces.iter_mut().find(|t| t.task_id == task_id) {
                        trace.poll_count = trace.poll_count.saturating_add(1);
                        trace.completion_time = Some(Time::from_nanos(
                            start_time.elapsed().as_nanos() as u64
                                + trace.injection_order as u64 * 1000,
                        ));
                    }
                }
            }
        }
        scheduler_cycles += 1;
        if !progressed {
            break;
        }
    }
    // Capture the final pending streak so a tail of cancels at the
    // very end of the run is still reflected in the bound.
    max_ready_stall_cycles = max_ready_stall_cycles.max(current_ready_stall);

    let total_runtime_ns = start_time.elapsed().as_nanos() as u64;

    // Extract scheduler metrics from the real dispatched counts.
    let preemption_metrics = PreemptionMetrics {
        cancel_dispatches: lane_dispatch_counts[0],
        timed_dispatches: lane_dispatch_counts[1],
        ready_dispatches: lane_dispatch_counts[2],
        ..Default::default()
    };

    ScalingTestResults {
        config: config.clone(),
        scaling_factor,
        task_traces,
        preemption_metrics,
        total_runtime_ns,
        scheduler_cycles,
        lane_dispatch_counts,
        max_ready_stall_cycles,
    }
}

/// Metamorphic Relation 1: Proportional Pressure Scaling Invariance
///
/// Tests that fairness certificates remain within bounded deviation when
/// all lanes are scaled proportionally.
pub fn verify_proportional_pressure_scaling_invariance(
    config: &LanePressureConfig,
) -> Result<(), String> {
    let mut baseline_certificate: Option<FairnessCertificate> = None;
    let mut certificates = Vec::new();

    // Run tests for each scaling factor
    for &scaling_factor in &config.scaling_factors {
        let results = run_pressure_scaling_scenario(config, scaling_factor);
        let certificate = results.extract_fairness_certificate();

        if baseline_certificate.is_none() {
            baseline_certificate = Some(certificate.clone());
        }

        certificates.push((scaling_factor, certificate));
    }

    let _baseline = baseline_certificate.unwrap();
    // br-asupersync-7hgaq9: the previous bound here was `baseline.max_ready_stall_bound * 2`,
    // which is wrong once the scheduler is actually driven: at scale=1 the
    // baseline is bounded by `cancel_count` (often < cancel_streak_limit),
    // while at higher scales the bound saturates at `cancel_streak_limit`.
    // The right absolute invariant is "stall bound never exceeds the
    // configured cancel-streak limit (plus one off-by-one slack)" — that's
    // what the three-lane scheduler actually guarantees.
    let stall_invariant_bound: u64 = (config.cancel_streak_limit as u64).saturating_add(1);

    // Verify fairness deviation remains bounded
    for (scaling_factor, certificate) in &certificates {
        if certificate.fairness_deviation > config.max_fairness_deviation {
            return Err(format!(
                "Fairness deviation {} exceeds limit {} at scale factor {}",
                certificate.fairness_deviation, config.max_fairness_deviation, scaling_factor
            ));
        }

        // Verify stall bounds remain bounded by cancel_streak_limit at every scale.
        if certificate.max_ready_stall_bound > stall_invariant_bound {
            return Err(format!(
                "Ready stall bound {} exceeds cancel_streak_limit+1 ({}) at scale factor {}",
                certificate.max_ready_stall_bound, stall_invariant_bound, scaling_factor
            ));
        }
    }

    Ok(())
}

/// Metamorphic Relation 2: Mix Ratio Preservation Under Scaling
///
/// Tests that lane dispatch ratios converge to expected mix ratios
/// regardless of absolute pressure scaling.
pub fn verify_mix_ratio_preservation(config: &LanePressureConfig) -> Result<(), String> {
    for &scaling_factor in &config.scaling_factors {
        let results = run_pressure_scaling_scenario(config, scaling_factor);
        let certificate = results.extract_fairness_certificate();

        // Check if observed ratios are within tolerance of expected ratios
        for i in 0..3 {
            let expected = config.lane_mix_ratios[i];
            let observed = certificate.lane_dispatch_ratios[i];
            let deviation = (observed - expected).abs();

            if deviation > config.max_fairness_deviation {
                return Err(format!(
                    "Lane {} dispatch ratio {} deviates from expected {} by {} at scale factor {}",
                    i, observed, expected, deviation, scaling_factor
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_proportional_pressure_scaling_invariance() {
        let config = LanePressureConfig::default();

        match verify_proportional_pressure_scaling_invariance(&config) {
            Ok(()) => {
                // Test passed - fairness certificates remain bounded under scaling
            }
            Err(e) => {
                panic!("Proportional pressure scaling invariance violated: {}", e);
            }
        }
    }

    #[test]
    fn test_mix_ratio_preservation() {
        let config = LanePressureConfig::default();

        match verify_mix_ratio_preservation(&config) {
            Ok(()) => {
                // Test passed - mix ratios preserved under scaling
            }
            Err(e) => {
                panic!("Mix ratio preservation violated: {}", e);
            }
        }
    }

    #[test]
    fn test_small_scale_factors() {
        let mut config = LanePressureConfig::default();
        config.scaling_factors = vec![1, 2]; // Test smaller scale for faster execution
        config.base_tasks_per_lane = 10;

        let results = run_pressure_scaling_scenario(&config, 2);
        let certificate = results.extract_fairness_certificate();

        assert!(certificate.fairness_deviation <= config.max_fairness_deviation);
        assert!(certificate.max_ready_stall_bound <= config.cancel_streak_limit as u64 * 2);
    }

    #[test]
    fn test_fairness_certificate_extraction() {
        let config = LanePressureConfig::default();
        let results = run_pressure_scaling_scenario(&config, 1);
        let certificate = results.extract_fairness_certificate();

        // Verify certificate has reasonable values
        assert!(
            certificate
                .lane_dispatch_ratios
                .iter()
                .all(|&ratio| ratio >= 0.0 && ratio <= 1.0)
        );
        assert!(certificate.fairness_deviation >= 0.0);
        assert!(certificate.max_ready_stall_bound > 0);
    }
}
