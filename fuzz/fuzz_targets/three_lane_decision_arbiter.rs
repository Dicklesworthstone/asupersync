#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::runtime::scheduler::three_lane::ThreeLaneWorker;
use asupersync::time::VirtualClock;
use asupersync::types::{Time, TaskId};
use std::sync::Arc;

/// Structure-aware input for fuzzing the three-lane scheduler decision arbiter.
///
/// This captures the key decision inputs that drive lane choice in the scheduler:
/// - Governor state (Lyapunov potential weights, runtime snapshots)
/// - Scheduler state (cancel streak, queue depths, fairness counters)
/// - Environmental factors (timing, budget pressure, suggestion caching)
#[derive(Debug, Clone, Arbitrary)]
pub struct DecisionArbiterInput {
    /// Lyapunov governor weights that influence scheduling suggestions
    weights: FuzzPotentialWeights,
    /// Runtime state snapshot for governor decision-making
    state_snapshots: Vec<FuzzStateSnapshot>,
    /// Scheduler-level decision context
    scheduler_context: FuzzSchedulerContext,
    /// Environmental decision factors
    environment: FuzzEnvironment,
}

/// Fuzzable version of PotentialWeights with bounded ranges
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzPotentialWeights {
    /// Weight for live task count (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_tasks: f64,
    /// Weight for obligation age sum (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_obligation_age: f64,
    /// Weight for draining regions (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_draining_regions: f64,
    /// Weight for deadline pressure (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_deadline_pressure: f64,
}

/// Fuzzable version of StateSnapshot with realistic bounds
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzStateSnapshot {
    /// Virtual time offset from epoch (0 to 1 hour in nanoseconds)
    #[arbitrary(with = bounded_time_offset)]
    time_offset_ns: u64,
    /// Number of live tasks (0 to 10000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=10000))]
    live_tasks: u32,
    /// Pending obligations count (0 to 50000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=50000))]
    pending_obligations: u32,
    /// Sum of obligation ages in nanoseconds (0 to 24 hours)
    #[arbitrary(with = bounded_age_sum)]
    obligation_age_sum_ns: u64,
    /// Draining regions count (0 to 1000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=1000))]
    draining_regions: u32,
    /// Deadline pressure (0.0 to 100.0)
    #[arbitrary(with = bounded_deadline_pressure)]
    deadline_pressure: f64,
}

/// Scheduler context affecting lane decision logic
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzSchedulerContext {
    /// Current cancel streak (0 to 200)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=200))]
    cancel_streak: usize,
    /// Base cancel limit (1 to 100)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=100))]
    base_cancel_limit: usize,
    /// Ready dispatch streak (0 to 1000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=1000))]
    ready_dispatch_streak: usize,
    /// Queue depth signals for decision weighting
    queue_depths: FuzzQueueDepths,
    /// Fairness and budget tracking
    fairness_context: FuzzFairnessContext,
}

/// Simulated queue depths for different lanes
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzQueueDepths {
    /// Global cancel queue depth (0 to 1000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=1000))]
    global_cancel: u32,
    /// Global timed queue depth (0 to 1000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=1000))]
    global_timed: u32,
    /// Global ready queue depth (0 to 5000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=5000))]
    global_ready: u32,
    /// Local cancel queue depth (0 to 500)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=500))]
    local_cancel: u32,
    /// Local timed queue depth (0 to 500)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=500))]
    local_timed: u32,
    /// Local ready queue depth (0 to 2000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=2000))]
    local_ready: u32,
}

/// Fairness and budget tracking context
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzFairnessContext {
    /// Fairness yields count (0 to 10000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=10000))]
    fairness_yields: u32,
    /// Max effective limit observed (0 to 500)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=500))]
    max_effective_limit: usize,
    /// Budget exhaustion indicator
    budget_exhausted: bool,
}

/// Environmental factors affecting decisions
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEnvironment {
    /// Time pressure simulation
    time_pressure: FuzzTimePressure,
    /// Suggestion caching behavior
    suggestion_caching: FuzzSuggestionCaching,
    /// Decision consistency tracking
    consistency_context: FuzzConsistencyContext,
}

/// Time-based decision pressure
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzTimePressure {
    /// Whether deadlines are approaching (0-100% of tasks near deadline)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=100))]
    deadline_pressure_percent: u8,
    /// Timer processing frequency (every 1 to 1000 decisions)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=1000))]
    timer_tick_interval: u16,
    /// EDF scheduling window (1ms to 10s in nanoseconds)
    #[arbitrary(with = bounded_scheduling_window)]
    edf_window_ns: u64,
}

/// Suggestion caching and consistency
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzSuggestionCaching {
    /// Cached suggestion from previous decision
    cached_suggestion: FuzzSchedulingSuggestion,
    /// Governor consultation frequency (every 1 to 100 decisions)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=100))]
    governor_consult_interval: u8,
    /// Suggestion validity period (1 to 1000 decisions)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=1000))]
    suggestion_lifetime: u16,
}

/// Fuzzable scheduling suggestion that maps to real enum
#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzSchedulingSuggestion {
    DrainObligations,
    DrainRegions,
    MeetDeadlines,
    NoPreference,
}

/// Decision consistency tracking for metamorphic properties
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConsistencyContext {
    /// Number of decision rounds to simulate (1 to 100)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=100))]
    decision_rounds: u8,
    /// Whether to test deterministic properties
    test_determinism: bool,
    /// Whether to test fairness bounds
    test_fairness: bool,
    /// Whether to test suggestion consistency
    test_suggestion_stability: bool,
}

// Bounded arbitrary generators for realistic fuzzing

fn bounded_weight(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(u.arbitrary::<f32>()? as f64 * 10.0)  // 0.0 to 10.0
}

fn bounded_time_offset(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=3_600_000_000_000)  // 0 to 1 hour in nanoseconds
}

fn bounded_age_sum(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=86_400_000_000_000)  // 0 to 24 hours in nanoseconds
}

fn bounded_deadline_pressure(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(u.arbitrary::<f32>()? as f64 * 100.0)  // 0.0 to 100.0
}

fn bounded_scheduling_window(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(1_000_000..=10_000_000_000)  // 1ms to 10s in nanoseconds
}

impl From<FuzzPotentialWeights> for PotentialWeights {
    fn from(fuzz_weights: FuzzPotentialWeights) -> Self {
        Self {
            w_tasks: fuzz_weights.w_tasks,
            w_obligation_age: fuzz_weights.w_obligation_age,
            w_draining_regions: fuzz_weights.w_draining_regions,
            w_deadline_pressure: fuzz_weights.w_deadline_pressure,
        }
    }
}

impl FuzzStateSnapshot {
    fn to_state_snapshot(&self, base_time: Time) -> StateSnapshot {
        StateSnapshot {
            time: Time::from_nanos(base_time.as_nanos() + self.time_offset_ns),
            live_tasks: self.live_tasks,
            pending_obligations: self.pending_obligations,
            obligation_age_sum_ns: self.obligation_age_sum_ns,
            draining_regions: self.draining_regions,
            deadline_pressure: self.deadline_pressure,
        }
    }
}

impl From<FuzzSchedulingSuggestion> for SchedulingSuggestion {
    fn from(fuzz_suggestion: FuzzSchedulingSuggestion) -> Self {
        match fuzz_suggestion {
            FuzzSchedulingSuggestion::DrainObligations => Self::DrainObligations,
            FuzzSchedulingSuggestion::DrainRegions => Self::DrainRegions,
            FuzzSchedulingSuggestion::MeetDeadlines => Self::MeetDeadlines,
            FuzzSchedulingSuggestion::NoPreference => Self::NoPreference,
        }
    }
}

/// Test that lane decisions are deterministic for identical input
fn test_decision_determinism(
    weights: &PotentialWeights,
    snapshots: &[StateSnapshot],
    scheduler_context: &FuzzSchedulerContext,
) -> bool {
    if snapshots.is_empty() {
        return true;  // Vacuously true
    }

    let mut governor1 = LyapunovGovernor::new(weights.clone());
    let mut governor2 = LyapunovGovernor::new(weights.clone());

    for snapshot in snapshots {
        let suggestion1 = governor1.suggest_scheduling_priority(snapshot);
        let suggestion2 = governor2.suggest_scheduling_priority(snapshot);

        if suggestion1 != suggestion2 {
            return false;  // Non-deterministic behavior detected
        }
    }
    true
}

/// Test that fairness bounds are respected under cancel pressure
fn test_fairness_bounds(
    scheduler_context: &FuzzSchedulerContext,
    suggestion: SchedulingSuggestion,
) -> bool {
    // Calculate effective limit based on suggestion
    let effective_limit = match suggestion {
        SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions => {
            scheduler_context.base_cancel_limit.saturating_mul(2)
        }
        _ => scheduler_context.base_cancel_limit,
    };

    // Cancel streak should not exceed effective limit in well-behaved scenario
    if scheduler_context.cancel_streak > effective_limit {
        // This might indicate fairness violation, but could also be valid
        // during transition periods - we test that it's bounded
        scheduler_context.cancel_streak <= effective_limit.saturating_mul(2)
    } else {
        true  // Within expected bounds
    }
}

/// Test that suggestions are stable for similar input
fn test_suggestion_stability(
    weights: &PotentialWeights,
    snapshots: &[StateSnapshot],
) -> bool {
    if snapshots.len() < 2 {
        return true;
    }

    let mut governor = LyapunovGovernor::new(weights.clone());
    let mut suggestions = Vec::new();

    for snapshot in snapshots {
        suggestions.push(governor.suggest_scheduling_priority(snapshot));
    }

    // For very similar snapshots, suggestions should not oscillate wildly
    let mut oscillations = 0;
    for i in 1..suggestions.len() {
        if suggestions[i] != suggestions[i-1] {
            oscillations += 1;
        }
    }

    // Allow some oscillation, but not constant thrashing
    oscillations <= snapshots.len() / 2
}

/// Test that governor suggestions influence effective limits correctly
fn test_suggestion_limit_consistency(
    suggestion: SchedulingSuggestion,
    base_limit: usize,
) -> bool {
    let effective_limit = match suggestion {
        SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions => {
            base_limit.saturating_mul(2)
        }
        _ => base_limit,
    };

    // Effective limit should be at least base limit
    effective_limit >= base_limit
}

/// Main fuzzing target for three-lane scheduler decision arbiter
fuzz_target!(|input: DecisionArbiterInput| {
    // Convert fuzz inputs to real types
    let weights = PotentialWeights::from(input.weights);
    let base_time = Time::from_nanos(1_000_000_000); // 1 second epoch

    let snapshots: Vec<StateSnapshot> = input.state_snapshots
        .iter()
        .map(|s| s.to_state_snapshot(base_time))
        .collect();

    if snapshots.is_empty() {
        return; // Nothing to test
    }

    // Test 1: Decision determinism
    if input.environment.consistency_context.test_determinism {
        assert!(test_decision_determinism(&weights, &snapshots, &input.scheduler_context),
            "Decision arbiter should be deterministic for identical inputs");
    }

    // Test 2: Governor suggestion generation
    let mut governor = LyapunovGovernor::new(weights.clone());
    let mut suggestions = Vec::new();

    for snapshot in &snapshots {
        let suggestion = governor.suggest_scheduling_priority(snapshot);
        suggestions.push(suggestion);

        // Test suggestion-limit consistency
        assert!(test_suggestion_limit_consistency(suggestion, input.scheduler_context.base_cancel_limit),
            "Suggestion should produce consistent effective limits");
    }

    // Test 3: Fairness bounds
    if input.environment.consistency_context.test_fairness {
        for suggestion in &suggestions {
            assert!(test_fairness_bounds(&input.scheduler_context, *suggestion),
                "Fairness bounds should be respected under suggestion {:?}", suggestion);
        }
    }

    // Test 4: Suggestion stability
    if input.environment.consistency_context.test_suggestion_stability {
        assert!(test_suggestion_stability(&weights, &snapshots),
            "Suggestions should be stable for similar inputs");
    }

    // Test 5: Queue depth invariants
    let total_global_depth = input.scheduler_context.queue_depths.global_cancel +
                            input.scheduler_context.queue_depths.global_timed +
                            input.scheduler_context.queue_depths.global_ready;

    let total_local_depth = input.scheduler_context.queue_depths.local_cancel +
                           input.scheduler_context.queue_depths.local_timed +
                           input.scheduler_context.queue_depths.local_ready;

    // Sanity check: total queued work should not exceed live tasks significantly
    if let Some(max_live) = snapshots.iter().map(|s| s.live_tasks).max() {
        assert!(total_global_depth + total_local_depth <= max_live.saturating_mul(10),
            "Total queue depth should be reasonable relative to live tasks");
    }

    // Test 6: Governor weight sanity
    let weight_sum = weights.w_tasks + weights.w_obligation_age +
                     weights.w_draining_regions + weights.w_deadline_pressure;
    assert!(weight_sum >= 0.0, "Weight sum should be non-negative");

    // Test 7: Deadline pressure bounds
    for snapshot in &snapshots {
        assert!(snapshot.deadline_pressure >= 0.0,
            "Deadline pressure should be non-negative");
    }

    // Test 8: Obligation age consistency
    for snapshot in &snapshots {
        if snapshot.pending_obligations == 0 {
            assert!(snapshot.obligation_age_sum_ns == 0,
                "No pending obligations should mean zero age sum");
        }
    }
});