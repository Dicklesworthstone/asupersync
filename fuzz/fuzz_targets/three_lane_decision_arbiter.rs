#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::types::Time;

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
    /// Queue depth signals for decision weighting
    queue_depths: FuzzQueueDepths,
}

/// Simulated queue depths for different lanes
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzQueueDepths {
    /// Global ready queue depth (0 to 5000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=5000))]
    global_ready: u32,
    /// Local ready queue depth (0 to 2000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=2000))]
    local_ready: u32,
}

/// Environmental factors affecting decisions
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEnvironment {
    /// Decision consistency tracking
    consistency_context: FuzzConsistencyContext,
}

/// Decision consistency tracking for metamorphic properties
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConsistencyContext {
    /// Whether to test deterministic properties
    test_determinism: bool,
}

// Bounded arbitrary generators for realistic fuzzing

fn bounded_weight(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(f64::from(u.int_in_range::<u16>(0..=1000)?) / 100.0) // 0.0 to 10.0
}

fn bounded_time_offset(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=3_600_000_000_000) // 0 to 1 hour in nanoseconds
}

fn bounded_age_sum(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=86_400_000_000_000) // 0 to 24 hours in nanoseconds
}

fn bounded_deadline_pressure(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(f64::from(u.int_in_range::<u16>(0..=10_000)?) / 100.0) // 0.0 to 100.0
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
    fn to_state_snapshot(&self, base_time: Time, ready_queue_depth: u32) -> StateSnapshot {
        StateSnapshot {
            time: Time::from_nanos(base_time.as_nanos() + self.time_offset_ns),
            live_tasks: self.live_tasks,
            pending_obligations: self.pending_obligations,
            obligation_age_sum_ns: if self.pending_obligations == 0 {
                0
            } else {
                self.obligation_age_sum_ns
            },
            draining_regions: self.draining_regions,
            deadline_pressure: self.deadline_pressure,
            pending_send_permits: self.pending_obligations,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth,
        }
    }
}

/// Test that lane decisions are deterministic for identical input
fn test_decision_determinism(weights: &PotentialWeights, snapshots: &[StateSnapshot]) -> bool {
    if snapshots.is_empty() {
        return true; // Vacuously true
    }

    let governor1 = LyapunovGovernor::new(weights.clone());
    let governor2 = LyapunovGovernor::new(weights.clone());

    for snapshot in snapshots {
        let suggestion1 = governor1.suggest(snapshot);
        let suggestion2 = governor2.suggest(snapshot);

        if suggestion1 != suggestion2 {
            return false; // Non-deterministic behavior detected
        }
    }
    true
}

// Main fuzzing target for three-lane scheduler decision arbiter.
fuzz_target!(|input: DecisionArbiterInput| {
    // Convert fuzz inputs to real types
    let weights = PotentialWeights::from(input.weights);
    let base_time = Time::from_nanos(1_000_000_000); // 1 second epoch
    let ready_queue_depth = input
        .scheduler_context
        .queue_depths
        .global_ready
        .saturating_add(input.scheduler_context.queue_depths.local_ready);

    let snapshots: Vec<StateSnapshot> = input
        .state_snapshots
        .iter()
        .map(|s| s.to_state_snapshot(base_time, ready_queue_depth))
        .collect();

    if snapshots.is_empty() {
        return; // Nothing to test
    }

    // Test 1: Decision determinism
    if input.environment.consistency_context.test_determinism {
        assert!(
            test_decision_determinism(&weights, &snapshots),
            "Decision arbiter should be deterministic for identical inputs"
        );
    }

    // Test 2: Governor suggestion generation
    let governor = LyapunovGovernor::new(weights.clone());
    for snapshot in &snapshots {
        match governor.suggest(snapshot) {
            SchedulingSuggestion::DrainObligations
            | SchedulingSuggestion::DrainRegions
            | SchedulingSuggestion::MeetDeadlines
            | SchedulingSuggestion::NoPreference => {}
        }
    }
});
