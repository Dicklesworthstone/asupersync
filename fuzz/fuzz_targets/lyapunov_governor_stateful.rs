#![no_main]

use arbitrary::Arbitrary;
use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::types::Time;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

/// Maximum operations per fuzz run to prevent timeout
const MAX_OPERATIONS: usize = 500;
/// Maximum history depth for convergence tracking
const MAX_HISTORY_DEPTH: usize = 100;
/// Maximum potential values to prevent overflow
const MAX_POTENTIAL_VALUE: f64 = 1e12;
/// Maximum time advance per step
const MAX_TIME_ADVANCE_NS: u64 = 1_000_000_000; // 1 second

/// Fuzz input representing Lyapunov governor operations
#[derive(Arbitrary, Debug, Clone)]
struct LyapunovGovernorFuzzInput {
    /// Initial weights configuration
    pub initial_weights: WeightsConfig,
    /// Sequence of governor operations
    pub operations: Vec<GovernorOperation>,
}

/// Weight configuration for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct WeightsConfig {
    pub w_tasks: WeightValue,
    pub w_obligation_age: WeightValue,
    pub w_draining_regions: WeightValue,
    pub w_deadline_pressure: WeightValue,
}

/// Bounded weight value to ensure valid, finite weights
#[derive(Arbitrary, Debug, Clone)]
enum WeightValue {
    Zero,
    Small,      // 0.1
    Default,    // 1.0
    Medium,     // 5.0
    Large,      // 10.0
    VeryLarge,  // 100.0
}

impl WeightValue {
    fn to_f64(&self) -> f64 {
        match self {
            Self::Zero => 0.0,
            Self::Small => 0.1,
            Self::Default => 1.0,
            Self::Medium => 5.0,
            Self::Large => 10.0,
            Self::VeryLarge => 100.0,
        }
    }
}

impl WeightsConfig {
    fn to_potential_weights(&self) -> PotentialWeights {
        PotentialWeights {
            w_tasks: self.w_tasks.to_f64(),
            w_obligation_age: self.w_obligation_age.to_f64(),
            w_draining_regions: self.w_draining_regions.to_f64(),
            w_deadline_pressure: self.w_deadline_pressure.to_f64(),
        }
    }
}

/// Individual governor operations
#[derive(Arbitrary, Debug, Clone)]
enum GovernorOperation {
    /// Update state snapshot and get suggestion
    ComputeAndSuggest { state_config: StateConfig },
    /// Compute potential without suggestion
    ComputePotentialOnly { state_config: StateConfig },
    /// Advance time significantly
    AdvanceTime { time_advance_ns: u32 },
    /// Simulate system quiescence
    SimulateQuiescence,
    /// Simulate high obligation pressure
    SimulateObligationPressure { count: u16, age_multiplier: u8 },
    /// Simulate deadline pressure
    SimulateDeadlinePressure { pressure: u8 },
    /// Simulate region drain scenario
    SimulateRegionDrain { draining_count: u8 },
    /// Test convergence analysis
    AnalyzeConvergence,
    /// Verify governor invariants
    VerifyInvariants,
}

/// State configuration for creating snapshots
#[derive(Arbitrary, Debug, Clone)]
struct StateConfig {
    pub live_tasks: u16,
    pub pending_obligations: u16,
    pub obligation_age_factor: u8,   // Multiplier for age calculation
    pub draining_regions: u8,
    pub deadline_pressure_factor: u8,
    pub pending_send_permits: u16,
    pub pending_acks: u16,
    pub pending_leases: u16,
    pub pending_io_ops: u16,
    pub cancel_requested_tasks: u16,
    pub cancelling_tasks: u16,
    pub finalizing_tasks: u16,
    pub ready_queue_depth: u16,
}

/// Shadow model for governor verification
#[derive(Debug)]
struct GovernorShadowModel {
    /// Track potential history
    potential_history: Vec<f64>,
    /// Track suggestion history
    suggestion_history: Vec<SchedulingSuggestion>,
    /// Track state snapshots
    snapshot_history: Vec<StateSnapshot>,
    /// Current time
    current_time: Time,
    /// Properties for verification
    properties: GovernorProperties,
}

#[derive(Debug, Default)]
struct GovernorProperties {
    total_computations: usize,
    max_potential_seen: f64,
    min_potential_seen: f64,
    quiescent_states: usize,
    drain_obligation_suggestions: usize,
    drain_region_suggestions: usize,
    meet_deadline_suggestions: usize,
    no_preference_suggestions: usize,
    potential_increases: usize,
    potential_decreases: usize,
    monotone_violations: usize,
}

impl GovernorShadowModel {
    fn new() -> Self {
        Self {
            potential_history: Vec::new(),
            suggestion_history: Vec::new(),
            snapshot_history: Vec::new(),
            current_time: Time::ZERO,
            properties: GovernorProperties::default(),
        }
    }

    fn record_computation(&mut self, potential: f64, suggestion: SchedulingSuggestion, snapshot: StateSnapshot) {
        // Update potential history
        if let Some(&last_potential) = self.potential_history.last() {
            if potential > last_potential {
                self.properties.potential_increases += 1;
                if potential > last_potential + 1e-6 {
                    self.properties.monotone_violations += 1;
                }
            } else if potential < last_potential {
                self.properties.potential_decreases += 1;
            }
        }

        self.potential_history.push(potential);
        self.suggestion_history.push(suggestion);
        self.snapshot_history.push(snapshot.clone());

        // Update properties
        self.properties.total_computations += 1;
        self.properties.max_potential_seen = self.properties.max_potential_seen.max(potential);
        if self.properties.total_computations == 1 {
            self.properties.min_potential_seen = potential;
        } else {
            self.properties.min_potential_seen = self.properties.min_potential_seen.min(potential);
        }

        if snapshot.is_quiescent() {
            self.properties.quiescent_states += 1;
        }

        match suggestion {
            SchedulingSuggestion::DrainObligations => self.properties.drain_obligation_suggestions += 1,
            SchedulingSuggestion::DrainRegions => self.properties.drain_region_suggestions += 1,
            SchedulingSuggestion::MeetDeadlines => self.properties.meet_deadline_suggestions += 1,
            SchedulingSuggestion::NoPreference => self.properties.no_preference_suggestions += 1,
        }

        // Bound history size
        if self.potential_history.len() > MAX_HISTORY_DEPTH {
            let remove_count = self.potential_history.len() - MAX_HISTORY_DEPTH;
            self.potential_history.drain(..remove_count);
            self.suggestion_history.drain(..remove_count);
            self.snapshot_history.drain(..remove_count);
        }
    }

    fn advance_time(&mut self, advance_ns: u64) {
        self.current_time = Time::from_nanos(
            self.current_time.as_nanos().saturating_add(advance_ns)
        );
    }

    fn verify_lyapunov_properties(&self) -> bool {
        // Verify basic properties
        if self.potential_history.is_empty() {
            return true;
        }

        // Check non-negativity
        for &potential in &self.potential_history {
            if potential < 0.0 || !potential.is_finite() {
                return false;
            }
        }

        // Check that quiescent states have zero potential (approximately)
        for (i, snapshot) in self.snapshot_history.iter().enumerate() {
            if snapshot.is_quiescent() {
                let potential = self.potential_history[i];
                if potential > 1e-6 {
                    return false; // Quiescent should have ~zero potential
                }
            }
        }

        true
    }

    fn analyze_convergence(&self) -> Option<ConvergenceAnalysis> {
        if self.potential_history.len() < 2 {
            return None;
        }

        let mut monotone = true;
        let mut max_increase = 0.0f64;
        let mut increase_count = 0;

        for window in self.potential_history.windows(2) {
            let (prev, curr) = (window[0], window[1]);
            if curr > prev + 1e-9 {
                monotone = false;
                let increase = curr - prev;
                max_increase = max_increase.max(increase);
                increase_count += 1;
            }
        }

        let final_quiescent = self.snapshot_history
            .last()
            .map_or(false, |s| s.is_quiescent());

        Some(ConvergenceAnalysis {
            monotone,
            reached_quiescence: final_quiescent,
            steps: self.potential_history.len(),
            increase_count,
            max_increase,
            v_max: self.properties.max_potential_seen,
            v_final: self.potential_history.last().copied().unwrap_or(0.0),
        })
    }
}

#[derive(Debug)]
struct ConvergenceAnalysis {
    monotone: bool,
    reached_quiescence: bool,
    steps: usize,
    increase_count: usize,
    max_increase: f64,
    v_max: f64,
    v_final: f64,
}

impl StateConfig {
    fn to_snapshot(&self, current_time: Time) -> StateSnapshot {
        StateSnapshot {
            time: current_time,
            live_tasks: self.live_tasks.min(10000) as u32,
            pending_obligations: self.pending_obligations.min(10000) as u32,
            obligation_age_sum_ns: (self.obligation_age_factor as u64).saturating_mul(1_000_000) // Convert to reasonable ns values
                .saturating_mul(self.pending_obligations.min(1000) as u64),
            draining_regions: self.draining_regions.min(100) as u32,
            deadline_pressure: (self.deadline_pressure_factor as f64) * 0.1, // Scale to reasonable range
            pending_send_permits: self.pending_send_permits.min(10000) as u32,
            pending_acks: self.pending_acks.min(10000) as u32,
            pending_leases: self.pending_leases.min(10000) as u32,
            pending_io_ops: self.pending_io_ops.min(10000) as u32,
            cancel_requested_tasks: self.cancel_requested_tasks.min(10000) as u32,
            cancelling_tasks: self.cancelling_tasks.min(10000) as u32,
            finalizing_tasks: self.finalizing_tasks.min(10000) as u32,
            ready_queue_depth: self.ready_queue_depth.min(10000) as u32,
        }
    }
}

impl StateSnapshot {
    fn is_quiescent(&self) -> bool {
        self.live_tasks == 0
            && self.pending_obligations == 0
            && self.draining_regions == 0
            && self.pending_send_permits == 0
            && self.pending_acks == 0
            && self.pending_leases == 0
            && self.pending_io_ops == 0
            && self.cancel_requested_tasks == 0
            && self.cancelling_tasks == 0
            && self.finalizing_tasks == 0
            && self.ready_queue_depth == 0
    }
}

fuzz_target!(|input: LyapunovGovernorFuzzInput| {
    // Guard against excessive input size
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Create governor with fuzzer-provided weights
    let weights = input.initial_weights.to_potential_weights();
    if !weights.is_valid() {
        return; // Skip invalid weight configurations
    }

    let mut governor = LyapunovGovernor::new(weights);
    let mut shadow = GovernorShadowModel::new();

    // Execute operations and verify against shadow model
    for operation in input.operations {
        match operation {
            GovernorOperation::ComputeAndSuggest { state_config } => {
                let snapshot = state_config.to_snapshot(shadow.current_time);

                // Execute on real governor
                let potential = governor.compute_potential(&snapshot);
                let suggestion = governor.suggest(&snapshot);

                // Verify basic constraints
                assert!(potential >= 0.0, "Potential must be non-negative");
                assert!(potential.is_finite(), "Potential must be finite");
                assert!(potential <= MAX_POTENTIAL_VALUE, "Potential exceeded maximum");

                // Verify suggestion logic
                if snapshot.is_quiescent() {
                    assert_eq!(suggestion, SchedulingSuggestion::NoPreference, "Quiescent state should suggest NoPreference");
                    assert!(potential <= 1e-6, "Quiescent state should have ~zero potential");
                }

                // Record in shadow model
                shadow.record_computation(potential, suggestion, snapshot);
            }

            GovernorOperation::ComputePotentialOnly { state_config } => {
                let snapshot = state_config.to_snapshot(shadow.current_time);

                // Test compute_record (doesn't modify history)
                let record = governor.compute_record(&snapshot);
                assert!(record.total >= 0.0, "Potential record total must be non-negative");
                assert!(record.total.is_finite(), "Potential record total must be finite");

                // Verify component breakdown
                assert!(record.task_component >= 0.0, "Task component must be non-negative");
                assert!(record.obligation_component >= 0.0, "Obligation component must be non-negative");
                assert!(record.region_component >= 0.0, "Region component must be non-negative");
                assert!(record.deadline_component >= 0.0, "Deadline component must be non-negative");

                // Verify total is sum of components (approximately)
                let component_sum = record.task_component + record.obligation_component
                    + record.region_component + record.deadline_component;
                let diff = (record.total - component_sum).abs();
                assert!(diff < 1e-9, "Total should equal sum of components");
            }

            GovernorOperation::AdvanceTime { time_advance_ns } => {
                let advance = (time_advance_ns as u64).min(MAX_TIME_ADVANCE_NS);
                shadow.advance_time(advance);
            }

            GovernorOperation::SimulateQuiescence => {
                let quiescent_snapshot = StateSnapshot {
                    time: shadow.current_time,
                    live_tasks: 0,
                    pending_obligations: 0,
                    obligation_age_sum_ns: 0,
                    draining_regions: 0,
                    deadline_pressure: 0.0,
                    pending_send_permits: 0,
                    pending_acks: 0,
                    pending_leases: 0,
                    pending_io_ops: 0,
                    cancel_requested_tasks: 0,
                    cancelling_tasks: 0,
                    finalizing_tasks: 0,
                    ready_queue_depth: 0,
                };

                let potential = governor.compute_potential(&quiescent_snapshot);
                let suggestion = governor.suggest(&quiescent_snapshot);

                assert!(potential <= 1e-6, "Quiescent state should have near-zero potential");
                assert_eq!(suggestion, SchedulingSuggestion::NoPreference, "Quiescent should suggest NoPreference");

                shadow.record_computation(potential, suggestion, quiescent_snapshot);
            }

            GovernorOperation::SimulateObligationPressure { count, age_multiplier } => {
                let snapshot = StateSnapshot {
                    time: shadow.current_time,
                    live_tasks: (count as u32).min(1000),
                    pending_obligations: (count as u32).min(1000),
                    obligation_age_sum_ns: (age_multiplier as u64).saturating_mul(1_000_000_000)
                        .saturating_mul(count as u64),
                    draining_regions: 0,
                    deadline_pressure: 0.0,
                    pending_send_permits: (count as u32).min(1000),
                    pending_acks: 0,
                    pending_leases: 0,
                    pending_io_ops: 0,
                    cancel_requested_tasks: 0,
                    cancelling_tasks: 0,
                    finalizing_tasks: 0,
                    ready_queue_depth: (count as u32).min(100),
                };

                let potential = governor.compute_potential(&snapshot);
                let suggestion = governor.suggest(&snapshot);

                // High obligation pressure should tend toward DrainObligations
                if count > 0 && weights.w_obligation_age > 0.0 {
                    assert!(potential > 0.0, "Non-zero obligations should yield positive potential");
                }

                shadow.record_computation(potential, suggestion, snapshot);
            }

            GovernorOperation::SimulateDeadlinePressure { pressure } => {
                let snapshot = StateSnapshot {
                    time: shadow.current_time,
                    live_tasks: 10,
                    pending_obligations: 0,
                    obligation_age_sum_ns: 0,
                    draining_regions: 0,
                    deadline_pressure: (pressure as f64).min(100.0),
                    pending_send_permits: 0,
                    pending_acks: 0,
                    pending_leases: 0,
                    pending_io_ops: 0,
                    cancel_requested_tasks: 0,
                    cancelling_tasks: 0,
                    finalizing_tasks: 0,
                    ready_queue_depth: 5,
                };

                let potential = governor.compute_potential(&snapshot);
                let suggestion = governor.suggest(&snapshot);

                shadow.record_computation(potential, suggestion, snapshot);
            }

            GovernorOperation::SimulateRegionDrain { draining_count } => {
                let snapshot = StateSnapshot {
                    time: shadow.current_time,
                    live_tasks: (draining_count as u32).min(100),
                    pending_obligations: 0,
                    obligation_age_sum_ns: 0,
                    draining_regions: (draining_count as u32).min(100),
                    deadline_pressure: 0.0,
                    pending_send_permits: 0,
                    pending_acks: 0,
                    pending_leases: 0,
                    pending_io_ops: 0,
                    cancel_requested_tasks: 0,
                    cancelling_tasks: 0,
                    finalizing_tasks: 0,
                    ready_queue_depth: 0,
                };

                let potential = governor.compute_potential(&snapshot);
                let suggestion = governor.suggest(&snapshot);

                shadow.record_computation(potential, suggestion, snapshot);
            }

            GovernorOperation::AnalyzeConvergence => {
                if let Some(analysis) = shadow.analyze_convergence() {
                    // Verify convergence properties
                    assert_eq!(analysis.steps, shadow.potential_history.len(), "Step count should match history length");
                    assert!(analysis.v_max >= analysis.v_final, "Max potential should be >= final potential");

                    if analysis.increase_count == 0 {
                        assert!(analysis.monotone, "No increases should mean monotone");
                    }
                }
            }

            GovernorOperation::VerifyInvariants => {
                // Verify shadow model Lyapunov properties
                assert!(shadow.verify_lyapunov_properties(), "Lyapunov properties violated");

                // Verify governor internal state
                // Note: We can't directly access governor internals, but we can verify
                // that repeated calls with same input yield same result
                if let Some(last_snapshot) = shadow.snapshot_history.last() {
                    let potential1 = governor.compute_record(last_snapshot);
                    let potential2 = governor.compute_record(last_snapshot);
                    assert_eq!(potential1.total, potential2.total, "Determinism check failed");

                    let suggestion1 = governor.suggest(last_snapshot);
                    let suggestion2 = governor.suggest(last_snapshot);
                    assert_eq!(suggestion1, suggestion2, "Suggestion determinism check failed");
                }
            }
        }

        // Always verify basic invariants after each operation
        assert!(shadow.verify_lyapunov_properties(), "Basic Lyapunov properties violated");

        // Prevent unbounded growth
        if shadow.properties.total_computations > MAX_OPERATIONS {
            break;
        }
    }

    // Final comprehensive verification
    verify_lyapunov_governor_invariants(&governor, &shadow);
});

/// Verify Lyapunov governor system invariants
fn verify_lyapunov_governor_invariants(
    _governor: &LyapunovGovernor,
    shadow: &GovernorShadowModel,
) {
    // Verify shadow model consistency
    assert!(shadow.verify_lyapunov_properties(), "Final Lyapunov properties verification failed");

    // Verify history consistency
    assert_eq!(
        shadow.potential_history.len(),
        shadow.suggestion_history.len(),
        "History lengths should match"
    );
    assert_eq!(
        shadow.potential_history.len(),
        shadow.snapshot_history.len(),
        "History lengths should match snapshots"
    );

    // Verify property counts
    let total_suggestions = shadow.properties.drain_obligation_suggestions
        + shadow.properties.drain_region_suggestions
        + shadow.properties.meet_deadline_suggestions
        + shadow.properties.no_preference_suggestions;
    assert_eq!(
        total_suggestions,
        shadow.properties.total_computations,
        "Total suggestions should equal total computations"
    );

    // Verify convergence trends (if we have enough data)
    if shadow.potential_history.len() >= 10 {
        let first_potential = shadow.potential_history[0];
        let last_potential = shadow.potential_history.last().copied().unwrap();

        // General trend should be toward lower potential (though not strictly monotonic)
        if first_potential > 0.0 && shadow.properties.potential_decreases > 0 {
            // At least some decrease should have occurred
            assert!(
                shadow.properties.potential_decreases >= shadow.properties.potential_increases / 2,
                "Should see more decreases than increases over time"
            );
        }
    }

    // Verify no excessive violations
    if shadow.potential_history.len() >= 5 {
        let violation_rate = shadow.properties.monotone_violations as f64 / shadow.potential_history.len() as f64;
        assert!(
            violation_rate < 0.5,
            "Monotone violation rate should be < 50%"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_governor_operations() {
        let input = LyapunovGovernorFuzzInput {
            initial_weights: WeightsConfig {
                w_tasks: WeightValue::Default,
                w_obligation_age: WeightValue::Medium,
                w_draining_regions: WeightValue::Small,
                w_deadline_pressure: WeightValue::Large,
            },
            operations: vec![
                GovernorOperation::SimulateObligationPressure { count: 10, age_multiplier: 5 },
                GovernorOperation::SimulateQuiescence,
                GovernorOperation::SimulateDeadlinePressure { pressure: 50 },
                GovernorOperation::VerifyInvariants,
            ],
        };

        // Should not panic
        fuzz_target(&input);
    }

    #[test]
    fn test_quiescent_state_behavior() {
        let input = LyapunovGovernorFuzzInput {
            initial_weights: WeightsConfig {
                w_tasks: WeightValue::Default,
                w_obligation_age: WeightValue::Default,
                w_draining_regions: WeightValue::Default,
                w_deadline_pressure: WeightValue::Default,
            },
            operations: vec![
                GovernorOperation::SimulateQuiescence,
                GovernorOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }

    #[test]
    fn test_convergence_analysis() {
        let input = LyapunovGovernorFuzzInput {
            initial_weights: WeightsConfig {
                w_tasks: WeightValue::Default,
                w_obligation_age: WeightValue::Large,
                w_draining_regions: WeightValue::Default,
                w_deadline_pressure: WeightValue::Default,
            },
            operations: vec![
                GovernorOperation::SimulateObligationPressure { count: 20, age_multiplier: 10 },
                GovernorOperation::SimulateObligationPressure { count: 15, age_multiplier: 8 },
                GovernorOperation::SimulateObligationPressure { count: 10, age_multiplier: 5 },
                GovernorOperation::SimulateObligationPressure { count: 5, age_multiplier: 3 },
                GovernorOperation::SimulateQuiescence,
                GovernorOperation::AnalyzeConvergence,
                GovernorOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }
}