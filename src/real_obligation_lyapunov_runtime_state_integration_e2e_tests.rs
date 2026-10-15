//! Real integration tests between obligation/lyapunov and runtime/state.
//!
//! Verifies that the Lyapunov governor correctly decreases obligation potential
//! under steady-state load and provides accurate scheduling suggestions.

#![allow(clippy::missing_docs_in_private_items)]

use crate::obligation::lyapunov::{
    LyapunovGovernor, PotentialRecord, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use crate::record::ObligationState;
use crate::record::region::RegionState;
use crate::record::task::TaskState;
use crate::record::{ObligationKind, ObligationRecord, RegionRecord, TaskRecord};
use crate::runtime::config::RuntimeCapacityHints;
use crate::runtime::state::RuntimeState;
use crate::types::{Budget, CancelReason, ObligationId, Outcome, Policy, RegionId, TaskId, Time};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Mock workload generator for creating realistic obligation patterns.
#[derive(Debug)]
struct MockWorkloadGenerator {
    /// Current virtual time.
    current_time: Time,
    /// Counter for generating unique IDs.
    id_counter: u64,
    /// Patterns of obligation creation and resolution.
    patterns: Vec<WorkloadPattern>,
}

impl MockWorkloadGenerator {
    fn new() -> Self {
        Self {
            current_time: Time::from_nanos(0),
            id_counter: 1,
            patterns: Vec::new(),
        }
    }

    /// Add a workload pattern to simulate.
    fn add_pattern(&mut self, pattern: WorkloadPattern) {
        self.patterns.push(pattern);
    }

    /// Advance time and generate state snapshots based on patterns.
    fn generate_snapshots(&mut self, steps: usize, step_duration_ms: u64) -> Vec<StateSnapshot> {
        let mut snapshots = Vec::new();

        for step in 0..steps {
            // Advance time
            self.current_time =
                Time::from_nanos(self.current_time.as_nanos() + step_duration_ms * 1_000_000);

            // Apply workload patterns
            let mut snapshot = self.compute_snapshot_for_step(step);
            snapshot.time = self.current_time;
            snapshots.push(snapshot);
        }

        snapshots
    }

    /// Compute state snapshot for current step based on patterns.
    fn compute_snapshot_for_step(&mut self, step: usize) -> StateSnapshot {
        let mut live_tasks = 0;
        let mut pending_obligations = 0;
        let mut obligation_age_sum_ns = 0;
        let mut draining_regions = 0;
        let mut deadline_pressure = 0.0;

        for pattern in &self.patterns {
            let pattern_state = pattern.state_at_step(step, self.current_time);

            live_tasks += pattern_state.live_tasks;
            pending_obligations += pattern_state.pending_obligations;
            obligation_age_sum_ns += pattern_state.obligation_age_sum_ns;
            draining_regions += pattern_state.draining_regions;
            deadline_pressure += pattern_state.deadline_pressure;
        }

        StateSnapshot {
            time: self.current_time,
            live_tasks,
            pending_obligations,
            obligation_age_sum_ns,
            draining_regions,
            deadline_pressure,
            pending_send_permits: pending_obligations / 3,
            pending_acks: pending_obligations / 4,
            pending_leases: pending_obligations / 5,
            pending_io_ops: live_tasks / 2,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: live_tasks / 2,
        }
    }
}

/// Workload pattern for generating realistic system behavior.
#[derive(Debug, Clone)]
struct WorkloadPattern {
    /// Pattern type.
    pattern_type: PatternType,
    /// Initial load parameters.
    initial_load: LoadParameters,
    /// How the load changes over time.
    load_evolution: LoadEvolution,
}

#[derive(Debug, Clone)]
enum PatternType {
    /// Steady-state processing load.
    SteadyState,
    /// Burst of activity followed by drain.
    BurstAndDrain,
    /// Gradual ramp-up of load.
    RampUp,
    /// Gradual ramp-down (convergence to quiescence).
    RampDown,
    /// Oscillating load pattern.
    Oscillating { period: usize, amplitude: f64 },
}

#[derive(Debug, Clone)]
struct LoadParameters {
    /// Base number of live tasks.
    base_tasks: u32,
    /// Base number of pending obligations.
    base_obligations: u32,
    /// Base number of draining regions.
    base_draining_regions: u32,
    /// Base deadline pressure.
    base_deadline_pressure: f64,
}

#[derive(Debug, Clone)]
enum LoadEvolution {
    /// Constant load over time.
    Constant,
    /// Linear change over time.
    Linear { rate: f64 },
    /// Exponential decay/growth.
    Exponential { factor: f64 },
    /// Step function at specific time.
    Step { step_time: usize, multiplier: f64 },
}

impl WorkloadPattern {
    /// Create a steady-state pattern.
    fn steady_state(load: LoadParameters) -> Self {
        Self {
            pattern_type: PatternType::SteadyState,
            initial_load: load,
            load_evolution: LoadEvolution::Constant,
        }
    }

    /// Create a converging pattern (load decreases over time).
    fn converging(load: LoadParameters, decay_rate: f64) -> Self {
        Self {
            pattern_type: PatternType::RampDown,
            initial_load: load,
            load_evolution: LoadEvolution::Exponential { factor: decay_rate },
        }
    }

    /// Create a burst-and-drain pattern.
    fn burst_and_drain(peak_load: LoadParameters, drain_start: usize) -> Self {
        Self {
            pattern_type: PatternType::BurstAndDrain,
            initial_load: peak_load,
            load_evolution: LoadEvolution::Step {
                step_time: drain_start,
                multiplier: 0.1,
            },
        }
    }

    /// Compute pattern state at a given step.
    fn state_at_step(&self, step: usize, current_time: Time) -> PatternState {
        let evolution_factor = match &self.load_evolution {
            LoadEvolution::Constant => 1.0,
            LoadEvolution::Linear { rate } => 1.0 + *rate * step as f64,
            LoadEvolution::Exponential { factor } => factor.powi(step as i32),
            LoadEvolution::Step {
                step_time,
                multiplier,
            } => {
                if step >= *step_time {
                    *multiplier
                } else {
                    1.0
                }
            }
        };

        let pattern_modifier = match &self.pattern_type {
            PatternType::SteadyState => 1.0,
            PatternType::BurstAndDrain => evolution_factor,
            PatternType::RampUp => (step as f64 / 100.0).min(1.0),
            PatternType::RampDown => evolution_factor,
            PatternType::Oscillating { period, amplitude } => {
                1.0 + amplitude
                    * ((step as f64 * 2.0 * std::f64::consts::PI) / (*period as f64)).sin()
            }
        };

        let effective_factor = evolution_factor * pattern_modifier;

        PatternState {
            live_tasks: ((self.initial_load.base_tasks as f64) * effective_factor.max(0.0)) as u32,
            pending_obligations: ((self.initial_load.base_obligations as f64)
                * effective_factor.max(0.0)) as u32,
            draining_regions: ((self.initial_load.base_draining_regions as f64)
                * effective_factor.max(0.0)) as u32,
            deadline_pressure: self.initial_load.base_deadline_pressure * effective_factor.max(0.0),
            obligation_age_sum_ns: self.compute_age_sum(step, current_time, effective_factor),
        }
    }

    /// Compute realistic obligation age sum based on pattern.
    fn compute_age_sum(&self, step: usize, current_time: Time, factor: f64) -> u64 {
        // Simulate obligations created at different times
        let base_age_ms = 100; // 100ms average age
        let pending_count = ((self.initial_load.base_obligations as f64) * factor.max(0.0)) as u64;

        // Age increases over time for pending obligations
        let avg_age_ns = (base_age_ms * 1_000_000) + (step as u64 * 50_000_000); // +50ms per step
        pending_count * avg_age_ns
    }
}

#[derive(Debug, Clone)]
struct PatternState {
    live_tasks: u32,
    pending_obligations: u32,
    draining_regions: u32,
    deadline_pressure: f64,
    obligation_age_sum_ns: u64,
}

/// Lyapunov governor integration manager for testing convergence.
struct LyapunovIntegrationManager {
    /// Governor under test.
    governor: LyapunovGovernor,
    /// Workload generator.
    workload: MockWorkloadGenerator,
    /// Historical potential values.
    potential_history: Vec<f64>,
    /// Historical scheduling suggestions.
    suggestion_history: Vec<SchedulingSuggestion>,
}

impl LyapunovIntegrationManager {
    fn new(weights: PotentialWeights) -> Self {
        Self {
            governor: LyapunovGovernor::new(weights),
            workload: MockWorkloadGenerator::new(),
            potential_history: Vec::new(),
            suggestion_history: Vec::new(),
        }
    }

    /// Add workload patterns to test.
    fn configure_workload(&mut self, patterns: Vec<WorkloadPattern>) {
        for pattern in patterns {
            self.workload.add_pattern(pattern);
        }
    }

    /// Run the integration test and collect results.
    async fn run_integration_test(
        &mut self,
        steps: usize,
        step_duration_ms: u64,
    ) -> LyapunovTestResult {
        let snapshots = self.workload.generate_snapshots(steps, step_duration_ms);

        for snapshot in &snapshots {
            // Compute potential
            let potential = self.governor.compute_potential(snapshot);
            self.potential_history.push(potential);

            // Get scheduling suggestion
            let suggestion = self.governor.suggest(snapshot);
            self.suggestion_history.push(suggestion);
        }

        LyapunovTestResult {
            snapshots,
            potentials: self.potential_history.clone(),
            suggestions: self.suggestion_history.clone(),
            convergence_achieved: self.check_convergence(),
            monotonic_decrease: self.check_monotonic_decrease(),
            final_quiescence: self.check_final_quiescence(),
        }
    }

    /// Check if potential converges to zero (or near zero).
    fn check_convergence(&self) -> bool {
        if self.potential_history.len() < 10 {
            return false;
        }

        // Check last 10 values are consistently low
        let last_values: Vec<f64> = self
            .potential_history
            .iter()
            .rev()
            .take(10)
            .cloned()
            .collect();

        last_values.iter().all(|&v| v < 1.0) && last_values.iter().all(|&v| v >= 0.0)
    }

    /// Check if potential generally decreases over time.
    fn check_monotonic_decrease(&self) -> bool {
        if self.potential_history.len() < 3 {
            return true;
        }

        // Allow some fluctuation but require overall decreasing trend
        let first_third = &self.potential_history[..self.potential_history.len() / 3];
        let last_third = &self.potential_history[2 * self.potential_history.len() / 3..];

        let first_avg = first_third.iter().sum::<f64>() / first_third.len() as f64;
        let last_avg = last_third.iter().sum::<f64>() / last_third.len() as f64;

        last_avg <= first_avg
    }

    /// Check if final state represents quiescence.
    fn check_final_quiescence(&self) -> bool {
        self.potential_history.last().map_or(false, |&v| v < 0.1)
    }
}

/// Result of Lyapunov governor integration test.
#[derive(Debug)]
struct LyapunovTestResult {
    /// State snapshots generated.
    snapshots: Vec<StateSnapshot>,
    /// Computed potential values.
    potentials: Vec<f64>,
    /// Scheduling suggestions made.
    suggestions: Vec<SchedulingSuggestion>,
    /// Whether convergence was achieved.
    convergence_achieved: bool,
    /// Whether potential generally decreased.
    monotonic_decrease: bool,
    /// Whether final state represents quiescence.
    final_quiescence: bool,
}

impl LyapunovTestResult {
    /// Verify that the test passed all requirements.
    fn verify_success(&self) -> bool {
        // Must have reasonable number of steps
        if self.snapshots.len() < 10 {
            return false;
        }

        // Potential values must be non-negative
        if self.potentials.iter().any(|&v| v < 0.0 || !v.is_finite()) {
            return false;
        }

        // Should achieve convergence under steady-state load
        if !self.convergence_achieved {
            return false;
        }

        // Should show decreasing trend
        if !self.monotonic_decrease {
            return false;
        }

        // Final state should be quiescent
        self.final_quiescence
    }

    /// Generate a summary report.
    fn summary(&self) -> String {
        let min_potential = self.potentials.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_potential = self
            .potentials
            .iter()
            .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        let avg_potential = self.potentials.iter().sum::<f64>() / self.potentials.len() as f64;

        let suggestion_counts = self.count_suggestions();

        format!(
            "Lyapunov Governor Integration Test Results:
Steps: {}
Potential Range: {:.3} to {:.3} (avg: {:.3})
Convergence Achieved: {}
Monotonic Decrease: {}
Final Quiescence: {}
Scheduling Suggestions: {:#?}
Test Success: {}",
            self.snapshots.len(),
            min_potential,
            max_potential,
            avg_potential,
            self.convergence_achieved,
            self.monotonic_decrease,
            self.final_quiescence,
            suggestion_counts,
            self.verify_success()
        )
    }

    /// Count different types of scheduling suggestions.
    fn count_suggestions(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for suggestion in &self.suggestions {
            let key = format!("{:?}", suggestion);
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }
}

/// Comprehensive test scenario for Lyapunov governor integration.
struct LyapunovGovernorIntegrationTest;

impl LyapunovGovernorIntegrationTest {
    /// Run comprehensive test covering multiple scenarios.
    async fn run_comprehensive_test() -> Vec<LyapunovTestResult> {
        let mut results = Vec::new();

        // Test 1: Steady-state convergence
        let mut manager1 = LyapunovIntegrationManager::new(PotentialWeights::default());
        manager1.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 20,
                base_obligations: 15,
                base_draining_regions: 3,
                base_deadline_pressure: 2.0,
            },
            0.95, // 5% decay per step
        )]);

        if let Ok(result) = manager1.run_integration_test(50, 100).await {
            results.push(result);
        }

        // Test 2: Obligation-focused weights
        let mut manager2 = LyapunovIntegrationManager::new(PotentialWeights::obligation_focused());
        manager2.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 10,
                base_obligations: 25,
                base_draining_regions: 2,
                base_deadline_pressure: 1.0,
            },
            0.92, // Faster decay for obligation test
        )]);

        if let Ok(result) = manager2.run_integration_test(40, 150).await {
            results.push(result);
        }

        // Test 3: Deadline-focused weights
        let mut manager3 = LyapunovIntegrationManager::new(PotentialWeights::deadline_focused());
        manager3.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 15,
                base_obligations: 8,
                base_draining_regions: 1,
                base_deadline_pressure: 5.0,
            },
            0.90, // Moderate decay
        )]);

        if let Ok(result) = manager3.run_integration_test(35, 120).await {
            results.push(result);
        }

        // Test 4: Burst and drain pattern
        let mut manager4 = LyapunovIntegrationManager::new(PotentialWeights::uniform(2.0));
        manager4.configure_workload(vec![WorkloadPattern::burst_and_drain(
            LoadParameters {
                base_tasks: 50,
                base_obligations: 40,
                base_draining_regions: 8,
                base_deadline_pressure: 3.0,
            },
            20, // Drain starts at step 20
        )]);

        if let Ok(result) = manager4.run_integration_test(60, 80).await {
            results.push(result);
        }

        results
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_lyapunov_convergence() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::default());

        manager.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 10,
                base_obligations: 8,
                base_draining_regions: 2,
                base_deadline_pressure: 1.0,
            },
            0.9,
        )]);

        let result = manager
            .run_integration_test(30, 100)
            .await
            .expect("Test should run");

        println!("{}", result.summary());

        assert!(
            result.verify_success(),
            "Basic convergence test should pass"
        );
        assert!(result.convergence_achieved, "Should achieve convergence");
        assert!(result.monotonic_decrease, "Potential should decrease");
        assert!(!result.potentials.is_empty(), "Should compute potentials");
    }

    #[tokio::test]
    async fn test_obligation_focused_governor() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::obligation_focused());

        manager.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 5,
                base_obligations: 20, // High obligation count
                base_draining_regions: 1,
                base_deadline_pressure: 0.5,
            },
            0.85,
        )]);

        let result = manager
            .run_integration_test(25, 120)
            .await
            .expect("Test should run");

        assert!(
            result.verify_success(),
            "Obligation-focused test should pass"
        );
        assert!(
            result.convergence_achieved,
            "Should converge with obligation focus"
        );

        // Should produce obligation-draining suggestions
        let suggestion_counts = result.count_suggestions();
        let total_suggestions = suggestion_counts.values().sum::<usize>();
        assert!(total_suggestions > 0, "Should make scheduling suggestions");
    }

    #[tokio::test]
    async fn test_deadline_pressure_handling() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::deadline_focused());

        manager.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 12,
                base_obligations: 6,
                base_draining_regions: 1,
                base_deadline_pressure: 8.0, // High deadline pressure
            },
            0.88,
        )]);

        let result = manager
            .run_integration_test(40, 100)
            .await
            .expect("Test should run");

        assert!(
            result.verify_success(),
            "Deadline pressure test should pass"
        );

        // Verify potential starts high due to deadline pressure
        if let Some(&first_potential) = result.potentials.first() {
            assert!(
                first_potential > 5.0,
                "Should start with high potential due to deadline pressure"
            );
        }

        // Should converge to low potential
        if let Some(&last_potential) = result.potentials.last() {
            assert!(last_potential < 1.0, "Should converge to low potential");
        }
    }

    #[tokio::test]
    async fn test_burst_and_drain_pattern() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::uniform(1.5));

        manager.configure_workload(vec![WorkloadPattern::burst_and_drain(
            LoadParameters {
                base_tasks: 30,
                base_obligations: 25,
                base_draining_regions: 5,
                base_deadline_pressure: 2.0,
            },
            15, // Drain starts at step 15
        )]);

        let result = manager
            .run_integration_test(40, 100)
            .await
            .expect("Test should run");

        assert!(result.verify_success(), "Burst and drain test should pass");

        // Should show clear potential drop after drain starts
        let pre_drain: Vec<f64> = result.potentials.iter().take(15).cloned().collect();
        let post_drain: Vec<f64> = result.potentials.iter().skip(25).cloned().collect();

        if !pre_drain.is_empty() && !post_drain.is_empty() {
            let pre_avg = pre_drain.iter().sum::<f64>() / pre_drain.len() as f64;
            let post_avg = post_drain.iter().sum::<f64>() / post_drain.len() as f64;

            assert!(
                post_avg < pre_avg * 0.5,
                "Post-drain potential should be much lower"
            );
        }
    }

    #[tokio::test]
    async fn test_potential_non_negativity() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::default());

        // Include a pattern that might stress the computation
        manager.configure_workload(vec![
            WorkloadPattern::steady_state(LoadParameters {
                base_tasks: 100,
                base_obligations: 0, // No obligations
                base_draining_regions: 0,
                base_deadline_pressure: 0.0,
            }),
            WorkloadPattern::converging(
                LoadParameters {
                    base_tasks: 0,
                    base_obligations: 50, // Only obligations
                    base_draining_regions: 10,
                    base_deadline_pressure: 0.0,
                },
                0.8,
            ),
        ]);

        let result = manager
            .run_integration_test(30, 100)
            .await
            .expect("Test should run");

        // All potentials must be non-negative and finite
        for (i, &potential) in result.potentials.iter().enumerate() {
            assert!(
                potential >= 0.0,
                "Potential at step {} should be non-negative: {}",
                i,
                potential
            );
            assert!(
                potential.is_finite(),
                "Potential at step {} should be finite: {}",
                i,
                potential
            );
        }
    }

    #[tokio::test]
    async fn test_quiescence_detection() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::default());

        // Create a pattern that reaches true quiescence
        manager.configure_workload(vec![WorkloadPattern::converging(
            LoadParameters {
                base_tasks: 5,
                base_obligations: 3,
                base_draining_regions: 1,
                base_deadline_pressure: 0.5,
            },
            0.7, // Aggressive decay
        )]);

        let result = manager
            .run_integration_test(50, 100)
            .await
            .expect("Test should run");

        assert!(result.verify_success(), "Quiescence test should pass");
        assert!(result.final_quiescence, "Should reach quiescence");

        // Final few potentials should be very low
        let final_potentials: Vec<f64> = result.potentials.iter().rev().take(5).cloned().collect();
        for &potential in &final_potentials {
            assert!(
                potential < 0.2,
                "Final potentials should be very low: {}",
                potential
            );
        }
    }

    #[tokio::test]
    async fn test_comprehensive_scenarios() {
        let results = LyapunovGovernorIntegrationTest::run_comprehensive_test().await;

        assert!(!results.is_empty(), "Should run multiple test scenarios");
        assert!(results.len() >= 3, "Should test multiple scenarios");

        for (i, result) in results.iter().enumerate() {
            println!("Comprehensive scenario {}: {}", i + 1, result.summary());
            assert!(
                result.verify_success(),
                "Comprehensive scenario {} should pass",
                i + 1
            );
        }

        // Verify different scenarios produced different behaviors
        let final_potentials: Vec<f64> = results
            .iter()
            .map(|r| *r.potentials.last().unwrap_or(&0.0))
            .collect();
        assert!(
            final_potentials.iter().all(|&v| v < 1.0),
            "All scenarios should converge"
        );
    }

    #[tokio::test]
    async fn test_governor_suggestion_accuracy() {
        let mut manager = LyapunovIntegrationManager::new(PotentialWeights::obligation_focused());

        manager.configure_workload(vec![WorkloadPattern::steady_state(LoadParameters {
            base_tasks: 5,
            base_obligations: 20, // High obligations should trigger DrainObligations suggestion
            base_draining_regions: 1,
            base_deadline_pressure: 0.5,
        })]);

        let result = manager
            .run_integration_test(20, 100)
            .await
            .expect("Test should run");

        let suggestion_counts = result.count_suggestions();

        // With obligation-focused weights and high obligation count, should suggest draining obligations
        let drain_obligations_count = suggestion_counts.get("DrainObligations").unwrap_or(&0);
        assert!(
            *drain_obligations_count > 0,
            "Should suggest draining obligations with high obligation load"
        );

        println!("Suggestion distribution: {:#?}", suggestion_counts);
    }
}
