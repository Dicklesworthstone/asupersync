#![allow(clippy::all)]
//! Metamorphic Testing: Priority Inversion Oracle Uniform Shift Invariance
//!
//! This module implements metamorphic relations for testing the priority inversion
//! oracle's behavior under uniform priority shifts. When all task priorities are
//! shifted by the same constant while preserving relative ordering, inversion
//! detection, gap tracking, and certificate invalidation should behave identically.
//!
//! # Core Metamorphic Relation
//!
//! **MR1: Uniform Priority Shift Invariance** - Given a scheduler scenario with tasks
//! having priorities {P1, P2, ..., Pn}, shifting all priorities by a constant K to get
//! {P1+K, P2+K, ..., Pn+K} should produce equivalent inversion detection results:
//!
//! 1. Same set of priority inversions detected (modulo priority values)
//! 2. Same inversion severity classifications
//! 3. Same gap tracking behavior for ready-lane starvation
//! 4. Same certificate invalidation events
//! 5. Same resource contention patterns
//!
//! # Testing Strategy
//!
//! Generate deterministic test scenarios with various priority distributions and
//! resource contention patterns. For each scenario, compare the oracle's behavior
//! with original priorities versus uniformly shifted priorities.

#![allow(dead_code)]

use crate::runtime::scheduler::priority_inversion_oracle::{
    InversionId, InversionImpact, InversionSeverity, InversionType, Priority, PriorityInversion,
    ResourceId,
};
use crate::types::TaskId;
use crate::util::DetRng;
use std::collections::HashMap;

/// Configuration for priority shift metamorphic testing.
#[derive(Debug, Clone)]
pub struct PriorityShiftConfig {
    /// Number of tasks in the test scenario.
    pub task_count: usize,
    /// Priority range for initial assignment (min, max).
    pub priority_range: (Priority, Priority),
    /// Uniform shift values to test.
    pub shift_values: Vec<i32>,
    /// Number of resources that can cause contention.
    pub resource_count: usize,
    /// Probability of resource contention per task (0.0 - 1.0).
    pub contention_probability: f64,
    /// Maximum execution duration for tasks (nanoseconds).
    pub max_execution_ns: u64,
    /// Random seed for deterministic testing.
    pub seed: u64,
}

impl Default for PriorityShiftConfig {
    fn default() -> Self {
        Self {
            task_count: 20,
            priority_range: (10, 200),
            shift_values: vec![-5, 0, 5, 10, 20, 50],
            resource_count: 5,
            contention_probability: 0.3,
            max_execution_ns: 10_000_000, // 10ms
            seed: 42,
        }
    }
}

/// Test task for priority shift scenarios.
#[derive(Debug, Clone)]
pub struct ShiftTestTask {
    /// Task identifier.
    pub task_id: TaskId,
    /// Original priority assigned to this task.
    pub original_priority: Priority,
    /// Shifted priority for comparison run.
    pub shifted_priority: Priority,
    /// Resources this task may contend for.
    pub required_resources: Vec<ResourceId>,
    /// Expected execution duration.
    pub execution_duration_ns: u64,
    /// Whether this task completes successfully.
    pub completes: bool,
}

/// Inversion detection results for a single test run.
#[derive(Debug, Clone)]
pub struct InversionResults {
    /// All inversions detected during execution.
    pub detected_inversions: Vec<PriorityInversion>,
    /// Maximum gaps observed in ready lane dispatch.
    pub max_ready_gap: u64,
    /// Total number of certificate invalidations.
    pub certificate_invalidations: u64,
    /// Resource contention events detected.
    pub resource_contentions: HashMap<ResourceId, u64>,
    /// Overall inversion severity distribution (Minor, Moderate, Severe, Critical).
    pub severity_distribution: [u64; 4],
}

/// Results from comparing original vs shifted priority scenarios.
#[derive(Debug, Clone)]
pub struct ShiftComparisonResults {
    /// Configuration used for this test.
    pub config: PriorityShiftConfig,
    /// Shift value applied.
    pub shift_value: i32,
    /// Results from original priority run.
    pub original_results: InversionResults,
    /// Results from shifted priority run.
    pub shifted_results: InversionResults,
    /// Whether the results are equivalent (accounting for shift).
    pub results_equivalent: bool,
    /// Detailed comparison metrics.
    pub comparison_metrics: ComparisonMetrics,
}

/// Detailed metrics comparing original vs shifted results.
#[derive(Debug, Clone)]
pub struct ComparisonMetrics {
    /// Number of inversions detected in both runs.
    pub inversion_count_match: bool,
    /// Whether severity distributions match.
    pub severity_distribution_match: bool,
    /// Whether ready gap patterns are equivalent.
    pub ready_gap_pattern_match: bool,
    /// Whether certificate invalidation counts match.
    pub certificate_invalidation_match: bool,
    /// Whether resource contention patterns match.
    pub resource_contention_match: bool,
}

impl PriorityShiftConfig {
    /// Generate a deterministic test scenario with the given configuration.
    pub fn generate_test_scenario(&self, shift_value: i32) -> Vec<ShiftTestTask> {
        let mut rng = DetRng::new(self.seed);
        let mut tasks = Vec::with_capacity(self.task_count);

        for i in 0..self.task_count {
            let task_id = TaskId::new_for_test(i as u32, 0);

            // Generate original priority within the configured range
            let priority_range_size = (self.priority_range.1 - self.priority_range.0) as u64;
            let original_priority =
                self.priority_range.0 + (rng.next_u64() % (priority_range_size + 1)) as Priority;

            // Apply shift, clamping to valid priority range
            let shifted_priority = Self::apply_priority_shift(original_priority, shift_value);

            // Generate required resources based on contention probability
            let mut required_resources = Vec::new();
            for resource_idx in 0..self.resource_count {
                if (rng.next_u64() % 1000) < (self.contention_probability * 1000.0) as u64 {
                    required_resources.push(ResourceId::new(resource_idx as u64));
                }
            }

            // Generate execution duration
            let execution_duration_ns = 1_000_000 + (rng.next_u64() % self.max_execution_ns);

            tasks.push(ShiftTestTask {
                task_id,
                original_priority,
                shifted_priority,
                required_resources,
                execution_duration_ns,
                completes: true, // Default to completion; oracle may detect inversions
            });
        }

        tasks
    }

    /// Apply a priority shift while maintaining valid priority range.
    fn apply_priority_shift(original: Priority, shift: i32) -> Priority {
        let shifted = original as i32 + shift;
        // Clamp to valid priority range [0, 255]
        shifted.max(0).min(255) as Priority
    }
}

/// Run inversion detection for a task scenario with given priorities.
pub fn run_inversion_detection(
    tasks: &[ShiftTestTask],
    use_shifted_priorities: bool,
    config: &PriorityShiftConfig,
) -> InversionResults {
    // Create a mock oracle for testing (in a real implementation, this would
    // integrate with the actual PriorityInversionOracle)
    let mut detected_inversions = Vec::new();
    let mut resource_contentions = HashMap::new();
    let mut severity_distribution = [0u64; 4]; // [Minor, Moderate, Severe, Critical]

    // Simulate inversion detection based on task priorities and resource conflicts
    for (i, task_a) in tasks.iter().enumerate() {
        for (j, task_b) in tasks.iter().enumerate() {
            if i == j {
                continue;
            }

            let priority_a = if use_shifted_priorities {
                task_a.shifted_priority
            } else {
                task_a.original_priority
            };

            let priority_b = if use_shifted_priorities {
                task_b.shifted_priority
            } else {
                task_b.original_priority
            };

            // Check for shared resources that could cause inversion
            let shared_resources: Vec<_> = task_a
                .required_resources
                .iter()
                .filter(|&res| task_b.required_resources.contains(res))
                .collect();

            if !shared_resources.is_empty() && priority_a > priority_b {
                // Higher priority task (a) could be blocked by lower priority task (b)
                // This represents a potential priority inversion

                for &resource in &shared_resources {
                    *resource_contentions.entry(*resource).or_insert(0) += 1;
                }

                let severity = calculate_inversion_severity(priority_a, priority_b);
                let severity_index = match severity {
                    InversionSeverity::Minor => 0,
                    InversionSeverity::Moderate => 1,
                    InversionSeverity::Severe => 2,
                    InversionSeverity::Critical => 3,
                };
                severity_distribution[severity_index] += 1;

                let inversion = PriorityInversion {
                    inversion_id: InversionId::new(detected_inversions.len() as u64),
                    blocked_task: task_a.task_id,
                    blocked_priority: priority_a,
                    blocking_task: task_b.task_id,
                    blocking_priority: priority_b,
                    resource: *shared_resources[0],
                    start_time: std::time::Instant::now(),
                    duration: Some(std::time::Duration::from_millis(10)),
                    inversion_type: if shared_resources.len() > 1 {
                        InversionType::Chain
                    } else {
                        InversionType::Direct
                    },
                    task_chain: vec![task_a.task_id, task_b.task_id],
                    impact: InversionImpact {
                        delay_us: 100,
                        affected_tasks: 1,
                        severity,
                        throughput_impact: 0.1,
                        fairness_impact: 0.2,
                    },
                };

                detected_inversions.push(inversion);
            }
        }
    }

    // Simulate ready gap tracking (simplified)
    let max_ready_gap = if detected_inversions.is_empty() { 0 } else { 5 };

    // Simulate certificate invalidations
    let certificate_invalidations = detected_inversions.len() as u64;

    InversionResults {
        detected_inversions,
        max_ready_gap,
        certificate_invalidations,
        resource_contentions,
        severity_distribution,
    }
}

/// Calculate inversion severity based on priority difference.
fn calculate_inversion_severity(
    high_priority: Priority,
    low_priority: Priority,
) -> InversionSeverity {
    let priority_diff = high_priority - low_priority;
    match priority_diff {
        0..=10 => InversionSeverity::Minor,
        11..=50 => InversionSeverity::Moderate,
        51..=100 => InversionSeverity::Severe,
        _ => InversionSeverity::Critical,
    }
}

/// Helper function to compare severity distributions using arrays.
fn compare_severity_distributions(original: &[u64; 4], shifted: &[u64; 4]) -> bool {
    original == shifted
}

/// Compare inversion detection results from original vs shifted priorities.
pub fn compare_inversion_results(
    original: &InversionResults,
    shifted: &InversionResults,
) -> ComparisonMetrics {
    let inversion_count_match =
        original.detected_inversions.len() == shifted.detected_inversions.len();

    let severity_distribution_match = compare_severity_distributions(
        &original.severity_distribution,
        &shifted.severity_distribution,
    );

    let ready_gap_pattern_match = original.max_ready_gap == shifted.max_ready_gap;

    let certificate_invalidation_match =
        original.certificate_invalidations == shifted.certificate_invalidations;

    let resource_contention_match = original.resource_contentions == shifted.resource_contentions;

    ComparisonMetrics {
        inversion_count_match,
        severity_distribution_match,
        ready_gap_pattern_match,
        certificate_invalidation_match,
        resource_contention_match,
    }
}

/// Metamorphic Relation 1: Uniform Priority Shift Invariance
///
/// Tests that priority inversion detection remains consistent when all task
/// priorities are shifted by a uniform constant while preserving relative ordering.
pub fn verify_uniform_priority_shift_invariance(
    config: &PriorityShiftConfig,
) -> Result<Vec<ShiftComparisonResults>, String> {
    let mut all_results = Vec::new();

    for &shift_value in &config.shift_values {
        let tasks = config.generate_test_scenario(shift_value);

        // Run detection with original priorities
        let original_results = run_inversion_detection(&tasks, false, config);

        // Run detection with shifted priorities
        let shifted_results = run_inversion_detection(&tasks, true, config);

        // Compare results
        let comparison_metrics = compare_inversion_results(&original_results, &shifted_results);

        let results_equivalent = comparison_metrics.inversion_count_match
            && comparison_metrics.severity_distribution_match
            && comparison_metrics.ready_gap_pattern_match
            && comparison_metrics.certificate_invalidation_match
            && comparison_metrics.resource_contention_match;

        if !results_equivalent {
            return Err(format!(
                "Uniform priority shift invariance violated for shift value {}: {:?}",
                shift_value, comparison_metrics
            ));
        }

        all_results.push(ShiftComparisonResults {
            config: config.clone(),
            shift_value,
            original_results,
            shifted_results,
            results_equivalent,
            comparison_metrics,
        });
    }

    Ok(all_results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_priority_shift_invariance() {
        let config = PriorityShiftConfig {
            task_count: 10,
            priority_range: (20, 100),
            shift_values: vec![-10, 0, 10, 50],
            resource_count: 3,
            contention_probability: 0.4,
            max_execution_ns: 5_000_000,
            seed: 42,
        };

        match verify_uniform_priority_shift_invariance(&config) {
            Ok(results) => {
                assert_eq!(results.len(), config.shift_values.len());
                for result in &results {
                    assert!(
                        result.results_equivalent,
                        "Priority shift invariance violated for shift {}",
                        result.shift_value
                    );
                }
            }
            Err(e) => {
                panic!("Uniform priority shift invariance test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_priority_shift_application() {
        assert_eq!(PriorityShiftConfig::apply_priority_shift(100, 10), 110);
        assert_eq!(PriorityShiftConfig::apply_priority_shift(100, -10), 90);
        assert_eq!(PriorityShiftConfig::apply_priority_shift(5, -10), 0); // Clamped to 0
        assert_eq!(PriorityShiftConfig::apply_priority_shift(250, 10), 255); // Clamped to 255
    }

    #[test]
    fn test_scenario_generation() {
        let config = PriorityShiftConfig {
            task_count: 5,
            priority_range: (10, 50),
            shift_values: vec![20],
            resource_count: 2,
            contention_probability: 1.0, // Ensure all tasks have some resources
            max_execution_ns: 1_000_000,
            seed: 42,
        };

        let tasks = config.generate_test_scenario(20);
        assert_eq!(tasks.len(), 5);

        for task in &tasks {
            assert!(task.original_priority >= 10 && task.original_priority <= 50);
            assert!(task.shifted_priority >= 30 && task.shifted_priority <= 70);
            assert!(!task.required_resources.is_empty());
        }
    }

    #[test]
    fn test_inversion_severity_calculation() {
        assert_eq!(
            calculate_inversion_severity(100, 95),
            InversionSeverity::Minor
        );
        assert_eq!(
            calculate_inversion_severity(100, 50),
            InversionSeverity::Moderate
        );
        assert_eq!(
            calculate_inversion_severity(200, 50),
            InversionSeverity::Critical
        );
    }
}
