#![allow(clippy::all)]
//! Metamorphic Testing: Priority Inversion Oracle Uniform Shift Invariance
//!
//! This module implements metamorphic relations for testing the priority inversion
//! oracle's behavior under uniform priority shifts. When all task priorities are
//! shifted by the same constant while preserving relative ordering, inversion
//! detection should behave identically.
//!
//! # Core Metamorphic Relation
//!
//! **MR1: Uniform Priority Shift Invariance** - Given a scheduler scenario with tasks
//! having priorities {P1, P2, ..., Pn}, shifting all priorities by a constant K to get
//! {P1+K, P2+K, ..., Pn+K} should produce equivalent inversion detection results:
//!
//! 1. Same set of priority inversions detected (modulo priority values)
//! 2. Same inversion severity classifications
//! 3. Same total inversion counts reported by the production oracle
//! 4. Same resource contention patterns
//!
//! # Testing Strategy
//!
//! Generate deterministic test scenarios with various priority distributions and
//! resource contention patterns. For each scenario, compare the oracle's behavior
//! with original priorities versus uniformly shifted priorities.

#![allow(dead_code)]

use crate::runtime::scheduler::priority::DispatchLane;
use crate::runtime::scheduler::priority_inversion_oracle::{
    InversionOracleConfig, InversionSeverity, InversionType, Priority, PriorityInversion,
    PriorityInversionOracle, ResourceId,
};
use crate::types::TaskId;
use crate::util::DetRng;
use std::collections::{HashMap, HashSet};

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
    /// All active inversions detected during execution.
    pub detected_inversions: Vec<PriorityInversion>,
    /// Total inversion count reported by the production oracle.
    pub total_inversions: u64,
    /// Active inversion count reported by the production oracle.
    pub active_inversions: u64,
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
    /// Whether the same blocked-task/blocking-task/resource signatures were detected.
    pub inversion_signature_match: bool,
    /// Whether severity distributions match.
    pub severity_distribution_match: bool,
    /// Whether the oracle reported the same total inversion count.
    pub total_inversion_match: bool,
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

fn shift_preserves_ordering(tasks: &[ShiftTestTask], shift_value: i32) -> bool {
    tasks.iter().all(|task| {
        i32::from(task.original_priority) + shift_value == i32::from(task.shifted_priority)
    })
}

fn inversion_signature(inversion: &PriorityInversion) -> (TaskId, TaskId, ResourceId, bool) {
    (
        inversion.blocked_task,
        inversion.blocking_task,
        inversion.resource,
        matches!(inversion.inversion_type, InversionType::Chain),
    )
}

/// Run inversion detection for a task scenario with given priorities.
///
/// Drives the real `PriorityInversionOracle` rather than computing a
/// hand-rolled priority diff: the metamorphic invariant we want to
/// pin is that the *production* oracle is shift-invariant, not that
/// `(a - b)` is shift-invariant (which is trivially true).
///
/// Construction sequence per scenario:
///  1. Spawn every task into the oracle (`track_task_spawned`).
///  2. For each resource referenced by ≥2 tasks: have the lowest-
///     priority sharer acquire the resource, then have every other
///     sharer call `track_resource_waiting` in priority-ascending
///     order. Each waiting call where the waiter's priority exceeds
///     the holder's plus `priority_threshold` is what the oracle
///     reports as a `PriorityInversion`.
///  3. Read `get_active_inversions()` and `get_stats()` and project
///     into the metamorphic-test struct.
pub fn run_inversion_detection(
    tasks: &[ShiftTestTask],
    use_shifted_priorities: bool,
    _config: &PriorityShiftConfig,
) -> InversionResults {
    let oracle = PriorityInversionOracle::with_config(InversionOracleConfig {
        min_inversion_duration_us: 0,
        priority_threshold: 1,
        detect_chain_inversions: false,
        enable_impact_analysis: true,
        ..InversionOracleConfig::default()
    });

    let priority_of = |task: &ShiftTestTask| -> Priority {
        if use_shifted_priorities {
            task.shifted_priority
        } else {
            task.original_priority
        }
    };

    // Step 1: spawn every task. DispatchLane::Ready and worker_id=None
    // are diagnostic defaults; the oracle uses them only for reporting;
    // inversion detection only inspects `priority`.
    for task in tasks {
        oracle.track_task_spawned(task.task_id, priority_of(task), DispatchLane::Ready, None);
    }

    // Step 2: build per-resource sharer lists while keeping a stable
    // discovery order. `ResourceId` is hashable but not orderable, so
    // we cannot use a `BTreeMap` here.
    let mut sharers: HashMap<ResourceId, Vec<(Priority, TaskId)>> = HashMap::new();
    let mut resource_order = Vec::new();
    for task in tasks {
        for &resource in &task.required_resources {
            if !sharers.contains_key(&resource) {
                resource_order.push(resource);
            }
            sharers
                .entry(resource)
                .or_default()
                .push((priority_of(task), task.task_id));
        }
    }

    for resource in resource_order {
        let Some(users) = sharers.get_mut(&resource) else {
            continue;
        };
        if users.len() < 2 {
            continue;
        }

        // Lowest priority owns first; on tie, lowest task id.
        users.sort();
        let (_, owner_task) = users[0];
        oracle.track_resource_acquired(owner_task, resource);
        // Every higher-priority sharer waits — each call may register
        // an inversion on the owner. priority-ascending wait order
        // matches the deterministic sort, so the oracle's per-resource
        // detection sequence is identical between the original and
        // shifted runs (modulo the priority numbers themselves).
        for &(_, waiter) in &users[1..] {
            oracle.track_resource_waiting(waiter, resource);
        }
    }

    // Step 3: harvest the oracle's view.
    let detected_inversions = oracle.get_active_inversions();
    let stats = oracle.get_stats();
    let mut resource_contentions: HashMap<ResourceId, u64> = HashMap::new();
    let mut severity_distribution = [0u64; 4];
    for inv in &detected_inversions {
        *resource_contentions.entry(inv.resource).or_insert(0) += 1;
        let idx = match inv.impact.severity {
            InversionSeverity::Minor => 0,
            InversionSeverity::Moderate => 1,
            InversionSeverity::Severe => 2,
            InversionSeverity::Critical => 3,
        };
        severity_distribution[idx] += 1;
    }

    InversionResults {
        detected_inversions,
        total_inversions: stats.total_inversions,
        active_inversions: stats.active_inversions,
        resource_contentions,
        severity_distribution,
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
    let inversion_signature_match = original
        .detected_inversions
        .iter()
        .map(inversion_signature)
        .collect::<HashSet<_>>()
        == shifted
            .detected_inversions
            .iter()
            .map(inversion_signature)
            .collect::<HashSet<_>>();

    let severity_distribution_match = compare_severity_distributions(
        &original.severity_distribution,
        &shifted.severity_distribution,
    );
    let total_inversion_match = original.total_inversions == shifted.total_inversions;

    let resource_contention_match = original.resource_contentions == shifted.resource_contentions;

    ComparisonMetrics {
        inversion_count_match,
        inversion_signature_match,
        severity_distribution_match,
        total_inversion_match,
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
        if !shift_preserves_ordering(&tasks, shift_value) {
            return Err(format!(
                "Uniform priority shift invariance requires unclamped priorities for shift {}",
                shift_value
            ));
        }

        // Run detection with original priorities
        let original_results = run_inversion_detection(&tasks, false, config);
        if original_results.total_inversions == 0 {
            return Err(format!(
                "Priority shift scenario for shift {} did not exercise the production oracle",
                shift_value
            ));
        }

        // Run detection with shifted priorities
        let shifted_results = run_inversion_detection(&tasks, true, config);

        // Compare results
        let comparison_metrics = compare_inversion_results(&original_results, &shifted_results);

        let results_equivalent = comparison_metrics.inversion_count_match
            && comparison_metrics.inversion_signature_match
            && comparison_metrics.severity_distribution_match
            && comparison_metrics.total_inversion_match
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

        let results = verify_uniform_priority_shift_invariance(&config);
        assert!(
            results.is_ok(),
            "Uniform priority shift invariance test failed: {:?}",
            results
        );
        let Ok(results) = results else {
            return;
        };

        assert_eq!(results.len(), config.shift_values.len());
        for result in &results {
            assert!(
                result.results_equivalent,
                "Priority shift invariance violated for shift {}",
                result.shift_value
            );
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
        let config = PriorityShiftConfig {
            task_count: 3,
            priority_range: (10, 12),
            shift_values: vec![5],
            resource_count: 1,
            contention_probability: 1.0,
            max_execution_ns: 1_000_000,
            seed: 7,
        };
        let tasks = config.generate_test_scenario(5);
        let results = run_inversion_detection(&tasks, false, &config);

        assert_eq!(results.total_inversions, results.active_inversions);
        assert!(!results.detected_inversions.is_empty());
        assert_eq!(
            results.severity_distribution.iter().sum::<u64>(),
            results.detected_inversions.len() as u64
        );
    }

    #[test]
    fn test_uniform_shift_rejects_clamped_priorities() {
        let config = PriorityShiftConfig {
            task_count: 4,
            priority_range: (250, 255),
            shift_values: vec![10],
            resource_count: 1,
            contention_probability: 1.0,
            max_execution_ns: 1_000_000,
            seed: 11,
        };

        let error = verify_uniform_priority_shift_invariance(&config)
            .expect_err("clamped shifts should be rejected");
        assert!(error.contains("requires unclamped priorities"));
    }
}
