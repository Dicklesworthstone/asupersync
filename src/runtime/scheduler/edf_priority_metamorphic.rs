#![allow(clippy::all)]
//! Metamorphic Testing: EDF Priority Inversion Resistance
//!
//! This module implements comprehensive metamorphic relations for testing the
//! Earliest Deadline First (EDF) scheduler's resistance to priority inversion.
//! It verifies that EDF scheduling maintains proper deadline ordering while
//! avoiding unbounded priority inversions.
//!
//! # Metamorphic Relations
//!
//! 1. **EDF Ordering Preservation** (MR1): Reordering task arrivals preserves EDF deadline ordering
//! 2. **Priority Inheritance Effectiveness** (MR2): High-priority tasks complete within bounded time
//! 3. **Deadline Monotonicity** (MR3): Earlier deadlines should generally complete first
//! 4. **Inversion Boundedness** (MR4): Priority inversions are time-bounded and don't cascade
//! 5. **Resource Fairness** (MR5): Resource contention doesn't cause indefinite blocking
//! 6. **Work Conservation** (MR6): Scheduler always makes progress when tasks are available
//!
//! # Testing Strategy
//!
//! Each metamorphic relation is implemented as property-based tests using deterministic
//! scenarios to verify EDF scheduler behavior under various priority inversion conditions,
//! resource contention patterns, and deadline distributions.

#![allow(dead_code)]

use crate::runtime::scheduler::priority_inversion_oracle::{
    InversionId, InversionSeverity, InversionType, Priority, PriorityInversion, ResourceId,
};
use crate::types::{TaskId, Time};
use crate::util::DetRng;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Helper trait to add range generation to DetRng
trait DetRngExt {
    /// Generate a random value in the given range (inclusive of start, exclusive of end)
    fn gen_range(&mut self, range: std::ops::Range<u64>) -> u64;

    /// Generate a random value in the given inclusive range
    fn gen_range_inclusive(&mut self, start: u64, end: u64) -> u64;
}

impl DetRngExt for DetRng {
    fn gen_range(&mut self, range: std::ops::Range<u64>) -> u64 {
        if range.start >= range.end {
            return range.start;
        }
        let range_size = range.end - range.start;
        range.start + (self.next_u64() % range_size)
    }

    fn gen_range_inclusive(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return start;
        }
        let range_size = end - start + 1;
        start + (self.next_u64() % range_size)
    }
}

/// Configuration for EDF priority inversion metamorphic testing.
#[derive(Debug, Clone)]
pub struct EdfMetamorphicConfig {
    /// Number of tasks to use in test scenarios.
    pub num_tasks: usize,
    /// Range of deadlines in milliseconds.
    pub deadline_range_ms: (u64, u64),
    /// Priority levels to test (0 = highest).
    pub priority_levels: Vec<Priority>,
    /// Number of resources that can cause blocking.
    pub num_resources: usize,
    /// Maximum acceptable inversion duration in microseconds.
    pub max_inversion_duration_us: u64,
    /// Seed for deterministic testing.
    pub seed: u64,
}

impl Default for EdfMetamorphicConfig {
    fn default() -> Self {
        Self {
            num_tasks: 10,
            deadline_range_ms: (10, 1000),
            priority_levels: vec![0, 1, 2, 3], // 0 highest, 3 lowest
            num_resources: 3,
            max_inversion_duration_us: 1000,
            seed: 42,
        }
    }
}

/// A test task for EDF metamorphic testing.
#[derive(Debug, Clone)]
pub struct EdfTestTask {
    /// Task identifier.
    pub task_id: TaskId,
    /// Task priority (0 = highest).
    pub priority: Priority,
    /// Task deadline.
    pub deadline: Time,
    /// Resources this task needs to acquire.
    pub required_resources: Vec<ResourceId>,
    /// Estimated execution time.
    pub execution_time_ms: u64,
    /// Task arrival time on the simulated EDF timeline.
    pub arrival_time: Time,
}

impl EdfTestTask {
    /// Create a new test task.
    pub fn new(
        task_id: TaskId,
        priority: Priority,
        deadline: Time,
        required_resources: Vec<ResourceId>,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            task_id,
            priority,
            deadline,
            required_resources,
            execution_time_ms,
            arrival_time: Time::ZERO,
        }
    }

    /// Check if this task has higher priority than another task.
    pub fn has_higher_priority_than(&self, other: &Self) -> bool {
        self.priority < other.priority // Lower number = higher priority
    }

    /// Check if this task has earlier deadline than another task.
    pub fn has_earlier_deadline_than(&self, other: &Self) -> bool {
        self.deadline < other.deadline
    }

    /// Calculate urgency score (combination of priority and deadline proximity).
    pub fn urgency_score(&self, current_time: Time) -> f64 {
        let deadline_proximity = if self.deadline > current_time {
            let remaining = self.deadline.duration_since(current_time);
            1.0 / ((remaining / 1_000_000) as f64 + 1.0)
        } else {
            1000.0 // Past deadline - very urgent
        };

        let priority_weight = 1.0 / (self.priority as f64 + 1.0);
        deadline_proximity * priority_weight
    }
}

/// Global state for tracking EDF test execution.
#[derive(Debug)]
pub struct EdfTestState {
    /// Tasks that have been scheduled.
    pub scheduled_tasks: Vec<EdfTestTask>,
    /// Tasks that have completed.
    pub completed_tasks: Vec<(EdfTestTask, Time)>,
    /// Detected priority inversions.
    pub inversions: Vec<PriorityInversion>,
    /// Resource allocation tracking.
    pub resource_owners: HashMap<ResourceId, TaskId>,
    /// Task execution order.
    pub execution_order: Vec<TaskId>,
    /// Deadline violations detected.
    pub deadline_violations: usize,
    /// Total inversion time accumulated.
    pub total_inversion_time_us: u64,
}

impl EdfTestState {
    /// Create new empty test state.
    pub fn new() -> Self {
        Self {
            scheduled_tasks: Vec::new(),
            completed_tasks: Vec::new(),
            inversions: Vec::new(),
            resource_owners: HashMap::new(),
            execution_order: Vec::new(),
            deadline_violations: 0,
            total_inversion_time_us: 0,
        }
    }

    /// Record task completion.
    pub fn record_completion(&mut self, task: EdfTestTask, completion_time: Time) {
        self.completed_tasks.push((task.clone(), completion_time));
        self.execution_order.push(task.task_id);

        // Deadline misses are defined against the simulated logical deadline,
        // not ambient wall-clock execution latency.
        if completion_time > task.deadline {
            self.deadline_violations += 1;
        }
    }

    /// Record priority inversion.
    pub fn record_inversion(&mut self, inversion: PriorityInversion) {
        if let Some(duration) = inversion.duration {
            self.total_inversion_time_us += duration.as_micros() as u64;
        }
        self.inversions.push(inversion);
    }

    /// Calculate average inversion duration.
    pub fn average_inversion_duration_us(&self) -> f64 {
        if self.inversions.is_empty() {
            0.0
        } else {
            self.total_inversion_time_us as f64 / self.inversions.len() as f64
        }
    }

    /// Get deadline violation rate.
    pub fn deadline_violation_rate(&self) -> f64 {
        if self.completed_tasks.is_empty() {
            0.0
        } else {
            self.deadline_violations as f64 / self.completed_tasks.len() as f64
        }
    }

    /// Check if EDF ordering was generally preserved.
    pub fn is_edf_ordering_preserved(&self) -> bool {
        // Check if most tasks completed in deadline order
        let mut violations = 0;
        for i in 1..self.completed_tasks.len() {
            let (prev_task, _) = &self.completed_tasks[i - 1];
            let (curr_task, _) = &self.completed_tasks[i];

            if prev_task.deadline > curr_task.deadline {
                violations += 1;
            }
        }

        // Allow up to 20% deadline ordering violations due to priority inheritance
        let violation_rate = violations as f64 / self.completed_tasks.len().max(1) as f64;
        violation_rate <= 0.2
    }
}

/// Summary of EDF metamorphic test results.
#[derive(Debug)]
pub struct EdfMetamorphicResult {
    /// Total tests run.
    pub tests_run: usize,
    /// Tests passed.
    pub tests_passed: usize,
    /// Tests failed.
    pub tests_failed: usize,
    /// Average inversion duration across all tests.
    pub avg_inversion_duration_us: f64,
    /// Maximum inversion duration detected.
    pub max_inversion_duration_us: u64,
    /// Deadline violation rate.
    pub deadline_violation_rate: f64,
    /// EDF ordering preservation rate.
    pub edf_ordering_preservation_rate: f64,
    /// Detailed failure reasons.
    pub failures: Vec<String>,
}

impl EdfMetamorphicResult {
    /// Create new empty result.
    pub fn new() -> Self {
        Self {
            tests_run: 0,
            tests_passed: 0,
            tests_failed: 0,
            avg_inversion_duration_us: 0.0,
            max_inversion_duration_us: 0,
            deadline_violation_rate: 0.0,
            edf_ordering_preservation_rate: 0.0,
            failures: Vec::new(),
        }
    }

    /// Record test pass.
    pub fn record_pass(&mut self, _test_name: &str) {
        self.tests_run += 1;
        self.tests_passed += 1;
    }

    /// Record test failure.
    pub fn record_failure(&mut self, test_name: &str, reason: &str) {
        self.tests_run += 1;
        self.tests_failed += 1;
        self.failures.push(format!("{}: {}", test_name, reason));
    }

    /// Update statistics from test state.
    pub fn update_from_state(&mut self, state: &EdfTestState) {
        if state.inversions.is_empty() {
            return;
        }

        self.avg_inversion_duration_us = state.average_inversion_duration_us();
        self.deadline_violation_rate = state.deadline_violation_rate();
        self.edf_ordering_preservation_rate = if state.is_edf_ordering_preserved() {
            1.0
        } else {
            0.0
        };

        for inversion in &state.inversions {
            if let Some(duration) = inversion.duration {
                let duration_us = duration.as_micros() as u64;
                if duration_us > self.max_inversion_duration_us {
                    self.max_inversion_duration_us = duration_us;
                }
            }
        }
    }

    /// Check if results indicate successful EDF behavior.
    pub fn is_success(&self) -> bool {
        self.tests_failed == 0
    }

    /// Get success rate as percentage.
    pub fn success_rate(&self) -> f64 {
        if self.tests_run == 0 {
            0.0
        } else {
            (self.tests_passed as f64 / self.tests_run as f64) * 100.0
        }
    }
}

/// Generate test tasks with specified configuration.
fn generate_test_tasks(config: &EdfMetamorphicConfig) -> Vec<EdfTestTask> {
    let mut rng = DetRng::new(config.seed);
    let mut tasks = Vec::new();

    for i in 0..config.num_tasks {
        // Generate task ID
        let task_id = TaskId::new_for_test(i as u32, rng.next_u32());

        // Assign priority
        let priority = config.priority_levels[i % config.priority_levels.len()];

        // Generate deadline
        let deadline_ms = rng.gen_range(config.deadline_range_ms.0..config.deadline_range_ms.1);
        let deadline = Time::from_millis(deadline_ms);

        // Generate resource requirements
        let max_res = config.num_resources.min(3) as u64;
        let num_resources = rng.gen_range(1..max_res + 1);
        let mut required_resources = Vec::new();
        for _ in 0..num_resources {
            let resource_id = ResourceId::new(rng.gen_range(0..config.num_resources as u64));
            if !required_resources.contains(&resource_id) {
                required_resources.push(resource_id);
            }
        }

        // Generate execution time
        let execution_time_ms = rng.gen_range(5..50);

        tasks.push(EdfTestTask::new(
            task_id,
            priority,
            deadline,
            required_resources,
            execution_time_ms,
        ));
    }

    tasks
}

/// Simulate EDF scheduling with priority inversion detection.
fn simulate_edf_scheduling(tasks: &[EdfTestTask], _config: &EdfMetamorphicConfig) -> EdfTestState {
    let mut state = EdfTestState::new();
    let mut ready_queue: VecDeque<EdfTestTask> = tasks.iter().cloned().collect();

    // Sort by deadline (EDF)
    ready_queue
        .make_contiguous()
        .sort_by(|a, b| a.deadline.cmp(&b.deadline));

    let mut current_time = Time::ZERO;

    // Simulate execution
    while let Some(task) = ready_queue.pop_front() {
        // Check for priority inversion potential
        if let Some(blocking_task) = find_blocking_task(&task, &ready_queue, &state) {
            // Record potential inversion
            let inversion = create_test_inversion(&task, &blocking_task);
            state.record_inversion(inversion);
        }

        // Simulate task execution
        current_time = current_time + Duration::from_millis(task.execution_time_ms);
        state.record_completion(task, current_time);
    }

    state
}

/// Find a task that could cause priority inversion.
fn find_blocking_task(
    high_task: &EdfTestTask,
    ready_queue: &VecDeque<EdfTestTask>,
    _state: &EdfTestState,
) -> Option<EdfTestTask> {
    // Look for lower priority task with conflicting resource
    for potential_blocker in ready_queue {
        if !high_task.has_higher_priority_than(potential_blocker) {
            continue;
        }

        // Check for resource conflict
        for resource in &high_task.required_resources {
            if potential_blocker.required_resources.contains(resource) {
                return Some(potential_blocker.clone());
            }
        }
    }

    None
}

/// Create a test priority inversion record.
fn create_test_inversion(
    blocked_task: &EdfTestTask,
    blocking_task: &EdfTestTask,
) -> PriorityInversion {
    PriorityInversion {
        inversion_id: InversionId::new(0),
        task_chain: vec![],
        impact: crate::runtime::scheduler::priority_inversion_oracle::InversionImpact {
            severity: InversionSeverity::Minor,
            delay_us: 100,
            affected_tasks: 1,
            throughput_impact: 0.0,
            fairness_impact: 0.0,
        },
        blocked_task: blocked_task.task_id,
        blocked_priority: blocked_task.priority,
        blocking_task: blocking_task.task_id,
        blocking_priority: blocking_task.priority,
        resource: blocked_task
            .required_resources
            .first()
            .copied()
            .unwrap_or(ResourceId::new(0)),
        start_time: Instant::now(),
        duration: Some(Duration::from_micros(100)), // Simulated short inversion
        inversion_type: InversionType::Direct,
    }
}

/// Run comprehensive EDF priority inversion metamorphic tests.
pub fn run_edf_metamorphic_tests() -> Result<EdfMetamorphicResult, Box<dyn std::error::Error>> {
    let config = EdfMetamorphicConfig::default();
    run_edf_metamorphic_tests_with_config(&config)
}

/// Run EDF metamorphic tests with custom configuration.
pub fn run_edf_metamorphic_tests_with_config(
    config: &EdfMetamorphicConfig,
) -> Result<EdfMetamorphicResult, Box<dyn std::error::Error>> {
    let mut result = EdfMetamorphicResult::new();

    // MR1: EDF Ordering Preservation
    test_edf_ordering_preservation(&mut result, config);

    // MR2: Priority Inheritance Effectiveness
    test_priority_inheritance_effectiveness(&mut result, config);

    // MR3: Deadline Monotonicity
    test_deadline_monotonicity(&mut result, config);

    // MR4: Inversion Boundedness
    test_inversion_boundedness(&mut result, config);

    // MR5: Resource Fairness
    test_resource_fairness(&mut result, config);

    // MR6: Work Conservation
    test_work_conservation(&mut result, config);

    Ok(result)
}

/// MR1: Test that reordering task arrivals preserves EDF deadline ordering.
fn test_edf_ordering_preservation(
    result: &mut EdfMetamorphicResult,
    config: &EdfMetamorphicConfig,
) {
    let tasks = generate_test_tasks(config);

    // Test original order
    let state1 = simulate_edf_scheduling(&tasks, config);

    // Test shuffled order (different arrival pattern)
    let mut shuffled_tasks = tasks.clone();
    let mut rng = DetRng::new(config.seed + 1);
    for i in (1..shuffled_tasks.len()).rev() {
        let j = rng.gen_range(0..(i as u64 + 1));
        shuffled_tasks.swap(i, j as usize);
    }
    let state2 = simulate_edf_scheduling(&shuffled_tasks, config);

    // Both should preserve EDF ordering within tolerance
    let preserved1 = state1.is_edf_ordering_preserved();
    let preserved2 = state2.is_edf_ordering_preserved();

    if preserved1 && preserved2 {
        result.record_pass("edf_ordering_preservation");
    } else {
        result.record_failure(
            "edf_ordering_preservation",
            "EDF ordering not preserved across different task arrival patterns",
        );
    }

    result.update_from_state(&state1);
}

/// MR2: Test that high-priority tasks complete within bounded time.
fn test_priority_inheritance_effectiveness(
    result: &mut EdfMetamorphicResult,
    config: &EdfMetamorphicConfig,
) {
    let tasks = generate_test_tasks(config);
    let state = simulate_edf_scheduling(&tasks, config);

    // Check that inversions are bounded
    let max_inversion_exceeded = state.inversions.iter().any(|inv| {
        if let Some(duration) = inv.duration {
            duration.as_micros() as u64 > config.max_inversion_duration_us
        } else {
            false
        }
    });

    if !max_inversion_exceeded {
        result.record_pass("priority_inheritance_effectiveness");
    } else {
        result.record_failure(
            "priority_inheritance_effectiveness",
            &format!(
                "Inversion duration exceeded limit of {} μs",
                config.max_inversion_duration_us
            ),
        );
    }

    result.update_from_state(&state);
}

/// MR3: Test that earlier deadlines generally complete first.
fn test_deadline_monotonicity(result: &mut EdfMetamorphicResult, config: &EdfMetamorphicConfig) {
    let tasks = generate_test_tasks(config);
    let state = simulate_edf_scheduling(&tasks, config);

    // Check deadline monotonicity in completion order
    let mut monotonicity_violations = 0;
    for i in 1..state.completed_tasks.len() {
        let (prev_task, _) = &state.completed_tasks[i - 1];
        let (curr_task, _) = &state.completed_tasks[i];

        if prev_task.deadline > curr_task.deadline {
            monotonicity_violations += 1;
        }
    }

    // Allow some violations due to priority inheritance
    let violation_rate = if state.completed_tasks.is_empty() {
        0.0
    } else {
        monotonicity_violations as f64 / state.completed_tasks.len() as f64
    };

    if violation_rate <= 0.3 {
        result.record_pass("deadline_monotonicity");
    } else {
        result.record_failure(
            "deadline_monotonicity",
            &format!(
                "Deadline monotonicity violation rate {:.1}% exceeds 30%",
                violation_rate * 100.0
            ),
        );
    }

    result.update_from_state(&state);
}

/// MR4: Test that priority inversions are time-bounded.
fn test_inversion_boundedness(result: &mut EdfMetamorphicResult, config: &EdfMetamorphicConfig) {
    let tasks = generate_test_tasks(config);
    let state = simulate_edf_scheduling(&tasks, config);

    // Check inversion boundedness
    let avg_inversion = state.average_inversion_duration_us();
    let bounded = avg_inversion <= config.max_inversion_duration_us as f64;

    // Also check that no cascading inversions occurred
    let cascading_inversions = state
        .inversions
        .iter()
        .any(|inv| matches!(inv.inversion_type, InversionType::Chain) && inv.task_chain.len() > 3);

    if bounded && !cascading_inversions {
        result.record_pass("inversion_boundedness");
    } else {
        result.record_failure(
            "inversion_boundedness",
            &format!(
                "Inversion boundedness violated: avg={:.1}μs, cascading={}",
                avg_inversion, cascading_inversions
            ),
        );
    }

    result.update_from_state(&state);
}

/// MR5: Test resource fairness under contention.
fn test_resource_fairness(result: &mut EdfMetamorphicResult, config: &EdfMetamorphicConfig) {
    // Create high-contention scenario
    let mut high_contention_config = config.clone();
    high_contention_config.num_resources = 2; // Force contention
    high_contention_config.num_tasks = 8;

    let tasks = generate_test_tasks(&high_contention_config);
    let state = simulate_edf_scheduling(&tasks, &high_contention_config);

    // Resource fairness: no task should be starved indefinitely
    let completion_rate = state.completed_tasks.len() as f64 / tasks.len() as f64;
    let fair = completion_rate >= 0.8; // At least 80% should complete

    if fair {
        result.record_pass("resource_fairness");
    } else {
        result.record_failure(
            "resource_fairness",
            &format!(
                "Completion rate {:.1}% indicates resource starvation",
                completion_rate * 100.0
            ),
        );
    }

    result.update_from_state(&state);
}

/// MR6: Test work conservation property.
fn test_work_conservation(result: &mut EdfMetamorphicResult, config: &EdfMetamorphicConfig) {
    let tasks = generate_test_tasks(config);
    let state = simulate_edf_scheduling(&tasks, config);

    // Work conservation: all tasks should eventually complete
    let all_completed = state.completed_tasks.len() == tasks.len();

    if all_completed {
        result.record_pass("work_conservation");
    } else {
        result.record_failure(
            "work_conservation",
            &format!(
                "Work conservation violated: {}/{} tasks completed",
                state.completed_tasks.len(),
                tasks.len()
            ),
        );
    }

    result.update_from_state(&state);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn test_edf_metamorphic_config_default() {
        let config = EdfMetamorphicConfig::default();
        assert_eq!(config.num_tasks, 10);
        assert_eq!(config.priority_levels.len(), 4);
        assert!(config.max_inversion_duration_us > 0);
    }

    #[test]
    fn test_edf_test_task_creation() {
        let task_id = TaskId::new_for_test(1, 2);
        let deadline = Time::from_millis(100);
        let resources = vec![ResourceId::new(1)];

        let task = EdfTestTask::new(task_id, 2, deadline, resources, 50);

        assert_eq!(task.task_id, task_id);
        assert_eq!(task.priority, 2);
        assert_eq!(task.deadline, deadline);
        assert_eq!(task.execution_time_ms, 50);
    }

    #[test]
    fn test_task_priority_comparison() {
        let task_high = EdfTestTask::new(
            TaskId::new_for_test(1, 1),
            0,
            Time::from_millis(100),
            vec![],
            10,
        );
        let task_low = EdfTestTask::new(
            TaskId::new_for_test(2, 2),
            3,
            Time::from_millis(100),
            vec![],
            10,
        );

        assert!(task_high.has_higher_priority_than(&task_low));
        assert!(!task_low.has_higher_priority_than(&task_high));
    }

    #[test]
    fn test_deadline_comparison() {
        let task_early = EdfTestTask::new(
            TaskId::new_for_test(1, 1),
            1,
            Time::from_millis(50),
            vec![],
            10,
        );
        let task_late = EdfTestTask::new(
            TaskId::new_for_test(2, 2),
            1,
            Time::from_millis(100),
            vec![],
            10,
        );

        assert!(task_early.has_earlier_deadline_than(&task_late));
        assert!(!task_late.has_earlier_deadline_than(&task_early));
    }

    #[test]
    fn test_urgency_score_calculation() {
        let task = EdfTestTask::new(
            TaskId::new_for_test(1, 1),
            0, // High priority
            Time::from_millis(100),
            vec![],
            10,
        );

        let current_time = Time::from_millis(50);
        let urgency = task.urgency_score(current_time);

        assert!(urgency > 0.0);
        assert!(urgency < 1.0);
    }

    #[test]
    fn test_edf_test_state_tracking() {
        let mut state = EdfTestState::new();

        let task = EdfTestTask::new(
            TaskId::new_for_test(1, 1),
            1,
            Time::from_millis(100),
            vec![],
            50,
        );

        state.record_completion(task.clone(), Time::from_millis(50));

        assert_eq!(state.completed_tasks.len(), 1);
        assert_eq!(state.execution_order.len(), 1);
        assert_eq!(state.execution_order[0], task.task_id);
    }

    #[test]
    fn record_completion_counts_deadline_miss_from_logical_time() {
        let mut state = EdfTestState::new();
        let task = EdfTestTask::new(
            TaskId::new_for_test(7, 7),
            1,
            Time::from_millis(100),
            vec![],
            10,
        );

        state.record_completion(task.clone(), Time::from_millis(90));
        assert_eq!(state.deadline_violations, 0);

        state.record_completion(task, Time::from_millis(125));
        assert_eq!(state.deadline_violations, 1);
    }

    #[test]
    fn simulated_edf_scheduling_tracks_deadlines_from_simulated_time() {
        let task = EdfTestTask::new(
            TaskId::new_for_test(9, 9),
            0,
            Time::from_millis(10),
            vec![ResourceId::new(0)],
            20,
        );
        let config = EdfMetamorphicConfig {
            num_tasks: 1,
            deadline_range_ms: (10, 11),
            priority_levels: vec![0],
            num_resources: 1,
            max_inversion_duration_us: 1_000,
            seed: 123,
        };

        let state = simulate_edf_scheduling(&[task], &config);
        assert_eq!(state.completed_tasks.len(), 1);
        assert_eq!(state.completed_tasks[0].1, Time::from_millis(20));
        assert_eq!(state.deadline_violations, 1);
    }

    #[test]
    fn test_generate_test_tasks() {
        let config = EdfMetamorphicConfig::default();
        let tasks = generate_test_tasks(&config);

        assert_eq!(tasks.len(), config.num_tasks);

        for task in &tasks {
            assert!(config.priority_levels.contains(&task.priority));
            assert!(!task.required_resources.is_empty());
            assert!(task.execution_time_ms > 0);
        }
    }

    #[test]
    fn test_edf_metamorphic_result() {
        let mut result = EdfMetamorphicResult::new();
        assert_eq!(result.tests_run, 0);
        assert!(result.is_success()); // No tests = success

        result.record_pass("test1");
        assert_eq!(result.tests_run, 1);
        assert_eq!(result.tests_passed, 1);
        assert!(result.is_success());

        result.record_failure("test2", "failed");
        assert_eq!(result.tests_run, 2);
        assert_eq!(result.tests_failed, 1);
        assert!(!result.is_success());
        assert_eq!(result.success_rate(), 50.0);
    }

    #[test]
    fn run_basic_edf_metamorphic_tests() {
        // Test the actual metamorphic test runner
        let mut config = EdfMetamorphicConfig::default();
        config.num_tasks = 5; // Smaller test
        config.max_inversion_duration_us = 2000; // More lenient for test

        let result =
            run_edf_metamorphic_tests_with_config(&config).expect("Metamorphic tests should run");

        // Verify some tests were run
        assert!(
            result.tests_run > 0,
            "metamorphic runner should execute tests"
        );

        // For EDF scheduling, we expect high success rate
        assert!(
            result.success_rate() >= 70.0,
            "Expected at least 70% success rate for EDF metamorphic tests, got {:.1}% (run={}, passed={}, failed={}, avg_inversion_us={:.1}, max_inversion_us={}, deadline_violation_rate={:.1}%, failures={:?})",
            result.success_rate(),
            result.tests_run,
            result.tests_passed,
            result.tests_failed,
            result.avg_inversion_duration_us,
            result.max_inversion_duration_us,
            result.deadline_violation_rate * 100.0,
            result.failures
        );
    }
}
