#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for Three-Lane Scheduler Priority Promotion Idempotence
//!
//! Tests that worker-local priority promotion operations are idempotent:
//! promoting a task already in the cancel lane should not change the relative
//! scheduling order of tasks.
//!
//! Target: src/runtime/scheduler/three_lane.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Priority Promotion Idempotence**: promote(task_x) ≈ promote(task_x) ∘ promote(task_x)
//! 2. **Lane Order Preservation**: Repeated promotions preserve non-target priority ordering
//! 3. **Deduplication Consistency**: move_to_cancel_lane correctly handles duplicates
//! 4. **Scheduling Sequence Stability**: Task dispatch order remains consistent across promotion repetitions

#![cfg(test)]

use proptest::prelude::*;
use std::sync::Arc;

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
use asupersync::sync::ContendedMutex;
use asupersync::types::TaskId;

fn task_id(raw: u64) -> TaskId {
    TaskId::new_for_test(
        u32::try_from(raw).expect("generated task id must fit in u32"),
        0,
    )
}

fn sorted_task_multiset(tasks: &[TaskId]) -> Vec<TaskId> {
    let mut sorted = tasks.to_vec();
    sorted.sort_unstable();
    sorted
}

fn unique_tasks(raw: Vec<(u64, u8)>) -> Vec<(TaskId, u8)> {
    let mut tasks = Vec::with_capacity(raw.len());
    for (id, priority) in raw {
        let task = task_id(id);
        if !tasks
            .iter()
            .any(|&(existing, _): &(TaskId, u8)| existing == task)
        {
            tasks.push((task, priority));
        }
    }
    tasks
}

/// Test harness for priority promotion idempotence testing
struct PromotionIdempotenceHarness {
    scheduler: ThreeLaneScheduler,
    workers: Vec<ThreeLaneWorker>,
}

impl PromotionIdempotenceHarness {
    /// Create a new test harness with pre-configured tasks
    fn new(num_workers: usize, _num_initial_tasks: usize) -> Self {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(num_workers, &state, 16);
        let workers = scheduler.take_workers();

        Self { scheduler, workers }
    }

    /// Capture the current scheduling sequence by dispatching all available tasks
    fn capture_scheduling_sequence(&mut self) -> Vec<TaskId> {
        let mut sequence = Vec::new();

        // Use first worker for deterministic testing
        if let Some(worker) = self.workers.get_mut(0) {
            while let Some(task) = worker.next_task() {
                sequence.push(task);
            }
        }

        sequence
    }

    /// Inject tasks into ready lane with specified priorities
    fn inject_ready_tasks(&self, tasks: &[(TaskId, u8)]) {
        for &(task_id, priority) in tasks {
            self.scheduler.inject_ready(task_id, priority);
        }
    }

    /// Promote tasks into the worker-local cancel lane with specified priorities.
    fn promote_local_cancel_tasks(&self, tasks: &[(TaskId, u8)]) {
        if let Some(worker) = self.workers.first() {
            for &(task_id, priority) in tasks {
                worker.schedule_local_cancel(task_id, priority);
            }
        }
    }

    /// Reset scheduler state for clean test runs
    fn reset_scheduler_state(&mut self) {
        // Clear all lanes by consuming available tasks
        if let Some(worker) = self.workers.get_mut(0) {
            while worker.next_task().is_some() {
                // Consume and discard
            }
        }
    }
}

/// Generate test data for priority promotion scenarios
#[derive(Debug, Clone)]
struct PromotionScenario {
    ready_tasks: Vec<(TaskId, u8)>,  // (task_id, priority) in ready lane
    cancel_tasks: Vec<(TaskId, u8)>, // (task_id, priority) in cancel lane
    target_task: (TaskId, u8),       // Task to test promotion idempotence on
    num_promotions: usize,           // Number of times to promote target_task
}

impl Arbitrary for PromotionScenario {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            prop::collection::vec((1000u64..2000u64, 0u8..255u8), 1..8), // ready_tasks
            prop::collection::vec((2000u64..3000u64, 0u8..255u8), 0..5), // cancel_tasks
            (3000u64..4000u64, 0u8..255u8),                              // target_task
            2usize..8usize,                                              // num_promotions
        )
            .prop_map(|(ready_raw, cancel_raw, target_raw, num_promotions)| {
                let ready_tasks = unique_tasks(ready_raw);
                let cancel_tasks = unique_tasks(cancel_raw);
                let target_task = (task_id(target_raw.0), target_raw.1);

                PromotionScenario {
                    ready_tasks,
                    cancel_tasks,
                    target_task,
                    num_promotions,
                }
            })
            .boxed()
    }
}

impl PromotionScenario {
    fn priority_for_task(&self, task: TaskId) -> Option<u8> {
        if task == self.target_task.0 {
            return Some(self.target_task.1);
        }

        self.cancel_tasks
            .iter()
            .chain(self.ready_tasks.iter())
            .find_map(|&(task_id, priority)| (task_id == task).then_some(priority))
    }

    fn priority_sequence_for(&self, sequence: &[TaskId]) -> Vec<u8> {
        sequence
            .iter()
            .map(|&task| {
                self.priority_for_task(task)
                    .expect("scheduled task should come from the scenario")
            })
            .collect()
    }
}

/// Test that priority promotion is idempotent
#[test]
fn test_priority_promotion_idempotence() {
    proptest!(|(scenario in any::<PromotionScenario>())| {
        let mut harness = PromotionIdempotenceHarness::new(1, 0);

        // Test single promotion
        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);
        harness.promote_local_cancel_tasks(&[scenario.target_task]);  // Single promotion
        let single_sequence = harness.capture_scheduling_sequence();

        // Test multiple promotions
        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);
        for _ in 0..scenario.num_promotions {
            harness.promote_local_cancel_tasks(&[scenario.target_task]);  // Multiple promotions
        }
        let multiple_sequence = harness.capture_scheduling_sequence();

        // Metamorphic relation: repeated promotion should not change membership
        // or priority ordering. Equal-priority task ties are scheduler-defined.
        prop_assert_eq!(sorted_task_multiset(&single_sequence), sorted_task_multiset(&multiple_sequence),
            "Priority promotion idempotence violated: single promotion changed dispatched task membership");
        prop_assert_eq!(scenario.priority_sequence_for(&single_sequence), scenario.priority_sequence_for(&multiple_sequence),
            "Priority promotion idempotence violated: single promotion priority sequence differs from multiple promotions");
    });
}

/// Test that lane order is preserved across repeated promotions
#[test]
fn test_lane_order_preservation() {
    proptest!(|(scenario in any::<PromotionScenario>())| {
        let mut harness = PromotionIdempotenceHarness::new(1, 0);

        // Capture baseline order without target task
        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);
        let baseline_sequence = harness.capture_scheduling_sequence();

        // Capture order with target task promoted once
        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);
        harness.promote_local_cancel_tasks(&[scenario.target_task]);
        let once_sequence = harness.capture_scheduling_sequence();

        // Capture order with target task promoted multiple times
        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);
        for _ in 0..scenario.num_promotions {
            harness.promote_local_cancel_tasks(&[scenario.target_task]);
        }
        let multiple_sequence = harness.capture_scheduling_sequence();

        // The non-target membership and priority order should be preserved.
        let extract_non_target = |seq: &[TaskId]| -> Vec<TaskId> {
            seq.iter()
                .filter(|&&task| task != scenario.target_task.0)
                .copied()
                .collect()
        };
        let extract_non_target_priorities = |seq: &[TaskId]| -> Vec<u8> {
            seq.iter()
                .filter(|&&task| task != scenario.target_task.0)
                .map(|&task| {
                    scenario
                        .priority_for_task(task)
                        .expect("scheduled task should come from the scenario")
                })
                .collect()
        };

        let baseline_non_target = extract_non_target(&baseline_sequence);
        let once_non_target = extract_non_target(&once_sequence);
        let multiple_non_target = extract_non_target(&multiple_sequence);
        let baseline_non_target_priorities = extract_non_target_priorities(&baseline_sequence);
        let once_non_target_priorities = extract_non_target_priorities(&once_sequence);
        let multiple_non_target_priorities = extract_non_target_priorities(&multiple_sequence);

        prop_assert_eq!(sorted_task_multiset(&baseline_non_target), sorted_task_multiset(&once_non_target),
            "Lane membership preservation violated: single promotion changed non-target tasks");
        prop_assert_eq!(sorted_task_multiset(&once_non_target), sorted_task_multiset(&multiple_non_target),
            "Lane membership preservation violated: multiple promotions changed non-target tasks");
        prop_assert_eq!(&baseline_non_target_priorities, &once_non_target_priorities,
            "Lane order preservation violated: single promotion changed non-target priority order");
        prop_assert_eq!(&once_non_target_priorities, &multiple_non_target_priorities,
            "Lane order preservation violated: multiple promotions changed non-target priority order");
    });
}

/// Test that the target task appears exactly once regardless of promotion count
#[test]
fn test_deduplication_consistency() {
    proptest!(|(scenario in any::<PromotionScenario>())| {
        let mut harness = PromotionIdempotenceHarness::new(1, 0);

        harness.reset_scheduler_state();
        harness.inject_ready_tasks(&scenario.ready_tasks);
        harness.promote_local_cancel_tasks(&scenario.cancel_tasks);

        // Promote target task multiple times
        for _ in 0..scenario.num_promotions {
            harness.promote_local_cancel_tasks(&[scenario.target_task]);
        }

        let sequence = harness.capture_scheduling_sequence();
        let target_count = sequence.iter()
            .filter(|&&task| task == scenario.target_task.0)
            .count();

        prop_assert_eq!(target_count, 1,
            "Deduplication consistency violated: target task appeared {} times, expected 1", target_count);
    });
}

/// Test scheduling sequence stability under promotion stress
#[test]
fn test_scheduling_sequence_stability() {
    proptest!(|(scenario in any::<PromotionScenario>())| {
        let num_trials = 5;
        let mut sequences = Vec::new();

        for _ in 0..num_trials {
            let mut harness = PromotionIdempotenceHarness::new(1, 0);
            harness.reset_scheduler_state();
            harness.inject_ready_tasks(&scenario.ready_tasks);
            harness.promote_local_cancel_tasks(&scenario.cancel_tasks);

            // Apply stress promotions
            for _ in 0..scenario.num_promotions {
                harness.promote_local_cancel_tasks(&[scenario.target_task]);
            }

            let sequence = harness.capture_scheduling_sequence();
            sequences.push(sequence);
        }

        // All trials should produce identical sequences
        for i in 1..sequences.len() {
            prop_assert_eq!(&sequences[0], &sequences[i],
                "Scheduling sequence stability violated: trial {} differs from baseline", i);
        }
    });
}

/// Test promotion behavior with mixed priority levels
#[test]
fn test_mixed_priority_promotion_idempotence() {
    let mut harness = PromotionIdempotenceHarness::new(1, 0);

    // Test scenario: multiple tasks with different priorities
    let ready_tasks = vec![
        (TaskId::new_for_test(1001, 0), 10), // Low priority
        (TaskId::new_for_test(1002, 0), 50), // Medium priority
        (TaskId::new_for_test(1003, 0), 90), // High priority
    ];
    let target_task = (TaskId::new_for_test(2001, 0), 75); // Medium-high priority

    // Single promotion
    harness.reset_scheduler_state();
    harness.inject_ready_tasks(&ready_tasks);
    harness.promote_local_cancel_tasks(&[target_task]);
    let single_sequence = harness.capture_scheduling_sequence();

    // Triple promotion
    harness.reset_scheduler_state();
    harness.inject_ready_tasks(&ready_tasks);
    harness.promote_local_cancel_tasks(&[target_task]); // First
    harness.promote_local_cancel_tasks(&[target_task]); // Second
    harness.promote_local_cancel_tasks(&[target_task]); // Third
    let triple_sequence = harness.capture_scheduling_sequence();

    assert_eq!(
        single_sequence, triple_sequence,
        "Mixed priority promotion idempotence failed"
    );

    // Ensure target task is scheduled before lower priority ready tasks
    if let (Some(target_pos), Some(low_prio_pos)) = (
        single_sequence.iter().position(|&t| t == target_task.0),
        single_sequence
            .iter()
            .position(|&t| t == TaskId::new_for_test(1001, 0)),
    ) {
        assert!(
            target_pos < low_prio_pos,
            "Priority ordering violated: target task should appear before lower priority tasks"
        );
    }
}
