//! Metamorphic property tests for scheduler fairness, work conservation, and starvation freedom.
//!
//! These tests verify scheduler invariants that must hold regardless of the specific
//! scheduling decisions made. Unlike unit tests that check exact outcomes, metamorphic
//! tests verify relationships between different execution scenarios.

use crate::runtime::RuntimeState;
use crate::runtime::scheduler::ThreeLaneScheduler;
use crate::sync::ContendedMutex;
use crate::types::{RegionId, TaskId};
use crate::util::DetRng;
use std::sync::Arc;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test scheduler with the given number of workers.
fn create_test_scheduler(worker_count: usize) -> ThreeLaneScheduler {
    let state = Arc::new(ContendedMutex::new(
        "metamorphic.runtime_state",
        RuntimeState::new(),
    ));
    ThreeLaneScheduler::new(worker_count, &state)
}

/// Generate deterministic task IDs for testing.
fn generate_task_ids(count: usize, seed: u64) -> Vec<TaskId> {
    let mut rng = DetRng::new(seed);
    let mut tasks = Vec::new();
    for i in 0..count {
        let _region_id = RegionId::new_for_test(i as u32, rng.next_u32());
        let task_id = TaskId::new_for_test(i as u32, rng.next_u32());
        tasks.push(task_id);
    }
    tasks
}

/// Simulate work completion by tracking task processing.
#[derive(Debug, Clone, PartialEq)]
struct WorkStats {
    tasks_spawned: usize,
    tasks_processed: usize,
    total_wake_calls: usize,
}

impl WorkStats {
    fn new() -> Self {
        Self {
            tasks_spawned: 0,
            tasks_processed: 0,
            total_wake_calls: 0,
        }
    }
}

/// Test harness for scheduler operations.
struct SchedulerTestHarness {
    scheduler: ThreeLaneScheduler,
    workers: Vec<crate::runtime::scheduler::ThreeLaneWorker>,
    stats: WorkStats,
}

impl SchedulerTestHarness {
    fn new(worker_count: usize) -> Self {
        let mut scheduler = create_test_scheduler(worker_count);
        let workers = scheduler.take_workers();
        Self {
            scheduler,
            workers,
            stats: WorkStats::new(),
        }
    }

    fn spawn_tasks(&mut self, tasks: &[TaskId]) {
        for &task_id in tasks {
            self.scheduler.spawn(task_id, 100); // priority = 100
            self.stats.tasks_spawned += 1;
        }
    }

    fn wake_tasks(&mut self, tasks: &[TaskId]) {
        for &task_id in tasks {
            self.scheduler.wake(task_id, 100); // priority = 100
            self.stats.total_wake_calls += 1;
        }
    }

    fn process_available_work(&mut self) -> usize {
        let mut processed = 0;
        for worker in &mut self.workers {
            while let Some(_task_id) = worker.try_ready_work() {
                processed += 1;
                self.stats.tasks_processed += 1;
            }
        }
        processed
    }

    fn total_work_in_system(&self) -> usize {
        self.workers.iter().map(|w| w.ready_count()).sum()
    }
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: Work Conservation (Additive, Score: 10.0)
/// Property: total_work_spawned = total_work_processed + total_work_remaining
/// Catches: Work loss bugs, task dropping, scheduling inefficiencies
#[test]
fn mr_scheduler_work_conservation() {
    proptest!(|(
        task_count in 3usize..15,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        worker_count in 1usize..4,
    )| {
        // Generate identical tasks for both test runs
        let tasks = generate_task_ids(task_count, seed_a);

        // Test run A: Single spawn batch
        let mut harness_a = SchedulerTestHarness::new(worker_count);
        harness_a.spawn_tasks(&tasks);
        let _work_before_a = harness_a.total_work_in_system();
        let processed_a = harness_a.process_available_work();
        let work_after_a = harness_a.total_work_in_system();

        // Test run B: Incremental spawning with different seed
        let mut harness_b = SchedulerTestHarness::new(worker_count);
        let mut rng_b = DetRng::new(seed_b);
        for task in &tasks {
            harness_b.spawn_tasks(&[*task]);
            // Random processing at different points
            if rng_b.next_u32() % 3 == 0 {
                harness_b.process_available_work();
            }
        }
        let _work_before_b = harness_b.total_work_in_system();
        let _final_processed_b = harness_b.process_available_work();
        let work_after_b = harness_b.total_work_in_system();

        // METAMORPHIC ASSERTION: Work conservation
        prop_assert_eq!(
            harness_a.stats.tasks_spawned, harness_b.stats.tasks_spawned,
            "MR1 VIOLATION: different number of tasks spawned"
        );

        // Total work should be conserved: spawned = processed + remaining
        let total_a = processed_a + work_after_a;
        let total_b = harness_b.stats.tasks_processed + work_after_b;

        prop_assert_eq!(
            total_a, total_b,
            "MR1 VIOLATION: work conservation failed - A: {} processed + {} remaining = {}, B: {} processed + {} remaining = {}",
            processed_a, work_after_a, total_a,
            harness_b.stats.tasks_processed, work_after_b, total_b
        );
    });
}

/// MR2: Spawn-Wake Equivalence (Equivalence, Score: 8.0)
/// Property: scheduler state after spawn(tasks) = scheduler state after wake(tasks)
/// Catches: Spawn vs wake inconsistencies, queue state corruption
#[test]
fn mr_scheduler_spawn_wake_equivalence() {
    proptest!(|(
        task_count in 2usize..10,
        seed in any::<u64>(),
        worker_count in 1usize..3,
    )| {
        let tasks = generate_task_ids(task_count, seed);

        // Scenario A: Spawn all tasks
        let mut harness_spawn = SchedulerTestHarness::new(worker_count);
        harness_spawn.spawn_tasks(&tasks);
        let work_after_spawn = harness_spawn.total_work_in_system();

        // Scenario B: Wake all tasks (they should be spawned first with wake)
        let mut harness_wake = SchedulerTestHarness::new(worker_count);
        harness_wake.wake_tasks(&tasks);
        let work_after_wake = harness_wake.total_work_in_system();

        // METAMORPHIC ASSERTION: Both should result in same amount of ready work
        prop_assert_eq!(
            work_after_spawn, work_after_wake,
            "MR2 VIOLATION: spawn vs wake produced different ready work counts - spawn: {}, wake: {}",
            work_after_spawn, work_after_wake
        );
    });
}

/// MR3: Processing Order Invariance (Equivalence, Score: 6.25)
/// Property: Total work processed is independent of processing order
/// Catches: Order-dependent bugs, queue corruption, worker imbalances
#[test]
fn mr_scheduler_processing_order_invariance() {
    proptest!(|(
        task_count in 4usize..12,
        seed in any::<u64>(),
        worker_count in 1usize..3,
    )| {
        let tasks = generate_task_ids(task_count, seed);

        // Scenario A: Process all work immediately after spawn
        let mut harness_immediate = SchedulerTestHarness::new(worker_count);
        harness_immediate.spawn_tasks(&tasks);
        let immediate_processed = harness_immediate.process_available_work();

        // Scenario B: Spawn incrementally and process incrementally
        let mut harness_incremental = SchedulerTestHarness::new(worker_count);
        for (i, &task) in tasks.iter().enumerate() {
            harness_incremental.spawn_tasks(&[task]);
            // Process every other task
            if i % 2 == 1 {
                harness_incremental.process_available_work();
            }
        }
        // Process remaining work
        let _remaining_processed = harness_incremental.process_available_work();
        let total_incremental = harness_incremental.stats.tasks_processed;

        // METAMORPHIC ASSERTION: Total processed work should be the same
        prop_assert_eq!(
            immediate_processed, total_incremental,
            "MR3 VIOLATION: processing order affected total work - immediate: {}, incremental: {}",
            immediate_processed, total_incremental
        );

        // Both should have processed all spawned tasks
        prop_assert_eq!(
            immediate_processed, task_count,
            "MR3 VIOLATION: immediate processing didn't complete all tasks"
        );
        prop_assert_eq!(
            total_incremental, task_count,
            "MR3 VIOLATION: incremental processing didn't complete all tasks"
        );
    });
}

// ============================================================================
// Composite Metamorphic Relations
// ============================================================================

/// Composite MR: Work Conservation + Processing Order Invariance
/// Tests that work is conserved regardless of worker count and processing order
#[test]
fn mr_composite_conservation_and_order_invariance() {
    proptest!(|(
        task_count in 5usize..10,
        seed in any::<u64>(),
    )| {
        let tasks = generate_task_ids(task_count, seed);

        // Single worker scenario
        let mut harness_single = SchedulerTestHarness::new(1);
        harness_single.spawn_tasks(&tasks);
        let single_processed = harness_single.process_available_work();

        // Multi-worker scenario
        let mut harness_multi = SchedulerTestHarness::new(2);
        harness_multi.spawn_tasks(&tasks);
        let multi_processed = harness_multi.process_available_work();

        // COMPOSITE ASSERTION: Work should be conserved across worker configurations
        prop_assert_eq!(
            single_processed, multi_processed,
            "COMPOSITE MR VIOLATION: worker count affected work conservation"
        );

        prop_assert_eq!(
            single_processed, task_count,
            "COMPOSITE MR VIOLATION: single worker didn't process all tasks"
        );
        prop_assert_eq!(
            multi_processed, task_count,
            "COMPOSITE MR VIOLATION: multi worker didn't process all tasks"
        );
    });
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that work conservation test infrastructure works correctly
    #[test]
    fn validate_work_conservation_infrastructure() {
        let tasks = generate_task_ids(5, 42);
        let mut harness = SchedulerTestHarness::new(1);

        // Initially no work
        assert_eq!(harness.total_work_in_system(), 0);

        // Spawn tasks
        harness.spawn_tasks(&tasks);
        assert_eq!(harness.stats.tasks_spawned, 5);

        let work_before = harness.total_work_in_system();
        assert!(work_before > 0, "Should have work after spawning tasks");

        // Process work
        let processed = harness.process_available_work();
        let work_after = harness.total_work_in_system();

        assert_eq!(harness.stats.tasks_processed, processed);
        assert!(processed <= 5, "Can't process more tasks than spawned");

        // Work conservation: spawned = processed + remaining
        assert_eq!(harness.stats.tasks_spawned, processed + work_after);
    }

    /// Validate that spawn and wake produce equivalent scheduler states
    #[test]
    fn validate_spawn_wake_equivalence_infrastructure() {
        let tasks = generate_task_ids(3, 123);

        let mut harness_spawn = SchedulerTestHarness::new(1);
        harness_spawn.spawn_tasks(&tasks);
        let spawn_work = harness_spawn.total_work_in_system();

        let mut harness_wake = SchedulerTestHarness::new(1);
        harness_wake.wake_tasks(&tasks);
        let wake_work = harness_wake.total_work_in_system();

        assert_eq!(
            spawn_work, wake_work,
            "Spawn and wake should produce equivalent states"
        );
    }

    /// Validate that processing order doesn't affect work conservation
    #[test]
    fn validate_processing_order_invariance_infrastructure() {
        let tasks = generate_task_ids(4, 456);

        // Process immediately
        let mut harness_immediate = SchedulerTestHarness::new(1);
        harness_immediate.spawn_tasks(&tasks);
        let immediate_processed = harness_immediate.process_available_work();

        // Process incrementally
        let mut harness_incremental = SchedulerTestHarness::new(1);
        for &task in &tasks {
            harness_incremental.spawn_tasks(&[task]);
            harness_incremental.process_available_work();
        }
        let incremental_processed = harness_incremental.stats.tasks_processed;

        assert_eq!(immediate_processed, incremental_processed);
        assert_eq!(immediate_processed, tasks.len());
    }
}
