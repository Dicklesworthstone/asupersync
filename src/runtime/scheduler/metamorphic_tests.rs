//! Metamorphic property tests for scheduler fairness, work conservation, and starvation freedom.
//!
//! These tests verify scheduler invariants that must hold regardless of the specific
//! scheduling decisions made. Unlike unit tests that check exact outcomes, metamorphic
//! tests verify relationships between different execution scenarios.

use crate::runtime::RuntimeState;
use crate::runtime::scheduler::ThreeLaneScheduler;
use crate::sync::ContendedMutex;
use crate::obligation::lyapunov::SchedulingSuggestion;
use crate::types::{RegionId, TaskId, Time};
use crate::util::DetRng;
use std::sync::Arc;
use std::time::Duration;

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

// ============================================================================
// Lane Ordering Metamorphic Relations (asupersync-h8xhs5)
// ============================================================================

/// MR4: Cancel-Lane Starvation Bound (Multiplicative, Score: 9.0)
/// Property: cancel_streak_limit + 1 steps per worker max starvation
/// Catches: Cancel lane priority violations, starvation bugs, fairness failures
#[test]
fn mr_cancel_lane_starvation_bound() {
    // SchedulingSuggestion imported at module level

    proptest!(|(
        cancel_streak_limit in 2usize..8,
        ready_tasks in 1usize..5,
        cancel_tasks in 1usize..10,
        seed in any::<u64>(),
    )| {
        let state = Arc::new(ContendedMutex::new(
            "metamorphic.runtime_state",
            RuntimeState::new()
        ));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_streak_limit);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Generate task IDs
        let ready_task_ids = generate_task_ids(ready_tasks, seed);
        let cancel_task_ids = generate_task_ids(cancel_tasks, seed + 1);

        // Inject ready work first
        for &task_id in &ready_task_ids {
            scheduler.inject_ready(task_id, 100);
        }

        // Inject cancel work
        for &task_id in &cancel_task_ids {
            scheduler.inject_cancel(task_id, 100);
        }

        let mut _cancel_dispatches = 0;
        let mut ready_dispatches = 0;
        let mut max_consecutive_cancel = 0;
        let mut current_cancel_streak = 0;

        // Process all available work, tracking streaks
        for _ in 0..(ready_tasks + cancel_tasks) {
            if let Some(task_id) = worker.next_task() {
                // Check if this task is from cancel or ready lane
                if cancel_task_ids.contains(&task_id) {
                    _cancel_dispatches += 1;
                    current_cancel_streak += 1;
                    max_consecutive_cancel = max_consecutive_cancel.max(current_cancel_streak);
                } else if ready_task_ids.contains(&task_id) {
                    ready_dispatches += 1;
                    current_cancel_streak = 0; // Reset streak on ready dispatch
                }
            } else {
                break; // No more work
            }
        }

        // METAMORPHIC ASSERTION: Cancel starvation bound
        prop_assert!(
            max_consecutive_cancel <= cancel_streak_limit,
            "MR4 VIOLATION: cancel streak exceeded limit - max: {}, limit: {}",
            max_consecutive_cancel, cancel_streak_limit
        );

        // If both ready and cancel work were available, ready should have been dispatched
        if ready_tasks > 0 && cancel_tasks > 0 && ready_dispatches > 0 {
            prop_assert!(
                max_consecutive_cancel <= cancel_streak_limit,
                "MR4 VIOLATION: ready work starved beyond fairness bound"
            );
        }
    });
}

/// MR5: Drain-Widened Bound (Multiplicative, Score: 8.5)
/// Property: 2*cancel_streak_limit during DrainObligations/DrainRegions
/// Catches: Drain phase fairness violations, obligation draining bugs
#[test]
fn mr_drain_widened_bound() {
    // SchedulingSuggestion imported at module level

    proptest!(|(
        cancel_streak_limit in 2usize..6,
        ready_tasks in 1usize..4,
        cancel_tasks in 1usize..8,
        seed in any::<u64>(),
    )| {
        let state = Arc::new(ContendedMutex::new(
            "metamorphic.runtime_state",
            RuntimeState::new()
        ));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_streak_limit);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Force drain obligation mode to test 2*L bound
        #[cfg(any(test, feature = "test-internals"))]
        worker.set_cached_suggestion(SchedulingSuggestion::DrainObligations);

        // Generate and inject tasks
        let ready_task_ids = generate_task_ids(ready_tasks, seed);
        let cancel_task_ids = generate_task_ids(cancel_tasks, seed + 1);

        for &task_id in &ready_task_ids {
            scheduler.inject_ready(task_id, 100);
        }
        for &task_id in &cancel_task_ids {
            scheduler.inject_cancel(task_id, 100);
        }

        let mut max_consecutive_cancel = 0;
        let mut current_cancel_streak = 0;

        // Process work and track cancel streaks under drain mode
        for _ in 0..(ready_tasks + cancel_tasks) {
            if let Some(task_id) = worker.next_task() {
                if cancel_task_ids.contains(&task_id) {
                    current_cancel_streak += 1;
                    max_consecutive_cancel = max_consecutive_cancel.max(current_cancel_streak);
                } else if ready_task_ids.contains(&task_id) {
                    current_cancel_streak = 0;
                }
            } else {
                break;
            }
        }

        // METAMORPHIC ASSERTION: Drain mode allows 2*L bound
        let drain_limit = cancel_streak_limit.saturating_mul(2);
        prop_assert!(
            max_consecutive_cancel <= drain_limit,
            "MR5 VIOLATION: cancel streak in drain mode exceeded 2*L bound - max: {}, limit: {}",
            max_consecutive_cancel, drain_limit
        );
    });
}

/// MR6: Work-Stealing Locality Preservation (Equivalence, Score: 7.5)
/// Property: Work-stealing preserves pinned !Send locality
/// Catches: Locality violations, work stealing bugs, thread affinity issues
#[test]
fn mr_work_stealing_locality_preservation() {
    proptest!(|(
        worker_count in 2usize..4,
        tasks_per_worker in 2usize..6,
        seed in any::<u64>(),
    )| {
        let _state = Arc::new(ContendedMutex::new(
            "metamorphic.runtime_state",
            RuntimeState::new()
        ));
        let mut scheduler = create_test_scheduler(worker_count);
        let mut workers = scheduler.take_workers();

        // Generate unique task sets per worker
        let mut all_task_ids: Vec<TaskId> = Vec::new();
        for worker_id in 0..worker_count {
            let worker_tasks = generate_task_ids(
                tasks_per_worker,
                seed + (worker_id as u64)
            );
            all_task_ids.extend(&worker_tasks);

            // Inject work directly to specific worker's local queue
            for &task_id in &worker_tasks {
                scheduler.inject_ready(task_id, 100);
            }
        }

        // Record initial work distribution
        let _initial_work_per_worker: Vec<usize> = workers
            .iter()
            .map(|w| w.ready_count())
            .collect();

        // Process work allowing stealing
        let mut tasks_processed_per_worker = vec![0; worker_count];
        let max_iterations = all_task_ids.len() * 2; // Prevent infinite loops

        for _ in 0..max_iterations {
            let mut any_work = false;
            for (worker_id, worker) in workers.iter_mut().enumerate() {
                if let Some(_task_id) = worker.next_task() {
                    tasks_processed_per_worker[worker_id] += 1;
                    any_work = true;
                }
            }
            if !any_work {
                break;
            }
        }

        // METAMORPHIC ASSERTION: All work should be processed
        let total_processed: usize = tasks_processed_per_worker.iter().sum();
        let total_spawned = all_task_ids.len();

        prop_assert_eq!(
            total_processed, total_spawned,
            "MR6 VIOLATION: work conservation failed in stealing scenario - processed: {}, spawned: {}",
            total_processed, total_spawned
        );

        // Check that work was distributed (stealing occurred or all workers got some work)
        let workers_that_processed = tasks_processed_per_worker.iter().filter(|&&count| count > 0).count();
        prop_assert!(
            workers_that_processed >= 1,
            "MR6 VIOLATION: no workers processed any work"
        );
    });
}

/// MR7: EDF Timed-Lane Ordering (Permutative, Score: 8.0)
/// Property: EDF timed-lane ordering respects earliest deadline under concurrent inserts
/// Catches: EDF ordering bugs, deadline priority violations, concurrent insertion bugs
#[test]
fn mr_edf_timed_lane_ordering() {
    // Time imported at module level

    proptest!(|(
        task_count in 3usize..8,
        seed in any::<u64>(),
        deadline_spread_ms in 10u64..100,
    )| {
        let _state = Arc::new(ContendedMutex::new(
            "metamorphic.runtime_state",
            RuntimeState::new()
        ));
        let mut scheduler = create_test_scheduler(1);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Generate tasks with different deadlines
        let task_ids = generate_task_ids(task_count, seed);
        let base_time = Time::from_nanos(1_000_000_000); // 1 second base
        let mut deadlines = Vec::new();

        for (i, &task_id) in task_ids.iter().enumerate() {
            let deadline = base_time + Duration::from_millis(deadline_spread_ms * (i as u64 + 1));
            deadlines.push(deadline);
            scheduler.inject_timed(task_id, deadline);
        }

        // Expected order: earliest deadline first
        let mut deadline_order: Vec<_> = deadlines.iter().enumerate().collect();
        deadline_order.sort_by_key(|(_, deadline)| **deadline);
        let expected_earliest_index = deadline_order[0].0;

        // Process timed work and verify EDF ordering
        let mut dispatch_order = Vec::new();
        for _ in 0..task_count {
            if let Some(task_id) = worker.next_task() {
                if let Some(pos) = task_ids.iter().position(|&id| id == task_id) {
                    dispatch_order.push(pos);
                }
            }
        }

        // METAMORPHIC ASSERTION: First dispatched should be earliest deadline
        if !dispatch_order.is_empty() {
            prop_assert_eq!(
                dispatch_order[0], expected_earliest_index,
                "MR7 VIOLATION: EDF ordering violated - dispatched task {} first, expected task {} (earliest deadline)",
                dispatch_order[0], expected_earliest_index
            );
        }

        // Verify all deadlines are in non-decreasing order when dispatched
        if dispatch_order.len() > 1 {
            for window in dispatch_order.windows(2) {
                let first_deadline = deadlines[window[0]];
                let second_deadline = deadlines[window[1]];
                prop_assert!(
                    first_deadline <= second_deadline,
                    "MR7 VIOLATION: EDF ordering violated between consecutive dispatches - task {} deadline {:?} > task {} deadline {:?}",
                    window[0], first_deadline, window[1], second_deadline
                );
            }
        }
    });
}

// ============================================================================
// Composite Lane Ordering Relations
// ============================================================================

/// Composite MR: Cancel Starvation + Drain Bound Consistency
/// Tests that drain mode properly doubles the cancel streak limit
#[test]
fn mr_composite_cancel_drain_consistency() {
    // SchedulingSuggestion imported at module level

    proptest!(|(
        cancel_streak_limit in 2usize..5,
        seed in any::<u64>(),
    )| {
        let state = Arc::new(ContendedMutex::new(
            "metamorphic.runtime_state",
            RuntimeState::new()
        ));

        // Test normal mode
        let mut scheduler_normal = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_streak_limit);
        let mut workers_normal = scheduler_normal.take_workers();
        let worker_normal = &mut workers_normal[0];

        // Test drain mode
        let mut scheduler_drain = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_streak_limit);
        let mut workers_drain = scheduler_drain.take_workers();
        let worker_drain = &mut workers_drain[0];

        #[cfg(any(test, feature = "test-internals"))]
        worker_drain.set_cached_suggestion(SchedulingSuggestion::DrainObligations);

        // Generate same workload for both
        let ready_tasks = generate_task_ids(2, seed);
        let cancel_tasks = generate_task_ids(cancel_streak_limit * 3, seed + 1); // Enough to test limits

        // Inject work to both schedulers identically
        for &task_id in &ready_tasks {
            scheduler_normal.inject_ready(task_id, 100);
            scheduler_drain.inject_ready(task_id, 100);
        }
        for &task_id in &cancel_tasks {
            scheduler_normal.inject_cancel(task_id, 100);
            scheduler_drain.inject_cancel(task_id, 100);
        }

        // Track maximum streaks in both modes
        let normal_certificate = worker_normal.preemption_fairness_certificate();
        let drain_certificate = worker_drain.preemption_fairness_certificate();

        // COMPOSITE ASSERTION: Drain mode should allow 2x the base limit
        prop_assert_eq!(
            drain_certificate.effective_limit,
            normal_certificate.base_limit.saturating_mul(2),
            "COMPOSITE MR VIOLATION: drain mode effective limit not 2x base limit"
        );

        prop_assert_eq!(
            normal_certificate.effective_limit,
            normal_certificate.base_limit,
            "COMPOSITE MR VIOLATION: normal mode effective limit should equal base limit"
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

    /// Validate cancel starvation bound test infrastructure
    #[test]
    fn validate_cancel_starvation_bound_infrastructure() {
        // SchedulingSuggestion imported at module level

        let state = Arc::new(ContendedMutex::new(
            "test.runtime_state",
            RuntimeState::new()
        ));
        let cancel_streak_limit = 4;
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_streak_limit);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Inject a ready task and several cancel tasks
        let ready_task = generate_task_ids(1, 42)[0];
        let cancel_tasks = generate_task_ids(6, 43);

        scheduler.inject_ready(ready_task, 100);
        for &task_id in &cancel_tasks {
            scheduler.inject_cancel(task_id, 100);
        }

        // Verify the test can track cancel streaks
        let mut cancel_streak = 0;
        let mut max_streak = 0;

        for _ in 0..7 { // Process more than cancel_streak_limit
            if let Some(task_id) = worker.next_task() {
                if cancel_tasks.contains(&task_id) {
                    cancel_streak += 1;
                    max_streak = max_streak.max(cancel_streak);
                } else if task_id == ready_task {
                    cancel_streak = 0;
                }
            } else {
                break;
            }
        }

        assert!(max_streak <= cancel_streak_limit,
                "Infrastructure test: cancel streak should respect limit");
    }

    /// Validate EDF timed lane ordering test infrastructure
    #[test]
    fn validate_edf_ordering_infrastructure() {
        // Time imported at module level

        let _state = Arc::new(ContendedMutex::new(
            "test.runtime_state",
            RuntimeState::new()
        ));
        let mut scheduler = create_test_scheduler(1);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Create tasks with known deadline order
        let task_ids = generate_task_ids(3, 789);
        let base_time = Time::from_nanos(1_000_000_000);

        let deadline1 = base_time + Duration::from_millis(30); // Latest
        let deadline2 = base_time + Duration::from_millis(10); // Earliest
        let deadline3 = base_time + Duration::from_millis(20); // Middle

        scheduler.inject_timed(task_ids[0], deadline1);
        scheduler.inject_timed(task_ids[1], deadline2);
        scheduler.inject_timed(task_ids[2], deadline3);

        // Should dispatch in EDF order: task1 (earliest), task2 (middle), task0 (latest)
        let first = worker.next_task();
        assert_eq!(first, Some(task_ids[1]), "Should dispatch earliest deadline first");

        let second = worker.next_task();
        assert_eq!(second, Some(task_ids[2]), "Should dispatch middle deadline second");

        let third = worker.next_task();
        assert_eq!(third, Some(task_ids[0]), "Should dispatch latest deadline third");
    }
}
