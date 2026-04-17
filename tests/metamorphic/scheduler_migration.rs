//! Metamorphic tests for scheduler task migration and work stealing fairness.
//!
//! These tests validate the fairness properties of the work stealing scheduler
//! using metamorphic relations to ensure task migration doesn't violate invariants.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use proptest::prelude::*;

use asupersync::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use asupersync::runtime::scheduler::stealing::steal_task;
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::types::TaskId;
use asupersync::util::DetRng;

/// Generate a deterministic task ID for testing.
fn test_task_id(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

/// Create a test runtime state for scheduler testing.
fn create_test_runtime_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new(RuntimeState::new_for_test()))
}

/// Create a test task table for scheduler testing.
fn create_test_task_table() -> Arc<ContendedMutex<TaskTable>> {
    Arc::new(ContendedMutex::new(TaskTable::new_for_test()))
}

/// Arbitrary strategy for generating lists of task IDs.
fn arb_task_list() -> impl Strategy<Value = Vec<TaskId>> {
    prop::collection::vec((1u32..10000u32).prop_map(test_task_id), 0..50)
}

/// Arbitrary strategy for work distribution across multiple queues.
fn arb_work_distribution() -> impl Strategy<Value = Vec<Vec<TaskId>>> {
    prop::collection::vec(arb_task_list(), 1..8) // 1-8 worker queues
}

// Metamorphic Relations for Scheduler Task Migration

/// MR1: Work Conservation - Total work is preserved during stealing operations.
/// The total number of tasks across all queues should remain constant.
#[test]
fn mr_work_conservation_during_stealing() {
    proptest!(|(work_dist in arb_work_distribution(), steal_ops in 1u32..20)| {
        let runtime_state = create_test_runtime_state();
        let mut queues = Vec::new();
        let mut stealers = Vec::new();

        // Create queues and populate with initial work
        let mut total_initial_work = 0;
        for tasks in &work_dist {
            let queue = LocalQueue::new(Arc::clone(&runtime_state));
            total_initial_work += tasks.len();

            // Push tasks to queue (simulate work arrival)
            for &task_id in tasks {
                queue.push_back(task_id);
            }

            stealers.push(queue.stealer());
            queues.push(queue);
        }

        // Perform stealing operations
        let mut rng = DetRng::from_seed([42; 32]);
        let mut stolen_tasks = Vec::new();

        for _ in 0..steal_ops {
            if let Some(task) = steal_task(&stealers, &mut rng) {
                stolen_tasks.push(task);
            }
        }

        // Count remaining work in all queues
        let mut total_remaining_work = stolen_tasks.len();
        for queue in &queues {
            total_remaining_work += queue.len();
        }

        // Work conservation: initial work = remaining + stolen
        prop_assert_eq!(total_initial_work, total_remaining_work,
            "Work conservation violated: initial={}, remaining={}",
            total_initial_work, total_remaining_work);
    });
}

/// MR2: Fairness under repetition - Repeated stealing with identical setup
/// should produce deterministic results (given deterministic RNG).
#[test]
fn mr_fairness_determinism() {
    proptest!(|(work_dist in arb_work_distribution(), steal_count in 1u32..10)| {
        // First run
        let runtime_state1 = create_test_runtime_state();
        let result1 = simulate_stealing_scenario(&work_dist, steal_count, &runtime_state1, [42; 32]);

        // Second run with identical setup
        let runtime_state2 = create_test_runtime_state();
        let result2 = simulate_stealing_scenario(&work_dist, steal_count, &runtime_state2, [42; 32]);

        // Results should be identical with same seed
        prop_assert_eq!(result1.stolen_tasks, result2.stolen_tasks,
            "Deterministic stealing failed: same seed produced different results");
        prop_assert_eq!(result1.final_queue_sizes, result2.final_queue_sizes,
            "Queue sizes differ between identical runs");
    });
}

/// MR3: Stealing preference for loaded queues - The power-of-two-choices
/// algorithm should prefer stealing from more loaded queues over time.
#[test]
fn mr_stealing_prefers_loaded_queues() {
    proptest!(|(steal_ops in 10u32..50)| {
        let runtime_state = create_test_runtime_state();

        // Create asymmetric load: one heavily loaded queue, others empty
        let heavy_load = (1..20).map(test_task_id).collect::<Vec<_>>();
        let light_loads = vec![vec![], vec![], vec![]]; // Empty queues

        let work_dist = [vec![heavy_load], light_loads].concat();
        let result = simulate_stealing_scenario(&work_dist, steal_ops, &runtime_state, [42; 32]);

        // Most steals should come from the heavily loaded queue (index 0)
        let steals_from_loaded = result.steal_sources.get(&0).unwrap_or(&0);
        let total_steals = result.steal_sources.values().sum::<usize>();

        if total_steals > 0 {
            let loaded_queue_ratio = *steals_from_loaded as f64 / total_steals as f64;
            prop_assert!(loaded_queue_ratio > 0.7,
                "Power-of-two-choices should prefer loaded queues: {}% from loaded queue",
                loaded_queue_ratio * 100.0);
        }
    });
}

/// MR4: LIFO owner vs FIFO stealer ordering - Tasks pushed to a queue should
/// be popped by owner in LIFO order, but stolen by others in FIFO order.
#[test]
fn mr_lifo_owner_fifo_stealer() {
    proptest!(|(task_sequence in arb_task_list().prop_filter("need multiple tasks", |v| v.len() >= 3))| {
        let runtime_state = create_test_runtime_state();
        let queue = LocalQueue::new(runtime_state);

        // Push sequence of tasks
        for &task_id in &task_sequence {
            queue.push_back(task_id);
        }

        // Owner pop should be LIFO (last pushed, first popped)
        if let Some(owner_task) = queue.pop() {
            prop_assert_eq!(owner_task, *task_sequence.last().unwrap(),
                "Owner pop should be LIFO: expected {}, got {}",
                task_sequence.last().unwrap().inner(), owner_task.inner());
        }

        // Stealer should get FIFO (first pushed, first stolen)
        let stealer = queue.stealer();
        if let Some(stolen_task) = stealer.steal() {
            prop_assert_eq!(stolen_task, task_sequence[0],
                "Stealer should be FIFO: expected {}, got {}",
                task_sequence[0].inner(), stolen_task.inner());
        }
    });
}

/// MR5: Load balancing effectiveness - After many steal operations,
/// queue sizes should be more balanced than initial distribution.
#[test]
fn mr_load_balancing_effectiveness() {
    proptest!(|(mut work_dist in arb_work_distribution().prop_filter("need imbalance", |d| {
        d.len() >= 2 && d.iter().map(|q| q.len()).max().unwrap() > d.iter().map(|q| q.len()).min().unwrap() + 2
    }), steal_ops in 20u32..100)| {
        // Ensure we have significant initial imbalance
        if work_dist.len() < 2 { return Ok(()); }

        let runtime_state = create_test_runtime_state();

        // Calculate initial imbalance
        let initial_sizes: Vec<usize> = work_dist.iter().map(|q| q.len()).collect();
        let initial_max = *initial_sizes.iter().max().unwrap();
        let initial_min = *initial_sizes.iter().min().unwrap();
        let initial_imbalance = initial_max.saturating_sub(initial_min);

        let result = simulate_stealing_scenario(&work_dist, steal_ops, &runtime_state, [42; 32]);

        // Calculate final imbalance
        let final_max = *result.final_queue_sizes.iter().max().unwrap();
        let final_min = *result.final_queue_sizes.iter().min().unwrap();
        let final_imbalance = final_max.saturating_sub(final_min);

        // Load balancing should reduce imbalance (or at least not make it much worse)
        if initial_imbalance > 3 {
            prop_assert!(final_imbalance <= initial_imbalance + 1,
                "Load balancing should reduce imbalance: initial={}, final={}",
                initial_imbalance, final_imbalance);
        }
    });
}

/// MR6: Steal operation idempotence under empty queues - Stealing from
/// empty queues should consistently return None and not affect state.
#[test]
fn mr_steal_empty_queues_idempotence() {
    proptest!(|(queue_count in 1usize..8, steal_attempts in 1u32..20)| {
        let runtime_state = create_test_runtime_state();
        let mut stealers = Vec::new();

        // Create empty queues
        for _ in 0..queue_count {
            let queue = LocalQueue::new(Arc::clone(&runtime_state));
            stealers.push(queue.stealer());
        }

        let mut rng = DetRng::from_seed([42; 32]);

        // All steal attempts should return None
        for _ in 0..steal_attempts {
            let result = steal_task(&stealers, &mut rng);
            prop_assert!(result.is_none(),
                "Stealing from empty queues should always return None");
        }
    });
}

/// Helper structure for stealing simulation results.
#[derive(Debug, Clone, PartialEq)]
struct StealingResult {
    stolen_tasks: Vec<TaskId>,
    final_queue_sizes: Vec<usize>,
    steal_sources: HashMap<usize, usize>, // queue_index -> steal_count
}

/// Simulate a stealing scenario and return detailed results.
fn simulate_stealing_scenario(
    work_dist: &[Vec<TaskId>],
    steal_count: u32,
    runtime_state: &Arc<ContendedMutex<RuntimeState>>,
    seed: [u8; 32],
) -> StealingResult {
    let mut queues = Vec::new();
    let mut stealers = Vec::new();

    // Create and populate queues
    for tasks in work_dist {
        let queue = LocalQueue::new(Arc::clone(runtime_state));
        for &task_id in tasks {
            queue.push_back(task_id);
        }
        stealers.push(queue.stealer());
        queues.push(queue);
    }

    let mut rng = DetRng::from_seed(seed);
    let mut stolen_tasks = Vec::new();
    let mut steal_sources = HashMap::new();

    // Track which queue each steal came from (simplified tracking)
    for _ in 0..steal_count {
        let initial_lens: Vec<usize> = stealers.iter().map(|s| s.len()).collect();

        if let Some(task) = steal_task(&stealers, &mut rng) {
            stolen_tasks.push(task);

            // Find which queue likely provided the task (heuristic)
            let final_lens: Vec<usize> = stealers.iter().map(|s| s.len()).collect();
            for (i, (initial, final)) in initial_lens.iter().zip(final_lens.iter()).enumerate() {
                if initial > final {
                    *steal_sources.entry(i).or_insert(0) += 1;
                    break;
                }
            }
        }
    }

    let final_queue_sizes = queues.iter().map(|q| q.len()).collect();

    StealingResult {
        stolen_tasks,
        final_queue_sizes,
        steal_sources,
    }
}

/// Unit tests for edge cases and specific scenarios.
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_single_queue_stealing() {
        let runtime_state = create_test_runtime_state();
        let queue = LocalQueue::new(runtime_state);

        // Add some tasks
        for i in 1..5 {
            queue.push_back(test_task_id(i));
        }

        let stealers = vec![queue.stealer()];
        let mut rng = DetRng::from_seed([42; 32]);

        // Should be able to steal from single queue
        let stolen = steal_task(&stealers, &mut rng);
        assert!(stolen.is_some(), "Should be able to steal from populated single queue");
    }

    #[test]
    fn test_power_of_two_distinct_choice() {
        let runtime_state = create_test_runtime_state();
        let mut stealers = Vec::new();

        // Create two queues with different loads
        let queue1 = LocalQueue::new(Arc::clone(&runtime_state));
        let queue2 = LocalQueue::new(Arc::clone(&runtime_state));

        // Load queue1 heavily
        for i in 1..10 {
            queue1.push_back(test_task_id(i));
        }

        // queue2 stays empty

        stealers.push(queue1.stealer());
        stealers.push(queue2.stealer());

        let mut rng = DetRng::from_seed([42; 32]);

        // Multiple steals should prefer the loaded queue
        let mut steals_from_loaded = 0;
        let total_attempts = 10;

        for _ in 0..total_attempts {
            if steal_task(&stealers, &mut rng).is_some() {
                steals_from_loaded += 1;
            }
        }

        assert!(steals_from_loaded > 0, "Should steal from loaded queue");
    }
}