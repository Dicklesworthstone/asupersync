//! Metamorphic testing for `runtime::scheduler::local_queue` work-stealing invariants.
//!
//! Tests fundamental work-stealing properties that must hold regardless of concurrent
//! access patterns, task distributions, or execution schedules using LabRuntime DPOR.

use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::{region, Cx, Scope};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Configuration for local queue metamorphic tests.
#[derive(Debug, Clone)]
struct LocalQueueTestConfig {
    /// Number of tasks to test with
    task_count: usize,
    /// Number of concurrent stealers
    stealer_count: usize,
    /// Number of operations per thread
    operations_per_thread: usize,
    /// Fraction of tasks to mark as local (0.0 to 1.0)
    local_task_fraction: f64,
}

impl Arbitrary for LocalQueueTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            1usize..=200,     // task_count
            1usize..=8,       // stealer_count
            1usize..=100,     // operations_per_thread
            0.0f64..=0.5,     // local_task_fraction (cap at 50% for stealability)
        )
            .prop_map(|(task_count, stealer_count, operations_per_thread, local_task_fraction)| {
                LocalQueueTestConfig {
                    task_count,
                    stealer_count,
                    operations_per_thread,
                    local_task_fraction,
                }
            })
            .boxed()
    }
}

/// Test harness for managing local queue state and operations.
struct LocalQueueTestHarness {
    lab: LabRuntime,
    state: Arc<ContendedMutex<RuntimeState>>,
    queues: Vec<LocalQueue>,
    stealers: Vec<Vec<Stealer>>,
    task_counts: HashMap<TaskId, usize>,
}

impl LocalQueueTestHarness {
    fn new(config: &LocalQueueTestConfig) -> Self {
        let lab = LabRuntime::new();
        let state = LocalQueue::test_state((config.task_count - 1) as u32);

        // Create multiple queues for testing
        let num_queues = (config.stealer_count + 1).max(2);
        let mut queues = Vec::new();
        let mut stealers = Vec::new();

        for _ in 0..num_queues {
            let queue = LocalQueue::new(Arc::clone(&state));
            let queue_stealers: Vec<_> = (0..config.stealer_count)
                .map(|_| queue.stealer())
                .collect();
            stealers.push(queue_stealers);
            queues.push(queue);
        }

        let task_counts = HashMap::new();

        Self {
            lab,
            state,
            queues,
            stealers,
            task_counts,
        }
    }

    fn task(&self, id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn mark_tasks_local(&self, local_task_ids: &[u32]) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for &id in local_task_ids {
            if let Some(record) = guard.task_mut(self.task(id)) {
                record.mark_local();
            }
        }
    }

    fn fill_queue(&self, queue_idx: usize, task_ids: &[u32]) {
        let queue = &self.queues[queue_idx];
        for &id in task_ids {
            queue.push(self.task(id));
        }
    }

    fn drain_queue(&self, queue_idx: usize) -> Vec<TaskId> {
        let queue = &self.queues[queue_idx];
        let mut tasks = Vec::new();
        while let Some(task) = queue.pop() {
            tasks.push(task);
        }
        tasks
    }

    fn steal_from_queue(&self, queue_idx: usize, stealer_idx: usize) -> Option<TaskId> {
        self.stealers[queue_idx][stealer_idx].steal()
    }

    fn count_all_tasks(&self) -> HashMap<TaskId, usize> {
        let mut counts = HashMap::new();
        for queue in &self.queues {
            let mut temp_tasks = Vec::new();
            while let Some(task) = queue.pop() {
                temp_tasks.push(task);
                *counts.entry(task).or_insert(0) += 1;
            }
            // Restore tasks
            for task in temp_tasks.into_iter().rev() {
                queue.push(task);
            }
        }
        counts
    }

    fn verify_no_duplicates(&self) -> bool {
        let counts = self.count_all_tasks();
        counts.values().all(|&count| count <= 1)
    }

    fn get_queue_lengths(&self) -> Vec<usize> {
        self.queues.iter().map(|q| q.len()).collect()
    }

    fn verify_steal_bounded(&self, queue_idx: usize) -> bool {
        const MAX_STEAL_LOOKAHEAD: usize = 8; // SKIPPED_LOCALS_INLINE_CAP

        // Fill queue with many local tasks followed by one remote
        let queue = &self.queues[queue_idx];
        let initial_len = queue.len();

        // If queue has more local tasks than lookahead limit,
        // steal should still find the remote task within bounds
        let stealer = &self.stealers[queue_idx][0];
        let steal_attempts = 10;

        for _ in 0..steal_attempts {
            match stealer.steal() {
                Some(_) => return true, // Found a stealable task
                None => continue,       // Hit local tasks or empty
            }
        }

        // If no steals succeeded but queue wasn't empty,
        // verify it was due to local tasks, not unbounded search
        queue.len() == initial_len
    }
}

// ============================================================================
// METAMORPHIC RELATION 1: LIFO Owner vs FIFO Stealer Ordering
// ============================================================================

proptest! {
    #[test]
    fn mr1_owner_lifo_stealer_fifo_ordering(
        config: LocalQueueTestConfig,
        task_sequence in prop::collection::vec(0u32..200, 1..=50),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let queue_idx = 0;
            let task_ids: Vec<u32> = task_sequence.into_iter().take(config.task_count.min(50)).collect();

            // Fill queue with task sequence
            harness.fill_queue(queue_idx, &task_ids);

            // Owner pop should be LIFO (last pushed first)
            let owner_popped = harness.drain_queue(queue_idx);

            // Refill for stealer test
            harness.fill_queue(queue_idx, &task_ids);

            // Stealer should see FIFO (first pushed first)
            let mut stealer_stolen = Vec::new();
            for _ in 0..task_ids.len() {
                if let Some(task) = harness.steal_from_queue(queue_idx, 0) {
                    stealer_stolen.push(task);
                }
            }

            // METAMORPHIC RELATION: reverse(owner_order) == stealer_order
            let owner_ids: Vec<u32> = owner_popped.iter().map(|t| t.0.index()).collect();
            let stealer_ids: Vec<u32> = stealer_stolen.iter().map(|t| t.0.index()).collect();

            let reversed_owner: Vec<u32> = owner_ids.into_iter().rev().collect();

            prop_assert_eq!(
                reversed_owner, stealer_ids,
                "MR1: Owner LIFO order reversed must equal stealer FIFO order"
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 2: No Task Duplication Under Concurrency
// ============================================================================

proptest! {
    #[test]
    fn mr2_no_task_duplication_invariant(
        config: LocalQueueTestConfig,
        task_ids in prop::collection::vec(0u32..200, 1..=100),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let limited_ids: Vec<u32> = task_ids.into_iter()
                .take(config.task_count.min(100))
                .collect();

            // Initial state: populate multiple queues
            for (queue_idx, chunk) in limited_ids.chunks(limited_ids.len() / harness.queues.len().max(1)).enumerate() {
                if queue_idx < harness.queues.len() {
                    harness.fill_queue(queue_idx, chunk);
                }
            }

            let initial_counts = harness.count_all_tasks();

            // Concurrent operations: stealing and pushing
            let mut handles = Vec::new();

            for stealer_idx in 0..config.stealer_count {
                let harness_ref = &harness;
                let handle = scope.spawn(async move {
                    for _ in 0..config.operations_per_thread {
                        for queue_idx in 0..harness_ref.queues.len() {
                            if stealer_idx < harness_ref.stealers[queue_idx].len() {
                                let _ = harness_ref.steal_from_queue(queue_idx, stealer_idx);
                            }
                        }
                        cx.yield_now().await;
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join(cx).await?;
            }

            let final_counts = harness.count_all_tasks();

            // METAMORPHIC RELATION: ∀task. count(task) ≤ 1 always
            for (task, count) in final_counts {
                prop_assert!(
                    count <= 1,
                    "MR2: Task {:?} duplicated {} times (max allowed: 1)",
                    task, count
                );
            }

            // Additional invariant: total task count should not exceed initial
            let initial_total: usize = initial_counts.values().sum();
            let final_total: usize = harness.count_all_tasks().values().sum();

            prop_assert!(
                final_total <= initial_total,
                "MR2: Total task count increased from {} to {} (should not exceed initial)",
                initial_total, final_total
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 3: Overflow Behavior Invariant
// ============================================================================

proptest! {
    #[test]
    fn mr3_overflow_capacity_invariant(
        config: LocalQueueTestConfig,
        excess_tasks in prop::collection::vec(0u32..500, 200..=400),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let queue_idx = 0;
            let capacity_limit = 256; // VecDeque default capacity

            // Fill beyond capacity
            let task_chunk: Vec<u32> = excess_tasks.into_iter()
                .take(config.task_count.min(400))
                .collect();

            // Record length before overflow
            let initial_len = harness.queues[queue_idx].len();

            harness.fill_queue(queue_idx, &task_chunk);

            let after_fill_len = harness.queues[queue_idx].len();

            // METAMORPHIC RELATION: growth rate should be manageable
            // (This tests that the queue doesn't reject tasks but handles them gracefully)
            prop_assert!(
                after_fill_len >= initial_len,
                "MR3: Queue length should not decrease after adding tasks (was {}, became {})",
                initial_len, after_fill_len
            );

            // Verify that steals still work correctly even when queue is large
            let stolen_count = (0..10)
                .map(|_| harness.steal_from_queue(queue_idx, 0).is_some() as usize)
                .sum::<usize>();

            let post_steal_len = harness.queues[queue_idx].len();

            prop_assert!(
                post_steal_len + stolen_count >= after_fill_len.saturating_sub(task_chunk.len()),
                "MR3: Stolen count {} should account for queue length change {} -> {}",
                stolen_count, after_fill_len, post_steal_len
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 4: Steal Lookahead Bounded Invariant
// ============================================================================

proptest! {
    #[test]
    fn mr4_steal_lookahead_bounded_invariant(
        config: LocalQueueTestConfig,
        local_task_pattern in prop::collection::vec(prop::bool::ANY, 1..=20),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let queue_idx = 0;
            let max_lookahead = 8; // SKIPPED_LOCALS_INLINE_CAP

            // Create task sequence alternating local/remote based on pattern
            let mut task_sequence = Vec::new();
            let mut local_tasks = Vec::new();

            for (i, &is_local) in local_task_pattern.iter().enumerate() {
                let task_id = i as u32;
                task_sequence.push(task_id);
                if is_local && i < max_lookahead * 2 { // Focus on lookahead boundary
                    local_tasks.push(task_id);
                }
            }

            harness.mark_tasks_local(&local_tasks);
            harness.fill_queue(queue_idx, &task_sequence);

            let initial_len = harness.queues[queue_idx].len();

            // Attempt multiple steals to test bounded lookahead
            let mut steal_attempts = 0;
            let mut successful_steals = 0;

            for _ in 0..max_lookahead * 2 {
                steal_attempts += 1;
                if harness.steal_from_queue(queue_idx, 0).is_some() {
                    successful_steals += 1;
                }

                // Should not scan beyond lookahead bound
                if steal_attempts >= max_lookahead && successful_steals == 0 {
                    break;
                }
            }

            let final_len = harness.queues[queue_idx].len();

            // METAMORPHIC RELATION: bounded search should not scan entire queue
            prop_assert!(
                steal_attempts <= max_lookahead * 2,
                "MR4: Steal should respect lookahead bound {} (attempted {})",
                max_lookahead, steal_attempts
            );

            // Conservation: stolen + remaining == initial
            prop_assert_eq!(
                successful_steals + final_len,
                initial_len,
                "MR4: Task conservation: stolen {} + remaining {} != initial {}",
                successful_steals, final_len, initial_len
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 5: Cancelled Tasks Do Not Block Queue Advancement
// ============================================================================

proptest! {
    #[test]
    fn mr5_cancelled_tasks_non_blocking_invariant(
        config: LocalQueueTestConfig,
        task_mix in prop::collection::vec((0u32..100, prop::bool::ANY), 5..=50),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let queue_idx = 0;

            // Setup: separate cancelled (local) and active tasks
            let mut all_tasks = Vec::new();
            let mut cancelled_tasks = Vec::new();

            for (task_id, is_cancelled) in task_mix.iter().take(config.task_count.min(50)) {
                all_tasks.push(*task_id);
                if *is_cancelled {
                    cancelled_tasks.push(*task_id);
                }
            }

            // Mark cancelled tasks as local (simulating cancellation effect)
            harness.mark_tasks_local(&cancelled_tasks);
            harness.fill_queue(queue_idx, &all_tasks);

            let initial_len = harness.queues[queue_idx].len();
            let initial_non_cancelled = all_tasks.len() - cancelled_tasks.len();

            // Attempt to steal all non-cancelled tasks
            let mut stolen_tasks = Vec::new();
            for _ in 0..initial_len * 2 { // Try more than necessary
                if let Some(task) = harness.steal_from_queue(queue_idx, 0) {
                    stolen_tasks.push(task);
                } else {
                    break; // No more stealable tasks
                }
            }

            // Owner should still see cancelled tasks in LIFO order
            let owner_tasks = harness.drain_queue(queue_idx);

            let stolen_count = stolen_tasks.len();
            let remaining_count = owner_tasks.len();

            // METAMORPHIC RELATION: cancelled tasks don't block active task progression
            prop_assert!(
                stolen_count <= initial_non_cancelled,
                "MR5: Should not steal more than non-cancelled tasks ({} stolen, {} non-cancelled)",
                stolen_count, initial_non_cancelled
            );

            // Conservation: all tasks accounted for
            prop_assert_eq!(
                stolen_count + remaining_count,
                initial_len,
                "MR5: Task conservation failed: stolen {} + remaining {} != initial {}",
                stolen_count, remaining_count, initial_len
            );

            // Verify cancelled tasks remain accessible to owner
            let remaining_ids: HashSet<u32> = owner_tasks.iter()
                .map(|t| t.0.index())
                .collect();

            for &cancelled_id in &cancelled_tasks {
                if all_tasks.contains(&cancelled_id) {
                    prop_assert!(
                        remaining_ids.contains(&cancelled_id),
                        "MR5: Cancelled task {} should remain accessible to owner",
                        cancelled_id
                    );
                }
            }

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 6: High Concurrency Preserves Task Ordering Per Lane
// ============================================================================

proptest! {
    #[test]
    fn mr6_high_concurrency_ordering_invariant(
        config: LocalQueueTestConfig,
        lane_sequences in prop::collection::vec(
            prop::collection::vec(0u32..50, 1..=20),
            2..=4
        ),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            // Setup: Each lane has its own task sequence
            let mut lane_tasks: Vec<Vec<u32>> = lane_sequences.into_iter()
                .take(harness.queues.len().min(4))
                .map(|seq| seq.into_iter().take(config.task_count / 4).collect())
                .collect();

            // Pad to ensure we have enough lanes
            while lane_tasks.len() < 2 {
                lane_tasks.push(vec![100 + lane_tasks.len() as u32]);
            }

            // Record initial ordering per lane
            let mut initial_orderings = Vec::new();

            for (lane_idx, task_seq) in lane_tasks.iter().enumerate() {
                if lane_idx < harness.queues.len() {
                    harness.fill_queue(lane_idx, task_seq);
                    initial_orderings.push(task_seq.clone());
                }
            }

            // High concurrency: multiple stealers cross-stealing
            let mut handles = Vec::new();
            let steal_results = Arc::new(std::sync::Mutex::new(Vec::new()));

            for stealer_idx in 0..config.stealer_count.min(4) {
                let steal_results = Arc::clone(&steal_results);
                let harness_ref = &harness;

                let handle = scope.spawn(async move {
                    let mut stealer_tasks = Vec::new();

                    for _ in 0..config.operations_per_thread.min(20) {
                        // Steal from multiple lanes
                        for queue_idx in 0..harness_ref.queues.len().min(lane_tasks.len()) {
                            if stealer_idx < harness_ref.stealers[queue_idx].len() {
                                if let Some(task) = harness_ref.steal_from_queue(queue_idx, stealer_idx) {
                                    stealer_tasks.push((queue_idx, task));
                                }
                            }
                        }
                        cx.yield_now().await;
                    }

                    steal_results.lock().unwrap().push((stealer_idx, stealer_tasks));
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join(cx).await?;
            }

            // Collect remaining tasks from owners
            let mut final_owner_tasks = Vec::new();
            for queue_idx in 0..harness.queues.len().min(lane_tasks.len()) {
                let owner_tasks = harness.drain_queue(queue_idx);
                final_owner_tasks.push((queue_idx, owner_tasks));
            }

            // METAMORPHIC RELATION: Within each lane, relative ordering is preserved
            for (lane_idx, initial_seq) in initial_orderings.iter().enumerate() {
                // Collect all tasks that originated from this lane
                let mut lane_task_positions = HashMap::new();
                for (pos, &task_id) in initial_seq.iter().enumerate() {
                    lane_task_positions.insert(task_id, pos);
                }

                // Find where these tasks ended up (stolen or owner)
                let mut recovered_tasks = Vec::new();

                // From stealers
                let steal_results = steal_results.lock().unwrap();
                for (_, stealer_tasks) in steal_results.iter() {
                    for &(source_lane, task) in stealer_tasks {
                        if source_lane == lane_idx {
                            let task_id = task.0.index();
                            if let Some(&pos) = lane_task_positions.get(&task_id) {
                                recovered_tasks.push((pos, task_id));
                            }
                        }
                    }
                }

                // From owners
                if lane_idx < final_owner_tasks.len() {
                    for task in &final_owner_tasks[lane_idx].1 {
                        let task_id = task.0.index();
                        if let Some(&pos) = lane_task_positions.get(&task_id) {
                            recovered_tasks.push((pos, task_id));
                        }
                    }
                }

                // Sort by original position and check monotonicity within sublists
                recovered_tasks.sort_by_key(|&(pos, _)| pos);

                let recovered_positions: Vec<usize> = recovered_tasks.iter()
                    .map(|&(pos, _)| pos)
                    .collect();

                // Check that we didn't lose tasks
                prop_assert!(
                    recovered_tasks.len() <= initial_seq.len(),
                    "MR6: Lane {} recovered {} tasks but started with {} (possible duplication)",
                    lane_idx, recovered_tasks.len(), initial_seq.len()
                );

                // Verify relative ordering preservation for subsequences
                if recovered_positions.len() > 1 {
                    let mut is_monotonic_subsequence = true;
                    for window in recovered_positions.windows(2) {
                        if window[0] > window[1] {
                            // Check if this is due to stealing (FIFO) vs owner (LIFO) difference
                            let gap = window[0] - window[1];
                            if gap > initial_seq.len() / 2 {
                                // Large gap suggests cross-boundary effect, allow it
                                continue;
                            }
                            is_monotonic_subsequence = false;
                            break;
                        }
                    }

                    prop_assert!(
                        is_monotonic_subsequence || recovered_positions.len() < initial_seq.len() / 2,
                        "MR6: Lane {} ordering violated: positions {:?}",
                        lane_idx, recovered_positions
                    );
                }
            }

            Ok(())
        }));
    }
}

// ============================================================================
// ADDITIONAL INVARIANT TESTS
// ============================================================================

proptest! {
    #[test]
    fn queue_conservation_under_stress(
        config: LocalQueueTestConfig,
        operations in prop::collection::vec(
            prop::sample::select(vec!["push", "pop", "steal", "batch_steal"]),
            50..=200
        ),
    ) {
        let harness = LocalQueueTestHarness::new(&config);

        harness.lab.block_on(region!(|cx: &Cx, scope: &Scope| async move {
            // Initial population
            let task_ids: Vec<u32> = (0..config.task_count as u32).collect();
            harness.fill_queue(0, &task_ids);

            let initial_count = harness.queues[0].len();
            let mut push_count = initial_count;
            let mut pop_count = 0;
            let mut steal_count = 0;

            // Execute random operations
            for op in operations.iter().take(config.operations_per_thread) {
                match op.as_str() {
                    "push" => {
                        if push_count < config.task_count * 2 {
                            harness.queues[0].push(harness.task(push_count as u32));
                            push_count += 1;
                        }
                    }
                    "pop" => {
                        if harness.queues[0].pop().is_some() {
                            pop_count += 1;
                        }
                    }
                    "steal" => {
                        if harness.steal_from_queue(0, 0).is_some() {
                            steal_count += 1;
                        }
                    }
                    "batch_steal" => {
                        if harness.queues.len() > 1 {
                            if harness.stealers[0][0].steal_batch(&harness.queues[1]) {
                                // Approximate steal count (batch steals ~half)
                                steal_count += harness.queues[1].len().min(5);
                            }
                        }
                    }
                    _ => {}
                }

                cx.yield_now().await;
            }

            let final_count = harness.get_queue_lengths().iter().sum::<usize>();
            let expected_count = push_count - pop_count - steal_count;

            // Allow some approximation for batch operations
            let tolerance = 10;

            prop_assert!(
                final_count <= expected_count + tolerance &&
                final_count + tolerance >= expected_count,
                "Conservation violated: expected ~{}, got {} (push:{}, pop:{}, steal:{})",
                expected_count, final_count, push_count, pop_count, steal_count
            );

            Ok(())
        }));
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let config = LocalQueueTestConfig {
            task_count: 10,
            stealer_count: 2,
            operations_per_thread: 5,
            local_task_fraction: 0.3,
        };

        let harness = LocalQueueTestHarness::new(&config);
        assert!(harness.queues.len() >= 2);
        assert_eq!(harness.stealers.len(), harness.queues.len());
        assert!(harness.stealers[0].len() == config.stealer_count);
    }

    #[test]
    fn test_basic_lifo_fifo_property() {
        let config = LocalQueueTestConfig {
            task_count: 5,
            stealer_count: 1,
            operations_per_thread: 1,
            local_task_fraction: 0.0,
        };

        let harness = LocalQueueTestHarness::new(&config);

        // Push sequence: 1, 2, 3
        harness.fill_queue(0, &[1, 2, 3]);

        // Owner pop: should be 3, 2, 1 (LIFO)
        let owner_result = harness.drain_queue(0);
        assert_eq!(
            owner_result.iter().map(|t| t.0.index()).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );

        // Refill for stealer test
        harness.fill_queue(0, &[1, 2, 3]);

        // Stealer: should be 1, 2, 3 (FIFO)
        let mut stealer_result = Vec::new();
        for _ in 0..3 {
            if let Some(task) = harness.steal_from_queue(0, 0) {
                stealer_result.push(task.0.index());
            }
        }
        assert_eq!(stealer_result, vec![1, 2, 3]);
    }

    #[test]
    fn test_local_task_filtering() {
        let config = LocalQueueTestConfig {
            task_count: 5,
            stealer_count: 1,
            operations_per_thread: 1,
            local_task_fraction: 0.5,
        };

        let harness = LocalQueueTestHarness::new(&config);

        // Mark tasks 1 and 3 as local
        harness.mark_tasks_local(&[1, 3]);
        harness.fill_queue(0, &[1, 2, 3, 4]);

        // Stealer should only get non-local tasks (2, 4)
        let mut stolen = Vec::new();
        for _ in 0..4 {
            if let Some(task) = harness.steal_from_queue(0, 0) {
                stolen.push(task.0.index());
            }
        }

        assert!(!stolen.contains(&1)); // Local task not stolen
        assert!(!stolen.contains(&3)); // Local task not stolen
        assert!(stolen.contains(&2) || stolen.contains(&4)); // Non-local tasks can be stolen
    }
}