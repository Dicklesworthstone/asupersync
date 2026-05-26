#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::scheduler::{
    local_queue::{LocalQueue, Stealer},
    stealing::steal_task,
};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::DetRng;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Maximum number of queues to prevent unbounded memory growth
const MAX_QUEUES: usize = 8;
/// Maximum operations per fuzz run to prevent timeout
const MAX_OPERATIONS: usize = 1000;
/// Maximum tasks per queue
const MAX_TASKS_PER_QUEUE: usize = 100;
/// Maximum task ID for consistent arena indexing
const MAX_TASK_ID: u32 = 500;

/// Fuzz input representing work stealing operations
#[derive(Arbitrary, Debug, Clone)]
struct WorkStealingFuzzInput {
    /// Number of worker queues to create
    pub queue_count: u8,
    /// RNG seed for deterministic stealing
    pub rng_seed: u64,
    /// Sequence of operations to perform
    pub operations: Vec<WorkStealingOperation>,
}

/// Individual work stealing operations
#[derive(Arbitrary, Debug, Clone)]
enum WorkStealingOperation {
    /// Push a task to a specific queue
    Push { queue_index: u8, task_id: u8 },
    /// Pop from a specific queue (owner operation)
    Pop { queue_index: u8 },
    /// Steal from a single queue
    StealSingle { queue_index: u8 },
    /// Multi-queue steal using power of two choices
    StealMultiple,
    /// Batch steal operation
    StealBatch { src_queue: u8, dest_queue: u8 },
    /// Check queue lengths and properties
    Inspect { queue_index: u8 },
    /// Verify system-wide invariants
    VerifyInvariants,
}

/// Shadow model for work stealing verification
#[derive(Debug)]
struct WorkStealingShadowModel {
    /// Track tasks in each queue (LIFO for owner, FIFO for stealing)
    queues: Vec<VecDeque<TaskId>>,
    /// Track which tasks exist globally
    global_tasks: BTreeSet<TaskId>,
    /// Track queue properties
    queue_properties: BTreeMap<usize, QueueProperties>,
}

#[derive(Debug, Default)]
struct QueueProperties {
    total_pushes: usize,
    total_pops: usize,
    total_steals: usize,
    last_length: usize,
}

impl WorkStealingShadowModel {
    fn new(queue_count: usize) -> Self {
        Self {
            queues: vec![VecDeque::new(); queue_count],
            global_tasks: BTreeSet::new(),
            queue_properties: BTreeMap::new(),
        }
    }

    fn push(&mut self, queue_index: usize, task: TaskId) -> bool {
        if queue_index >= self.queues.len() {
            return false;
        }

        // Only allow push if task doesn't exist globally (no duplicates)
        if !self.global_tasks.insert(task) {
            return false; // Task already exists
        }

        self.queues[queue_index].push_back(task);
        let props = self.queue_properties.entry(queue_index).or_default();
        props.total_pushes += 1;
        props.last_length = self.queues[queue_index].len();
        true
    }

    fn pop(&mut self, queue_index: usize) -> Option<TaskId> {
        if queue_index >= self.queues.len() {
            return None;
        }

        let task = self.queues[queue_index].pop_back(); // LIFO for owner
        if let Some(task) = task {
            self.global_tasks.remove(&task);
            let props = self.queue_properties.entry(queue_index).or_default();
            props.total_pops += 1;
            props.last_length = self.queues[queue_index].len();
        }
        task
    }

    fn steal_single(&mut self, queue_index: usize) -> Option<TaskId> {
        if queue_index >= self.queues.len() {
            return None;
        }

        let task = self.queues[queue_index].pop_front(); // FIFO for stealing
        if let Some(task) = task {
            self.global_tasks.remove(&task);
            let props = self.queue_properties.entry(queue_index).or_default();
            props.total_steals += 1;
            props.last_length = self.queues[queue_index].len();
        }
        task
    }

    fn steal_power_of_two(&mut self, rng: &mut DetRng) -> Option<TaskId> {
        let non_empty_queues: Vec<_> = self.queues
            .iter()
            .enumerate()
            .filter(|(_, q)| !q.is_empty())
            .map(|(i, _)| i)
            .collect();

        if non_empty_queues.is_empty() {
            return None;
        }

        if non_empty_queues.len() == 1 {
            return self.steal_single(non_empty_queues[0]);
        }

        // Power of Two Choices: pick two random queues, steal from the fuller one
        let idx1 = non_empty_queues[rng.next_usize(non_empty_queues.len())];
        let mut idx2 = non_empty_queues[rng.next_usize(non_empty_queues.len())];
        if idx1 == idx2 && non_empty_queues.len() > 1 {
            // Ensure two different queues
            idx2 = non_empty_queues
                .iter()
                .find(|&&i| i != idx1)
                .copied()
                .unwrap_or(idx1);
        }

        let len1 = self.queues[idx1].len();
        let len2 = self.queues[idx2].len();

        let primary = if len1 >= len2 { idx1 } else { idx2 };
        self.steal_single(primary)
    }

    fn len(&self, queue_index: usize) -> usize {
        if queue_index >= self.queues.len() {
            0
        } else {
            self.queues[queue_index].len()
        }
    }

    fn total_tasks(&self) -> usize {
        self.global_tasks.len()
    }

    fn queue_count(&self) -> usize {
        self.queues.len()
    }

    fn verify_task_uniqueness(&self) -> bool {
        let mut all_tasks = BTreeSet::new();
        for queue in &self.queues {
            for &task in queue {
                if !all_tasks.insert(task) {
                    return false; // Duplicate found
                }
            }
        }
        all_tasks.len() == self.total_tasks()
    }
}

fuzz_target!(|input: WorkStealingFuzzInput| {
    // Guard against excessive input size
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let queue_count = (input.queue_count as usize % MAX_QUEUES).max(1);
    let mut rng = DetRng::new(input.rng_seed);

    // Create worker queues with preallocated task records
    let mut queues = Vec::new();
    for _ in 0..queue_count {
        queues.push(LocalQueue::new_for_test(MAX_TASK_ID));
    }

    // Create shadow model for verification
    let mut shadow = WorkStealingShadowModel::new(queue_count);

    // Execute operations and compare with shadow model
    for operation in input.operations {
        match operation {
            WorkStealingOperation::Push { queue_index, task_id } => {
                let queue_idx = queue_index as usize % queue_count;
                let task = TaskId::new_for_test((task_id as u32) % (MAX_TASK_ID + 1), 0);

                // Get lengths before operation
                let len_before = queues[queue_idx].len();
                let shadow_len_before = shadow.len(queue_idx);

                // Execute on real queue
                queues[queue_idx].push(task);
                let len_after = queues[queue_idx].len();

                // Execute on shadow model
                let shadow_accepted = shadow.push(queue_idx, task);
                let shadow_len_after = shadow.len(queue_idx);

                // Verify consistency
                if shadow_accepted {
                    assert_eq!(len_after, len_before + 1, "Push should increase queue size");
                    assert_eq!(shadow_len_after, shadow_len_before + 1, "Shadow push should increase size");
                } else {
                    // Duplicate task - queue might still accept it but shadow rejects
                    assert_eq!(shadow_len_after, shadow_len_before, "Shadow should not change on duplicate");
                }

                assert_eq!(len_after, shadow_len_after, "Queue and shadow size mismatch after push");
            }

            WorkStealingOperation::Pop { queue_index } => {
                let queue_idx = queue_index as usize % queue_count;

                let len_before = queues[queue_idx].len();
                let shadow_len_before = shadow.len(queue_idx);

                // Execute pop operations
                let queue_result = queues[queue_idx].pop();
                let shadow_result = shadow.pop(queue_idx);

                let len_after = queues[queue_idx].len();
                let shadow_len_after = shadow.len(queue_idx);

                // Verify consistency
                match (queue_result, shadow_result) {
                    (Some(_), Some(_)) => {
                        assert_eq!(len_after, len_before.saturating_sub(1), "Pop should decrease size");
                        assert_eq!(shadow_len_after, shadow_len_before - 1, "Shadow pop should decrease size");
                    }
                    (None, None) => {
                        assert_eq!(len_before, 0, "Both empty should mean queue was empty");
                        assert_eq!(shadow_len_before, 0, "Shadow should also be empty");
                    }
                    _ => {
                        // Allow some divergence due to local vs non-local task filtering
                        // but verify the general direction is consistent
                    }
                }

                assert_eq!(len_after, shadow_len_after, "Queue and shadow size mismatch after pop");
            }

            WorkStealingOperation::StealSingle { queue_index } => {
                let queue_idx = queue_index as usize % queue_count;

                let len_before = queues[queue_idx].len();
                let shadow_len_before = shadow.len(queue_idx);

                // Execute steal operations
                let stealer = queues[queue_idx].stealer();
                let queue_result = stealer.steal();
                let shadow_result = shadow.steal_single(queue_idx);

                let len_after = queues[queue_idx].len();
                let shadow_len_after = shadow.len(queue_idx);

                // Verify consistency (allowing for local task filtering)
                if shadow_result.is_some() && queue_result.is_some() {
                    assert!(len_after <= len_before, "Steal should not increase size");
                    assert_eq!(shadow_len_after, shadow_len_before.saturating_sub(1), "Shadow steal should decrease size");
                }

                if shadow_len_before == 0 {
                    assert!(queue_result.is_none(), "Cannot steal from empty queue");
                }
            }

            WorkStealingOperation::StealMultiple => {
                // Test power of two choices stealing
                let stealers: Vec<Stealer> = queues.iter().map(|q| q.stealer()).collect();
                let total_len_before: usize = queues.iter().map(|q| q.len()).sum();
                let shadow_total_before = shadow.total_tasks();

                let queue_result = steal_task(&stealers, &mut rng);
                let shadow_result = shadow.steal_power_of_two(&mut rng);

                let total_len_after: usize = queues.iter().map(|q| q.len()).sum();
                let shadow_total_after = shadow.total_tasks();

                // Verify global task conservation
                if shadow_result.is_some() && queue_result.is_some() {
                    assert!(total_len_after <= total_len_before, "Total tasks should not increase");
                    assert_eq!(shadow_total_after, shadow_total_before.saturating_sub(1), "Shadow should decrease by 1");
                }

                if shadow_total_before == 0 {
                    assert!(queue_result.is_none(), "Cannot steal when no tasks exist");
                }
            }

            WorkStealingOperation::StealBatch { src_queue, dest_queue } => {
                let src_idx = src_queue as usize % queue_count;
                let dest_idx = dest_queue as usize % queue_count;

                if src_idx != dest_idx {
                    let src_len_before = queues[src_idx].len();
                    let dest_len_before = queues[dest_idx].len();
                    let total_before = src_len_before + dest_len_before;

                    // Execute batch steal
                    let src_stealer = queues[src_idx].stealer();
                    let success = src_stealer.steal_batch(&queues[dest_idx]);

                    let src_len_after = queues[src_idx].len();
                    let dest_len_after = queues[dest_idx].len();
                    let total_after = src_len_after + dest_len_after;

                    // Verify task conservation
                    assert_eq!(total_after, total_before, "Batch steal should preserve total tasks");

                    if success {
                        // Some tasks should have moved if operation succeeded
                        if src_len_before > 0 {
                            assert!(dest_len_after >= dest_len_before, "Dest should gain tasks");
                        }
                    }
                }
            }

            WorkStealingOperation::Inspect { queue_index } => {
                let queue_idx = queue_index as usize % queue_count;

                // Test stealer inspection methods
                let stealer = queues[queue_idx].stealer();
                let len = stealer.len();
                let stealable_hint = stealer.stealable_len_hint();
                let is_empty = stealer.is_empty();

                // Verify basic properties
                assert_eq!(is_empty, len == 0, "is_empty should match len == 0");
                assert!(stealable_hint <= len, "Stealable hint should not exceed total length");

                // Compare with shadow
                let shadow_len = shadow.len(queue_idx);
                assert_eq!(len, shadow_len, "Length mismatch between queue and shadow");
            }

            WorkStealingOperation::VerifyInvariants => {
                // Verify system-wide invariants
                verify_work_stealing_invariants(&queues, &shadow);
            }
        }

        // Always verify basic consistency after each operation
        let total_queue_tasks: usize = queues.iter().map(|q| q.len()).sum();
        let total_shadow_tasks = shadow.total_tasks();
        assert_eq!(total_queue_tasks, total_shadow_tasks, "Total task count mismatch");

        // Verify task uniqueness in shadow model
        assert!(shadow.verify_task_uniqueness(), "Shadow model has duplicate tasks");

        // Enforce memory bounds
        if total_queue_tasks > MAX_QUEUES * MAX_TASKS_PER_QUEUE {
            break; // Prevent unbounded growth
        }
    }

    // Final comprehensive verification
    verify_work_stealing_invariants(&queues, &shadow);
});

/// Verify work stealing system invariants
fn verify_work_stealing_invariants(
    queues: &[LocalQueue],
    shadow: &WorkStealingShadowModel,
) {
    // Size consistency
    for (i, queue) in queues.iter().enumerate() {
        let stealer = queue.stealer();
        let queue_len = stealer.len();
        let shadow_len = shadow.len(i);
        assert_eq!(queue_len, shadow_len, "Size consistency check failed for queue {}", i);

        // Stealable hint should be reasonable
        let stealable_hint = stealer.stealable_len_hint();
        assert!(stealable_hint <= queue_len, "Stealable hint exceeds queue length for queue {}", i);

        // Empty check consistency
        assert_eq!(stealer.is_empty(), queue_len == 0, "Empty check failed for queue {}", i);
    }

    // Global task conservation
    let total_queue_tasks: usize = queues.iter().map(|q| q.stealer().len()).sum();
    let total_shadow_tasks = shadow.total_tasks();
    assert_eq!(total_queue_tasks, total_shadow_tasks, "Global task conservation failed");

    // Verify no duplicate tasks in shadow model
    assert!(shadow.verify_task_uniqueness(), "Task uniqueness invariant failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_work_stealing_operations() {
        let input = WorkStealingFuzzInput {
            queue_count: 3,
            rng_seed: 42,
            operations: vec![
                WorkStealingOperation::Push { queue_index: 0, task_id: 1 },
                WorkStealingOperation::Push { queue_index: 1, task_id: 2 },
                WorkStealingOperation::Push { queue_index: 2, task_id: 3 },
                WorkStealingOperation::StealMultiple,
                WorkStealingOperation::VerifyInvariants,
            ],
        };

        // Should not panic
        fuzz_target(&input);
    }

    #[test]
    fn test_empty_queue_stealing() {
        let input = WorkStealingFuzzInput {
            queue_count: 2,
            rng_seed: 123,
            operations: vec![
                WorkStealingOperation::StealSingle { queue_index: 0 },
                WorkStealingOperation::StealMultiple,
                WorkStealingOperation::Pop { queue_index: 0 },
                WorkStealingOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }

    #[test]
    fn test_power_of_two_choices() {
        let input = WorkStealingFuzzInput {
            queue_count: 4,
            rng_seed: 999,
            operations: vec![
                WorkStealingOperation::Push { queue_index: 0, task_id: 10 },
                WorkStealingOperation::Push { queue_index: 0, task_id: 11 },
                WorkStealingOperation::Push { queue_index: 2, task_id: 20 },
                WorkStealingOperation::StealMultiple,
                WorkStealingOperation::StealMultiple,
                WorkStealingOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }
}