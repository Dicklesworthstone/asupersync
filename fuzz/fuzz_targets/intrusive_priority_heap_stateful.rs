#![no_main]

use arbitrary::Arbitrary;
use asupersync::record::task::{TaskRecord, TaskState};
use asupersync::runtime::scheduler::intrusive_heap::IntrusivePriorityHeap;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::arena::Arena;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

/// Maximum number of tasks to prevent unbounded memory growth
const MAX_TASKS: usize = 1000;
/// Maximum operations per fuzz run to prevent timeout
const MAX_OPERATIONS: usize = 10000;
/// Maximum priority value
const MAX_PRIORITY: u8 = 255;

/// Fuzz input representing a sequence of heap operations
#[derive(Arbitrary, Debug, Clone)]
struct HeapFuzzInput {
    /// Initial heap capacity
    pub initial_capacity: u8,
    /// Sequence of operations to perform
    pub operations: Vec<HeapOperation>,
}

/// Individual operations that can be performed on the heap
#[derive(Arbitrary, Debug, Clone)]
enum HeapOperation {
    /// Push a task with given priority
    Push { task_index: u8, priority: u8 },
    /// Pop the highest priority task
    Pop,
    /// Remove a specific task by index
    Remove { task_index: u8 },
    /// Peek at the highest priority task
    Peek,
    /// Check if a task is contained in the heap
    Contains { task_index: u8 },
    /// Clear the entire heap
    Clear,
    /// Check heap invariants
    VerifyInvariants,
}

/// Shadow model to verify heap behavior
#[derive(Debug)]
struct HeapShadowModel {
    /// Track which tasks should be in the heap with their priorities and generations
    expected_tasks: BTreeMap<TaskId, (u8, u64)>, // priority, generation
    /// Next generation counter
    next_generation: u64,
}

impl HeapShadowModel {
    fn new() -> Self {
        Self {
            expected_tasks: BTreeMap::new(),
            next_generation: 0,
        }
    }

    fn push(&mut self, task: TaskId, priority: u8) -> bool {
        if !self.expected_tasks.contains_key(&task) {
            self.expected_tasks.insert(task, (priority, self.next_generation));
            self.next_generation = self.next_generation.wrapping_add(1);
            true
        } else {
            false // Already in heap
        }
    }

    fn pop(&mut self) -> Option<TaskId> {
        if self.expected_tasks.is_empty() {
            return None;
        }

        // Find highest priority task (max priority, then min generation for tie-breaking)
        let (&task_id, _) = self
            .expected_tasks
            .iter()
            .max_by(|(_, (prio_a, gen_a)), (_, (prio_b, gen_b))| {
                prio_a.cmp(prio_b).then(gen_b.cmp(gen_a)) // Note: gen_b.cmp(gen_a) for FIFO
            })?;

        self.expected_tasks.remove(&task_id);
        Some(task_id)
    }

    fn remove(&mut self, task: TaskId) -> bool {
        self.expected_tasks.remove(&task).is_some()
    }

    fn contains(&self, task: TaskId) -> bool {
        self.expected_tasks.contains_key(&task)
    }

    fn clear(&mut self) {
        self.expected_tasks.clear();
    }

    fn is_empty(&self) -> bool {
        self.expected_tasks.is_empty()
    }

    fn len(&self) -> usize {
        self.expected_tasks.len()
    }

    fn peek(&self) -> Option<TaskId> {
        if self.expected_tasks.is_empty() {
            return None;
        }

        // Find highest priority task (same logic as pop but don't remove)
        let (&task_id, _) = self
            .expected_tasks
            .iter()
            .max_by(|(_, (prio_a, gen_a)), (_, (prio_b, gen_b))| {
                prio_a.cmp(prio_b).then(gen_b.cmp(gen_a))
            })?;

        Some(task_id)
    }
}

fuzz_target!(|input: HeapFuzzInput| {
    // Guard against excessive input size
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Create heap with bounded initial capacity
    let initial_capacity = (input.initial_capacity as usize).min(MAX_TASKS);
    let mut heap = IntrusivePriorityHeap::with_capacity(initial_capacity);
    let mut arena = Arena::<TaskRecord>::new();
    let mut shadow = HeapShadowModel::new();

    // Pre-create task pool to avoid allocation patterns affecting the fuzz
    let mut task_pool = Vec::new();
    for i in 0..MAX_TASKS.min(256) {
        let task_id = TaskId::new_for_test(i);
        let region_id = RegionId::new_for_test(0);
        let budget = Budget::infinite(); // Use infinite budget for simplicity
        let record = TaskRecord::new_with_time(task_id, region_id, budget, Time::ZERO);
        let arena_index = arena.insert(record);
        assert_eq!(arena_index, i); // Ensure predictable indexing
        task_pool.push(task_id);
    }

    // Execute operations and compare with shadow model
    for operation in input.operations {
        match operation {
            HeapOperation::Push { task_index, priority } => {
                if task_index as usize >= task_pool.len() {
                    continue;
                }

                let task = task_pool[task_index as usize];
                let priority = priority.min(MAX_PRIORITY);

                // Execute on real heap
                let len_before = heap.len();
                heap.push(task, priority, &mut arena);
                let len_after = heap.len();

                // Execute on shadow model
                let shadow_added = shadow.push(task, priority);

                // Verify consistency
                if shadow_added {
                    assert_eq!(len_after, len_before + 1, "Push should increase heap size");
                } else {
                    assert_eq!(len_after, len_before, "Duplicate push should not change size");
                }

                assert_eq!(heap.len(), shadow.len(), "Heap and shadow size mismatch after push");
                assert_eq!(heap.is_empty(), shadow.is_empty(), "Empty state mismatch after push");
                assert_eq!(heap.contains(task, &arena), shadow.contains(task), "Contains mismatch after push");
            }

            HeapOperation::Pop => {
                let shadow_result = shadow.pop();
                let heap_result = heap.pop(&mut arena);

                assert_eq!(
                    heap_result, shadow_result,
                    "Pop result mismatch: heap={:?}, shadow={:?}",
                    heap_result, shadow_result
                );

                assert_eq!(heap.len(), shadow.len(), "Heap and shadow size mismatch after pop");
                assert_eq!(heap.is_empty(), shadow.is_empty(), "Empty state mismatch after pop");

                // Verify that popped task is no longer in heap
                if let Some(popped_task) = heap_result {
                    assert!(!heap.contains(popped_task, &arena), "Popped task still in heap");
                    assert!(!shadow.contains(popped_task), "Popped task still in shadow");
                }
            }

            HeapOperation::Remove { task_index } => {
                if task_index as usize >= task_pool.len() {
                    continue;
                }

                let task = task_pool[task_index as usize];

                let shadow_removed = shadow.remove(task);
                let heap_removed = heap.remove(task, &mut arena);

                assert_eq!(
                    heap_removed, shadow_removed,
                    "Remove result mismatch for task {:?}: heap={}, shadow={}",
                    task, heap_removed, shadow_removed
                );

                assert_eq!(heap.len(), shadow.len(), "Heap and shadow size mismatch after remove");
                assert_eq!(heap.is_empty(), shadow.is_empty(), "Empty state mismatch after remove");
                assert_eq!(heap.contains(task, &arena), shadow.contains(task), "Contains mismatch after remove");
            }

            HeapOperation::Peek => {
                let heap_result = heap.peek();
                let shadow_result = shadow.peek();

                assert_eq!(
                    heap_result, shadow_result,
                    "Peek result mismatch: heap={:?}, shadow={:?}",
                    heap_result, shadow_result
                );
            }

            HeapOperation::Contains { task_index } => {
                if task_index as usize >= task_pool.len() {
                    continue;
                }

                let task = task_pool[task_index as usize];
                let heap_contains = heap.contains(task, &arena);
                let shadow_contains = shadow.contains(task);

                assert_eq!(
                    heap_contains, shadow_contains,
                    "Contains result mismatch for task {:?}: heap={}, shadow={}",
                    task, heap_contains, shadow_contains
                );
            }

            HeapOperation::Clear => {
                heap.clear(&mut arena);
                shadow.clear();

                assert_eq!(heap.len(), 0, "Heap should be empty after clear");
                assert_eq!(shadow.len(), 0, "Shadow should be empty after clear");
                assert!(heap.is_empty(), "Heap should report empty after clear");
                assert!(shadow.is_empty(), "Shadow should report empty after clear");
                assert_eq!(heap.peek(), None, "Peek should return None after clear");

                // Verify all tasks report as not contained
                for &task in &task_pool {
                    assert!(!heap.contains(task, &arena), "No task should be contained after clear");
                    assert!(!shadow.contains(task), "No task should be in shadow after clear");
                }
            }

            HeapOperation::VerifyInvariants => {
                verify_heap_invariants(&heap, &arena, &shadow);
            }
        }

        // Always verify basic consistency after each operation
        assert_eq!(heap.len(), shadow.len(), "Size consistency check failed");
        assert_eq!(heap.is_empty(), shadow.is_empty(), "Empty state consistency check failed");

        // Verify peek consistency
        let heap_peek = heap.peek();
        let shadow_peek = shadow.peek();
        assert_eq!(heap_peek, shadow_peek, "Peek consistency check failed");

        // Enforce memory bounds
        if heap.len() > MAX_TASKS {
            break; // Prevent unbounded growth
        }
    }

    // Final comprehensive verification
    verify_heap_invariants(&heap, &arena, &shadow);
});

/// Verify heap maintains max-heap property and other invariants
fn verify_heap_invariants(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    shadow: &HeapShadowModel,
) {
    // Size consistency
    assert_eq!(heap.len(), shadow.len(), "Final size consistency check failed");
    assert_eq!(heap.is_empty(), shadow.is_empty(), "Final empty state consistency check failed");

    // If heap is empty, peek should return None
    if heap.is_empty() {
        assert_eq!(heap.peek(), None, "Empty heap should peek None");
    }

    // Verify heap property: each task should have heap_index set correctly if in heap
    // and priority/generation fields should match the heap's order expectations

    // Note: Since IntrusivePriorityHeap doesn't expose its internal structure for verification,
    // we rely on behavioral testing through the shadow model comparison.
    // The heap's internal invariants are maintained by its implementation.

    // Verify contains is consistent between heap and shadow
    for i in 0..256.min(arena.capacity()) {
        if let Some(task_id) = TaskId::try_from_arena_index(i) {
            if let Some(record) = arena.get(i) {
                let heap_contains = heap.contains(task_id, arena);
                let shadow_contains = shadow.contains(task_id);
                assert_eq!(
                    heap_contains, shadow_contains,
                    "Contains consistency check failed for task {:?}: heap={}, shadow={}",
                    task_id, heap_contains, shadow_contains
                );

                // If task is in heap, verify heap_index is set
                if heap_contains {
                    assert!(
                        record.heap_index.is_some(),
                        "Task {:?} in heap should have heap_index set",
                        task_id
                    );
                } else {
                    // Note: heap_index might still be set during operations, so we don't check it's None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_heap_operations() {
        let input = HeapFuzzInput {
            initial_capacity: 10,
            operations: vec![
                HeapOperation::Push {
                    task_index: 1,
                    priority: 100,
                },
                HeapOperation::Push {
                    task_index: 2,
                    priority: 50,
                },
                HeapOperation::Peek,
                HeapOperation::Pop,
                HeapOperation::Pop,
                HeapOperation::VerifyInvariants,
            ],
        };

        // Should not panic
        fuzz_target(&input);
    }

    #[test]
    fn test_duplicate_push() {
        let input = HeapFuzzInput {
            initial_capacity: 5,
            operations: vec![
                HeapOperation::Push {
                    task_index: 1,
                    priority: 100,
                },
                HeapOperation::Push {
                    task_index: 1,
                    priority: 200, // Different priority, but same task
                },
                HeapOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }

    #[test]
    fn test_empty_heap_operations() {
        let input = HeapFuzzInput {
            initial_capacity: 0,
            operations: vec![
                HeapOperation::Pop,
                HeapOperation::Peek,
                HeapOperation::Remove { task_index: 0 },
                HeapOperation::Contains { task_index: 0 },
                HeapOperation::Clear,
                HeapOperation::VerifyInvariants,
            ],
        };

        fuzz_target(&input);
    }
}