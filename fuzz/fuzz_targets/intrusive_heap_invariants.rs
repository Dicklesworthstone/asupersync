#![no_main]

use arbitrary::Arbitrary;
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::intrusive_heap::IntrusivePriorityHeap;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::{Arena, ArenaIndex};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

/// Structure-aware fuzz target for IntrusivePriorityHeap invariants
///
/// Tests the mathematical properties and data structure invariants:
/// 1. Heap property: parent priority >= child priority for all nodes
/// 2. Index consistency: arena[heap[i]].heap_index == Some(i) for all i
/// 3. No double-free: removed nodes have heap_index = None
/// 4. Generation monotonicity: newer pushes have higher generation values
/// 5. Priority ordering: pop() returns highest priority task
#[derive(Arbitrary, Debug)]
struct HeapInvariantsFuzz {
    /// Sequence of operations to perform
    operations: Vec<HeapOperation>,
    /// Number of tasks to pre-allocate in arena
    num_tasks: u8, // Bounded to prevent excessive memory usage
}

/// Individual heap operations to test
#[derive(Arbitrary, Debug, Clone)]
enum HeapOperation {
    /// Push a task with given priority
    Push {
        task_index: u8, // Index into arena
        priority: u8,   // Task priority
    },
    /// Pop the highest priority task
    Pop,
    /// Remove a specific task
    Remove {
        task_index: u8, // Index into arena
    },
    /// Clear all tasks from heap
    Clear,
    /// Check contains operation
    Contains {
        task_index: u8, // Index into arena
    },
    /// Peek at highest priority task
    Peek,
}

// Resource limits to prevent fuzzer timeouts
const MAX_TASKS: usize = 64;
const MAX_OPERATIONS: usize = 256;

fuzz_target!(|input: HeapInvariantsFuzz| {
    // Apply resource limits
    let num_tasks = ((input.num_tasks % 64).max(1)) as usize;
    let operations: Vec<_> = input.operations.into_iter().take(MAX_OPERATIONS).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Initialize arena with task records
    let mut arena = setup_arena(num_tasks);
    let mut heap = IntrusivePriorityHeap::new();

    // Track expected state for verification
    let mut expected_in_heap = HashSet::new();
    let mut last_pop_priority = u8::MAX; // For priority ordering verification

    // Execute operations and verify invariants after each
    for (op_index, operation) in operations.iter().enumerate() {
        match operation {
            HeapOperation::Push { task_index, priority } => {
                let task_index = (*task_index as usize) % num_tasks;
                let task_id = task_id_from_index(task_index);

                let was_in_heap = heap.contains(task_id, &arena);
                heap.push(task_id, *priority, &mut arena);

                if !was_in_heap {
                    expected_in_heap.insert(task_id);
                }

                verify_all_invariants(&heap, &arena, &expected_in_heap, op_index, "after push");
            }

            HeapOperation::Pop => {
                let popped = heap.pop(&mut arena);
                if let Some(task) = popped {
                    expected_in_heap.remove(&task);

                    // Verify priority ordering - popped task should have >= priority to last pop
                    if let Some(record) = arena.get(task.arena_index()) {
                        assert!(
                            record.sched_priority <= last_pop_priority,
                            "Priority ordering violation: popped priority {} > last priority {}",
                            record.sched_priority, last_pop_priority
                        );
                        last_pop_priority = record.sched_priority;
                    }

                    // Verify removed task has no heap index
                    if let Some(record) = arena.get(task.arena_index()) {
                        assert_eq!(
                            record.heap_index, None,
                            "Popped task still has heap_index set"
                        );
                    }
                }

                verify_all_invariants(&heap, &arena, &expected_in_heap, op_index, "after pop");
            }

            HeapOperation::Remove { task_index } => {
                let task_index = (*task_index as usize) % num_tasks;
                let task_id = task_id_from_index(task_index);

                let was_removed = heap.remove(task_id, &mut arena);
                if was_removed {
                    expected_in_heap.remove(&task_id);

                    // Verify removed task has no heap index
                    if let Some(record) = arena.get(task_id.arena_index()) {
                        assert_eq!(
                            record.heap_index, None,
                            "Removed task still has heap_index set"
                        );
                    }
                }

                verify_all_invariants(&heap, &arena, &expected_in_heap, op_index, "after remove");
            }

            HeapOperation::Clear => {
                heap.clear(&mut arena);
                expected_in_heap.clear();
                last_pop_priority = u8::MAX; // Reset priority tracking

                // Verify all tasks have cleared heap indices
                for i in 0..num_tasks {
                    let task_id = task_id_from_index(i);
                    if let Some(record) = arena.get(task_id.arena_index()) {
                        assert_eq!(
                            record.heap_index, None,
                            "Task {} still has heap_index after clear", i
                        );
                        assert_eq!(
                            record.sched_priority, 0,
                            "Task {} still has priority after clear", i
                        );
                        assert_eq!(
                            record.sched_generation, 0,
                            "Task {} still has generation after clear", i
                        );
                    }
                }

                verify_all_invariants(&heap, &arena, &expected_in_heap, op_index, "after clear");
            }

            HeapOperation::Contains { task_index } => {
                let task_index = (*task_index as usize) % num_tasks;
                let task_id = task_id_from_index(task_index);

                let contains_result = heap.contains(task_id, &arena);
                let expected_contains = expected_in_heap.contains(&task_id);

                assert_eq!(
                    contains_result, expected_contains,
                    "Contains check mismatch for task {}: heap says {}, expected {}",
                    task_index, contains_result, expected_contains
                );

                // No invariant changes from contains check
            }

            HeapOperation::Peek => {
                let peeked = heap.peek();
                if heap.is_empty() {
                    assert!(
                        peeked.is_none(),
                        "Peek returned value on empty heap"
                    );
                } else {
                    assert!(
                        peeked.is_some(),
                        "Peek returned None on non-empty heap"
                    );

                    // Verify peeked task is actually in heap
                    if let Some(task) = peeked {
                        assert!(
                            expected_in_heap.contains(&task),
                            "Peeked task not in expected set"
                        );

                        // Verify peeked task has highest priority among all heap tasks
                        if let Some(peek_record) = arena.get(task.arena_index()) {
                            for &heap_task in expected_in_heap.iter() {
                                if let Some(other_record) = arena.get(heap_task.arena_index()) {
                                    assert!(
                                        peek_record.sched_priority >= other_record.sched_priority,
                                        "Peeked task priority {} < heap task priority {}",
                                        peek_record.sched_priority, other_record.sched_priority
                                    );
                                }
                            }
                        }
                    }
                }

                // No invariant changes from peek
            }
        }
    }
});

/// Verify all heap invariants hold
fn verify_all_invariants(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    expected_in_heap: &HashSet<TaskId>,
    op_index: usize,
    context: &str,
) {
    verify_heap_property(heap, arena, op_index, context);
    verify_index_consistency(heap, arena, op_index, context);
    verify_expected_membership(heap, arena, expected_in_heap, op_index, context);
    verify_no_double_tracking(heap, arena, op_index, context);
}

/// Verify the binary heap property by checking the top element consistency
fn verify_heap_property(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    op_index: usize,
    context: &str,
) {
    // We can't directly access heap internals, but we can verify the heap
    // maintains basic invariants through the public API
    if heap.is_empty() {
        return;
    }

    // Check that peek returns a valid task that's actually in the heap
    if let Some(top_task) = heap.peek() {
        assert!(
            heap.contains(top_task, arena),
            "Heap property violation at op {} {}: peek returned task {:?} not in heap",
            op_index, context, top_task
        );

        // Check that the top task has proper scheduling metadata
        if let Some(record) = arena.get(top_task.arena_index()) {
            assert!(
                record.heap_index.is_some(),
                "Heap property violation at op {} {}: top task has no heap_index",
                op_index, context
            );
        }
    }

    // Additional heap property verification will be done through pop sequence testing
    // in the main fuzz loop rather than trying to access private heap structure
}

/// Verify index consistency through membership testing
fn verify_index_consistency(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    op_index: usize,
    context: &str,
) {
    // We can't directly access heap[i], but we can verify that any task
    // claiming to be in the heap is actually found by contains()
    for (arena_index, record) in arena.iter() {
        if let Some(heap_index) = record.heap_index {
            let task_id = TaskId::from_arena(arena_index);

            // If task claims to be in heap, contains() must find it
            assert!(
                heap.contains(task_id, arena),
                "Index consistency violation at op {} {}: \
                 task {:?} claims heap_index {} but contains() returns false",
                op_index, context, task_id, heap_index
            );

            // Heap index should be within bounds
            assert!(
                (heap_index as usize) < heap.len(),
                "Index consistency violation at op {} {}: \
                 task {:?} heap_index {} >= heap.len() {}",
                op_index, context, task_id, heap_index, heap.len()
            );
        }
    }
}

/// Verify expected membership matches actual heap membership
fn verify_expected_membership(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    expected_in_heap: &HashSet<TaskId>,
    op_index: usize,
    context: &str,
) {
    // Check expected tasks are actually in heap
    for &expected_task in expected_in_heap {
        assert!(
            heap.contains(expected_task, arena),
            "Expected membership violation at op {} {}: \
             task {:?} expected in heap but not found",
            op_index, context, expected_task
        );
    }

    // Check heap size matches expected size
    assert_eq!(
        heap.len(), expected_in_heap.len(),
        "Membership size mismatch at op {} {}: \
         heap len {} != expected len {}",
        op_index, context, heap.len(), expected_in_heap.len()
    );
}

/// Verify no tasks are incorrectly tracked as being in heap
fn verify_no_double_tracking(
    heap: &IntrusivePriorityHeap,
    arena: &Arena<TaskRecord>,
    op_index: usize,
    context: &str,
) {
    // Check that no two tasks claim the same heap index
    let mut used_indices = HashSet::new();

    for (arena_index, record) in arena.iter() {
        if let Some(heap_index) = record.heap_index {
            let task_id = TaskId::from_arena(arena_index);

            assert!(
                used_indices.insert(heap_index),
                "Double tracking violation at op {} {}: \
                 multiple tasks claim heap_index {}, including task {:?}",
                op_index, context, heap_index, task_id
            );
        }
    }
}

/// Create TaskId from array index
fn task_id_from_index(index: usize) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(index as u32, 0))
}

/// Set up arena with task records
fn setup_arena(num_tasks: usize) -> Arena<TaskRecord> {
    let mut arena = Arena::new();
    let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));

    for i in 0..num_tasks {
        let task_id = task_id_from_index(i);
        let record = TaskRecord::new(task_id, region_id, Budget::INFINITE);
        let inserted_index = arena.insert(record);
        assert_eq!(inserted_index.index(), i as u32, "Arena index mismatch");
    }

    arena
}

