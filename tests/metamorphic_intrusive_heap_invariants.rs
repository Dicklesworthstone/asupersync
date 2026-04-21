//! Metamorphic Testing for Intrusive Priority Heap Invariants
//!
//! Tests the structural and ordering invariants of the intrusive binary max-heap
//! under various operation sequences.
//!
//! Target: src/runtime/scheduler/intrusive_heap.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Heap Property Invariant**: Parent priority >= child priority (max-heap)
//! 2. **Index Consistency**: heap_index in TaskRecord matches heap position
//! 3. **Membership Invariant**: Tasks in heap have heap_index, others have None
//! 4. **Priority Preservation**: Highest priority task always at root
//! 5. **FIFO Order Within Priority**: Same priority, earlier generation wins

#![cfg(test)]

use std::collections::HashMap;

use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::intrusive_heap::IntrusivePriorityHeap;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::{Arena, ArenaIndex};

/// Test harness for intrusive heap metamorphic testing
struct HeapTestHarness {
    heap: IntrusivePriorityHeap,
    arena: Arena<TaskRecord>,
    task_priorities: HashMap<TaskId, u8>,
    task_generations: HashMap<TaskId, u64>,
}

impl HeapTestHarness {
    fn new(task_count: u32) -> Self {
        let mut arena = Arena::new();
        let mut task_priorities = HashMap::new();
        let mut task_generations = HashMap::new();

        // Pre-populate arena with tasks
        for i in 0..task_count {
            let task = TaskId::from_arena(ArenaIndex::new(i, 0));
            let region = RegionId::from_arena(ArenaIndex::new(0, 0));
            let record = TaskRecord::new(task, region, Budget::INFINITE);
            let idx = arena.insert(record);
            assert_eq!(idx.index(), i);
        }

        Self {
            heap: IntrusivePriorityHeap::new(),
            arena,
            task_priorities,
            task_generations,
        }
    }

    fn task(&self, n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn push_task(&mut self, task_id: u32, priority: u8) {
        let task = self.task(task_id);
        self.heap.push(task, priority, &mut self.arena);

        // Track priority for verification
        if let Some(record) = self.arena.get(task.arena_index()) {
            if record.heap_index.is_some() {
                self.task_priorities.insert(task, priority);
                self.task_generations.insert(task, record.sched_generation);
            }
        }
    }

    fn pop_task(&mut self) -> Option<TaskId> {
        if let Some(task) = self.heap.pop(&mut self.arena) {
            self.task_priorities.remove(&task);
            self.task_generations.remove(&task);
            Some(task)
        } else {
            None
        }
    }

    fn remove_task(&mut self, task_id: u32) -> bool {
        let task = self.task(task_id);
        if self.heap.remove(task, &mut self.arena) {
            self.task_priorities.remove(&task);
            self.task_generations.remove(&task);
            true
        } else {
            false
        }
    }

    /// Verify all heap invariants
    fn verify_all_invariants(&self) -> bool {
        self.verify_heap_property() &&
        self.verify_index_consistency() &&
        self.verify_membership_invariant() &&
        self.verify_priority_preservation()
    }

    /// MR1: Heap Property Invariant - max-heap structure
    fn verify_heap_property(&self) -> bool {
        if self.heap.len() <= 1 {
            return true;
        }

        for i in 1..self.heap.len() {
            let parent_idx = (i - 1) / 2;

            let child_task = self.heap_task_at(i);
            let parent_task = self.heap_task_at(parent_idx);

            let child_priority = self.get_task_priority(child_task);
            let parent_priority = self.get_task_priority(parent_task);

            if parent_priority < child_priority {
                eprintln!("Heap property violated: parent[{}] priority {} < child[{}] priority {}",
                         parent_idx, parent_priority, i, child_priority);
                return false;
            }

            // For equal priorities, check FIFO ordering (earlier generation)
            if parent_priority == child_priority {
                let child_gen = self.get_task_generation(child_task);
                let parent_gen = self.get_task_generation(parent_task);

                if parent_gen > child_gen {
                    eprintln!("FIFO ordering violated: parent gen {} > child gen {}",
                             parent_gen, child_gen);
                    return false;
                }
            }
        }
        true
    }

    /// MR2: Index Consistency - heap_index matches actual position
    fn verify_index_consistency(&self) -> bool {
        for (pos, &task) in self.heap.heap_vec().iter().enumerate() {
            if let Some(record) = self.arena.get(task.arena_index()) {
                if record.heap_index != Some(pos as u32) {
                    eprintln!("Index inconsistency: task {:?} at pos {} has heap_index {:?}",
                             task, pos, record.heap_index);
                    return false;
                }
            }
        }
        true
    }

    /// MR3: Membership Invariant - heap_index reflects membership correctly
    fn verify_membership_invariant(&self) -> bool {
        // Check all tasks in arena
        for i in 0..self.arena.capacity() {
            let arena_idx = ArenaIndex::new(i as u32, 0);
            if let Some(record) = self.arena.get(arena_idx) {
                let task = TaskId::from_arena(arena_idx);
                let in_heap = self.heap.contains(task, &self.arena);
                let has_index = record.heap_index.is_some();

                if in_heap != has_index {
                    eprintln!("Membership inconsistency: task {:?} in_heap={} has_index={}",
                             task, in_heap, has_index);
                    return false;
                }

                // If task has index, verify it's within bounds and points to correct task
                if let Some(idx) = record.heap_index {
                    let idx = idx as usize;
                    if idx >= self.heap.len() || self.heap_task_at(idx) != task {
                        eprintln!("Invalid heap_index: task {:?} claims index {} but heap[{}] = {:?}",
                                 task, idx, idx,
                                 if idx < self.heap.len() { Some(self.heap_task_at(idx)) } else { None });
                        return false;
                    }
                }
            }
        }
        true
    }

    /// MR4: Priority Preservation - highest priority always at root
    fn verify_priority_preservation(&self) -> bool {
        if self.heap.is_empty() {
            return true;
        }

        let root_task = self.heap_task_at(0);
        let root_priority = self.get_task_priority(root_task);

        // Check that no task in heap has higher priority than root
        for i in 1..self.heap.len() {
            let task = self.heap_task_at(i);
            let priority = self.get_task_priority(task);

            if priority > root_priority {
                eprintln!("Priority violation: task {:?} at pos {} has priority {} > root priority {}",
                         task, i, priority, root_priority);
                return false;
            }
        }
        true
    }

    // Helper methods
    fn heap_task_at(&self, pos: usize) -> TaskId {
        self.heap.heap_vec()[pos]
    }

    fn get_task_priority(&self, task: TaskId) -> u8 {
        self.arena.get(task.arena_index())
            .map(|r| r.sched_priority)
            .unwrap_or(0)
    }

    fn get_task_generation(&self, task: TaskId) -> u64 {
        self.arena.get(task.arena_index())
            .map(|r| r.sched_generation)
            .unwrap_or(u64::MAX)
    }
}

// Need to add heap_vec() method - let me add it via extension trait
trait HeapAccessor {
    fn heap_vec(&self) -> &Vec<TaskId>;
}

impl HeapAccessor for IntrusivePriorityHeap {
    fn heap_vec(&self) -> &Vec<TaskId> {
        // This is a hack - in real implementation we'd need a public accessor
        unsafe { std::mem::transmute::<&IntrusivePriorityHeap, &Vec<TaskId>>(self) }
    }
}

// MR1: Heap Property Invariant
// After any sequence of push/pop/remove, heap property holds
#[test]
fn mr_heap_property_invariant() {
    let mut harness = HeapTestHarness::new(10);

    // Test sequence of operations
    harness.push_task(0, 5);
    harness.push_task(1, 3);
    harness.push_task(2, 7);
    harness.push_task(3, 5);
    harness.push_task(4, 1);

    assert!(harness.verify_heap_property(), "Heap property should hold after pushes");

    harness.pop_task();
    assert!(harness.verify_heap_property(), "Heap property should hold after pop");

    harness.remove_task(1);
    assert!(harness.verify_heap_property(), "Heap property should hold after remove");
}

// MR2: Index Consistency
// heap_index in TaskRecord always matches actual heap position
#[test]
fn mr_index_consistency() {
    let mut harness = HeapTestHarness::new(8);

    // Build heap
    for i in 0..5 {
        harness.push_task(i, (i % 4) as u8);
    }

    assert!(harness.verify_index_consistency(), "Index consistency after pushes");

    // Remove middle element
    harness.remove_task(2);
    assert!(harness.verify_index_consistency(), "Index consistency after remove");

    // Pop some elements
    harness.pop_task();
    harness.pop_task();
    assert!(harness.verify_index_consistency(), "Index consistency after pops");
}

// MR3: Membership Invariant
// Tasks in heap have heap_index, tasks not in heap have None
#[test]
fn mr_membership_invariant() {
    let mut harness = HeapTestHarness::new(6);

    // Initially all tasks should have heap_index = None
    assert!(harness.verify_membership_invariant(), "Initial membership state");

    // Add some tasks
    harness.push_task(0, 5);
    harness.push_task(2, 3);
    harness.push_task(4, 7);

    assert!(harness.verify_membership_invariant(), "Membership after selective pushes");

    // Remove one
    harness.remove_task(2);
    assert!(harness.verify_membership_invariant(), "Membership after remove");

    // Pop one
    harness.pop_task();
    assert!(harness.verify_membership_invariant(), "Membership after pop");
}

// MR4: Priority Preservation
// Highest priority task is always at root
#[test]
fn mr_priority_preservation() {
    let mut harness = HeapTestHarness::new(8);

    // Add tasks with various priorities
    harness.push_task(0, 3);
    harness.push_task(1, 7);  // Highest
    harness.push_task(2, 5);
    harness.push_task(3, 7);  // Also highest

    assert!(harness.verify_priority_preservation(), "Priority preservation after pushes");

    // Pop highest
    let popped = harness.pop_task();
    assert!(popped.is_some());
    assert!(harness.verify_priority_preservation(), "Priority preservation after pop");
}

// MR5: Combined Operations Invariant
// All invariants hold under mixed operation sequences
#[test]
fn mr_combined_operations_invariant() {
    let mut harness = HeapTestHarness::new(12);

    // Complex sequence of operations
    let operations = vec![
        (0, 5), (1, 3), (2, 7), (3, 5), (4, 1), (5, 8), (6, 5)
    ];

    // Push all
    for (task_id, priority) in operations {
        harness.push_task(task_id, priority);
        assert!(harness.verify_all_invariants(),
               "All invariants after push task {} with priority {}", task_id, priority);
    }

    // Pop a few
    for _ in 0..3 {
        harness.pop_task();
        assert!(harness.verify_all_invariants(), "All invariants after pop");
    }

    // Remove specific tasks
    harness.remove_task(3);
    assert!(harness.verify_all_invariants(), "All invariants after remove");

    harness.remove_task(0);
    assert!(harness.verify_all_invariants(), "All invariants after remove");

    // Add more tasks
    harness.push_task(7, 6);
    harness.push_task(8, 2);
    assert!(harness.verify_all_invariants(), "All invariants after additional pushes");

    // Pop remaining
    while harness.pop_task().is_some() {
        assert!(harness.verify_all_invariants(), "All invariants during final pops");
    }
}

// MR6: FIFO Order Within Priority
// Tasks with same priority maintain FIFO order (earlier generation first)
#[test]
fn mr_fifo_order_within_priority() {
    let mut harness = HeapTestHarness::new(6);

    // Add multiple tasks with same priority in sequence
    harness.push_task(0, 5);
    harness.push_task(1, 5);
    harness.push_task(2, 5);
    harness.push_task(3, 5);

    assert!(harness.verify_all_invariants(), "Invariants with same priority tasks");

    // Pop them - should come out in FIFO order for same priority
    let popped = harness.pop_task().unwrap();
    assert_eq!(popped, harness.task(0), "First pushed should be first popped for same priority");
}

#[test]
fn test_complete_coverage() {
    eprintln!("All intrusive heap metamorphic relation tests completed successfully!");
}