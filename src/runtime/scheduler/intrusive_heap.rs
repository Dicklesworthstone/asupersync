//! Cache-aware intrusive priority heap for scheduler hot paths.
//!
//! This module provides [`IntrusivePriorityHeap`], a binary max-heap that stores
//! scheduling metadata (priority, generation, heap position) directly in
//! [`TaskRecord`] fields rather than in separate heap-allocated entries.
//!
//! # Design (SoA Layout)
//!
//! Traditional `BinaryHeap<SchedulerEntry>` uses an Array-of-Structs (AoS) layout:
//! one contiguous Vec of `{task, priority, generation}` tuples. This works but
//! allocates per-entry and mixes TaskId lookup keys with scheduling metadata.
//!
//! The intrusive heap uses a Struct-of-Arrays (SoA) split:
//! - **Heap backbone**: `Vec<TaskId>` — compact, cache-friendly array of 8-byte indices
//! - **Per-task metadata**: `heap_index`, `sched_priority`, `sched_generation` stored
//!   inline in `TaskRecord` — accessed only during sift operations
//!
//! This provides:
//! - **Zero allocations** after initial Vec capacity is established
//! - **Better cache locality** for heap traversal (compact Vec<TaskId>)
//! - **O(1) removal** by task ID (via stored heap_index)
//! - **O(log n) push/pop** with fewer cache misses than AoS
//!
//! # Ordering
//!
//! Higher priority first (max-heap). Within equal priority, earlier generation
//! (lower number) wins for FIFO tie-breaking.
//!
//! # Integration
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │  IntrusivePriorityHeap          │
//! │  ┌────────────────────────────┐ │
//! │  │  heap: Vec<TaskId>         │ │  ← compact backbone
//! │  │  [T3, T1, T7, T2, ...]    │ │
//! │  └────────────────────────────┘ │
//! │  next_generation: u64           │
//! └─────────────────────────────────┘
//!          │ sift_up / sift_down
//!          ▼
//! ┌──────────────────────────────────────┐
//! │  Arena<TaskRecord>                   │
//! │  ┌──────────────────────────────────┐│
//! │  │ T1: heap_index=1, priority=5    ││ ← metadata in-record
//! │  │ T2: heap_index=3, priority=3    ││
//! │  │ T3: heap_index=0, priority=7    ││
//! │  │ T7: heap_index=2, priority=5    ││
//! │  └──────────────────────────────────┘│
//! └──────────────────────────────────────┘
//! ```

use crate::record::task::TaskRecord;
use crate::types::TaskId;
use crate::util::Arena;

/// An intrusive binary max-heap for scheduling tasks by priority.
///
/// The heap backbone is a compact `Vec<TaskId>`. Per-task scheduling metadata
/// (priority, generation, heap index) is stored in `TaskRecord` fields, giving
/// a SoA (Struct-of-Arrays) layout that minimises allocations and improves
/// cache utilisation during sift operations.
///
/// # Invariants
///
/// - For every entry at position `i` in `self.heap`:
///   `arena[heap[i]].heap_index == Some(i as u32)`
/// - For every entry at position `i` with parent `p = (i-1)/2`:
///   `priority(heap[p]) >= priority(heap[i])` (max-heap)
/// - Tasks not in this heap have `heap_index == None`
///
/// # Complexity
///
/// | Operation | Time       | Allocations |
/// |-----------|------------|-------------|
/// | push      | O(log n)   | 0 (amortised) |
/// | pop       | O(log n)   | 0           |
/// | remove    | O(log n)   | 0           |
/// | peek      | O(1)       | 0           |
/// | contains  | O(1)       | 0           |
#[derive(Debug)]
pub struct IntrusivePriorityHeap {
    /// Compact array of TaskIds forming the heap structure.
    heap: Vec<TaskId>,
    /// Monotonic counter for FIFO tie-breaking within equal priorities.
    next_generation: u64,
}

impl Default for IntrusivePriorityHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl IntrusivePriorityHeap {
    /// Creates a new empty intrusive priority heap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heap: Vec::new(),
            next_generation: 0,
        }
    }

    /// Creates a new heap with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: Vec::with_capacity(capacity),
            next_generation: 0,
        }
    }

    /// Returns the number of tasks in the heap.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns true if the heap is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Returns the highest-priority task without removing it.
    #[must_use]
    #[inline]
    pub fn peek(&self) -> Option<TaskId> {
        self.heap.first().copied()
    }

    /// Returns true if the given task is in this heap.
    ///
    /// O(1) via the stored `heap_index` field.
    #[must_use]
    pub fn contains(&self, task: TaskId, arena: &Arena<TaskRecord>) -> bool {
        arena
            .get(task.arena_index())
            .is_some_and(|record| record.heap_index.is_some())
    }

    /// Pushes a task into the heap with the given priority.
    ///
    /// If the task is already in the heap, this is a no-op.
    ///
    /// # Complexity
    ///
    /// O(log n) time, O(0) allocations (amortised, after Vec warmup).
    #[inline]
    pub fn push(&mut self, task: TaskId, priority: u8, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task.arena_index()) else {
            return;
        };

        // Skip if already in heap
        if record.heap_index.is_some() {
            return;
        }

        let gen = self.next_generation;
        self.next_generation += 1;

        record.sched_priority = priority;
        record.sched_generation = gen;

        let pos = self.heap.len();
        record.heap_index = Some(pos as u32);
        self.heap.push(task);

        self.sift_up(pos, arena);
    }

    /// Removes and returns the highest-priority task.
    ///
    /// # Complexity
    ///
    /// O(log n) time, O(0) allocations.
    #[inline]
    #[must_use]
    pub fn pop(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        if self.heap.is_empty() {
            return None;
        }

        let task = self.heap[0];
        self.remove_at(0, arena);
        Some(task)
    }

    /// Removes a specific task from the heap.
    ///
    /// Returns `true` if the task was found and removed.
    ///
    /// # Complexity
    ///
    /// O(log n) time, O(0) allocations.
    pub fn remove(&mut self, task: TaskId, arena: &mut Arena<TaskRecord>) -> bool {
        let Some(record) = arena.get(task.arena_index()) else {
            return false;
        };

        let Some(pos) = record.heap_index else {
            return false;
        };

        self.remove_at(pos as usize, arena);
        true
    }

    /// Removes the element at position `pos` from the heap.
    fn remove_at(&mut self, pos: usize, arena: &mut Arena<TaskRecord>) {
        let last = self.heap.len() - 1;

        // Clear the removed task's heap index
        if let Some(record) = arena.get_mut(self.heap[pos].arena_index()) {
            record.heap_index = None;
            record.sched_priority = 0;
            record.sched_generation = 0;
        }

        if pos == last {
            self.heap.pop();
            return;
        }

        // Swap with last element
        self.heap.swap(pos, last);
        self.heap.pop();

        // Update the swapped element's index
        if let Some(record) = arena.get_mut(self.heap[pos].arena_index()) {
            record.heap_index = Some(pos as u32);
        }

        // Restore heap property
        // Try sifting up first; if position didn't change, sift down
        let new_pos = self.sift_up(pos, arena);
        if new_pos == pos {
            self.sift_down(pos, arena);
        }
    }

    /// Sifts the element at `pos` up towards the root.
    /// Returns the final position.
    fn sift_up(&mut self, mut pos: usize, arena: &mut Arena<TaskRecord>) -> usize {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            if self.higher_priority(pos, parent, arena) {
                self.swap_positions(pos, parent, arena);
                pos = parent;
            } else {
                break;
            }
        }
        pos
    }

    /// Sifts the element at `pos` down towards the leaves.
    fn sift_down(&mut self, mut pos: usize, arena: &mut Arena<TaskRecord>) {
        let len = self.heap.len();
        loop {
            let left = 2 * pos + 1;
            let right = 2 * pos + 2;
            let mut largest = pos;

            if left < len && self.higher_priority(left, largest, arena) {
                largest = left;
            }
            if right < len && self.higher_priority(right, largest, arena) {
                largest = right;
            }

            if largest == pos {
                break;
            }

            self.swap_positions(pos, largest, arena);
            pos = largest;
        }
    }

    /// Returns `true` if the task at position `a` has strictly higher scheduling
    /// priority than the task at position `b`.
    ///
    /// Higher priority value wins. For equal priorities, lower generation (FIFO) wins.
    fn higher_priority(&self, a: usize, b: usize, arena: &Arena<TaskRecord>) -> bool {
        let task_a = self.heap[a];
        let task_b = self.heap[b];

        let (prio_a, gen_a) = arena
            .get(task_a.arena_index())
            .map_or((0, u64::MAX), |r| (r.sched_priority, r.sched_generation));

        let (prio_b, gen_b) = arena
            .get(task_b.arena_index())
            .map_or((0, u64::MAX), |r| (r.sched_priority, r.sched_generation));

        match prio_a.cmp(&prio_b) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => gen_a < gen_b, // Earlier generation = higher priority (FIFO)
        }
    }

    /// Swaps two positions in the heap and updates their stored indices.
    fn swap_positions(&mut self, a: usize, b: usize, arena: &mut Arena<TaskRecord>) {
        self.heap.swap(a, b);

        if let Some(record) = arena.get_mut(self.heap[a].arena_index()) {
            record.heap_index = Some(a as u32);
        }
        if let Some(record) = arena.get_mut(self.heap[b].arena_index()) {
            record.heap_index = Some(b as u32);
        }
    }

    /// Clears all entries from the heap, resetting all task heap indices.
    pub fn clear(&mut self, arena: &mut Arena<TaskRecord>) {
        for &task in &self.heap {
            if let Some(record) = arena.get_mut(task.arena_index()) {
                record.heap_index = None;
                record.sched_priority = 0;
                record.sched_generation = 0;
            }
        }
        self.heap.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, RegionId};
    use crate::util::ArenaIndex;

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn setup_arena(count: u32) -> Arena<TaskRecord> {
        let mut arena = Arena::new();
        for i in 0..count {
            let id = task(i);
            let record = TaskRecord::new(id, region(), Budget::INFINITE);
            let idx = arena.insert(record);
            assert_eq!(idx.index(), i);
        }
        arena
    }

    #[test]
    fn empty_heap() {
        let heap = IntrusivePriorityHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
        assert!(heap.peek().is_none());
    }

    #[test]
    fn push_pop_single() {
        let mut arena = setup_arena(1);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 5, &mut arena);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek(), Some(task(0)));

        let popped = heap.pop(&mut arena);
        assert_eq!(popped, Some(task(0)));
        assert!(heap.is_empty());

        // Verify heap_index is cleared
        let record = arena.get(task(0).arena_index()).unwrap();
        assert!(record.heap_index.is_none());
    }

    #[test]
    fn priority_ordering() {
        let mut arena = setup_arena(5);
        let mut heap = IntrusivePriorityHeap::new();

        // Push with different priorities
        heap.push(task(0), 1, &mut arena); // lowest
        heap.push(task(1), 5, &mut arena); // highest
        heap.push(task(2), 3, &mut arena); // middle
        heap.push(task(3), 5, &mut arena); // equal to task 1
        heap.push(task(4), 2, &mut arena);

        // Pop should return highest priority first
        let first = heap.pop(&mut arena).unwrap();
        assert_eq!(first, task(1), "highest priority, earliest generation");

        let second = heap.pop(&mut arena).unwrap();
        assert_eq!(second, task(3), "same priority as task 1, later generation");

        let third = heap.pop(&mut arena).unwrap();
        assert_eq!(third, task(2), "priority 3");

        let fourth = heap.pop(&mut arena).unwrap();
        assert_eq!(fourth, task(4), "priority 2");

        let fifth = heap.pop(&mut arena).unwrap();
        assert_eq!(fifth, task(0), "priority 1 (lowest)");

        assert!(heap.is_empty());
    }

    #[test]
    fn fifo_within_same_priority() {
        let mut arena = setup_arena(5);
        let mut heap = IntrusivePriorityHeap::new();

        // All same priority
        for i in 0..5 {
            heap.push(task(i), 5, &mut arena);
        }

        // Should pop in insertion order (FIFO)
        for i in 0..5 {
            let popped = heap.pop(&mut arena).unwrap();
            assert_eq!(popped, task(i), "FIFO: expected task {i}");
        }
    }

    #[test]
    fn remove_by_task_id() {
        let mut arena = setup_arena(5);
        let mut heap = IntrusivePriorityHeap::new();

        for i in 0..5 {
            heap.push(task(i), u8::try_from(i).unwrap(), &mut arena);
        }
        assert_eq!(heap.len(), 5);

        // Remove task from middle
        let removed = heap.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(heap.len(), 4);

        // Verify removed task's heap_index is cleared
        let record = arena.get(task(2).arena_index()).unwrap();
        assert!(record.heap_index.is_none());

        // Pop remaining in priority order: 4, 3, 1, 0
        assert_eq!(heap.pop(&mut arena), Some(task(4)));
        assert_eq!(heap.pop(&mut arena), Some(task(3)));
        assert_eq!(heap.pop(&mut arena), Some(task(1)));
        assert_eq!(heap.pop(&mut arena), Some(task(0)));
    }

    #[test]
    fn remove_not_in_heap() {
        let mut arena = setup_arena(2);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 5, &mut arena);
        let removed = heap.remove(task(1), &mut arena);
        assert!(!removed);
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn contains_check() {
        let mut arena = setup_arena(3);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 5, &mut arena);
        heap.push(task(1), 3, &mut arena);

        assert!(heap.contains(task(0), &arena));
        assert!(heap.contains(task(1), &arena));
        assert!(!heap.contains(task(2), &arena));

        let _ = heap.pop(&mut arena);
        assert!(!heap.contains(task(0), &arena)); // Was popped
        assert!(heap.contains(task(1), &arena));
    }

    #[test]
    fn no_duplicate_push() {
        let mut arena = setup_arena(1);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 5, &mut arena);
        heap.push(task(0), 10, &mut arena); // duplicate, should be no-op
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn clear_resets_all() {
        let mut arena = setup_arena(5);
        let mut heap = IntrusivePriorityHeap::new();

        for i in 0..5 {
            heap.push(task(i), u8::try_from(i).unwrap(), &mut arena);
        }
        assert_eq!(heap.len(), 5);

        heap.clear(&mut arena);
        assert!(heap.is_empty());

        // Verify all heap indices cleared
        for i in 0..5 {
            let record = arena.get(task(i).arena_index()).unwrap();
            assert!(record.heap_index.is_none());
        }
    }

    #[test]
    fn high_volume() {
        let count = 1000u32;
        let mut arena = setup_arena(count);
        let mut heap = IntrusivePriorityHeap::with_capacity(count as usize);

        // Push all with varying priorities
        for i in 0..count {
            let priority = (i % 10) as u8;
            heap.push(task(i), priority, &mut arena);
        }
        assert_eq!(heap.len(), count as usize);

        // Pop all and count
        let mut popped_count = 0u32;
        while heap.pop(&mut arena).is_some() {
            popped_count += 1;
        }
        assert_eq!(popped_count, count);
        assert!(heap.is_empty());
    }

    #[test]
    fn interleaved_push_pop() {
        let mut arena = setup_arena(10);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 3, &mut arena);
        heap.push(task(1), 7, &mut arena);
        assert_eq!(heap.pop(&mut arena), Some(task(1))); // priority 7

        heap.push(task(2), 5, &mut arena);
        heap.push(task(3), 9, &mut arena);
        assert_eq!(heap.pop(&mut arena), Some(task(3))); // priority 9
        assert_eq!(heap.pop(&mut arena), Some(task(2))); // priority 5
        assert_eq!(heap.pop(&mut arena), Some(task(0))); // priority 3
        assert!(heap.is_empty());
    }

    #[test]
    fn reuse_after_pop() {
        let mut arena = setup_arena(1);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 5, &mut arena);
        let _ = heap.pop(&mut arena);

        // Re-push the same task
        heap.push(task(0), 8, &mut arena);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek(), Some(task(0)));

        let record = arena.get(task(0).arena_index()).unwrap();
        assert_eq!(record.sched_priority, 8);
    }

    #[test]
    fn remove_head() {
        let mut arena = setup_arena(3);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 1, &mut arena);
        heap.push(task(1), 9, &mut arena);
        heap.push(task(2), 5, &mut arena);

        // Remove the head (task 1, priority 9)
        let removed = heap.remove(task(1), &mut arena);
        assert!(removed);
        assert_eq!(heap.len(), 2);

        // Next pop should be task 2 (priority 5)
        assert_eq!(heap.pop(&mut arena), Some(task(2)));
        assert_eq!(heap.pop(&mut arena), Some(task(0)));
    }

    #[test]
    fn remove_tail() {
        let mut arena = setup_arena(3);
        let mut heap = IntrusivePriorityHeap::new();

        heap.push(task(0), 9, &mut arena);
        heap.push(task(1), 5, &mut arena);
        heap.push(task(2), 1, &mut arena);

        // Remove lowest priority (task 2)
        let removed = heap.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(heap.len(), 2);

        assert_eq!(heap.pop(&mut arena), Some(task(0)));
        assert_eq!(heap.pop(&mut arena), Some(task(1)));
    }
}
