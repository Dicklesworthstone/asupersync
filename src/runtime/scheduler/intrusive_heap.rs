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
//! - **Better cache locality** for heap traversal (compact `Vec<TaskId>`)
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
#[derive(Debug, Default)]
pub struct IntrusivePriorityHeap {
    /// Compact array of TaskIds forming the heap structure.
    heap: Vec<TaskId>,
    /// Monotonic counter for FIFO tie-breaking within equal priorities.
    ///
    /// The counter wraps explicitly and is reset when the heap drains, so an
    /// empty heap always starts a fresh generation epoch.
    next_generation: u64,
}

impl IntrusivePriorityHeap {
    /// Creates a new empty intrusive priority heap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        arena.get(task.arena_index()).is_some_and(|record| {
            let Some(pos) = record.heap_index else {
                return false;
            };
            let pos = pos as usize;
            pos < self.heap.len() && self.heap[pos] == task
        })
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

        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);

        record.sched_priority = priority;
        record.sched_generation = generation;

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

        let pos = pos as usize;
        // Defensively validate slot ownership before removing. A stale or
        // corrupted heap_index must not remove arbitrary tasks or panic.
        if pos >= self.heap.len() || self.heap[pos] != task {
            if let Some(record) = arena.get_mut(task.arena_index()) {
                record.heap_index = None;
                record.sched_priority = 0;
                record.sched_generation = 0;
            }
            return false;
        }

        self.remove_at(pos, arena);
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
            self.reset_generation_if_empty();
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
            std::cmp::Ordering::Equal => gen_b.wrapping_sub(gen_a).cast_signed() > 0, // Earlier generation = higher priority (FIFO)
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
        self.reset_generation_if_empty();
    }

    #[inline]
    fn reset_generation_if_empty(&mut self) {
        if self.heap.is_empty() {
            self.next_generation = 0;
        }
    }
}

#[cfg(any(test, feature = "test-internals"))]
impl IntrusivePriorityHeap {
    #[doc(hidden)]
    pub fn decrease_key_for_test(
        &mut self,
        task: TaskId,
        new_priority: u8,
        arena: &mut Arena<TaskRecord>,
    ) -> bool {
        let Some(record) = arena.get(task.arena_index()) else {
            return false;
        };

        let Some(pos) = record.heap_index else {
            return false;
        };

        let pos = pos as usize;
        if pos >= self.heap.len() || self.heap[pos] != task {
            return false;
        }

        let current_priority = record.sched_priority;
        if new_priority >= current_priority {
            return false;
        }

        if let Some(record) = arena.get_mut(task.arena_index()) {
            record.sched_priority = new_priority;
        }
        self.sift_down(pos, arena);
        true
    }

    #[doc(hidden)]
    #[must_use]
    pub fn verify_invariants_for_test(&self, arena: &Arena<TaskRecord>) -> bool {
        for (idx, &task) in self.heap.iter().enumerate() {
            let Some(record) = arena.get(task.arena_index()) else {
                return false;
            };
            if record.heap_index != Some(idx as u32) {
                return false;
            }

            if idx > 0 {
                let parent = (idx - 1) / 2;
                if self.higher_priority(idx, parent, arena) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
#[path = "intrusive_heap_inline_tests.rs"]
mod tests;
