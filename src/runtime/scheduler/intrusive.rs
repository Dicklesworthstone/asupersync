//! Cache-local intrusive ring queue for scheduler hot paths.
//!
//! This module provides intrusive data structures that use link fields embedded
//! in `TaskRecord` rather than allocating separate nodes. This eliminates
//! per-operation allocations and improves cache locality.
//!
//! # Structures
//!
//! - [`IntrusiveRing`]: FIFO queue with O(1) push_back, pop_front, remove
//! - [`IntrusiveStack`]: LIFO stack with FIFO steal (work-stealing pattern)
//!
//! # Design
//!
//! - Links (`next_in_queue`, `prev_in_queue`, `queue_tag`) are stored in `TaskRecord`
//! - Queues maintain only head/tail indices into the task arena
//! - Each task can be in at most one queue (enforced by `queue_tag`)
//! - All operations are O(1) with zero allocations
//!
//! # When to Use
//!
//! Use intrusive structures when:
//! - You have exclusive `&mut Arena<TaskRecord>` access
//! - You need zero-allocation queue operations (hot paths)
//! - You're in a single-owner context (not shared across threads)
//!
//! Use regular queues (VecDeque, BinaryHeap) when:
//! - You need shared access (`Arc<Mutex<...>>`)
//! - You don't have arena access (TaskId-only APIs)
//! - You need priority ordering (heap-based)
//!
//! # Integration Points
//!
//! | Component | Uses | Why |
//! |-----------|------|-----|
//! | `ThreeLaneWorker` | Can use intrusive | Has arena via `state` |
//! | `PriorityScheduler` | Regular queues | No arena access, needs priority |
//! | `LocalQueue` | Regular queues | Shared via `Arc<Mutex>` |
//! | `GlobalInjector` | Regular queues | Concurrent access |
//!
//! # Safety
//!
//! This implementation avoids ABA and use-after-free issues by:
//! 1. Requiring exclusive `&mut` access to the arena during all operations
//! 2. Using `queue_tag` to detect stale references
//! 3. Clearing links immediately on removal
//!
//! # Queue Tags
//!
//! | Tag | Queue |
//! |-----|-------|
//! | 0 | Not in any queue |
//! | 1 | Local ready queue |
//! | 2 | Local cancel queue |
//! | 3 | Reserved |

use crate::record::task::TaskRecord;
use crate::types::TaskId;
use crate::util::Arena;

/// Queue tag for the local ready queue.
pub const QUEUE_TAG_READY: u8 = 1;

/// Queue tag for the local cancel queue.
pub const QUEUE_TAG_CANCEL: u8 = 2;

/// An intrusive doubly-linked ring queue.
///
/// The queue stores only head/tail indices; the actual links are stored
/// in `TaskRecord` fields. This provides O(1) operations with zero
/// per-operation allocations.
///
/// # Invariants
///
/// - If `head.is_none()`, then `tail.is_none()` and `len == 0`
/// - If `head.is_some()`, then `tail.is_some()` and `len > 0`
/// - For all tasks in the queue: `task.queue_tag == self.tag`
/// - The list forms a proper doubly-linked chain from head to tail
#[derive(Debug)]
pub struct IntrusiveRing {
    /// First task in the queue (front for pop_front).
    head: Option<TaskId>,
    /// Last task in the queue (back for push_back).
    tail: Option<TaskId>,
    /// Number of tasks in the queue.
    len: usize,
    /// Queue tag for membership detection.
    tag: u8,
}

impl IntrusiveRing {
    /// Creates a new empty intrusive ring with the given queue tag.
    #[must_use]
    pub const fn new(tag: u8) -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
            tag,
        }
    }

    /// Returns the number of tasks in the queue.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the queue is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the queue tag.
    #[must_use]
    #[inline]
    pub const fn tag(&self) -> u8 {
        self.tag
    }

    /// Pushes a task to the back of the queue.
    ///
    /// # Panics
    ///
    /// Panics if the task is already in a queue (queue_tag != 0).
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    pub fn push_back(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        // Check for double-enqueue
        debug_assert!(
            !record.is_in_queue(),
            "task {:?} already in queue (tag={})",
            task_id,
            record.queue_tag
        );

        if record.is_in_queue() {
            return;
        }

        match self.tail {
            None => {
                // Empty queue: new task becomes both head and tail
                record.set_queue_links(None, None, self.tag);
                self.head = Some(task_id);
                self.tail = Some(task_id);
            }
            Some(old_tail) => {
                // Link new task after current tail
                record.set_queue_links(Some(old_tail), None, self.tag);

                // Update old tail's next pointer
                if let Some(old_tail_record) = arena.get_mut(old_tail.arena_index()) {
                    old_tail_record.next_in_queue = Some(task_id);
                }

                self.tail = Some(task_id);
            }
        }

        self.len += 1;
    }

    /// Pops a task from the front of the queue.
    ///
    /// Returns `None` if the queue is empty.
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[must_use]
    pub fn pop_front(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        let head_id = self.head?;

        let next = {
            let record = arena.get_mut(head_id.arena_index())?;

            // Verify the task is actually in this queue
            debug_assert!(
                record.is_in_queue_tag(self.tag),
                "head task {:?} has wrong tag (expected {}, got {})",
                head_id,
                self.tag,
                record.queue_tag
            );

            let next = record.next_in_queue;
            record.clear_queue_links();
            next
        };

        self.head = next;

        match next {
            None => {
                // Queue is now empty
                self.tail = None;
            }
            Some(new_head) => {
                // Update new head's prev pointer
                if let Some(new_head_record) = arena.get_mut(new_head.arena_index()) {
                    new_head_record.prev_in_queue = None;
                }
            }
        }

        self.len -= 1;
        Some(head_id)
    }

    /// Removes a specific task from the queue.
    ///
    /// Returns `true` if the task was found and removed, `false` otherwise.
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    pub fn remove(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) -> bool {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return false;
        };

        // Check if task is in this queue
        if !record.is_in_queue_tag(self.tag) {
            return false;
        }

        let prev = record.prev_in_queue;
        let next = record.next_in_queue;

        // Clear the removed task's links
        record.clear_queue_links();

        // Update predecessor's next pointer
        match prev {
            None => {
                // Task was the head
                self.head = next;
            }
            Some(prev_id) => {
                if let Some(prev_record) = arena.get_mut(prev_id.arena_index()) {
                    prev_record.next_in_queue = next;
                }
            }
        }

        // Update successor's prev pointer
        match next {
            None => {
                // Task was the tail
                self.tail = prev;
            }
            Some(next_id) => {
                if let Some(next_record) = arena.get_mut(next_id.arena_index()) {
                    next_record.prev_in_queue = prev;
                }
            }
        }

        self.len -= 1;
        true
    }

    /// Returns true if the given task is in this queue.
    ///
    /// # Complexity
    ///
    /// O(1) time.
    #[must_use]
    pub fn contains(&self, task_id: TaskId, arena: &Arena<TaskRecord>) -> bool {
        arena
            .get(task_id.arena_index())
            .is_some_and(|record| record.is_in_queue_tag(self.tag))
    }

    /// Returns the head task ID without removing it.
    #[must_use]
    #[inline]
    pub const fn peek_front(&self) -> Option<TaskId> {
        self.head
    }

    /// Clears the queue, removing all tasks.
    ///
    /// # Complexity
    ///
    /// O(n) time to clear all links.
    pub fn clear(&mut self, arena: &mut Arena<TaskRecord>) {
        let mut current = self.head;
        while let Some(task_id) = current {
            if let Some(record) = arena.get_mut(task_id.arena_index()) {
                let next = record.next_in_queue;
                record.clear_queue_links();
                current = next;
            } else {
                break;
            }
        }

        self.head = None;
        self.tail = None;
        self.len = 0;
    }
}

impl Default for IntrusiveRing {
    fn default() -> Self {
        Self::new(0)
    }
}

/// An intrusive LIFO stack for work-stealing local queues.
///
/// Unlike `IntrusiveRing` which is FIFO, this stack provides LIFO
/// semantics for the owner while supporting FIFO stealing.
/// This matches the cache-locality optimization of processing
/// recently-pushed work first.
///
/// # Invariants
///
/// - If `top.is_none()`, then `len == 0`
/// - For all tasks in the stack: `task.queue_tag == self.tag`
#[derive(Debug)]
pub struct IntrusiveStack {
    /// Top of the stack (most recently pushed).
    top: Option<TaskId>,
    /// Bottom of the stack (oldest, for stealing).
    bottom: Option<TaskId>,
    /// Number of tasks in the stack.
    len: usize,
    /// Queue tag for membership detection.
    tag: u8,
}

impl IntrusiveStack {
    /// Creates a new empty intrusive stack with the given queue tag.
    #[must_use]
    pub const fn new(tag: u8) -> Self {
        Self {
            top: None,
            bottom: None,
            len: 0,
            tag,
        }
    }

    /// Returns the number of tasks in the stack.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the stack is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pushes a task onto the top of the stack.
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    pub fn push(&mut self, task_id: TaskId, arena: &mut Arena<TaskRecord>) {
        let Some(record) = arena.get_mut(task_id.arena_index()) else {
            return;
        };

        if record.is_in_queue() {
            return;
        }

        match self.top {
            None => {
                // Empty stack
                record.set_queue_links(None, None, self.tag);
                self.top = Some(task_id);
                self.bottom = Some(task_id);
            }
            Some(old_top) => {
                // Link new task as new top, pointing down to old top
                record.set_queue_links(None, Some(old_top), self.tag);

                // Update old top's prev pointer (points up to new top)
                if let Some(old_top_record) = arena.get_mut(old_top.arena_index()) {
                    old_top_record.prev_in_queue = Some(task_id);
                }

                self.top = Some(task_id);
            }
        }

        self.len += 1;
    }

    /// Pops a task from the top of the stack (LIFO).
    ///
    /// # Complexity
    ///
    /// O(1) time, O(0) allocations.
    #[must_use]
    pub fn pop(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        let top_id = self.top?;

        let next_down = {
            let record = arena.get_mut(top_id.arena_index())?;
            let next_down = record.next_in_queue; // Points down to older task
            record.clear_queue_links();
            next_down
        };

        self.top = next_down;

        match next_down {
            None => {
                // Stack is now empty
                self.bottom = None;
            }
            Some(new_top) => {
                // Update new top's prev pointer
                if let Some(new_top_record) = arena.get_mut(new_top.arena_index()) {
                    new_top_record.prev_in_queue = None;
                }
            }
        }

        self.len -= 1;
        Some(top_id)
    }

    /// Steals tasks from the bottom of the stack (FIFO for stealing).
    ///
    /// Returns up to `max_steal` tasks, starting from the oldest.
    ///
    /// # Complexity
    ///
    /// O(k) time where k is the number stolen, O(0) allocations.
    pub fn steal_batch(&mut self, max_steal: usize, arena: &mut Arena<TaskRecord>) -> Vec<TaskId> {
        let steal_count = (self.len / 2).max(1).min(max_steal);
        let mut stolen = Vec::with_capacity(steal_count);

        for _ in 0..steal_count {
            if let Some(bottom_id) = self.steal_one(arena) {
                stolen.push(bottom_id);
            } else {
                break;
            }
        }

        stolen
    }

    /// Steals one task from the bottom of the stack.
    #[must_use]
    fn steal_one(&mut self, arena: &mut Arena<TaskRecord>) -> Option<TaskId> {
        let bottom_id = self.bottom?;

        let prev_up = {
            let record = arena.get_mut(bottom_id.arena_index())?;
            let prev_up = record.prev_in_queue; // Points up to newer task
            record.clear_queue_links();
            prev_up
        };

        self.bottom = prev_up;

        match prev_up {
            None => {
                // Stack is now empty
                self.top = None;
            }
            Some(new_bottom) => {
                // Update new bottom's next pointer
                if let Some(new_bottom_record) = arena.get_mut(new_bottom.arena_index()) {
                    new_bottom_record.next_in_queue = None;
                }
            }
        }

        self.len -= 1;
        Some(bottom_id)
    }

    /// Returns true if the given task is in this stack.
    #[must_use]
    pub fn contains(&self, task_id: TaskId, arena: &Arena<TaskRecord>) -> bool {
        arena
            .get(task_id.arena_index())
            .is_some_and(|record| record.is_in_queue_tag(self.tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::task::TaskRecord;
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
    fn empty_queue() {
        let ring = IntrusiveRing::new(QUEUE_TAG_READY);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert!(ring.peek_front().is_none());
    }

    #[test]
    fn push_pop_single() {
        let mut arena = setup_arena(1);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
        assert_eq!(ring.peek_front(), Some(task(0)));

        let popped = ring.pop_front(&mut arena);
        assert_eq!(popped, Some(task(0)));
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        // Verify task links are cleared
        let record = arena.get(task(0).arena_index()).unwrap();
        assert!(!record.is_in_queue());
    }

    #[test]
    fn fifo_ordering() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4
        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }
        assert_eq!(ring.len(), 5);

        // Pop should return 0, 1, 2, 3, 4 (FIFO)
        for i in 0..5 {
            let popped = ring.pop_front(&mut arena);
            assert_eq!(popped, Some(task(i)), "expected task {i}");
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn remove_from_middle() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove task 2 from the middle
        let removed = ring.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 4);

        // Verify task 2's links are cleared
        let record = arena.get(task(2).arena_index()).unwrap();
        assert!(!record.is_in_queue());

        // Pop remaining: 0, 1, 3, 4
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(3)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(4)));
        assert!(ring.is_empty());
    }

    #[test]
    fn remove_head() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..3 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove head (task 0)
        let removed = ring.remove(task(0), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 2);

        // Pop remaining: 1, 2
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(2)));
    }

    #[test]
    fn remove_tail() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..3 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove tail (task 2)
        let removed = ring.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 2);

        // Pop remaining: 0, 1
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
    }

    #[test]
    fn remove_only_element() {
        let mut arena = setup_arena(1);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        let removed = ring.remove(task(0), &mut arena);

        assert!(removed);
        assert!(ring.is_empty());
        assert!(ring.head.is_none());
        assert!(ring.tail.is_none());
    }

    #[test]
    fn remove_not_in_queue() {
        let mut arena = setup_arena(2);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);

        // Try to remove task 1 which is not in the queue
        let removed = ring.remove(task(1), &mut arena);
        assert!(!removed);
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn contains() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);

        assert!(ring.contains(task(0), &arena));
        assert!(ring.contains(task(1), &arena));
        assert!(!ring.contains(task(2), &arena));

        let _ = ring.pop_front(&mut arena);
        assert!(!ring.contains(task(0), &arena));
        assert!(ring.contains(task(1), &arena));
    }

    #[test]
    fn clear() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }

        ring.clear(&mut arena);
        assert!(ring.is_empty());

        // Verify all tasks have cleared links
        for i in 0..5 {
            let record = arena.get(task(i).arena_index()).unwrap();
            assert!(!record.is_in_queue());
        }
    }

    #[test]
    fn different_queue_tags() {
        let mut arena = setup_arena(4);
        let mut ready_ring = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut cancel_ring = IntrusiveRing::new(QUEUE_TAG_CANCEL);

        // Put tasks 0,1 in ready queue and tasks 2,3 in cancel queue
        ready_ring.push_back(task(0), &mut arena);
        ready_ring.push_back(task(1), &mut arena);
        cancel_ring.push_back(task(2), &mut arena);
        cancel_ring.push_back(task(3), &mut arena);

        // Verify containment
        assert!(ready_ring.contains(task(0), &arena));
        assert!(ready_ring.contains(task(1), &arena));
        assert!(!ready_ring.contains(task(2), &arena));
        assert!(!ready_ring.contains(task(3), &arena));

        assert!(!cancel_ring.contains(task(0), &arena));
        assert!(!cancel_ring.contains(task(1), &arena));
        assert!(cancel_ring.contains(task(2), &arena));
        assert!(cancel_ring.contains(task(3), &arena));

        // Cannot remove task from wrong queue
        assert!(!ready_ring.remove(task(2), &mut arena));
        assert!(!cancel_ring.remove(task(0), &mut arena));

        // Can remove from correct queue
        assert!(ready_ring.remove(task(0), &mut arena));
        assert!(cancel_ring.remove(task(2), &mut arena));
    }

    #[test]
    fn interleaved_push_pop() {
        let mut arena = setup_arena(10);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));

        ring.push_back(task(2), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(2)));

        ring.push_back(task(3), &mut arena);
        ring.push_back(task(4), &mut arena);
        ring.push_back(task(5), &mut arena);

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop_front(&mut arena), Some(task(3)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(4)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(5)));
        assert!(ring.is_empty());
    }

    #[test]
    fn high_volume() {
        let count = 1000u32;
        let mut arena = setup_arena(count);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..count {
            ring.push_back(task(i), &mut arena);
        }
        assert_eq!(ring.len(), count as usize);

        for i in 0..count {
            let popped = ring.pop_front(&mut arena);
            assert_eq!(popped, Some(task(i)));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn reuse_after_pop() {
        let mut arena = setup_arena(2);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        // Push and pop task 0
        ring.push_back(task(0), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));

        // Re-enqueue task 0
        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);

        // Should get task 0 first (FIFO)
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
    }

    // ── IntrusiveStack tests ─────────────────────────────────────────────

    #[test]
    fn stack_empty() {
        let stack = IntrusiveStack::new(QUEUE_TAG_READY);
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn stack_push_pop_single() {
        let mut arena = setup_arena(1);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);
        assert_eq!(stack.len(), 1);
        assert!(!stack.is_empty());

        let popped = stack.pop(&mut arena);
        assert_eq!(popped, Some(task(0)));
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_lifo_ordering() {
        let mut arena = setup_arena(5);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4
        for i in 0..5 {
            stack.push(task(i), &mut arena);
        }
        assert_eq!(stack.len(), 5);

        // Pop should return 4, 3, 2, 1, 0 (LIFO)
        for i in (0..5).rev() {
            let popped = stack.pop(&mut arena);
            assert_eq!(popped, Some(task(i)), "expected task {i}");
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_steal_fifo() {
        let mut arena = setup_arena(8);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4, 5, 6, 7
        for i in 0..8 {
            stack.push(task(i), &mut arena);
        }

        // Steal should return oldest first (FIFO for stealing)
        let stolen = stack.steal_batch(4, &mut arena);
        assert_eq!(stolen.len(), 4);
        // Should have stolen 0, 1, 2, 3 (the oldest)
        for (i, task_id) in stolen.into_iter().enumerate() {
            assert_eq!(task_id, task(i as u32), "stolen task {i}");
        }

        // Remaining should be 7, 6, 5, 4 (LIFO order)
        assert_eq!(stack.len(), 4);
        assert_eq!(stack.pop(&mut arena), Some(task(7)));
        assert_eq!(stack.pop(&mut arena), Some(task(6)));
        assert_eq!(stack.pop(&mut arena), Some(task(5)));
        assert_eq!(stack.pop(&mut arena), Some(task(4)));
    }

    #[test]
    fn stack_work_stealing_semantics() {
        // Simulates owner pushing and popping while thief steals
        let mut arena = setup_arena(10);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Owner pushes 0, 1, 2, 3, 4, 5
        for i in 0..6 {
            stack.push(task(i), &mut arena);
        }

        // Owner pops most recent (5)
        assert_eq!(stack.pop(&mut arena), Some(task(5)));

        // Stack now has [0, 1, 2, 3, 4] with len=5
        // Thief steals oldest - steal_batch takes at most half the queue
        // (5/2).max(1).min(2) = 2, so 2 tasks stolen
        let stolen = stack.steal_batch(2, &mut arena);
        assert_eq!(stolen.len(), 2);
        assert_eq!(stolen[0], task(0)); // Oldest is stolen first
        assert_eq!(stolen[1], task(1));

        // Stack now has [2, 3, 4] with len=3
        // Owner pushes 6
        stack.push(task(6), &mut arena);

        // Stack is [2, 3, 4, 6] - owner pops LIFO (6, 4, 3, 2)
        assert_eq!(stack.pop(&mut arena), Some(task(6)));
        assert_eq!(stack.pop(&mut arena), Some(task(4)));
        assert_eq!(stack.pop(&mut arena), Some(task(3)));
        assert_eq!(stack.pop(&mut arena), Some(task(2)));
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_steal_from_small() {
        let mut arena = setup_arena(2);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);

        // Steal from single-element stack
        let stolen = stack.steal_batch(4, &mut arena);
        assert_eq!(stolen.len(), 1);
        assert_eq!(stolen[0], task(0));
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_steal_from_empty() {
        let mut arena = setup_arena(0);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        let stolen = stack.steal_batch(4, &mut arena);
        assert!(stolen.is_empty());
    }

    #[test]
    fn stack_contains() {
        let mut arena = setup_arena(3);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);
        stack.push(task(1), &mut arena);

        assert!(stack.contains(task(0), &arena));
        assert!(stack.contains(task(1), &arena));
        assert!(!stack.contains(task(2), &arena));

        let _ = stack.pop(&mut arena); // Remove task 1
        assert!(stack.contains(task(0), &arena));
        assert!(!stack.contains(task(1), &arena));
    }
}
