//! Cache-local intrusive ring queue for scheduler hot paths.
//!
//! This module provides an intrusive doubly-linked ring implementation that
//! uses the link fields embedded in `TaskRecord` rather than allocating
//! separate node structures. This eliminates per-operation allocations and
//! improves cache locality by keeping queue metadata with task data.
//!
//! # Design
//!
//! - Links (`next_in_queue`, `prev_in_queue`, `queue_tag`) are stored in `TaskRecord`
//! - The ring maintains only head/tail indices into the task arena
//! - Each task can be in at most one queue (enforced by `queue_tag`)
//! - O(1) push_back, pop_front, and remove operations
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

        ring.pop_front(&mut arena);
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
}
