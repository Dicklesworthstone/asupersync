//! Timer heap for deadline management.
//!
//! This module provides a min-heap of timers for efficiently tracking
//! the next deadline that needs to fire.

use crate::types::{TaskId, Time};
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// A timer entry in the heap.
#[derive(Debug, Clone, Eq, PartialEq)]
struct TimerEntry {
    deadline: Time,
    task: TaskId,
    /// Generation to handle cancellation without removal.
    generation: u64,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (earliest deadline first)
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A min-heap of timers ordered by deadline.
#[derive(Debug, Default)]
pub struct TimerHeap {
    heap: BinaryHeap<TimerEntry>,
    next_generation: u64,
}

impl TimerHeap {
    /// Creates a new empty timer heap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of timers in the heap.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns true if the heap is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Adds a timer for a task with the given deadline.
    pub fn insert(&mut self, task: TaskId, deadline: Time) {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.heap.push(TimerEntry {
            deadline,
            task,
            generation,
        });
    }

    /// Returns the earliest deadline, if any.
    #[must_use]
    pub fn peek_deadline(&self) -> Option<Time> {
        self.heap.peek().map(|e| e.deadline)
    }

    /// Pops all timers that have expired (deadline <= now).
    pub fn pop_expired(&mut self, now: Time) -> Vec<TaskId> {
        let mut expired = Vec::new();
        while let Some(entry) = self.heap.peek() {
            if entry.deadline <= now {
                let entry = self.heap.pop().unwrap();
                expired.push(entry.task);
            } else {
                break;
            }
        }
        expired
    }

    /// Clears all timers.
    pub fn clear(&mut self) {
        self.heap.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    // =========================================================================
    // Construction and Default Tests
    // =========================================================================

    #[test]
    fn new_creates_empty_heap() {
        let heap = TimerHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
    }

    #[test]
    fn default_creates_empty_heap() {
        let heap = TimerHeap::default();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
    }

    #[test]
    fn new_and_default_are_equivalent() {
        let new_heap = TimerHeap::new();
        let default_heap = TimerHeap::default();
        assert_eq!(new_heap.len(), default_heap.len());
        assert_eq!(new_heap.is_empty(), default_heap.is_empty());
        assert_eq!(new_heap.peek_deadline(), default_heap.peek_deadline());
    }

    // =========================================================================
    // len() and is_empty() Tests
    // =========================================================================

    #[test]
    fn len_reflects_insertions() {
        let mut heap = TimerHeap::new();
        assert_eq!(heap.len(), 0);

        heap.insert(task(1), Time::from_millis(100));
        assert_eq!(heap.len(), 1);

        heap.insert(task(2), Time::from_millis(200));
        assert_eq!(heap.len(), 2);

        heap.insert(task(3), Time::from_millis(300));
        assert_eq!(heap.len(), 3);
    }

    #[test]
    fn is_empty_false_after_insert() {
        let mut heap = TimerHeap::new();
        assert!(heap.is_empty());

        heap.insert(task(1), Time::from_millis(100));
        assert!(!heap.is_empty());
    }

    #[test]
    fn len_decreases_after_pop_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(300));
        assert_eq!(heap.len(), 3);

        let expired = heap.pop_expired(Time::from_millis(150));
        assert_eq!(expired.len(), 1);
        assert_eq!(heap.len(), 2);
    }

    // =========================================================================
    // insert() Tests
    // =========================================================================

    #[test]
    fn insert_single_timer() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));
    }

    #[test]
    fn insert_multiple_maintains_min_heap() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(300));
        heap.insert(task(2), Time::from_millis(100));
        heap.insert(task(3), Time::from_millis(200));

        // Earliest deadline should be at the top
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));
    }

    #[test]
    fn insert_with_time_zero() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::ZERO);
        assert_eq!(heap.peek_deadline(), Some(Time::ZERO));
    }

    #[test]
    fn insert_with_time_max() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::MAX);
        assert_eq!(heap.peek_deadline(), Some(Time::MAX));
    }

    #[test]
    fn insert_same_task_multiple_times() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(1), Time::from_millis(200));
        heap.insert(task(1), Time::from_millis(50));

        // All three entries should exist
        assert_eq!(heap.len(), 3);
        // Earliest deadline first
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(50)));
    }

    // =========================================================================
    // peek_deadline() Tests
    // =========================================================================

    #[test]
    fn peek_deadline_empty_returns_none() {
        let heap = TimerHeap::new();
        assert_eq!(heap.peek_deadline(), None);
    }

    #[test]
    fn peek_deadline_does_not_remove() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));

        // Multiple peeks should return the same value
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn peek_deadline_updates_after_pop() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));

        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));

        let _ = heap.pop_expired(Time::from_millis(100));
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(200)));
    }

    // =========================================================================
    // pop_expired() Tests
    // =========================================================================

    #[test]
    fn pop_expired_empty_heap_returns_empty() {
        let mut heap = TimerHeap::new();
        let expired = heap.pop_expired(Time::from_millis(1000));
        assert!(expired.is_empty());
    }

    #[test]
    fn pop_expired_none_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));

        let expired = heap.pop_expired(Time::from_millis(50));
        assert!(expired.is_empty());
        assert_eq!(heap.len(), 2);
    }

    #[test]
    fn pop_expired_all_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(300));

        let expired = heap.pop_expired(Time::from_millis(500));
        assert_eq!(expired.len(), 3);
        assert!(heap.is_empty());
    }

    #[test]
    fn pop_expired_some_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(300));

        let expired = heap.pop_expired(Time::from_millis(250));
        assert_eq!(expired.len(), 2);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(300)));
    }

    #[test]
    fn pop_expired_exact_deadline_is_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));

        let expired = heap.pop_expired(Time::from_millis(100));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], task(1));
    }

    #[test]
    fn pop_expired_returns_in_deadline_order() {
        let mut heap = TimerHeap::new();
        // Insert out of order
        heap.insert(task(3), Time::from_millis(300));
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));

        let expired = heap.pop_expired(Time::from_millis(500));
        // Should be in earliest-first order
        assert_eq!(expired, vec![task(1), task(2), task(3)]);
    }

    #[test]
    fn earliest_first() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(50));
        heap.insert(task(3), Time::from_millis(150));

        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(50)));

        let expired = heap.pop_expired(Time::from_millis(100));
        assert_eq!(expired, vec![task(2), task(1)]);
    }

    #[test]
    fn pop_expired_with_time_zero() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::ZERO);
        heap.insert(task(2), Time::from_millis(100));

        let expired = heap.pop_expired(Time::ZERO);
        assert_eq!(expired, vec![task(1)]);
    }

    // =========================================================================
    // Generation (FIFO for Same Deadline) Tests
    // =========================================================================

    #[test]
    fn same_deadline_fifo_order() {
        let mut heap = TimerHeap::new();
        // Insert multiple tasks with the same deadline
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(100));
        heap.insert(task(3), Time::from_millis(100));

        let expired = heap.pop_expired(Time::from_millis(100));
        // Should be FIFO order (earliest generation first)
        assert_eq!(expired, vec![task(1), task(2), task(3)]);
    }

    #[test]
    fn generation_increments() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(100));

        // Internal check: generation should have incremented
        assert_eq!(heap.next_generation, 2);
    }

    #[test]
    fn mixed_deadlines_and_generations() {
        let mut heap = TimerHeap::new();
        // Insert with same deadline (100ms)
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(100));
        // Insert earlier deadline
        heap.insert(task(3), Time::from_millis(50));
        // Insert another with 100ms
        heap.insert(task(4), Time::from_millis(100));

        let expired = heap.pop_expired(Time::from_millis(100));
        // task(3) at 50ms first, then task(1), task(2), task(4) at 100ms in FIFO
        assert_eq!(expired, vec![task(3), task(1), task(2), task(4)]);
    }

    // =========================================================================
    // clear() Tests
    // =========================================================================

    #[test]
    fn clear_empties_heap() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(300));

        assert_eq!(heap.len(), 3);
        heap.clear();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
        assert_eq!(heap.peek_deadline(), None);
    }

    #[test]
    fn clear_empty_heap_is_noop() {
        let mut heap = TimerHeap::new();
        heap.clear();
        assert!(heap.is_empty());
    }

    #[test]
    fn insert_after_clear() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.clear();

        heap.insert(task(2), Time::from_millis(200));
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(200)));
    }

    // =========================================================================
    // Edge Cases and Stress Tests
    // =========================================================================

    #[test]
    fn time_max_is_never_expired() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::MAX);

        // Even at max-1, should not expire
        let expired = heap.pop_expired(Time::from_nanos(u64::MAX - 1));
        assert!(expired.is_empty());
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn time_max_expires_at_max() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::MAX);

        let expired = heap.pop_expired(Time::MAX);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn multiple_pop_expired_calls() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(300));

        let expired1 = heap.pop_expired(Time::from_millis(150));
        assert_eq!(expired1, vec![task(1)]);

        let expired2 = heap.pop_expired(Time::from_millis(250));
        assert_eq!(expired2, vec![task(2)]);

        let expired3 = heap.pop_expired(Time::from_millis(350));
        assert_eq!(expired3, vec![task(3)]);

        let expired4 = heap.pop_expired(Time::from_millis(500));
        assert!(expired4.is_empty());
    }

    #[test]
    fn stress_many_timers() {
        let mut heap = TimerHeap::new();

        // Insert 100 timers with various deadlines
        for i in 0..100u32 {
            heap.insert(task(i), Time::from_millis(u64::from(i * 10)));
        }

        assert_eq!(heap.len(), 100);
        assert_eq!(heap.peek_deadline(), Some(Time::ZERO)); // task(0) at 0ms

        // Pop first 50 (0-490ms)
        let expired = heap.pop_expired(Time::from_millis(490));
        assert_eq!(expired.len(), 50);
        assert_eq!(heap.len(), 50);

        // Verify remaining
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(500)));
    }

    #[test]
    fn interleaved_insert_and_pop() {
        let mut heap = TimerHeap::new();

        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));

        let expired1 = heap.pop_expired(Time::from_millis(150));
        assert_eq!(expired1, vec![task(1)]);

        heap.insert(task(3), Time::from_millis(50)); // Earlier than remaining
        heap.insert(task(4), Time::from_millis(300));

        // task(3) at 50ms is already expired at current time 150ms
        let expired2 = heap.pop_expired(Time::from_millis(150));
        assert_eq!(expired2, vec![task(3)]);

        // task(2) at 200ms, task(4) at 300ms remain
        assert_eq!(heap.len(), 2);
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(200)));
    }

    // =========================================================================
    // TimerEntry Ordering Tests
    // =========================================================================

    #[test]
    fn timer_entry_ordering_by_deadline() {
        let early = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(1),
            generation: 0,
        };
        let late = TimerEntry {
            deadline: Time::from_millis(200),
            task: task(2),
            generation: 0,
        };

        // Reversed for min-heap: early > late
        assert!(early > late);
        assert!(late < early);
    }

    #[test]
    fn timer_entry_ordering_same_deadline_by_generation() {
        let first = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(1),
            generation: 0,
        };
        let second = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(2),
            generation: 1,
        };

        // Same deadline: earlier generation should come first
        // Reversed for min-heap: first > second
        assert!(first > second);
    }

    #[test]
    fn timer_entry_equality() {
        let a = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(1),
            generation: 0,
        };
        let b = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(1),
            generation: 0,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn timer_entry_clone() {
        let original = TimerEntry {
            deadline: Time::from_millis(100),
            task: task(1),
            generation: 5,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
