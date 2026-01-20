//! Timer heap for deadline management.
//!
//! This module provides a small min-heap of `(deadline, task)` pairs to support
//! deadline-driven wakeups.

use crate::types::{TaskId, Time};
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Eq, PartialEq)]
struct TimerEntry {
    deadline: Time,
    task: TaskId,
    generation: u64,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (earliest deadline first).
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

    /// Pops all tasks whose deadline is `<= now`.
    pub fn pop_expired(&mut self, now: Time) -> Vec<TaskId> {
        let mut expired = Vec::new();
        while let Some(entry) = self.heap.peek() {
            if entry.deadline <= now {
                if let Some(entry) = self.heap.pop() {
                    expired.push(entry.task);
                } else {
                    break;
                }
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
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn empty_heap_has_no_deadline() {
        init_test("empty_heap_has_no_deadline");
        let heap = TimerHeap::new();
        crate::assert_with_log!(heap.is_empty(), "heap starts empty", true, heap.is_empty());
        crate::assert_with_log!(
            heap.peek_deadline() == None::<Time>,
            "empty heap has no deadline",
            None::<Time>,
            heap.peek_deadline()
        );
        crate::test_complete!("empty_heap_has_no_deadline");
    }

    #[test]
    fn insert_orders_by_deadline() {
        init_test("insert_orders_by_deadline");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(200));
        heap.insert(task(2), Time::from_millis(100));
        heap.insert(task(3), Time::from_millis(150));

        crate::assert_with_log!(
            heap.peek_deadline() == Some(Time::from_millis(100)),
            "earliest deadline is kept at top",
            Some(Time::from_millis(100)),
            heap.peek_deadline()
        );
        crate::test_complete!("insert_orders_by_deadline");
    }

    #[test]
    fn pop_expired_returns_all_due_tasks() {
        init_test("pop_expired_returns_all_due_tasks");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(50));

        crate::test_section!("pop");
        let expired = heap.pop_expired(Time::from_millis(125));
        crate::assert_with_log!(
            expired.len() == 2,
            "two tasks expired",
            2usize,
            expired.len()
        );
        crate::assert_with_log!(
            expired.contains(&task(1)),
            "expired contains task 1",
            true,
            expired.contains(&task(1))
        );
        crate::assert_with_log!(
            expired.contains(&task(3)),
            "expired contains task 3",
            true,
            expired.contains(&task(3))
        );
        crate::assert_with_log!(
            heap.peek_deadline() == Some(Time::from_millis(200)),
            "remaining deadline is 200ms",
            Some(Time::from_millis(200)),
            heap.peek_deadline()
        );
        crate::test_complete!("pop_expired_returns_all_due_tasks");
    }
}
