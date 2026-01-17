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
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn empty_heap_has_no_deadline() {
        let heap = TimerHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.peek_deadline(), None);
    }

    #[test]
    fn insert_orders_by_deadline() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(200));
        heap.insert(task(2), Time::from_millis(100));
        heap.insert(task(3), Time::from_millis(150));

        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(100)));
    }

    #[test]
    fn pop_expired_returns_all_due_tasks() {
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(50));

        let expired = heap.pop_expired(Time::from_millis(125));
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&task(1)));
        assert!(expired.contains(&task(3)));
        assert_eq!(heap.peek_deadline(), Some(Time::from_millis(200)));
    }
}
