//! Lane-aware global injection queue.
//!
//! Provides a thread-safe injection point for tasks from outside the worker threads.
//! Tasks are routed to the appropriate priority lane: cancel > timed > ready.

use crate::types::{TaskId, Time};
use crossbeam_queue::SegQueue;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A scheduled task with its priority metadata.
#[derive(Debug, Clone, Copy)]
pub struct PriorityTask {
    /// The task identifier.
    pub task: TaskId,
    /// Scheduling priority (0-255, higher = more important).
    pub priority: u8,
}

/// A scheduled task with a deadline.
#[derive(Debug, Clone, Copy)]
pub struct TimedTask {
    /// The task identifier.
    pub task: TaskId,
    /// Absolute deadline for EDF scheduling.
    pub deadline: Time,
}

/// Lane-aware global injection queue.
///
/// This queue separates tasks by their scheduling lane to maintain strict
/// priority ordering even for cross-thread wakeups:
/// - Cancel lane: Highest priority, always processed first
/// - Timed lane: EDF ordering, processed after cancel
/// - Ready lane: Standard priority ordering, processed last
#[derive(Debug, Default)]
pub struct GlobalInjector {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_queue: SegQueue<PriorityTask>,
    /// Timed lane: tasks with deadlines (EDF ordering).
    timed_queue: SegQueue<TimedTask>,
    /// Ready lane: general ready tasks.
    ready_queue: SegQueue<PriorityTask>,
    /// Approximate count of pending tasks (for metrics/decisions).
    pending_count: AtomicUsize,
}

impl GlobalInjector {
    /// Creates a new empty global injector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects a task into the cancel lane.
    ///
    /// Cancel lane tasks have the highest priority and will be processed
    /// before any timed or ready work.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        self.cancel_queue.push(PriorityTask { task, priority });
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Injects a task into the timed lane.
    ///
    /// Timed tasks are scheduled by their deadline (earliest deadline first)
    /// and have priority over ready tasks but not cancel tasks.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        self.timed_queue.push(TimedTask { task, deadline });
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Injects a task into the ready lane.
    ///
    /// Ready tasks have the lowest lane priority but are still ordered
    /// by their individual priority within the lane.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        self.ready_queue.push(PriorityTask { task, priority });
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Pops a task from the cancel lane.
    ///
    /// Returns `None` if the cancel lane is empty.
    #[must_use]
    pub fn pop_cancel(&self) -> Option<PriorityTask> {
        let result = self.cancel_queue.pop();
        if result.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Pops a task from the timed lane.
    ///
    /// Returns `None` if the timed lane is empty.
    /// Note: The caller should check if the deadline is due before executing.
    #[must_use]
    pub fn pop_timed(&self) -> Option<TimedTask> {
        let result = self.timed_queue.pop();
        if result.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Pops a task from the ready lane.
    ///
    /// Returns `None` if the ready lane is empty.
    #[must_use]
    pub fn pop_ready(&self) -> Option<PriorityTask> {
        let result = self.ready_queue.pop();
        if result.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Returns true if all lanes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cancel_queue.is_empty() && self.timed_queue.is_empty() && self.ready_queue.is_empty()
    }

    /// Returns the approximate number of pending tasks across all lanes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }

    /// Returns true if the cancel lane has pending work.
    #[must_use]
    pub fn has_cancel_work(&self) -> bool {
        !self.cancel_queue.is_empty()
    }

    /// Returns true if the timed lane has pending work.
    #[must_use]
    pub fn has_timed_work(&self) -> bool {
        !self.timed_queue.is_empty()
    }

    /// Returns true if the ready lane has pending work.
    #[must_use]
    pub fn has_ready_work(&self) -> bool {
        !self.ready_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(1, id)
    }

    #[test]
    fn inject_and_pop_cancel() {
        let injector = GlobalInjector::new();

        injector.inject_cancel(task(1), 100);
        injector.inject_cancel(task(2), 50);

        assert!(!injector.is_empty());
        assert!(injector.has_cancel_work());

        let first = injector.pop_cancel().unwrap();
        assert_eq!(first.task, task(1));

        let second = injector.pop_cancel().unwrap();
        assert_eq!(second.task, task(2));

        assert!(injector.pop_cancel().is_none());
    }

    #[test]
    fn inject_and_pop_timed() {
        let injector = GlobalInjector::new();

        injector.inject_timed(task(1), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        assert!(injector.has_timed_work());

        // FIFO order (not sorted - workers handle EDF locally)
        let first = injector.pop_timed().unwrap();
        assert_eq!(first.task, task(1));

        let second = injector.pop_timed().unwrap();
        assert_eq!(second.task, task(2));
    }

    #[test]
    fn inject_and_pop_ready() {
        let injector = GlobalInjector::new();

        injector.inject_ready(task(1), 100);

        assert!(injector.has_ready_work());

        let popped = injector.pop_ready().unwrap();
        assert_eq!(popped.task, task(1));
        assert_eq!(popped.priority, 100);
    }

    #[test]
    fn pending_count_accuracy() {
        let injector = GlobalInjector::new();

        assert_eq!(injector.len(), 0);

        injector.inject_cancel(task(1), 100);
        injector.inject_timed(task(2), Time::from_secs(10));
        injector.inject_ready(task(3), 50);

        assert_eq!(injector.len(), 3);

        let _ = injector.pop_cancel();
        assert_eq!(injector.len(), 2);

        let _ = injector.pop_timed();
        let _ = injector.pop_ready();
        assert_eq!(injector.len(), 0);
    }
}
