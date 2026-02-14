//! Lane-aware global injection queue.
//!
//! Provides a thread-safe injection point for tasks from outside the worker threads.
//! Tasks are routed to the appropriate priority lane: cancel > timed > ready.

use crate::types::{TaskId, Time};
use crossbeam_queue::SegQueue;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A scheduled task with its priority metadata.
#[derive(Debug, Clone, Copy)]
pub struct PriorityTask {
    /// The task identifier.
    pub task: TaskId,
    /// Scheduling priority (0-255, higher = more important).
    pub priority: u8,
}

/// A scheduled task with a deadline.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TimedTask {
    /// The task identifier.
    pub task: TaskId,
    /// Absolute deadline for EDF scheduling.
    pub deadline: Time,
    /// Insertion order for FIFO tiebreaking among equal deadlines.
    generation: u64,
}

impl TimedTask {
    /// Creates a new timed task with the given deadline and generation.
    fn new(task: TaskId, deadline: Time, generation: u64) -> Self {
        Self {
            task,
            deadline,
            generation,
        }
    }
}

impl Ord for TimedTask {
    #[inline]
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering for min-heap (earliest deadline first).
        // For equal deadlines, lower generation (earlier insertion) comes first.
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

impl PartialOrd for TimedTask {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

/// Lane-aware global injection queue.
///
/// This queue separates tasks by their scheduling lane to maintain strict
/// priority ordering even for cross-thread wakeups:
/// - Cancel lane: Highest priority, always processed first
/// - Timed lane: EDF ordering (earliest deadline first), processed after cancel
/// - Ready lane: Standard priority ordering, processed last
#[derive(Debug)]
pub struct GlobalInjector {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_queue: SegQueue<PriorityTask>,
    /// Timed lane: tasks with deadlines (EDF ordering via min-heap).
    timed_queue: Mutex<TimedQueue>,
    /// Ready lane: general ready tasks.
    ready_queue: SegQueue<PriorityTask>,
    /// Approximate count of pending tasks (for metrics/decisions).
    pending_count: AtomicUsize,
    /// Approximate count of ready-lane tasks only.
    ready_count: AtomicUsize,
}

/// Thread-safe EDF queue for timed tasks.
#[derive(Debug, Default)]
struct TimedQueue {
    /// Min-heap ordered by deadline (earliest first).
    heap: BinaryHeap<TimedTask>,
    /// Next generation number for FIFO tiebreaking.
    next_generation: u64,
}

impl Default for GlobalInjector {
    fn default() -> Self {
        Self {
            cancel_queue: SegQueue::new(),
            timed_queue: Mutex::new(TimedQueue::default()),
            ready_queue: SegQueue::new(),
            pending_count: AtomicUsize::new(0),
            ready_count: AtomicUsize::new(0),
        }
    }
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
    #[inline]
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        self.cancel_queue.push(PriorityTask { task, priority });
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Injects a task into the timed lane.
    ///
    /// Timed tasks are scheduled by their deadline (earliest deadline first)
    /// and have priority over ready tasks but not cancel tasks.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        let mut queue = self.timed_queue.lock().unwrap();
        let generation = queue.next_generation;
        queue.next_generation += 1;
        queue.heap.push(TimedTask::new(task, deadline, generation));
        drop(queue);
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Injects a task into the ready lane.
    ///
    /// Ready tasks have the lowest lane priority. The global ready queue
    /// uses FIFO ordering for lock-free throughput; per-task priority
    /// ordering is applied by the local `PriorityScheduler` after stealing.
    #[inline]
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        self.ready_queue.push(PriorityTask { task, priority });
        self.ready_count.fetch_add(1, Ordering::Relaxed);
        self.pending_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Pops a task from the cancel lane.
    ///
    /// Returns `None` if the cancel lane is empty.
    #[inline]
    #[must_use]
    pub fn pop_cancel(&self) -> Option<PriorityTask> {
        let result = self.cancel_queue.pop();
        if result.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Pops a task from the timed lane (earliest deadline first).
    ///
    /// Returns `None` if the timed lane is empty.
    /// The caller should check if the deadline is due before executing.
    #[must_use]
    pub fn pop_timed(&self) -> Option<TimedTask> {
        let mut queue = self.timed_queue.lock().unwrap();
        let result = queue.heap.pop();
        drop(queue);
        if result.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Peeks at the earliest deadline in the timed lane without removing it.
    ///
    /// Returns `None` if the timed lane is empty.
    #[must_use]
    pub fn peek_earliest_deadline(&self) -> Option<Time> {
        let queue = self.timed_queue.lock().unwrap();
        queue.heap.peek().map(|t| t.deadline)
    }

    /// Pops the earliest timed task only if its deadline is due.
    ///
    /// Returns `None` if the timed lane is empty or if the earliest
    /// deadline is still in the future.
    #[must_use]
    pub fn pop_timed_if_due(&self, now: Time) -> Option<TimedTask> {
        let mut queue = self.timed_queue.lock().unwrap();
        if let Some(entry) = queue.heap.peek() {
            if entry.deadline <= now {
                let result = queue.heap.pop();
                drop(queue);
                if result.is_some() {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                }
                return result;
            }
        }
        None
    }

    /// Pops a task from the ready lane.
    ///
    /// Returns `None` if the ready lane is empty.
    #[inline]
    #[must_use]
    pub fn pop_ready(&self) -> Option<PriorityTask> {
        let result = self.ready_queue.pop();
        if result.is_some() {
            self.ready_count.fetch_sub(1, Ordering::Relaxed);
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Returns true if all lanes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cancel_queue.is_empty()
            && self.timed_queue.lock().unwrap().heap.is_empty()
            && self.ready_queue.is_empty()
    }

    /// Returns true if there is work that can be executed immediately.
    #[must_use]
    pub fn has_runnable_work(&self, now: Time) -> bool {
        if !self.cancel_queue.is_empty() || !self.ready_queue.is_empty() {
            return true;
        }
        let queue = self.timed_queue.lock().unwrap();
        queue.heap.peek().is_some_and(|t| t.deadline <= now)
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
        !self.timed_queue.lock().unwrap().heap.is_empty()
    }

    /// Returns true if the ready lane has pending work.
    #[must_use]
    pub fn has_ready_work(&self) -> bool {
        !self.ready_queue.is_empty()
    }

    /// Returns the approximate number of tasks in the ready lane.
    #[must_use]
    pub fn ready_count(&self) -> usize {
        self.ready_count.load(Ordering::Relaxed)
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

        // EDF order: earliest deadline first
        let first = injector.pop_timed().unwrap();
        assert_eq!(first.task, task(2)); // deadline 50s comes first
        assert_eq!(first.deadline, Time::from_secs(50));

        let second = injector.pop_timed().unwrap();
        assert_eq!(second.task, task(1)); // deadline 100s comes second
        assert_eq!(second.deadline, Time::from_secs(100));
    }

    #[test]
    fn edf_ordering_multiple_tasks() {
        let injector = GlobalInjector::new();

        // Insert in random order
        injector.inject_timed(task(3), Time::from_secs(75));
        injector.inject_timed(task(1), Time::from_secs(25));
        injector.inject_timed(task(4), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        // Should pop in deadline order: 25, 50, 75, 100
        assert_eq!(injector.pop_timed().unwrap().task, task(1));
        assert_eq!(injector.pop_timed().unwrap().task, task(2));
        assert_eq!(injector.pop_timed().unwrap().task, task(3));
        assert_eq!(injector.pop_timed().unwrap().task, task(4));
    }

    #[test]
    fn equal_deadlines_fifo_order() {
        let injector = GlobalInjector::new();

        // Same deadline, should maintain insertion order
        injector.inject_timed(task(1), Time::from_secs(50));
        injector.inject_timed(task(2), Time::from_secs(50));
        injector.inject_timed(task(3), Time::from_secs(50));

        // FIFO among equal deadlines
        assert_eq!(injector.pop_timed().unwrap().task, task(1));
        assert_eq!(injector.pop_timed().unwrap().task, task(2));
        assert_eq!(injector.pop_timed().unwrap().task, task(3));
    }

    #[test]
    fn pop_timed_if_due() {
        let injector = GlobalInjector::new();

        injector.inject_timed(task(1), Time::from_secs(100));
        injector.inject_timed(task(2), Time::from_secs(50));

        // At t=25, nothing is due
        assert!(injector.pop_timed_if_due(Time::from_secs(25)).is_none());
        assert!(injector.has_timed_work()); // Tasks still in queue

        // At t=50, task 2 is due
        let due = injector.pop_timed_if_due(Time::from_secs(50)).unwrap();
        assert_eq!(due.task, task(2));

        // At t=75, task 1 is still not due
        assert!(injector.pop_timed_if_due(Time::from_secs(75)).is_none());

        // At t=100, task 1 is due
        let due = injector.pop_timed_if_due(Time::from_secs(100)).unwrap();
        assert_eq!(due.task, task(1));
    }

    #[test]
    fn peek_earliest_deadline() {
        let injector = GlobalInjector::new();

        assert!(injector.peek_earliest_deadline().is_none());

        injector.inject_timed(task(1), Time::from_secs(100));
        assert_eq!(
            injector.peek_earliest_deadline(),
            Some(Time::from_secs(100))
        );

        injector.inject_timed(task(2), Time::from_secs(50));
        assert_eq!(injector.peek_earliest_deadline(), Some(Time::from_secs(50)));

        // Peek doesn't remove
        assert_eq!(injector.peek_earliest_deadline(), Some(Time::from_secs(50)));
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
