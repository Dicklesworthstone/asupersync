//! Lane-aware global injection queue.
//!
//! Provides a thread-safe injection point for tasks from outside the worker threads.
//! Tasks are routed to the appropriate priority lane: cancel > timed > ready.

use crate::types::{TaskId, Time};
use crate::util::CachePadded;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
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
    /// Approximate count of ready-lane tasks only.
    ready_count: CachePadded<AtomicUsize>,
    /// Approximate count of timed-lane tasks, allowing callers to skip
    /// acquiring the timed_queue mutex when the lane is empty.
    timed_count: CachePadded<AtomicUsize>,
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
            ready_count: CachePadded::new(AtomicUsize::new(0)),
            timed_count: CachePadded::new(AtomicUsize::new(0)),
        }
    }
}

impl GlobalInjector {
    /// Decrements an advisory counter, saturating at zero.
    ///
    /// Uses `fetch_update` with `checked_sub` so the counter never wraps to
    /// `usize::MAX`, even transiently.  A `fetch_sub` + store-on-underflow
    /// approach would be slightly cheaper in the common case but would expose
    /// a brief window where readers see `usize::MAX`, which confuses `len()`,
    /// `is_empty()`, and `has_timed_work()` callers.
    #[inline]
    fn saturating_decrement(counter: &AtomicUsize) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            count.checked_sub(1)
        });
    }

    /// Decrements the ready counter, saturating at zero.
    #[inline]
    fn decrement_ready_count(&self) {
        Self::saturating_decrement(&self.ready_count);
    }

    /// Decrements the timed counter, saturating at zero.
    #[inline]
    fn decrement_timed_count(&self) {
        Self::saturating_decrement(&self.timed_count);
    }

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
    }

    /// Injects a task into the timed lane.
    ///
    /// Timed tasks are scheduled by their deadline (earliest deadline first)
    /// and have priority over ready tasks but not cancel tasks.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        // Increment counters *before* the push so that `timed_count` is always
        // >= the true heap length.  A brief over-count is harmless (pop just
        // finds an empty heap and saturates back to 0).
        self.timed_count.fetch_add(1, Ordering::Relaxed);
        let mut queue = self.timed_queue.lock();
        let generation = queue.next_generation;
        queue.next_generation += 1;
        queue.heap.push(TimedTask::new(task, deadline, generation));
        drop(queue);
    }

    /// Injects a task into the ready lane.
    ///
    /// Ready tasks have the lowest lane priority. The global ready queue
    /// uses FIFO ordering for lock-free throughput; per-task priority
    /// ordering is applied by the local `PriorityScheduler` after stealing.
    #[inline]
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        self.ready_count.fetch_add(1, Ordering::Relaxed);
        self.ready_queue.push(PriorityTask { task, priority });
    }

    /// Pops a task from the cancel lane.
    ///
    /// Returns `None` if the cancel lane is empty.
    #[inline]
    #[must_use]
    pub fn pop_cancel(&self) -> Option<PriorityTask> {
        self.cancel_queue.pop()
    }

    /// Pops a task from the timed lane (earliest deadline first).
    ///
    /// Returns `None` if the timed lane is empty.
    /// The caller should check if the deadline is due before executing.
    #[must_use]
    pub fn pop_timed(&self) -> Option<TimedTask> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut queue = self.timed_queue.lock();
        let result = queue.heap.pop();
        drop(queue);
        if result.is_some() {
            self.decrement_timed_count();
        }
        result
    }

    /// Peeks at the earliest deadline in the timed lane without removing it.
    ///
    /// Returns `None` if the timed lane is empty.
    #[must_use]
    pub fn peek_earliest_deadline(&self) -> Option<Time> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let queue = self.timed_queue.lock();
        queue.heap.peek().map(|t| t.deadline)
    }

    /// Pops the earliest timed task only if its deadline is due.
    ///
    /// Returns `None` if the timed lane is empty or if the earliest
    /// deadline is still in the future.
    #[must_use]
    pub fn pop_timed_if_due(&self, now: Time) -> Option<TimedTask> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut queue = self.timed_queue.lock();
        if let Some(entry) = queue.heap.peek() {
            if entry.deadline <= now {
                let result = queue.heap.pop();
                drop(queue);
                if result.is_some() {
                    self.decrement_timed_count();
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
            self.decrement_ready_count();
        }
        result
    }

    /// Returns true if all lanes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cancel_queue.is_empty()
            && self.timed_count.load(Ordering::Relaxed) == 0
            && self.ready_queue.is_empty()
    }

    /// Returns true if there is work that can be executed immediately.
    #[must_use]
    pub fn has_runnable_work(&self, now: Time) -> bool {
        if !self.cancel_queue.is_empty() || !self.ready_queue.is_empty() {
            return true;
        }
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let queue = self.timed_queue.lock();
        queue.heap.peek().is_some_and(|t| t.deadline <= now)
    }

    /// Returns the approximate number of pending tasks across all lanes.
    ///
    /// Derived from per-lane counters; avoids a dedicated atomic counter
    /// on every inject/pop.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cancel_queue.len()
            + self.timed_count.load(Ordering::Relaxed)
            + self.ready_count.load(Ordering::Relaxed)
    }

    /// Returns true if the cancel lane has pending work.
    #[must_use]
    pub fn has_cancel_work(&self) -> bool {
        !self.cancel_queue.is_empty()
    }

    /// Returns true if the timed lane has pending work.
    #[must_use]
    pub fn has_timed_work(&self) -> bool {
        self.timed_count.load(Ordering::Relaxed) > 0
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
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    #[test]
    fn pop_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate queue visibility preceding counter update due to interleaving.
        injector.cancel_queue.push(PriorityTask {
            task: task(10),
            priority: 1,
        });

        let popped_cancel = injector.pop_cancel().expect("cancel task should pop");
        assert_eq!(popped_cancel.task, task(10));

        injector.ready_queue.push(PriorityTask {
            task: task(11),
            priority: 2,
        });
        assert_eq!(injector.ready_count.load(Ordering::Relaxed), 0);

        let popped_ready = injector.pop_ready().expect("ready task should pop");
        assert_eq!(popped_ready.task, task(11));
        assert_eq!(injector.ready_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timed_pop_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate heap visibility preceding counter update due to interleaving.
        // Set timed_count to reflect the heap item (inject_timed now increments
        // counters before pushing, so timed_count >= heap.len() always holds).
        {
            let mut timed = injector.timed_queue.lock();
            timed
                .heap
                .push(TimedTask::new(task(12), Time::from_secs(10), 0));
        }
        injector.timed_count.fetch_add(1, Ordering::Relaxed);

        let popped_timed = injector.pop_timed().expect("timed task should pop");
        assert_eq!(popped_timed.task, task(12));
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timed_pop_if_due_does_not_underflow_when_counter_lags() {
        let injector = GlobalInjector::new();

        // Simulate heap visibility preceding counter update due to interleaving.
        // Set timed_count to reflect the heap item (inject_timed now increments
        // counters before pushing, so timed_count >= heap.len() always holds).
        {
            let mut timed = injector.timed_queue.lock();
            timed
                .heap
                .push(TimedTask::new(task(13), Time::from_secs(10), 0));
        }
        injector.timed_count.fetch_add(1, Ordering::Relaxed);

        // Not due yet: no pop and timed counter unchanged.
        assert!(injector.pop_timed_if_due(Time::from_secs(9)).is_none());
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 1);

        // Once due, pop must not underflow the lagging counter.
        let popped_timed = injector
            .pop_timed_if_due(Time::from_secs(10))
            .expect("timed task should pop when due");
        assert_eq!(popped_timed.task, task(13));
        assert_eq!(injector.timed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_decrements_saturate_counters_at_zero() {
        for _ in 0..2_000 {
            let injector = Arc::new(GlobalInjector::new());
            injector.ready_count.store(1, Ordering::Relaxed);
            let barrier = Arc::new(Barrier::new(3));

            let i1 = Arc::clone(&injector);
            let b1 = Arc::clone(&barrier);
            let h1 = thread::spawn(move || {
                b1.wait();
                i1.decrement_ready_count();
            });

            let i2 = Arc::clone(&injector);
            let b2 = Arc::clone(&barrier);
            let h2 = thread::spawn(move || {
                b2.wait();
                i2.decrement_ready_count();
            });

            barrier.wait();
            h1.join().expect("first decrement thread should complete");
            h2.join().expect("second decrement thread should complete");

            assert_eq!(
                injector.ready_count.load(Ordering::Relaxed),
                0,
                "ready counter must saturate at zero"
            );
        }
    }
}
