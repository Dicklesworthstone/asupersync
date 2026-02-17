//! Global injection queue.
//!
//! A thread-safe unbounded queue for tasks that cannot be locally scheduled
//! or are spawned from outside the runtime.

use crate::types::TaskId;
use crossbeam_queue::SegQueue;

/// A global task queue.
#[derive(Debug, Default)]
pub struct GlobalQueue {
    inner: SegQueue<TaskId>,
}

impl GlobalQueue {
    /// Creates a new global queue.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: SegQueue::new(),
        }
    }

    /// Pushes a task to the global queue.
    #[inline]
    pub fn push(&self, task: TaskId) {
        self.inner.push(task);
    }

    /// Pops a task from the global queue.
    #[inline]
    pub fn pop(&self) -> Option<TaskId> {
        self.inner.pop()
    }

    /// Returns a best-effort task count snapshot.
    ///
    /// Under concurrent producers/consumers this value may change immediately
    /// after it is observed.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns a best-effort emptiness snapshot.
    ///
    /// Under concurrent producers/consumers this hint may become stale
    /// immediately after it is observed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    #[test]
    fn test_global_queue_push_pop_basic() {
        let queue = GlobalQueue::new();

        queue.push(task(1));
        queue.push(task(2));
        queue.push(task(3));

        assert_eq!(queue.pop(), Some(task(1)));
        assert_eq!(queue.pop(), Some(task(2)));
        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_global_queue_fifo_ordering() {
        let queue = GlobalQueue::new();

        // Push in order
        for i in 0..10 {
            queue.push(task(i));
        }

        // Pop should be FIFO
        for i in 0..10 {
            assert_eq!(queue.pop(), Some(task(i)));
        }
    }

    #[test]
    fn test_global_queue_len() {
        let queue = GlobalQueue::new();
        assert_eq!(queue.len(), 0);

        queue.push(task(1));
        assert_eq!(queue.len(), 1);

        queue.push(task(2));
        assert_eq!(queue.len(), 2);

        queue.pop();
        assert_eq!(queue.len(), 1);

        queue.pop();
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_global_queue_is_empty() {
        let queue = GlobalQueue::new();
        assert!(queue.is_empty());

        queue.push(task(1));
        assert!(!queue.is_empty());

        queue.pop();
        assert!(queue.is_empty());
    }

    #[test]
    fn test_global_queue_mpsc() {
        // Multi-producer, single-consumer test
        let queue = Arc::new(GlobalQueue::new());
        let producers = 5;
        let items_per_producer = 100;
        let barrier = Arc::new(Barrier::new(producers + 1));

        let handles: Vec<_> = (0..producers)
            .map(|p| {
                let q = queue.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    b.wait();
                    for i in 0..items_per_producer {
                        q.push(task((p * 1000 + i) as u32));
                    }
                })
            })
            .collect();

        barrier.wait();

        for h in handles {
            h.join().expect("producer should complete");
        }

        // All items should be in queue
        assert_eq!(queue.len(), producers * items_per_producer);

        // Pop all and verify no duplicates
        let mut seen = HashSet::new();
        while let Some(t) = queue.pop() {
            assert!(seen.insert(t), "duplicate task found");
        }
        assert_eq!(seen.len(), producers * items_per_producer);
    }

    #[test]
    fn test_global_queue_spawn_lands_in_global() {
        // Simulating spawn() behavior
        let queue = GlobalQueue::new();

        // "spawn" a task
        let new_task = task(42);
        queue.push(new_task);

        // Should be retrievable
        assert_eq!(queue.pop(), Some(new_task));
    }

    #[test]
    fn test_global_queue_default() {
        let queue = GlobalQueue::default();
        assert!(queue.is_empty());
    }

    #[test]
    fn test_global_queue_high_volume() {
        let queue = GlobalQueue::new();
        let count = 50_000;

        for i in 0..count {
            queue.push(task(i));
        }

        assert_eq!(queue.len(), count as usize);

        let mut popped = 0;
        while queue.pop().is_some() {
            popped += 1;
        }

        assert_eq!(popped, count as usize);
    }

    #[test]
    fn test_global_queue_contention() {
        // High contention: many threads pushing and popping simultaneously
        let queue = Arc::new(GlobalQueue::new());
        let threads = 10;
        let ops_per_thread = 1000;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let q = queue.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    b.wait();
                    for i in 0..ops_per_thread {
                        q.push(task((t * 10000 + i) as u32));
                        // Interleave with pops
                        if i % 3 == 0 {
                            q.pop();
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread should complete without deadlock");
        }

        // Drain any leftover items from the concurrent phase
        while queue.pop().is_some() {}

        // Queue should still be functional after contention
        queue.push(task(999_999));
        assert_eq!(queue.pop(), Some(task(999_999)));
    }
}
