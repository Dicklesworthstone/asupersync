//! Per-worker local queue.
//!
//! Uses a lock-free deque for LIFO push/pop (producer) and FIFO steal (consumer).

use crate::types::TaskId;
use crossbeam_deque::{Steal, Worker};

/// A local task queue for a worker.
///
/// This queue is single-producer, multi-consumer. The worker owning this
/// queue pushes and pops from one end (LIFO), while other workers steal
/// from the other end (FIFO).
#[derive(Debug)]
pub struct LocalQueue {
    inner: Worker<TaskId>,
}

impl LocalQueue {
    /// Creates a new local queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Worker::new_fifo(),
        }
    }

    /// Pushes a task to the local queue.
    pub fn push(&self, task: TaskId) {
        self.inner.push(task);
    }

    /// Pops a task from the local queue (LIFO).
    #[must_use]
    pub fn pop(&self) -> Option<TaskId> {
        self.inner.pop()
    }

    /// Creates a stealer for this queue.
    #[must_use]
    pub fn stealer(&self) -> Stealer {
        Stealer {
            inner: self.inner.stealer(),
        }
    }
}

impl Default for LocalQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle to steal tasks from a local queue.
#[derive(Debug, Clone)]
pub struct Stealer {
    inner: crossbeam_deque::Stealer<TaskId>,
}

impl Stealer {
    /// Steals a task from the queue.
    #[must_use]
    pub fn steal(&self) -> Option<TaskId> {
        match self.inner.steal() {
            Steal::Success(task) => Some(task),
            Steal::Retry => {
                // Retry once? Or loop?
                // For simple stealing, we can retry loop or just return None and let caller loop.
                // Usually retry is for contention.
                // Let's retry a few times or until success/empty.
                loop {
                    match self.inner.steal() {
                        Steal::Success(task) => return Some(task),
                        Steal::Empty => return None,
                        Steal::Retry => {},
                    }
                }
            }
            Steal::Empty => None,
        }
    }

    /// Steals a batch of tasks.
    #[must_use]
    pub fn steal_batch(&self, dest: &LocalQueue) -> bool {
        // We steal into the destination worker's local queue
        loop {
            match self.inner.steal_batch(&dest.inner) {
                Steal::Success(()) => return true,
                Steal::Empty => return false,
                Steal::Retry => {},
            }
        }
    }
}
