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
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: SegQueue::new(),
        }
    }

    /// Pushes a task to the global queue.
    pub fn push(&self, task: TaskId) {
        self.inner.push(task);
    }

    /// Pops a task from the global queue.
    pub fn pop(&self) -> Option<TaskId> {
        self.inner.pop()
    }

    /// Returns the number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
