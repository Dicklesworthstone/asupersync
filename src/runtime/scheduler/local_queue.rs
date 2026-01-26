//! Per-worker local queue.
//!
//! Uses a lock-based deque for LIFO push/pop (owner) and FIFO steal (thief).
//! This stays within the project's `unsafe` prohibition while preserving
//! correct work-stealing semantics.

use crate::types::TaskId;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// A local task queue for a worker.
///
/// This queue is single-producer, multi-consumer. The worker owning this
/// queue pushes and pops from one end (LIFO), while other workers steal
/// from the other end (FIFO).
#[derive(Debug)]
pub struct LocalQueue {
    inner: Arc<Mutex<VecDeque<TaskId>>>,
}

impl LocalQueue {
    /// Creates a new local queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Pushes a task to the local queue.
    pub fn push(&self, task: TaskId) {
        let mut queue = self.inner.lock().expect("local queue lock poisoned");
        queue.push_back(task);
    }

    /// Pops a task from the local queue (LIFO).
    #[must_use]
    pub fn pop(&self) -> Option<TaskId> {
        let mut queue = self.inner.lock().expect("local queue lock poisoned");
        queue.pop_back()
    }

    /// Creates a stealer for this queue.
    #[must_use]
    pub fn stealer(&self) -> Stealer {
        Stealer {
            inner: Arc::clone(&self.inner),
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
    inner: Arc<Mutex<VecDeque<TaskId>>>,
}

impl Stealer {
    /// Steals a task from the queue.
    #[must_use]
    pub fn steal(&self) -> Option<TaskId> {
        let mut queue = self.inner.lock().expect("local queue lock poisoned");
        queue.pop_front()
    }

    /// Steals a batch of tasks.
    #[must_use]
    pub fn steal_batch(&self, dest: &LocalQueue) -> bool {
        let mut stolen = Vec::new();
        {
            let mut queue = self.inner.lock().expect("local queue lock poisoned");
            if queue.is_empty() {
                return false;
            }
            let steal_count = (queue.len() / 2).max(1);
            for _ in 0..steal_count {
                if let Some(task) = queue.pop_front() {
                    stolen.push(task);
                } else {
                    break;
                }
            }
        }

        for task in stolen {
            dest.push(task);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskId;
    use std::collections::HashSet;

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(1, id)
    }

    #[test]
    fn owner_pop_is_lifo() {
        let queue = LocalQueue::new();
        queue.push(task(1));
        queue.push(task(2));
        queue.push(task(3));

        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(queue.pop(), Some(task(2)));
        assert_eq!(queue.pop(), Some(task(1)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn thief_steal_is_fifo() {
        let queue = LocalQueue::new();
        queue.push(task(1));
        queue.push(task(2));
        queue.push(task(3));

        let stealer = queue.stealer();
        assert_eq!(stealer.steal(), Some(task(1)));
        assert_eq!(stealer.steal(), Some(task(2)));
        assert_eq!(stealer.steal(), Some(task(3)));
        assert_eq!(stealer.steal(), None);
    }

    #[test]
    fn steal_batch_moves_tasks_without_loss_or_dup() {
        let src = LocalQueue::new();
        let dest = LocalQueue::new();

        for id in 0..8 {
            src.push(task(id));
        }

        assert!(src.stealer().steal_batch(&dest));

        let mut seen = HashSet::new();
        let mut remaining = Vec::new();

        while let Some(task) = src.pop() {
            remaining.push(task);
        }
        while let Some(task) = dest.pop() {
            remaining.push(task);
        }

        for item in remaining {
            assert!(seen.insert(item), "duplicate task found: {item:?}");
        }

        assert_eq!(seen.len(), 8);
    }

    #[test]
    fn interleaved_owner_thief_operations_preserve_tasks() {
        let queue = LocalQueue::new();
        let stealer = queue.stealer();

        queue.push(task(1));
        assert_eq!(stealer.steal(), Some(task(1)));

        queue.push(task(2));
        queue.push(task(3));
        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(stealer.steal(), Some(task(2)));
        assert_eq!(queue.pop(), None);
    }
}
