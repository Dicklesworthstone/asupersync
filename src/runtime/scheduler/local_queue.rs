//! Per-worker local queue.
//!
//! Uses a lock-protected intrusive stack for LIFO push/pop (owner) and FIFO steal (thief).
//! The stack stores links in `TaskRecord` via the runtime state's task arena,
//! keeping hot-path operations allocation-free.

use super::intrusive::{IntrusiveStack, QUEUE_TAG_READY};
#[cfg(any(test, feature = "test-internals"))]
use crate::record::task::TaskRecord;
use crate::runtime::RuntimeState;
use crate::types::TaskId;
#[cfg(any(test, feature = "test-internals"))]
use crate::types::{Budget, RegionId};
use std::sync::{Arc, Mutex};

/// A local task queue for a worker.
///
/// This queue is single-producer, multi-consumer. The worker owning this
/// queue pushes and pops from one end (LIFO), while other workers steal
/// from the other end (FIFO).
#[derive(Debug)]
pub struct LocalQueue {
    state: Arc<Mutex<RuntimeState>>,
    inner: Arc<Mutex<IntrusiveStack>>,
}

impl LocalQueue {
    /// Creates a new local queue.
    #[must_use]
    pub fn new(state: Arc<Mutex<RuntimeState>>) -> Self {
        Self {
            state,
            inner: Arc::new(Mutex::new(IntrusiveStack::new(QUEUE_TAG_READY))),
        }
    }

    /// Creates a runtime state with preallocated task records for tests.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn test_state(max_task_id: u32) -> Arc<Mutex<RuntimeState>> {
        let mut state = RuntimeState::new();
        for id in 0..=max_task_id {
            let task_id = TaskId::new_for_test(id, 0);
            let record = TaskRecord::new(task_id, RegionId::new_for_test(0, 0), Budget::INFINITE);
            let idx = state.tasks.insert(record);
            debug_assert_eq!(idx.index(), id);
        }
        Arc::new(Mutex::new(state))
    }

    /// Creates a local queue with an isolated test runtime state.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn new_for_test(max_task_id: u32) -> Self {
        Self::new(Self::test_state(max_task_id))
    }

    /// Pushes a task to the local queue.
    pub fn push(&self, task: TaskId) {
        let mut state = self.state.lock().expect("runtime state lock poisoned");
        let mut stack = self.inner.lock().expect("local queue lock poisoned");
        stack.push(task, &mut state.tasks);
    }

    /// Pops a task from the local queue (LIFO).
    #[must_use]
    pub fn pop(&self) -> Option<TaskId> {
        let mut state = self.state.lock().expect("runtime state lock poisoned");
        let mut stack = self.inner.lock().expect("local queue lock poisoned");
        stack.pop(&mut state.tasks)
    }

    /// Returns true if the local queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let stack = self.inner.lock().expect("local queue lock poisoned");
        stack.is_empty()
    }

    /// Creates a stealer for this queue.
    #[must_use]
    pub fn stealer(&self) -> Stealer {
        Stealer {
            state: Arc::clone(&self.state),
            inner: Arc::clone(&self.inner),
        }
    }
}

/// A handle to steal tasks from a local queue.
#[derive(Debug, Clone)]
pub struct Stealer {
    state: Arc<Mutex<RuntimeState>>,
    inner: Arc<Mutex<IntrusiveStack>>,
}

impl Stealer {
    /// Steals a task from the queue.
    #[must_use]
    pub fn steal(&self) -> Option<TaskId> {
        let mut state = self.state.lock().expect("runtime state lock poisoned");
        let mut stack = self.inner.lock().expect("local queue lock poisoned");
        stack.steal_one(&mut state.tasks)
    }

    /// Steals a batch of tasks.
    #[must_use]
    pub fn steal_batch(&self, dest: &LocalQueue) -> bool {
        if Arc::ptr_eq(&self.inner, &dest.inner) {
            return false;
        }

        if !Arc::ptr_eq(&self.state, &dest.state) {
            return false;
        }
        debug_assert!(
            Arc::ptr_eq(&self.state, &dest.state),
            "steal_batch requires a shared RuntimeState"
        );

        let stolen = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");
            let mut src = self.inner.lock().expect("local queue lock poisoned");
            let mut dest_stack = dest.inner.lock().expect("local queue lock poisoned");
            src.steal_batch_into(usize::MAX, &mut state.tasks, &mut dest_stack)
        };
        stolen > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskId;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn queue(max_task_id: u32) -> LocalQueue {
        LocalQueue::new_for_test(max_task_id)
    }

    #[test]
    fn owner_pop_is_lifo() {
        let queue = queue(3);
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
        let queue = queue(3);
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
        let state = LocalQueue::test_state(7);
        let src = LocalQueue::new(Arc::clone(&state));
        let dest = LocalQueue::new(Arc::clone(&state));

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
        let queue = queue(3);
        let stealer = queue.stealer();

        queue.push(task(1));
        assert_eq!(stealer.steal(), Some(task(1)));

        queue.push(task(2));
        queue.push(task(3));
        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(stealer.steal(), Some(task(2)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn concurrent_owner_and_stealers_preserve_tasks() {
        let total: usize = 512;
        let queue = Arc::new(LocalQueue::new_for_test((total - 1) as u32));
        for id in 0..total {
            queue.push(task(id as u32));
        }

        let counts: Arc<Vec<AtomicUsize>> =
            Arc::new((0..total).map(|_| AtomicUsize::new(0)).collect());
        let stealer_threads = 4;
        let barrier = Arc::new(Barrier::new(stealer_threads + 2));

        let queue_owner = Arc::clone(&queue);
        let counts_owner = Arc::clone(&counts);
        let barrier_owner = Arc::clone(&barrier);
        let owner = thread::spawn(move || {
            barrier_owner.wait();
            while let Some(task) = queue_owner.pop() {
                let idx = task.0.index() as usize;
                counts_owner[idx].fetch_add(1, Ordering::SeqCst);
                thread::yield_now();
            }
        });

        let mut stealers = Vec::new();
        for _ in 0..stealer_threads {
            let stealer = queue.stealer();
            let counts = Arc::clone(&counts);
            let barrier = Arc::clone(&barrier);
            stealers.push(thread::spawn(move || {
                barrier.wait();
                while let Some(task) = stealer.steal() {
                    let idx = task.0.index() as usize;
                    counts[idx].fetch_add(1, Ordering::SeqCst);
                    thread::yield_now();
                }
            }));
        }

        barrier.wait();
        owner.join().expect("owner join");
        for handle in stealers {
            handle.join().expect("stealer join");
        }

        let mut total_seen = 0usize;
        for (idx, count) in counts.iter().enumerate() {
            let value = count.load(Ordering::SeqCst);
            assert_eq!(value, 1, "task {idx} seen {value} times");
            total_seen += value;
        }
        assert_eq!(total_seen, total);
    }

    // ========== Additional Local Queue Tests ==========

    #[test]
    fn test_local_queue_push_pop() {
        let queue = queue(1);

        // Push and pop single item
        queue.push(task(1));
        assert_eq!(queue.pop(), Some(task(1)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_local_queue_is_empty() {
        let queue = queue(1);
        assert!(queue.is_empty());

        queue.push(task(1));
        assert!(!queue.is_empty());

        let _ = queue.pop();
        assert!(queue.is_empty());
    }

    #[test]
    fn test_local_queue_lifo_optimization() {
        // LIFO ordering benefits cache locality for producer
        let queue = queue(5);

        // Push tasks in order 1,2,3,4,5
        for i in 1..=5 {
            queue.push(task(i));
        }

        // Pop should return in reverse order (LIFO)
        assert_eq!(queue.pop(), Some(task(5)));
        assert_eq!(queue.pop(), Some(task(4)));
        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(queue.pop(), Some(task(2)));
        assert_eq!(queue.pop(), Some(task(1)));
    }

    #[test]
    fn test_steal_batch_steals_half() {
        let state = LocalQueue::test_state(9);
        let src = LocalQueue::new(Arc::clone(&state));
        let dest = LocalQueue::new(Arc::clone(&state));

        // Push 10 tasks
        for i in 0..10 {
            src.push(task(i));
        }

        let _ = src.stealer().steal_batch(&dest);

        // Should steal ~half (5)
        let mut src_count = 0;
        while src.pop().is_some() {
            src_count += 1;
        }

        let mut dest_count = 0;
        while dest.pop().is_some() {
            dest_count += 1;
        }

        assert_eq!(src_count + dest_count, 10, "no tasks should be lost");
        assert!(
            (4..=6).contains(&dest_count),
            "should steal roughly half, got {dest_count}"
        );
    }

    #[test]
    fn test_steal_batch_steals_one() {
        // When queue has 1 item, steal batch should take it
        let state = LocalQueue::test_state(42);
        let src = LocalQueue::new(Arc::clone(&state));
        let dest = LocalQueue::new(Arc::clone(&state));

        src.push(task(42));
        let _ = src.stealer().steal_batch(&dest);

        // Source should be empty
        assert!(src.is_empty());
        // Dest should have the task
        assert_eq!(dest.pop(), Some(task(42)));
    }

    #[test]
    fn test_local_queue_stealer_clone() {
        let queue = queue(2);
        queue.push(task(1));
        queue.push(task(2));

        let stealer1 = queue.stealer();
        let stealer2 = stealer1.clone();

        // Both stealers should work
        let t1 = stealer1.steal();
        let t2 = stealer2.steal();

        assert!(t1.is_some());
        assert!(t2.is_some());
        assert_ne!(t1, t2, "stealers should get different tasks");
    }

    #[test]
    fn test_local_queue_high_volume() {
        let count = 10_000;
        let queue = queue(count - 1);

        // Push many tasks
        for i in 0..count {
            queue.push(task(i));
        }

        // Pop all tasks
        let mut popped = 0;
        while queue.pop().is_some() {
            popped += 1;
        }

        assert_eq!(popped, count, "should pop exactly {count} tasks");
    }

    #[test]
    fn test_local_queue_mixed_push_pop() {
        let queue = queue(3);

        // Interleaved push and pop
        queue.push(task(1));
        queue.push(task(2));
        assert_eq!(queue.pop(), Some(task(2)));

        queue.push(task(3));
        assert_eq!(queue.pop(), Some(task(3)));
        assert_eq!(queue.pop(), Some(task(1)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_steal_from_empty_is_idempotent() {
        let queue = queue(0);
        let stealer = queue.stealer();

        // Multiple steals from empty should all return None
        for _ in 0..10 {
            assert!(stealer.steal().is_none());
        }
    }

    #[test]
    fn test_steal_batch_from_empty() {
        let state = LocalQueue::test_state(0);
        let src = LocalQueue::new(Arc::clone(&state));
        let dest = LocalQueue::new(Arc::clone(&state));

        // steal_batch from empty should return false
        let result = src.stealer().steal_batch(&dest);
        assert!(!result, "steal_batch from empty should return false");
        assert!(dest.is_empty());
    }
}
