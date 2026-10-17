//! Global injection queue.
//!
//! A thread-safe unbounded queue for tasks that cannot be locally scheduled
//! or are spawned from outside the runtime.

use crate::types::TaskId;
use crate::util::CachePadded;
#[cfg(not(target_family = "wasm"))]
use crossbeam_queue::SegQueue;
#[cfg(target_family = "wasm")]
use parking_lot::Mutex;
#[cfg(target_family = "wasm")]
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(target_family = "wasm"))]
struct NativeQueueInner<T: Send> {
    queue: SegQueue<T>,
}

#[cfg(not(target_family = "wasm"))]
impl<T: Send> Default for NativeQueueInner<T> {
    fn default() -> Self {
        Self {
            queue: SegQueue::new(),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: Send> NativeQueueInner<T> {
    #[inline]
    fn enqueue(&self, item: T) {
        self.queue.push(item);
    }

    #[inline]
    fn dequeue(&self) -> Option<T> {
        self.queue.pop()
    }
}

#[cfg(target_family = "wasm")]
struct NativeQueueInner<T: Send> {
    queue: Mutex<VecDeque<T>>,
}

#[cfg(target_family = "wasm")]
impl<T: Send> Default for NativeQueueInner<T> {
    fn default() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }
}

#[cfg(target_family = "wasm")]
impl<T: Send> NativeQueueInner<T> {
    #[inline]
    fn enqueue(&self, item: T) {
        self.queue.lock().push_back(item);
    }

    #[inline]
    fn dequeue(&self) -> Option<T> {
        self.queue.lock().pop_front()
    }
}

/// Lock-free FIFO queue with a best-effort count snapshot.
///
/// This wraps `crossbeam_queue::SegQueue` on native targets so the scheduler
/// keeps unbounded MPMC FIFO semantics without the pthread-key teardown hazards
/// seen in `faa_array_queue`'s `os-thread-local` dependency. Browser wasm
/// builds use a mutex-backed FIFO because portable atomics are not guaranteed
/// there.
pub(crate) struct GlobalFifoQueue<T: Send> {
    inner: NativeQueueInner<T>,
    count: CachePadded<AtomicUsize>,
    published: CachePadded<AtomicUsize>,
}

impl<T: Send> Default for GlobalFifoQueue<T> {
    fn default() -> Self {
        Self {
            inner: NativeQueueInner::default(),
            count: CachePadded::new(AtomicUsize::new(0)),
            published: CachePadded::new(AtomicUsize::new(0)),
        }
    }
}

impl<T: Send> fmt::Debug for GlobalFifoQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalFifoQueue")
            .field("count", &self.len())
            .finish_non_exhaustive()
    }
}

impl<T: Send> GlobalFifoQueue<T> {
    #[inline]
    fn saturating_decrement(counter: &AtomicUsize) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            count.checked_sub(1)
        });
    }

    #[inline]
    fn saturating_sub(counter: &AtomicUsize, count: usize) {
        if count == 0 {
            return;
        }
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(count))
        });
    }

    #[inline]
    fn try_reserve_published(counter: &AtomicUsize) -> bool {
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .is_ok()
    }

    #[inline]
    pub(crate) fn push(&self, item: T) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.inner.enqueue(item);
        self.published.fetch_add(1, Ordering::Release);
    }

    #[inline]
    /// Enqueues an item without touching the advisory count snapshot.
    ///
    /// Callers MUST pre-account the item via [`Self::add_count`] before making
    /// the item visible through this path. Publishing the item first and only
    /// incrementing the counter later lets a concurrent pop consume the item
    /// and saturate the counter at zero, after which the delayed increment
    /// would leave a phantom positive count on an empty queue.
    pub(crate) fn push_uncounted(&self, item: T) {
        self.inner.enqueue(item);
        self.published.fetch_add(1, Ordering::Release);
    }

    #[inline]
    /// Bulk increments the advisory count snapshot for subsequent
    /// [`Self::push_uncounted`] publications.
    ///
    /// The intended sequence is `add_count(n)` followed by `n` uncounted
    /// publishes. Leading with the count avoids false-empty observations in
    /// scheduler hint paths; the queue may temporarily report work before an
    /// item is fully visible, but it must never publish an item before its
    /// counter credit exists.
    pub(crate) fn add_count(&self, count: usize) {
        if count > 0 {
            self.count.fetch_add(count, Ordering::Relaxed);
        }
    }

    #[inline]
    pub(crate) fn reserve_count(&self, count: usize) -> CountReservation<'_, T> {
        self.add_count(count);
        CountReservation {
            queue: self,
            remaining: count,
        }
    }

    #[inline]
    pub(crate) fn rollback_count(&self, count: usize) {
        Self::saturating_sub(&self.count, count);
    }

    #[inline]
    pub(crate) fn decrement_count(&self) {
        Self::saturating_decrement(&self.count);
    }

    #[inline]
    pub(crate) fn pop(&self) -> Option<T> {
        if !Self::try_reserve_published(&self.published) {
            return None;
        }

        let result = self.inner.dequeue();
        match result {
            Some(item) => {
                self.decrement_count();
                Some(item)
            }
            None => {
                self.published.fetch_add(1, Ordering::Release);
                None
            }
        }
    }

    #[inline]
    pub(crate) fn pop_batch_into(&self, max: usize, out: &mut Vec<T>) -> usize {
        if max == 0 {
            return 0;
        }

        let mut reserved = 0usize;
        for _ in 0..max {
            if Self::try_reserve_published(&self.published) {
                reserved += 1;
            } else {
                break;
            }
        }

        if reserved == 0 {
            return 0;
        }

        let start_len = out.len();
        for _ in 0..reserved {
            match self.inner.dequeue() {
                Some(item) => out.push(item),
                None => break,
            }
        }

        let drained = out.len().saturating_sub(start_len);
        if reserved > drained {
            self.published
                .fetch_add(reserved.saturating_sub(drained), Ordering::Release);
        }
        if drained > 0 {
            Self::saturating_sub(&self.count, drained);
        }
        drained
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub(crate) struct CountReservation<'a, T: Send> {
    queue: &'a GlobalFifoQueue<T>,
    remaining: usize,
}

impl<T: Send> CountReservation<'_, T> {
    #[inline]
    pub(crate) fn publish_one(&mut self) {
        self.remaining = self.remaining.saturating_sub(1);
    }
}

impl<T: Send> Drop for CountReservation<'_, T> {
    fn drop(&mut self) {
        self.queue.rollback_count(self.remaining);
    }
}

/// A global task queue.
#[derive(Debug, Default)]
pub struct GlobalQueue {
    inner: GlobalFifoQueue<TaskId>,
}

impl GlobalQueue {
    /// Creates a new global queue.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

#[doc(hidden)]
#[cfg(any(test, feature = "test-internals"))]
pub struct TestBatchReservation<'a> {
    queue: &'a GlobalQueue,
    reservation: CountReservation<'a, TaskId>,
}

#[cfg(any(test, feature = "test-internals"))]
impl TestBatchReservation<'_> {
    #[inline]
    pub fn publish_one(&mut self, task: TaskId) {
        self.queue.inner.push_uncounted(task);
        self.reservation.publish_one();
    }
}

#[cfg(any(test, feature = "test-internals"))]
impl GlobalQueue {
    #[doc(hidden)]
    #[must_use]
    pub fn reserve_batch_for_test(&self, count: usize) -> TestBatchReservation<'_> {
        TestBatchReservation {
            queue: self,
            reservation: self.inner.reserve_count(count),
        }
    }
}

#[cfg(test)]
#[path = "global_queue_inline_tests.rs"]
mod tests;
