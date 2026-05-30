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
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            count.checked_sub(1)
        });
    }

    #[inline]
    fn saturating_sub(counter: &AtomicUsize, count: usize) {
        if count == 0 {
            return;
        }
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(count))
        });
    }

    #[inline]
    fn try_reserve_published(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[inline]
    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn task_range(range: std::ops::Range<usize>) -> impl Iterator<Item = TaskId> {
        range.map(|i| task(i as u32))
    }

    fn drain_all(queue: &GlobalQueue) -> Vec<TaskId> {
        std::iter::from_fn(|| queue.pop()).collect()
    }

    fn run_cancelled_steal_schedule(
        total: usize,
        cancel_after: usize,
        chunk_plan: &[usize],
    ) -> (Vec<TaskId>, Vec<TaskId>) {
        let queue = GlobalQueue::new();
        for i in 0..total {
            queue.push(task(i as u32));
        }

        let mut stolen = Vec::new();
        let cancel_after = cancel_after.min(total);
        if cancel_after > 0 {
            let normalized_plan = if chunk_plan.is_empty() {
                vec![cancel_after]
            } else {
                chunk_plan
                    .iter()
                    .map(|chunk| (*chunk).max(1))
                    .collect::<Vec<_>>()
            };

            let mut chunk_index = 0usize;
            while stolen.len() < cancel_after {
                let remaining = cancel_after - stolen.len();
                let chunk = normalized_plan[chunk_index % normalized_plan.len()].min(remaining);
                for _ in 0..chunk {
                    stolen.push(
                        queue
                            .pop()
                            .expect("scheduled cancel cut should not exceed queued task count"),
                    );
                }
                chunk_index += 1;
            }
        }

        let resumed = drain_all(&queue);
        (stolen, resumed)
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
    fn test_global_queue_mpsc_preserves_per_producer_order() {
        let queue = Arc::new(GlobalQueue::new());
        let producers = 4usize;
        let items_per_producer = 256usize;
        let barrier = Arc::new(Barrier::new(producers));

        let handles: Vec<_> = (0..producers)
            .map(|producer| {
                let q = Arc::clone(&queue);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait();
                    for offset in 0..items_per_producer {
                        q.push(task((producer * 10_000 + offset) as u32));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("producer should complete");
        }

        let drained = drain_all(&queue);
        assert_eq!(drained.len(), producers * items_per_producer);

        let mut next_expected = vec![0usize; producers];
        for task_id in drained {
            let raw = task_id.as_u64() as usize;
            let producer = raw / 10_000;
            let offset = raw % 10_000;
            assert!(
                producer < producers,
                "task should decode to a known producer: {producer}"
            );
            assert_eq!(
                offset, next_expected[producer],
                "each producer's FIFO subsequence must stay ordered"
            );
            next_expected[producer] += 1;
        }

        assert!(
            next_expected
                .iter()
                .all(|count| *count == items_per_producer),
            "every producer subsequence should drain completely"
        );
    }

    #[test]
    fn test_global_queue_fifo_across_phased_producer_batches() {
        let queue = Arc::new(GlobalQueue::new());
        let producers = 4usize;
        let batch_len = 32usize;
        let start = Arc::new(Barrier::new(producers));
        let phase = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..producers)
            .map(|producer| {
                let q = Arc::clone(&queue);
                let barrier = Arc::clone(&start);
                let phase = Arc::clone(&phase);
                thread::spawn(move || {
                    barrier.wait();
                    while phase.load(Ordering::Acquire) != producer {
                        std::hint::spin_loop();
                    }
                    let base = producer * 1_000;
                    for offset in 0..batch_len {
                        q.push(task((base + offset) as u32));
                    }
                    phase.store(producer + 1, Ordering::Release);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("producer should complete");
        }

        let drained = drain_all(&queue);
        let expected = (0..producers)
            .flat_map(|producer| {
                let base = producer * 1_000;
                (0..batch_len).map(move |offset| task((base + offset) as u32))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            drained, expected,
            "producer batches released in a known order must preserve cross-producer FIFO order"
        );
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

    #[test]
    fn test_global_queue_drop_after_worker_threads_does_not_depend_on_os_tls_registry() {
        const WORKERS: usize = 11;
        const OPS_PER_WORKER: usize = 128;
        const ROUNDS: usize = 8;

        for round in 0..ROUNDS {
            let queue = Arc::new(GlobalQueue::new());
            let popped = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(WORKERS));

            let handles: Vec<_> = (0..WORKERS)
                .map(|worker| {
                    let queue = Arc::clone(&queue);
                    let popped = Arc::clone(&popped);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        let base = (round * 100_000 + worker * 1_000) as u32;
                        for offset in 0..OPS_PER_WORKER {
                            queue.push(task(base + offset as u32));
                            if offset % 3 == 0 && queue.pop().is_some() {
                                popped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("global queue worker should not panic");
            }

            while queue.pop().is_some() {
                popped.fetch_add(1, Ordering::Relaxed);
            }

            assert_eq!(
                popped.load(Ordering::Relaxed),
                WORKERS * OPS_PER_WORKER,
                "round {round}: every injected task should be drained before queue drop"
            );
            assert_eq!(
                queue.len(),
                0,
                "round {round}: queue count should converge before queue drop"
            );
        }
    }

    #[test]
    fn test_precounted_publish_window_does_not_fabricate_work_and_converges() {
        let queue = GlobalQueue::new();

        // Scheduler hint paths may make the advisory count visible before the
        // corresponding uncounted publication is visible cross-thread.
        queue.inner.add_count(1);
        assert_eq!(
            queue.len(),
            1,
            "pre-counted publish advertises pending work"
        );
        assert!(
            !queue.is_empty(),
            "pre-counted publish must not report an empty queue"
        );

        // The advisory count must not fabricate a task before publish.
        assert_eq!(
            queue.pop(),
            None,
            "count visibility alone must not conjure a dequeuable task"
        );
        assert_eq!(
            queue.len(),
            1,
            "observing the lead-count window must not consume the reserved count credit"
        );

        queue.inner.push_uncounted(task(77));
        assert_eq!(
            queue.pop(),
            Some(task(77)),
            "once the uncounted publish becomes visible, the reserved credit must pair with the real task"
        );
        assert_eq!(
            queue.len(),
            0,
            "after the published task is consumed, the advisory count must converge back to zero"
        );
        assert!(
            queue.is_empty(),
            "queue should report empty after convergence"
        );
    }

    #[test]
    fn precounted_publish_reservation_rolls_back_abandoned_credit() {
        let queue = GlobalQueue::new();
        {
            let _reservation = queue.inner.reserve_count(2);
            assert_eq!(
                queue.len(),
                2,
                "reserved publication advertises pending work while in flight"
            );
        }

        assert_eq!(
            queue.len(),
            0,
            "dropping an unused reservation must roll back phantom ready-count credit"
        );
        assert!(queue.is_empty(), "queue should report empty after rollback");
    }

    #[test]
    fn precounted_publish_reservation_rolls_back_unpublished_suffix_only() {
        let queue = GlobalQueue::new();
        {
            let mut reservation = queue.inner.reserve_count(3);
            queue.inner.push_uncounted(task(21));
            reservation.publish_one();
        }

        assert_eq!(
            queue.len(),
            1,
            "rollback must preserve credit for already published tasks"
        );
        assert_eq!(queue.pop(), Some(task(21)));
        assert!(
            queue.is_empty(),
            "queue should converge after draining the published prefix"
        );
    }

    proptest! {
        #[test]
        fn metamorphic_drained_prefix_does_not_perturb_later_injection_order(
            noise_len in 0usize..32,
            payload_len in 1usize..32,
        ) {
            let queue = GlobalQueue::new();

            for i in 0..noise_len {
                queue.push(task(i as u32));
            }
            for i in 0..noise_len {
                prop_assert_eq!(
                    queue.pop(),
                    Some(task(i as u32)),
                    "unrelated prefix should drain in FIFO order before target injection",
                );
            }

            let payload_base = 10_000u32;
            for i in 0..payload_len {
                queue.push(task(payload_base + i as u32));
            }

            let drained: Vec<_> = std::iter::from_fn(|| queue.pop()).collect();
            let expected: Vec<_> = (0..payload_len)
                .map(|i| task(payload_base + i as u32))
                .collect();

            prop_assert_eq!(
                drained,
                expected,
                "draining an unrelated injected prefix must not perturb the FIFO order of later injections",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after draining all later injections");
        }

        #[test]
        fn metamorphic_steal_prefix_partitions_fifo_stream_without_reordering(
            steal_prefix in 0usize..32,
            suffix_len in 1usize..32,
        ) {
            let queue = GlobalQueue::new();
            let total = steal_prefix + suffix_len;

            for i in 0..total {
                queue.push(task(i as u32));
            }

            let stolen: Vec<_> = (0..steal_prefix)
                .map(|_| queue.pop().expect("steal prefix should be available"))
                .collect();
            let remaining = drain_all(&queue);

            let expected_stolen = task_range(0..steal_prefix).collect::<Vec<_>>();
            let expected_remaining = task_range(steal_prefix..total).collect::<Vec<_>>();

            prop_assert_eq!(
                stolen,
                expected_stolen,
                "a thief draining the prefix must observe the oldest global tasks first",
            );
            prop_assert_eq!(
                remaining,
                expected_remaining,
                "stealing a prefix must leave the remaining suffix in FIFO order",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after draining both partitions");
        }

        #[test]
        fn metamorphic_steal_then_inject_equivalence_preserves_fifo_stream(
            total in 1usize..64,
            split in 0usize..64,
            stolen_prefix in 0usize..64,
        ) {
            let split = split.clamp(1, total);
            let stolen_prefix = stolen_prefix.min(split);

            let baseline = GlobalQueue::new();
            for task_id in task_range(0..total) {
                baseline.push(task_id);
            }
            let baseline_drained = drain_all(&baseline);

            let variant = GlobalQueue::new();
            for task_id in task_range(0..split) {
                variant.push(task_id);
            }

            let mut observed = Vec::new();
            for _ in 0..stolen_prefix {
                observed.push(
                    variant
                        .pop()
                        .expect("stolen prefix should not exceed injected prefix"),
                );
            }

            for task_id in task_range(split..total) {
                variant.push(task_id);
            }
            observed.extend(drain_all(&variant));

            let expected = task_range(0..total).collect::<Vec<_>>();
            let expected_stolen = task_range(0..stolen_prefix).collect::<Vec<_>>();

            prop_assert_eq!(
                baseline_drained,
                expected.clone(),
                "all-injected baseline should drain in FIFO order",
            );
            prop_assert_eq!(
                &observed[..stolen_prefix],
                expected_stolen.as_slice(),
                "stealing before later injections must still observe the FIFO head",
            );
            prop_assert_eq!(
                observed,
                expected,
                "steal-then-inject must preserve the same FIFO stream as injecting everything up front",
            );
            prop_assert!(
                variant.is_empty(),
                "variant queue should be empty after draining the recomposed stream"
            );
        }

        #[test]
        fn metamorphic_alternating_stealers_partition_queue_without_duplication(
            total in 1usize..64,
            first_stealer_is_a in any::<bool>(),
        ) {
            let queue = GlobalQueue::new();
            let expected = task_range(0..total).collect::<Vec<_>>();

            for task_id in &expected {
                queue.push(*task_id);
            }

            let mut stealer_a = Vec::new();
            let mut stealer_b = Vec::new();
            let mut observed = Vec::new();
            let mut a_turn = first_stealer_is_a;

            while let Some(next) = queue.pop() {
                observed.push(next);
                if a_turn {
                    stealer_a.push(next);
                } else {
                    stealer_b.push(next);
                }
                a_turn = !a_turn;
            }

            let mut seen = HashSet::new();
            for task_id in stealer_a.iter().chain(&stealer_b) {
                prop_assert!(
                    seen.insert(*task_id),
                    "a task must never be duplicated across competing stealers",
                );
            }

            prop_assert_eq!(
                observed,
                expected,
                "alternating stealers must still observe the queue in FIFO order",
            );
            prop_assert_eq!(
                seen.len(),
                total,
                "the union of both stealers must cover every task exactly once",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after alternating steals");
        }

        #[test]
        fn metamorphic_cancelled_steal_leaves_remaining_suffix_intact(
            taken_before_cancel in 0usize..32,
            trailing_len in 1usize..32,
        ) {
            let queue = GlobalQueue::new();
            let total = taken_before_cancel + trailing_len;

            for i in 0..total {
                queue.push(task(i as u32));
            }

            let stolen_before_cancel: Vec<_> = (0..taken_before_cancel)
                .map(|_| queue.pop().expect("cancelled stealer should only remove available prefix"))
                .collect();

            // Simulate the stealing worker being cancelled mid-loop; another worker
            // later resumes draining the shared global queue.
            let resumed_drain = drain_all(&queue);

            let expected_stolen = task_range(0..taken_before_cancel).collect::<Vec<_>>();
            let expected_suffix = task_range(taken_before_cancel..total).collect::<Vec<_>>();
            let total_observed = stolen_before_cancel.len() + resumed_drain.len();

            prop_assert_eq!(
                stolen_before_cancel,
                expected_stolen,
                "cancellation mid-steal must not reorder the already stolen prefix",
            );
            prop_assert_eq!(
                resumed_drain,
                expected_suffix,
                "after a stealer stops early, the remaining global suffix must stay FIFO",
            );
            prop_assert_eq!(
                total_observed,
                total,
                "cancelled steal must not drop or duplicate tasks across the handoff",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after the resumed drain");
        }

        #[test]
        fn metamorphic_cancel_cut_preserves_fifo_suffix_across_steal_chunking(
            total in 1usize..64,
            cancel_after in 0usize..64,
        ) {
            let cancel_after = cancel_after.min(total);

            let (bulk_prefix, bulk_suffix) =
                run_cancelled_steal_schedule(total, cancel_after, &[cancel_after.max(1)]);
            let (step_prefix, step_suffix) =
                run_cancelled_steal_schedule(total, cancel_after, &[1]);

            let expected_prefix = task_range(0..cancel_after).collect::<Vec<_>>();
            let expected_suffix = task_range(cancel_after..total).collect::<Vec<_>>();

            prop_assert_eq!(
                bulk_prefix,
                expected_prefix.clone(),
                "bulk stealing up to the cancellation cut must preserve the FIFO prefix",
            );
            prop_assert_eq!(
                step_prefix,
                expected_prefix,
                "per-pop cancellation checkpoints must preserve the same FIFO prefix",
            );
            prop_assert_eq!(
                bulk_suffix,
                expected_suffix.clone(),
                "bulk stealing to the cut must leave the remaining suffix in FIFO order",
            );
            prop_assert_eq!(
                step_suffix,
                expected_suffix,
                "chunking the steal loop with extra cancellation checks must not perturb the FIFO suffix",
            );
        }

        #[test]
        fn metamorphic_local_to_global_migration_appends_at_fifo_tail(
            ready_len in 1usize..32,
            migrated_len in 1usize..32,
        ) {
            let queue = GlobalQueue::new();
            let migrated_base = 10_000u32;

            for task_id in task_range(0..ready_len) {
                queue.push(task_id);
            }

            // Simulate a worker spilling its local queue into the shared global queue.
            for i in 0..migrated_len {
                queue.push(task(migrated_base + i as u32));
            }

            let drained = drain_all(&queue);
            let mut expected = task_range(0..ready_len).collect::<Vec<_>>();
            expected.extend((0..migrated_len).map(|i| task(migrated_base + i as u32)));

            prop_assert_eq!(
                drained,
                expected,
                "local-to-global migration must append migrated work after already queued global tasks without reordering either segment",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after draining migrated and ready work");
        }

        #[test]
        fn metamorphic_yield_now_reschedules_running_head_to_fifo_tail(
            trailing_len in 1usize..32,
        ) {
            let queue = GlobalQueue::new();
            let total = trailing_len + 1;

            for i in 0..total {
                queue.push(task(i as u32));
            }

            let yielded = queue.pop().expect("head task should be runnable");

            // Simulate the running task calling yield_now and being re-enqueued globally.
            queue.push(yielded);

            let drained = drain_all(&queue);
            let mut expected = task_range(1..total).collect::<Vec<_>>();
            expected.push(task(0));

            prop_assert_eq!(
                yielded,
                task(0),
                "yield_now should first remove the oldest runnable task from the head of the queue",
            );
            prop_assert_eq!(
                drained,
                expected,
                "yield_now must reschedule the running task at the back of the FIFO stream",
            );
            prop_assert!(queue.is_empty(), "queue should be empty after draining the yielded FIFO stream");
        }
    }
}
