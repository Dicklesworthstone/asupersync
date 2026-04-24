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
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[inline]
    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
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

            let expected_stolen: Vec<_> = (0..steal_prefix).map(|i| task(i as u32)).collect();
            let expected_remaining: Vec<_> =
                (steal_prefix..total).map(|i| task(i as u32)).collect();

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
        fn metamorphic_alternating_stealers_partition_queue_without_duplication(
            total in 1usize..64,
            first_stealer_is_a in any::<bool>(),
        ) {
            let queue = GlobalQueue::new();
            let expected: Vec<_> = (0..total).map(|i| task(i as u32)).collect();

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

            let expected_stolen: Vec<_> = (0..taken_before_cancel).map(|i| task(i as u32)).collect();
            let expected_suffix: Vec<_> =
                (taken_before_cancel..total).map(|i| task(i as u32)).collect();
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

            let expected_prefix: Vec<_> = (0..cancel_after).map(|i| task(i as u32)).collect();
            let expected_suffix: Vec<_> = (cancel_after..total).map(|i| task(i as u32)).collect();

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
            let ready_base = 0u32;
            let migrated_base = 10_000u32;

            for i in 0..ready_len {
                queue.push(task(ready_base + i as u32));
            }

            // Simulate a worker spilling its local queue into the shared global queue.
            for i in 0..migrated_len {
                queue.push(task(migrated_base + i as u32));
            }

            let drained = drain_all(&queue);
            let expected: Vec<_> = (0..ready_len)
                .map(|i| task(ready_base + i as u32))
                .chain((0..migrated_len).map(|i| task(migrated_base + i as u32)))
                .collect();

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
            let expected: Vec<_> = (1..total)
                .map(|i| task(i as u32))
                .chain(std::iter::once(task(0)))
                .collect();

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
