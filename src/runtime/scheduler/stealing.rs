//! Work stealing logic.

use crate::runtime::scheduler::local_queue::Stealer;
use crate::types::TaskId;
use crate::util::DetRng;

/// Tries to steal a task from a list of stealers.
///
/// Implements "The Power of Two Choices" randomized load balancing.
/// Instead of a sequential scan, this selects two candidates at random,
/// queries their lengths, and attempts to steal from the more loaded queue.
/// If that queue is empty or fails, it falls back to the other candidate.
/// This drastically reduces tail-latency on task distribution and minimizes
/// lock contention compared to linear probing or pure random choice.
#[inline]
pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {
    let len = stealers.len();
    if len == 0 {
        return None;
    }
    if len == 1 {
        return stealers[0].steal();
    }

    // Alien Artifact: Power of Two Choices (Mitzenmacher 2001)
    // Select two distinct random queues.
    let idx1 = rng.next_usize(len);
    let mut idx2 = rng.next_usize(len);
    if idx1 == idx2 {
        idx2 = (idx1 + 1) % len;
    }

    let len1 = stealers[idx1].len();
    let len2 = stealers[idx2].len();

    // Prefer the queue that appears to have more work.
    let (primary, secondary) = if len1 >= len2 {
        (idx1, idx2)
    } else {
        (idx2, idx1)
    };

    // Attempt steal from primary choice
    if let Some(task) = stealers[primary].steal() {
        return Some(task);
    }

    // Fallback to secondary if primary was empty/unstealable
    if let Some(task) = stealers[secondary].steal() {
        return Some(task);
    }

    // Fallback to linear scan if both failed but there might be hidden work
    // (e.g. they had tasks but they were local, so steal() returned None).
    let start = rng.next_usize(len);
    for i in 0..len {
        let idx = circular_index(start, i, len);
        if idx == primary || idx == secondary {
            continue; // Already tried
        }
        if let Some(task) = stealers[idx].steal() {
            return Some(task);
        }
    }

    None
}

#[inline]
fn circular_index(start: usize, offset: usize, len: usize) -> usize {
    debug_assert!(len > 0);
    // start is in [0, len) and offset is in [0, len).
    // Thus start + offset < 2 * len. Since len is the length of a Vec,
    // 2 * len cannot overflow usize. We do not need wrapping_add,
    // and using it would be mathematically incorrect if start was large
    // because (x + y) % len != (x % len + y % len) % len across overflow.
    (start + offset) % len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::scheduler::local_queue::LocalQueue;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    #[test]
    fn test_steal_from_busy_worker_succeeds() {
        let queue = LocalQueue::new_for_test(9);
        for i in 0..10 {
            queue.push(task(i));
        }

        let stealers = vec![queue.stealer()];
        let mut rng = DetRng::new(42);

        let stolen = steal_task(&stealers, &mut rng);
        assert!(stolen.is_some(), "should steal from busy queue");
    }

    #[test]
    fn test_steal_from_empty_returns_none() {
        let queue = LocalQueue::new_for_test(0);
        let stealers = vec![queue.stealer()];
        let mut rng = DetRng::new(42);

        let stolen = steal_task(&stealers, &mut rng);
        assert!(stolen.is_none(), "empty queue should return None");
    }

    #[test]
    fn test_steal_empty_stealers_list() {
        let stealers: Vec<Stealer> = vec![];
        let mut rng = DetRng::new(42);

        let stolen = steal_task(&stealers, &mut rng);
        assert!(stolen.is_none(), "empty stealers list should return None");
    }

    #[test]
    fn test_steal_skips_empty_queues() {
        // 3 queues: first two empty, third has work
        let q1 = LocalQueue::new_for_test(0);
        let q2 = LocalQueue::new_for_test(0);
        let q3 = LocalQueue::new_for_test(99);
        q3.push(task(99));

        let stealers = vec![q1.stealer(), q2.stealer(), q3.stealer()];

        // Different RNG seeds to ensure we eventually find the non-empty queue
        let mut found = false;
        for seed in 0..10 {
            let mut rng = DetRng::new(seed);
            let stolen = steal_task(&stealers, &mut rng);
            if let Some(t) = stolen {
                assert_eq!(t, task(99));
                found = true;
                break;
            }
        }

        assert!(
            found,
            "should have found task in q3 with at least one deterministic seed in [0, 10)"
        );
    }

    #[test]
    fn test_steal_visits_all_queues() {
        // Each queue has a unique task
        let queues: Vec<_> = (0..5).map(|_| LocalQueue::new_for_test(4)).collect();
        for (i, q) in queues.iter().enumerate() {
            q.push(task(i as u32));
        }

        let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();
        let mut seen = HashSet::new();

        // With 5 queues and sequential RNG, should eventually hit all
        let mut rng = DetRng::new(0);
        for _ in 0..10 {
            if let Some(t) = steal_task(&stealers, &mut rng) {
                seen.insert(t);
            }
        }

        // Should have stolen all 5 unique tasks
        assert_eq!(seen.len(), 5, "should visit all queues");
    }

    #[test]
    fn test_steal_contention_no_deadlock() {
        // Multiple stealers don't deadlock
        let queue = Arc::new(LocalQueue::new_for_test(99));
        for i in 0..100 {
            queue.push(task(i));
        }

        let stealer = queue.stealer();
        let stolen_count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(5));

        let handles: Vec<_> = (0_u64..5)
            .map(|i| {
                let s = stealer.clone();
                let count = stolen_count.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    let stealers = vec![s];
                    let mut rng = DetRng::new(i);
                    b.wait();

                    let mut local_count = 0;
                    while steal_task(&stealers, &mut rng).is_some() {
                        local_count += 1;
                        thread::yield_now();
                    }
                    count.fetch_add(local_count, Ordering::SeqCst);
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread should complete without deadlock");
        }

        assert_eq!(
            stolen_count.load(Ordering::SeqCst),
            100,
            "all tasks should be stolen exactly once"
        );
    }

    #[test]
    fn test_steal_deterministic_with_same_seed() {
        // Use two separate queue sets so the first steal doesn't mutate
        // the queues used by the second steal.
        let q1a = LocalQueue::new_for_test(3);
        let q2a = LocalQueue::new_for_test(3);
        let q3a = LocalQueue::new_for_test(3);
        q1a.push(task(1));
        q2a.push(task(2));
        q3a.push(task(3));
        let stealers_a = vec![q1a.stealer(), q2a.stealer(), q3a.stealer()];

        let q1b = LocalQueue::new_for_test(3);
        let q2b = LocalQueue::new_for_test(3);
        let q3b = LocalQueue::new_for_test(3);
        q1b.push(task(1));
        q2b.push(task(2));
        q3b.push(task(3));
        let stealers_b = vec![q1b.stealer(), q2b.stealer(), q3b.stealer()];

        let mut rng1 = DetRng::new(12345);
        let mut rng2 = DetRng::new(12345);

        let result1 = steal_task(&stealers_a, &mut rng1);
        let result2 = steal_task(&stealers_b, &mut rng2);

        assert_eq!(result1, result2, "same seed should give same steal target");
    }

    #[test]
    fn test_power_of_two_prefers_heavier_queue() {
        let heavy = LocalQueue::new_for_test(20);
        let light = LocalQueue::new_for_test(20);

        heavy.push(task(10));
        heavy.push(task(11));
        light.push(task(19));

        let stealers = vec![heavy.stealer(), light.stealer()];
        let mut rng = DetRng::new(7);

        let stolen = steal_task(&stealers, &mut rng);
        assert!(
            matches!(stolen, Some(t) if t == task(10) || t == task(11)),
            "power-of-two choice should prefer the heavier queue"
        );
    }

    #[test]
    fn test_power_of_two_falls_back_when_primary_is_local_only() {
        let state = LocalQueue::test_state(10);
        let local_only = LocalQueue::new(Arc::clone(&state));
        let remote = LocalQueue::new(Arc::clone(&state));

        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let first = guard.task_mut(task(0)).expect("task record missing");
            first.mark_local();
            let second = guard.task_mut(task(1)).expect("task record missing");
            second.mark_local();
            drop(guard);
        }

        // The local-only queue has more queued items, so two-choice will pick it first.
        local_only.push(task(0));
        local_only.push(task(1));
        remote.push(task(2));

        let stealers = vec![local_only.stealer(), remote.stealer()];
        let mut rng = DetRng::new(99);

        let stolen = steal_task(&stealers, &mut rng);
        assert_eq!(
            stolen,
            Some(task(2)),
            "steal should fall back to the secondary queue when primary has only local tasks"
        );
    }

    #[test]
    fn test_circular_index_math_correct() {
        let len = 5;
        let start = 3;
        let offset = 4;

        let idx = circular_index(start, offset, len);
        assert_eq!(idx, 2); // (3 + 4) % 5 = 7 % 5 = 2
    }
}
