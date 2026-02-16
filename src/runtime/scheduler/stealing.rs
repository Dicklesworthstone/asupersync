//! Work stealing logic.

use crate::runtime::scheduler::local_queue::Stealer;
use crate::types::TaskId;
use crate::util::DetRng;

/// Tries to steal a task from a list of stealers.
///
/// Starts at a random index and iterates through all stealers.
pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {
    if stealers.is_empty() {
        return None;
    }

    let len = stealers.len();
    let start = rng.next_usize(len);

    for i in 0..len {
        let idx = circular_index(start, i, len);
        if let Some(task) = stealers[idx].steal() {
            return Some(task);
        }
    }

    None
}

fn circular_index(start: usize, offset: usize, len: usize) -> usize {
    debug_assert!(len > 0);
    start.wrapping_add(offset) % len
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
    fn test_circular_index_wraps_without_overflow() {
        let len = usize::MAX;
        let start = usize::MAX - 1;
        let offset = 3;

        let idx = circular_index(start, offset, len);
        assert_eq!(idx, 1);
    }
}
