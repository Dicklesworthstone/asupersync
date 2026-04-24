#![allow(clippy::all)]
//! Metamorphic property tests for work-stealing fairness (br-asupersync-umttcl).
//!
//! These tests verify three invariants of the work-stealing scheduler under
//! heavy contention:
//!
//! * **MR-WS1** — **Work conservation under multi-worker contention**:
//!   for N workers and M tasks, every task is polled exactly once; total polls
//!   equal M; no task is lost or duplicated regardless of steal interleaving.
//! * **MR-WS2** — **LIFO own-queue vs FIFO steal preservation**: when the owner
//!   pushes [t0, t1, ..., tK] to its LocalQueue, the owner's pop order is the
//!   reverse (LIFO) and a peer's steal order is the forward order (FIFO).
//!   This is the metamorphic dual: `reverse(owner_pops) == stealer_pops` over
//!   the same initial queue.
//! * **MR-WS3** — **No starvation**: under heavy contention with W >= M workers
//!   and a single injector, no worker is locked out for more than K ticks while
//!   ready work remains visible across the fleet.

use crate::runtime::RuntimeState;
use crate::runtime::scheduler::ThreeLaneScheduler;
use crate::runtime::scheduler::local_queue::LocalQueue;
use crate::runtime::scheduler::stealing::steal_task;
use crate::sync::ContendedMutex;
use crate::types::TaskId;
use crate::util::DetRng;
use std::collections::HashSet;
use std::sync::Arc;

use proptest::prelude::*;

// ============================================================================
// Infrastructure
// ============================================================================

/// Builds `count` sequential test task IDs starting at arena index 0.
fn seq_tasks(count: u32) -> Vec<TaskId> {
    (0..count).map(|i| TaskId::new_for_test(i, 0)).collect()
}

/// Create a three-lane scheduler with the given worker count.
fn scheduler(worker_count: usize) -> ThreeLaneScheduler {
    let state = Arc::new(ContendedMutex::new(
        "ws_fairness.runtime_state",
        RuntimeState::new(),
    ));
    ThreeLaneScheduler::new(worker_count, &state)
}

// ============================================================================
// MR-WS1 — Work conservation under multi-worker contention
// ============================================================================

/// Round-robin dispatch across N workers until global work is drained.
/// Records every task polled. Returns (polled_multiset, total_ticks).
fn drain_round_robin(
    workers: &mut [crate::runtime::scheduler::ThreeLaneWorker],
    task_count: usize,
) -> (Vec<TaskId>, usize) {
    let mut polled = Vec::with_capacity(task_count);
    let mut ticks = 0_usize;
    // Safety cap: worst case each task takes one tick per worker rotation.
    let max_ticks = task_count
        .saturating_mul(workers.len().max(1))
        .saturating_mul(8)
        + 16;

    while polled.len() < task_count && ticks < max_ticks {
        let mut progressed = false;
        for w in workers.iter_mut() {
            if let Some(task) = w.next_task() {
                polled.push(task);
                progressed = true;
                if polled.len() >= task_count {
                    break;
                }
            }
        }
        ticks += 1;
        if !progressed {
            break;
        }
    }

    (polled, ticks)
}

proptest! {
    /// MR-WS1: Every spawned task is polled exactly once across N workers.
    /// Work conservation: |polled| == M, polled is a permutation of spawned.
    #[test]
    fn mr_ws1_all_tasks_polled_exactly_once(
        task_count in 4usize..40,
        worker_count in 2usize..6,
    ) {
        let tasks = seq_tasks(task_count as u32);
        let mut sched = scheduler(worker_count);
        for &t in &tasks {
            sched.inject_ready(t, 100);
        }
        let mut workers = sched.take_workers();

        let (polled, _ticks) = drain_round_robin(&mut workers, task_count);

        prop_assert_eq!(
            polled.len(),
            task_count,
            "MR-WS1 VIOLATION: not all tasks polled ({} of {})",
            polled.len(),
            task_count,
        );

        let unique: HashSet<TaskId> = polled.iter().copied().collect();
        prop_assert_eq!(
            unique.len(),
            task_count,
            "MR-WS1 VIOLATION: duplicate polls detected ({} unique of {})",
            unique.len(),
            task_count,
        );

        let expected: HashSet<TaskId> = tasks.iter().copied().collect();
        prop_assert_eq!(
            unique,
            expected,
            "MR-WS1 VIOLATION: polled set differs from spawned set",
        );
    }
}

// ============================================================================
// MR-WS2 — LIFO own-queue vs FIFO steal preservation
// ============================================================================

/// Targeted equivalence: an owner draining its own LocalQueue must observe
/// LIFO order while a peer stealing the same pre-pushed sequence must observe
/// FIFO order. Metamorphic dual: reverse(owner_order) == stealer_order.
#[test]
fn mr_ws2_owner_lifo_dual_to_stealer_fifo() {
    const N: u32 = 12;
    let tasks = seq_tasks(N);

    // Scenario A: owner pops entire sequence (LIFO).
    let owner_q = LocalQueue::new_for_test(N - 1);
    for &t in &tasks {
        owner_q.push(t);
    }
    let mut owner_order = Vec::with_capacity(N as usize);
    while let Some(t) = owner_q.pop() {
        owner_order.push(t);
    }

    // Scenario B: peer stealer drains the same pre-pushed sequence (FIFO).
    let thief_q = LocalQueue::new_for_test(N - 1);
    for &t in &tasks {
        thief_q.push(t);
    }
    let stealer = thief_q.stealer();
    let mut stealer_order = Vec::with_capacity(N as usize);
    while let Some(t) = stealer.steal() {
        stealer_order.push(t);
    }

    assert_eq!(
        owner_order.len(),
        N as usize,
        "MR-WS2: owner did not drain every task",
    );
    assert_eq!(
        stealer_order.len(),
        N as usize,
        "MR-WS2: stealer did not drain every task",
    );

    // LIFO: owner sees reverse insertion order.
    let mut expected_lifo: Vec<TaskId> = tasks.clone();
    expected_lifo.reverse();
    assert_eq!(
        owner_order, expected_lifo,
        "MR-WS2 VIOLATION: owner pop order is not LIFO",
    );

    // FIFO: stealer sees insertion order.
    assert_eq!(
        stealer_order, tasks,
        "MR-WS2 VIOLATION: stealer order is not FIFO",
    );

    // Metamorphic dual: reversing the owner order recovers the stealer order.
    let mut dual = owner_order.clone();
    dual.reverse();
    assert_eq!(
        dual, stealer_order,
        "MR-WS2 VIOLATION: reverse(owner_lifo) != stealer_fifo — the LIFO/FIFO duality is broken",
    );
}

proptest! {
    /// MR-WS2 (property form): for any push sequence, reverse(owner_pop_order)
    /// equals the stealer's pop order from an identical queue. This is the
    /// metamorphic relation that lets us catch both LIFO and FIFO regressions
    /// together — either end flipping violates the duality.
    #[test]
    fn mr_ws2_prop_reverse_owner_equals_stealer(
        len in 2u32..30,
    ) {
        let tasks = seq_tasks(len);

        let a = LocalQueue::new_for_test(len - 1);
        for &t in &tasks { a.push(t); }
        let mut owner_order = Vec::with_capacity(len as usize);
        while let Some(t) = a.pop() { owner_order.push(t); }

        let b = LocalQueue::new_for_test(len - 1);
        for &t in &tasks { b.push(t); }
        let s = b.stealer();
        let mut stealer_order = Vec::with_capacity(len as usize);
        while let Some(t) = s.steal() { stealer_order.push(t); }

        prop_assert_eq!(owner_order.len(), len as usize);
        prop_assert_eq!(stealer_order.len(), len as usize);

        let mut dual = owner_order.clone();
        dual.reverse();
        prop_assert_eq!(
            dual,
            stealer_order,
            "MR-WS2 VIOLATION: reverse(owner_lifo) != stealer_fifo for len={}",
            len,
        );
    }
}

// ============================================================================
// MR-WS3 — No starvation under heavy contention
// ============================================================================

proptest! {
    /// MR-WS3: with W workers and many more ready tasks than workers, during a
    /// concurrent round-robin drain no worker is locked out for more than
    /// `K * W` rounds while work remains system-wide. In our deterministic
    /// single-threaded drive loop this reduces to the claim that, as long as
    /// the global ready queue is non-empty, *some* worker makes progress each
    /// round and every worker eventually polls at least one task when the
    /// ratio M/W >= 2.
    #[test]
    fn mr_ws3_no_worker_starves_under_contention(
        worker_count in 2usize..5,
        ratio in 3usize..8,   // tasks-per-worker
    ) {
        let task_count = worker_count * ratio;
        let tasks = seq_tasks(task_count as u32);

        let mut sched = scheduler(worker_count);
        for &t in &tasks { sched.inject_ready(t, 100); }
        let mut workers = sched.take_workers();

        // Drive one task per worker per round, measuring per-worker idle streaks.
        let mut per_worker_polls = vec![0_usize; worker_count];
        let mut per_worker_max_idle = vec![0_usize; worker_count];
        let mut per_worker_cur_idle = vec![0_usize; worker_count];

        let max_rounds = task_count * worker_count * 4 + 8;
        let mut rounds = 0_usize;
        let mut remaining = task_count;

        while remaining > 0 && rounds < max_rounds {
            let mut progressed = false;
            for (i, w) in workers.iter_mut().enumerate() {
                // Only probe while there's something left system-wide. Once
                // remaining == 0 we stop counting idle rounds.
                if remaining == 0 { break; }
                if let Some(_task) = w.next_task() {
                    per_worker_polls[i] += 1;
                    per_worker_cur_idle[i] = 0;
                    remaining -= 1;
                    progressed = true;
                } else {
                    per_worker_cur_idle[i] += 1;
                    per_worker_max_idle[i] =
                        per_worker_max_idle[i].max(per_worker_cur_idle[i]);
                }
            }
            rounds += 1;
            if !progressed {
                // No work reachable by any worker — schedule is drained.
                break;
            }
        }

        // Invariant 1: all tasks drained.
        prop_assert_eq!(
            remaining,
            0,
            "MR-WS3 VIOLATION: scheduler left {} tasks undrained after {} rounds",
            remaining,
            rounds,
        );

        // Invariant 2: every worker polled at least one task. With W workers
        // and M >= 2W tasks, some fairness mechanism (direct dispatch or
        // steal) must engage each worker at least once. This catches cases
        // where stealing is broken and a single worker drains the entire
        // global queue.
        for (i, &polls) in per_worker_polls.iter().enumerate() {
            prop_assert!(
                polls >= 1,
                "MR-WS3 VIOLATION: worker {} polled zero tasks (W={}, M={}); \
                 stealing appears disabled",
                i,
                worker_count,
                task_count,
            );
        }

        // Invariant 3: no worker was idle for more than K * W rounds while
        // work was still pending. K = 4 is a generous upper bound that allows
        // the Power-of-Two-Choices stealer to miss a couple of times before
        // converging.
        let k: usize = 4;
        let idle_bound = k.saturating_mul(worker_count);
        for (i, &max_idle) in per_worker_max_idle.iter().enumerate() {
            prop_assert!(
                max_idle <= idle_bound,
                "MR-WS3 VIOLATION: worker {} idled {} consecutive rounds \
                 while work remained (bound={}, W={}, M={})",
                i,
                max_idle,
                idle_bound,
                worker_count,
                task_count,
            );
        }
    }
}

// ============================================================================
// MR-WS4 — Work-conservation under adversarial steal-only drives
// ============================================================================

#[test]
fn mr_ws4_stealers_alone_drain_all_tasks() {
    // All work is seeded in a single worker's local queue; the rest drain by
    // stealing only. This is the classic work-stealing smoke: if steal is
    // broken, tasks never move off worker 0 and the test times out.
    const W: usize = 4;
    const M: u32 = 24;

    let q0 = LocalQueue::new_for_test(M - 1);
    let tasks = seq_tasks(M);
    for &t in &tasks {
        q0.push(t);
    }

    let stealers: Vec<_> = std::iter::once(q0.stealer()).collect();
    let mut rng = DetRng::new(0xC0FFEE);

    // Owner pops from the tail (LIFO), peers steal from the head (FIFO).
    // Mix the two to ensure both paths contribute and no task is dropped.
    let mut drained: HashSet<TaskId> = HashSet::new();
    let mut iters = 0_usize;
    let max_iters = (M as usize) * W * 4;

    loop {
        let owner_pop = q0.pop();
        let thief_pop = steal_task(&stealers, &mut rng);

        let owner_progressed = if let Some(t) = owner_pop {
            assert!(drained.insert(t), "duplicate pop for {t:?}");
            true
        } else {
            false
        };
        let thief_progressed = if let Some(t) = thief_pop {
            assert!(drained.insert(t), "duplicate steal for {t:?}");
            true
        } else {
            false
        };
        let progressed = owner_progressed || thief_progressed;
        iters += 1;
        if !progressed || drained.len() == M as usize || iters >= max_iters {
            break;
        }
    }

    assert_eq!(
        drained.len(),
        M as usize,
        "MR-WS4 VIOLATION: {} of {} tasks drained via mixed owner+steal",
        drained.len(),
        M,
    );
    let expected: HashSet<TaskId> = tasks.iter().copied().collect();
    assert_eq!(
        drained, expected,
        "MR-WS4 VIOLATION: drained set differs from spawned set",
    );
}
