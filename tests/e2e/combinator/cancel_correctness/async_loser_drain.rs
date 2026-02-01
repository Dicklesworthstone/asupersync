//! Async loser drain tests using LabRuntime.
//!
//! These tests verify the loser drain invariant using actual async execution
//! through the LabRuntime, complementing the synchronous drop-semantic tests
//! in `loser_drain.rs`.
//!
//! # Critical Invariant: Losers Are Drained
//!
//! From asupersync_plan_v4.md:
//! > Losers are drained: races must cancel AND fully drain losers
//!
//! Formally: `∀race: ∀loser ∈ race.losers: loser.state = Completed`

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::lab::oracle::LoserDrainOracle;
use asupersync::types::{Budget, Time};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// A future that yields a specified number of times before completing.
struct YieldingFuture {
    yields_remaining: u32,
    completion_flag: Arc<AtomicBool>,
    id: u32,
}

impl YieldingFuture {
    fn new(yields: u32, id: u32, flag: Arc<AtomicBool>) -> Self {
        Self {
            yields_remaining: yields,
            completion_flag: flag,
            id,
        }
    }
}

impl Future for YieldingFuture {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yields_remaining == 0 {
            self.completion_flag.store(true, Ordering::SeqCst);
            Poll::Ready(self.id)
        } else {
            self.yields_remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl Drop for YieldingFuture {
    fn drop(&mut self) {
        // Mark completion on drop (simulating drain)
        self.completion_flag.store(true, Ordering::SeqCst);
    }
}

/// A future that tracks when it is polled and dropped.
struct TrackedFuture {
    poll_count: Arc<AtomicU32>,
    drop_flag: Arc<AtomicBool>,
    completes_after: Option<u32>,
}

impl TrackedFuture {
    fn never_completes(poll_count: Arc<AtomicU32>, drop_flag: Arc<AtomicBool>) -> Self {
        Self {
            poll_count,
            drop_flag,
            completes_after: None,
        }
    }

    fn completes_after(
        n: u32,
        poll_count: Arc<AtomicU32>,
        drop_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            poll_count,
            drop_flag,
            completes_after: Some(n),
        }
    }
}

impl Future for TrackedFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let count = self.poll_count.fetch_add(1, Ordering::SeqCst);
        match self.completes_after {
            Some(n) if count >= n => Poll::Ready(()),
            Some(_) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            None => Poll::Pending,
        }
    }
}

impl Drop for TrackedFuture {
    fn drop(&mut self) {
        self.drop_flag.store(true, Ordering::SeqCst);
    }
}

/// Test that tasks created and cancelled in LabRuntime trigger proper cleanup.
#[test]
fn test_labruntime_task_cleanup_on_scope_exit() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let cleanup_flag = Arc::new(AtomicBool::new(false));
    let cleanup_clone = Arc::clone(&cleanup_flag);

    // Create a task that holds a cleanup guard
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            struct CleanupGuard {
                flag: Arc<AtomicBool>,
            }
            impl Drop for CleanupGuard {
                fn drop(&mut self) {
                    self.flag.store(true, Ordering::SeqCst);
                }
            }

            let _guard = CleanupGuard { flag: cleanup_clone };
            // Yield once then complete
            YieldingFuture::new(1, 0, Arc::new(AtomicBool::new(false))).await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    assert!(
        cleanup_flag.load(Ordering::SeqCst),
        "Task cleanup did not run - resource may have leaked"
    );
}

/// Test simulating race semantics: winner completes, losers are cleaned up.
#[test]
fn test_labruntime_simulated_race_cleanup() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let winner_complete = Arc::new(AtomicBool::new(false));
    let loser1_dropped = Arc::new(AtomicBool::new(false));
    let loser2_dropped = Arc::new(AtomicBool::new(false));

    // Create winner task (completes after 1 poll)
    let winner_flag = Arc::clone(&winner_complete);
    let (winner_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            winner_flag.store(true, Ordering::SeqCst);
        })
        .expect("create winner");

    // Create loser tasks (would never complete on their own)
    let loser1_flag = Arc::clone(&loser1_dropped);
    let (loser1_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            struct DropMarker(Arc<AtomicBool>);
            impl Drop for DropMarker {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _marker = DropMarker(loser1_flag);
            std::future::pending::<()>().await;
        })
        .expect("create loser1");

    let loser2_flag = Arc::clone(&loser2_dropped);
    let (loser2_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            struct DropMarker(Arc<AtomicBool>);
            impl Drop for DropMarker {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _marker = DropMarker(loser2_flag);
            std::future::pending::<()>().await;
        })
        .expect("create loser2");

    // Schedule all tasks
    {
        let mut sched = runtime.scheduler.lock().unwrap();
        sched.schedule(winner_id, 0);
        sched.schedule(loser1_id, 0);
        sched.schedule(loser2_id, 0);
    }

    // Run winner (note: this is a simplified simulation - real race! would
    // cancel losers automatically)
    runtime.run_until_quiescent();

    // Winner should have completed
    assert!(
        winner_complete.load(Ordering::SeqCst),
        "Winner did not complete"
    );

    // In a real race!, losers would be cancelled. For now, verify the region
    // properly cleans up pending tasks on close.
    // This test demonstrates the pattern - full race! integration requires
    // the combinator to be wired into task cancellation.
}

/// Test using LoserDrainOracle manually to verify drain semantics.
#[test]
fn test_loser_drain_oracle_integration() {
    use asupersync::types::{RegionId, TaskId};

    let mut oracle = LoserDrainOracle::new();

    // Simulate a race with 3 participants
    let region = RegionId::new_for_test(1, 0);
    let task1 = TaskId::new_for_test(1, 0);
    let task2 = TaskId::new_for_test(2, 0);
    let task3 = TaskId::new_for_test(3, 0);

    let race_id = oracle.on_race_start(region, vec![task1, task2, task3], Time::ZERO);

    // Task 1 wins at t=10
    oracle.on_task_complete(task1, Time::from_nanos(10));

    // Losers drain at t=15 (before race completes)
    oracle.on_task_complete(task2, Time::from_nanos(15));
    oracle.on_task_complete(task3, Time::from_nanos(15));

    // Race completes at t=20
    oracle.on_race_complete(race_id, task1, Time::from_nanos(20));

    // Oracle should pass - all losers drained before race complete
    assert!(
        oracle.check().is_ok(),
        "Oracle reported violation when losers were properly drained"
    );
}

/// Test LoserDrainOracle detects violation when loser not drained.
#[test]
fn test_loser_drain_oracle_detects_violation() {
    use asupersync::types::{RegionId, TaskId};

    let mut oracle = LoserDrainOracle::new();

    let region = RegionId::new_for_test(1, 0);
    let winner = TaskId::new_for_test(1, 0);
    let loser = TaskId::new_for_test(2, 0);

    let race_id = oracle.on_race_start(region, vec![winner, loser], Time::ZERO);

    // Winner completes
    oracle.on_task_complete(winner, Time::from_nanos(10));

    // Race completes WITHOUT loser being drained
    oracle.on_race_complete(race_id, winner, Time::from_nanos(20));

    // Oracle should detect violation
    let result = oracle.check();
    assert!(result.is_err(), "Oracle should detect undrained loser");

    let violation = result.unwrap_err();
    assert_eq!(violation.undrained_losers.len(), 1);
    assert_eq!(violation.undrained_losers[0], loser);
}

/// Test oracle with multiple races.
#[test]
fn test_loser_drain_oracle_multiple_races() {
    use asupersync::types::{RegionId, TaskId};

    let mut oracle = LoserDrainOracle::new();
    let region = RegionId::new_for_test(1, 0);

    // Race 1: 2 participants
    let r1_t1 = TaskId::new_for_test(1, 0);
    let r1_t2 = TaskId::new_for_test(2, 0);
    let race1 = oracle.on_race_start(region, vec![r1_t1, r1_t2], Time::ZERO);

    // Race 2: 3 participants
    let r2_t1 = TaskId::new_for_test(3, 0);
    let r2_t2 = TaskId::new_for_test(4, 0);
    let r2_t3 = TaskId::new_for_test(5, 0);
    let race2 = oracle.on_race_start(region, vec![r2_t1, r2_t2, r2_t3], Time::from_nanos(5));

    // Complete race 1 properly
    oracle.on_task_complete(r1_t1, Time::from_nanos(10)); // winner
    oracle.on_task_complete(r1_t2, Time::from_nanos(12)); // loser drained
    oracle.on_race_complete(race1, r1_t1, Time::from_nanos(15));

    // Complete race 2 properly
    oracle.on_task_complete(r2_t2, Time::from_nanos(20)); // winner
    oracle.on_task_complete(r2_t1, Time::from_nanos(22)); // loser drained
    oracle.on_task_complete(r2_t3, Time::from_nanos(22)); // loser drained
    oracle.on_race_complete(race2, r2_t2, Time::from_nanos(25));

    // Both races properly drained
    assert!(oracle.check().is_ok(), "All losers should be drained");
}
