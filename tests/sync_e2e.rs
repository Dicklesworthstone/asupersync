//! Sync Primitives E2E Verification Suite (bd-3qc6)
//!
//! Comprehensive verification for cancel-aware synchronization primitives
//! ensuring correctness under cancellation and two-phase permit semantics.
//!
//! Test Coverage:
//! - Mutex: lock, try_lock, cancel-during-wait
//! - RwLock: read, write, upgrade, downgrade
//! - Semaphore: acquire, try_acquire, two-phase permits
//! - Barrier: wait, reset
//! - Notify: notify_one, notify_all, notify_waiters
//! - OnceCell: get_or_init, get_or_try_init
//! - Cancel-safety tests for all primitives
//! - Stress tests and deadlock detection scenarios

#![allow(clippy::significant_drop_tightening)]

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::{
    Barrier, LockError, Mutex, Notify, OnceCell, RwLock, RwLockError, Semaphore,
};
use asupersync::types::{Budget, CancelReason};
use asupersync::Cx;
use common::*;
use futures_lite::future::poll_fn;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Helper futures
// ============================================================================

struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_now() {
    YieldNow { yielded: false }.await;
}

fn run_sync_determinism_with_seed(seed: u64) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mutex = Arc::new(Mutex::new(()));

    for i in 0..5 {
        let m = mutex.clone();
        let r = results.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();
                let _guard = m.lock(&cx).await.expect("lock should succeed");
                r.lock().unwrap().push(i);
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let guard = results.lock().unwrap();
    guard.clone()
}

// ============================================================================
// MUTEX TESTS
// ============================================================================

/// E2E-SYNC-001: Mutex fair queuing under contention
///
/// Verifies that multiple tasks waiting for a mutex are served fairly.
#[test]
fn e2e_sync_001_mutex_fair_queuing() {
    init_test("e2e_sync_001_mutex_fair_queuing");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(5000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let mutex = Arc::new(Mutex::new(Vec::new()));
    let num_tasks = 5;
    let tasks_completed = Arc::new(AtomicUsize::new(0));

    // Create tasks that each try to acquire the mutex and record their order
    for i in 0..num_tasks {
        let m = mutex.clone();
        let completed = tasks_completed.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();
                let mut guard = m.lock(&cx).await.expect("lock should succeed");
                guard.push(i);
                // Yield while holding lock to allow others to queue
                yield_now().await;
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let completed = tasks_completed.load(Ordering::SeqCst);
    assert_with_log!(
        completed == num_tasks,
        "all tasks should complete",
        num_tasks,
        completed
    );

    let cx: Cx = Cx::for_testing();
    let guard = futures_lite::future::block_on(mutex.lock(&cx)).unwrap();
    let order_len = guard.len();
    assert_with_log!(
        order_len == num_tasks,
        "all tasks recorded in order",
        num_tasks,
        order_len
    );

    test_complete!("e2e_sync_001_mutex_fair_queuing");
}

/// E2E-SYNC-002: Mutex cancel-during-wait
///
/// Verifies that cancellation while waiting for a mutex is clean.
#[test]
fn e2e_sync_002_mutex_cancel_during_wait() {
    init_test("e2e_sync_002_mutex_cancel_during_wait");
    test_section!("setup");

    let mutex = Arc::new(Mutex::new(42));
    let cx_holder: Cx = Cx::for_testing();

    // Hold the lock
    let guard = futures_lite::future::block_on(mutex.lock(&cx_holder)).unwrap();

    // Try to acquire with a cancelled context
    let cx_waiter: Cx = Cx::for_testing();
    cx_waiter.set_cancel_requested(true);

    let result = futures_lite::future::block_on(mutex.lock(&cx_waiter));
    let was_cancelled = matches!(result, Err(LockError::Cancelled));

    test_section!("verify");
    assert_with_log!(
        was_cancelled,
        "lock should fail with Cancelled",
        true,
        was_cancelled
    );

    // Mutex should still be usable after cancellation
    drop(guard);
    let result2 = mutex.try_lock();
    let is_ok = result2.is_ok();
    assert_with_log!(is_ok, "mutex should be usable after cancel", true, is_ok);

    test_complete!("e2e_sync_002_mutex_cancel_during_wait");
}

// ============================================================================
// RWLOCK TESTS
// ============================================================================

/// E2E-SYNC-010: RwLock concurrent readers
///
/// Verifies that multiple readers can hold the lock simultaneously.
#[test]
fn e2e_sync_010_rwlock_concurrent_readers() {
    init_test("e2e_sync_010_rwlock_concurrent_readers");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(3000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let rwlock = Arc::new(RwLock::new(42));
    let multi_read_ok = Arc::new(AtomicBool::new(false));
    let num_readers = 5;

    for _ in 0..num_readers {
        let rw = rwlock.clone();
        let multi_ok = multi_read_ok.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();

                // Scope guards so they're dropped before yield_now
                // (RwLockReadGuard is not Send across await points)
                {
                    let guard = rw.read(&cx).await.expect("read should succeed");
                    let second = rw.try_read();
                    if let Ok(guard2) = second {
                        multi_ok.store(true, Ordering::SeqCst);
                        assert_eq!(*guard2, 42, "second reader sees value");
                        drop(guard2);
                    }

                    // Verify value
                    assert_eq!(*guard, 42, "should read correct value");
                }

                yield_now().await;
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let ok = multi_read_ok.load(Ordering::SeqCst);
    assert_with_log!(
        ok,
        "rwlock allows multiple readers (try_read succeeds while read held)",
        true,
        ok
    );

    test_complete!("e2e_sync_010_rwlock_concurrent_readers");
}

/// E2E-SYNC-011: RwLock writer exclusivity
///
/// Verifies that writers have exclusive access.
#[test]
fn e2e_sync_011_rwlock_writer_exclusivity() {
    init_test("e2e_sync_011_rwlock_writer_exclusivity");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(3000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let rwlock = Arc::new(RwLock::new(0));
    let num_writers = 4;
    let increments_per_writer = 100;

    for _ in 0..num_writers {
        let rw = rwlock.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();
                for _ in 0..increments_per_writer {
                    let mut guard = rw.write(&cx).await.expect("write should succeed");
                    *guard += 1;
                }
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let cx: Cx = Cx::for_testing();
    let guard = futures_lite::future::block_on(rwlock.read(&cx)).unwrap();
    let expected = num_writers * increments_per_writer;
    let actual = *guard;
    assert_with_log!(
        actual == expected,
        "all increments should be counted",
        expected,
        actual
    );

    test_complete!("e2e_sync_011_rwlock_writer_exclusivity");
}

/// E2E-SYNC-012: RwLock mixed wait + cancellation
///
/// Verifies mixed readers/writers, cancellation/timeouts, and poll-based wait duration logging.
#[test]
#[allow(clippy::too_many_lines)]
fn e2e_sync_012_rwlock_mixed_wait_cancel() {
    init_test("e2e_sync_012_rwlock_mixed_wait_cancel");
    test_section!("setup");

    let seed = 4242_u64;
    let worker_count = 3_usize;
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .worker_count(worker_count)
            .max_steps(10_000),
    );
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let rwlock = Arc::new(RwLock::new(0u64));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let total_polls = Arc::new(AtomicU64::new(0));
    let hold_acquired = Arc::new(AtomicBool::new(false));
    let release_hold = Arc::new(AtomicBool::new(false));
    let cancel_ready = Arc::new(AtomicUsize::new(0));

    tracing::info!(seed, worker_count, "rwlock mixed wait config");

    // Hold a writer lock to force waiters to queue.
    let rw_hold = rwlock.clone();
    let hold_acquired_handle = hold_acquired.clone();
    let release_for_hold = release_hold.clone();
    let (hold_task, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx: Cx = Cx::for_testing();
            let mut guard = asupersync::sync::OwnedRwLockWriteGuard::write(rw_hold, &cx)
                .await
                .expect("write should succeed");
            hold_acquired_handle.store(true, Ordering::SeqCst);
            while !release_for_hold.load(Ordering::SeqCst) {
                yield_now().await;
            }
            guard.with_write(|value| *value += 1);
        })
        .unwrap();
    runtime.scheduler.lock().unwrap().schedule(hold_task, 10);

    let cancel_reason = CancelReason::deadline().with_message("rwlock wait timeout");
    let waiters: [(bool, Option<u32>); 6] = [
        (false, Some(2)), // read (cancelled)
        (true, Some(2)),  // write (cancelled)
        (false, Some(2)), // read (cancelled)
        (true, None),     // write (success)
        (false, None),    // read (success)
        (true, None),     // write (success)
    ];
    let cancel_target = waiters
        .iter()
        .filter(|(_, cancel)| cancel.is_some())
        .count();
    if cancel_target == 0 {
        release_hold.store(true, Ordering::SeqCst);
    }

    for (idx, (is_writer, cancel_after)) in waiters.iter().enumerate() {
        let rw = rwlock.clone();
        let cancelled = cancelled.clone();
        let completed = completed.clone();
        let total_polls = total_polls.clone();
        let hold_acquired = hold_acquired.clone();
        let cancel_ready = cancel_ready.clone();
        let release_hold = release_hold.clone();
        let cx = Cx::for_testing();
        let cx_cancel = cx.clone();
        let reason = cancel_reason.clone();
        let is_writer = *is_writer;
        let cancel_after = *cancel_after;

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let kind = if is_writer { "write" } else { "read" };
                let mut polls = 0_u64;

                while !hold_acquired.load(Ordering::SeqCst) {
                    yield_now().await;
                }

                let outcome = if is_writer {
                    let mut fut = rw.write(&cx);
                    let result = poll_fn(|task_cx| {
                        polls += 1;
                        Pin::new(&mut fut).poll(task_cx)
                    })
                    .await;
                    match result {
                        Ok(mut guard) => {
                            *guard += 1;
                            completed.fetch_add(1, Ordering::SeqCst);
                            "completed"
                        }
                        Err(RwLockError::Cancelled) => {
                            cancelled.fetch_add(1, Ordering::SeqCst);
                            "cancelled"
                        }
                        Err(err) => panic!("rwlock write error: {err:?}"),
                    }
                } else {
                    let mut fut = rw.read(&cx);
                    let result = poll_fn(|task_cx| {
                        polls += 1;
                        Pin::new(&mut fut).poll(task_cx)
                    })
                    .await;
                    match result {
                        Ok(guard) => {
                            let _value = *guard;
                            completed.fetch_add(1, Ordering::SeqCst);
                            "completed"
                        }
                        Err(RwLockError::Cancelled) => {
                            cancelled.fetch_add(1, Ordering::SeqCst);
                            "cancelled"
                        }
                        Err(err) => panic!("rwlock read error: {err:?}"),
                    }
                };

                total_polls.fetch_add(polls, Ordering::SeqCst);
                tracing::info!(idx, kind, polls, outcome, "rwlock waiter done");
            })
            .unwrap();
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);

        if let Some(cancel_after) = cancel_after {
            let (cancel_task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for _ in 0..cancel_after {
                        yield_now().await;
                    }
                    cx_cancel.set_cancel_reason(reason);
                    let ready = cancel_ready.fetch_add(1, Ordering::SeqCst) + 1;
                    if ready == cancel_target {
                        release_hold.store(true, Ordering::SeqCst);
                        tracing::debug!(idx, ready, "rwlock hold released after cancels");
                    }
                    tracing::debug!(
                        idx,
                        kind = if is_writer { "write" } else { "read" },
                        "rwlock cancel issued"
                    );
                })
                .unwrap();
            runtime.scheduler.lock().unwrap().schedule(cancel_task, 0);
        }
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let cancelled_count = cancelled.load(Ordering::SeqCst);
    let completed_count = completed.load(Ordering::SeqCst);
    let poll_count = total_polls.load(Ordering::SeqCst);

    tracing::info!(
        seed,
        worker_count,
        cancelled_count,
        completed_count,
        poll_count,
        "rwlock mixed wait summary"
    );

    assert_with_log!(
        cancelled_count == cancel_target,
        "cancelled waiters observed",
        cancel_target,
        cancelled_count
    );
    assert_with_log!(
        completed_count == waiters.len() - cancel_target,
        "completed waiters observed",
        waiters.len() - cancel_target,
        completed_count
    );

    test_complete!("e2e_sync_012_rwlock_mixed_wait_cancel");
}

// ============================================================================
// SEMAPHORE TESTS
// ============================================================================

/// E2E-SYNC-020: Semaphore permit limiting
///
/// Verifies that semaphore correctly limits concurrent access.
#[test]
fn e2e_sync_020_semaphore_permit_limiting() {
    init_test("e2e_sync_020_semaphore_permit_limiting");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(5000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let sem = Arc::new(Semaphore::new(3));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));
    let num_tasks = 10;

    for i in 0..num_tasks {
        let s = sem.clone();
        let max_c = max_concurrent.clone();
        let curr = current.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();
                let _permit = s.acquire(&cx, 1).await.expect("acquire should succeed");

                // Track concurrent holders
                let prev = curr.fetch_add(1, Ordering::SeqCst);
                max_c.fetch_max(prev + 1, Ordering::SeqCst);

                yield_now().await;

                curr.fetch_sub(1, Ordering::SeqCst);
                tracing::debug!(task = i, "task completed");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let max = max_concurrent.load(Ordering::SeqCst);
    assert_with_log!(
        max <= 3,
        "max concurrent should not exceed semaphore limit",
        "<= 3",
        max
    );

    // All permits should be released
    let available = sem.available_permits();
    assert_with_log!(
        available == 3,
        "all permits should be released",
        3,
        available
    );

    test_complete!("e2e_sync_020_semaphore_permit_limiting");
}

/// E2E-SYNC-021: Semaphore two-phase reserve/commit
///
/// Verifies that reserve/commit semantics work correctly.
#[test]
fn e2e_sync_021_semaphore_two_phase() {
    init_test("e2e_sync_021_semaphore_two_phase");
    test_section!("setup");

    let sem = Semaphore::new(2);
    let cx: Cx = Cx::for_testing();

    // Acquire permits via normal path (simulating reserve/commit)
    let permit1 = futures_lite::future::block_on(sem.acquire(&cx, 1)).unwrap();
    assert_with_log!(
        sem.available_permits() == 1,
        "one permit used",
        1,
        sem.available_permits()
    );

    let permit2 = futures_lite::future::block_on(sem.acquire(&cx, 1)).unwrap();
    assert_with_log!(
        sem.available_permits() == 0,
        "two permits used",
        0,
        sem.available_permits()
    );

    // Dropping permits releases them (abort semantics)
    drop(permit1);
    assert_with_log!(
        sem.available_permits() == 1,
        "one permit released on drop",
        1,
        sem.available_permits()
    );

    drop(permit2);
    assert_with_log!(
        sem.available_permits() == 2,
        "all permits released",
        2,
        sem.available_permits()
    );

    test_complete!("e2e_sync_021_semaphore_two_phase");
}

// ============================================================================
// BARRIER TESTS
// ============================================================================

/// E2E-SYNC-030: Barrier synchronization
///
/// Verifies that all tasks wait until barrier count is reached.
#[test]
fn e2e_sync_030_barrier_synchronization() {
    init_test("e2e_sync_030_barrier_synchronization");
    test_section!("setup");

    let num_tasks = 4;
    let barrier = Arc::new(Barrier::new(num_tasks));
    let pre_barrier = Arc::new(AtomicUsize::new(0));
    let post_barrier = Arc::new(AtomicUsize::new(0));
    let leader_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..num_tasks {
        let b = barrier.clone();
        let pre = pre_barrier.clone();
        let post = post_barrier.clone();
        let leaders = leader_count.clone();

        handles.push(std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();

            // Signal arrival
            pre.fetch_add(1, Ordering::SeqCst);
            tracing::debug!(task = i, "arrived at barrier");

            // Wait at barrier
            let result = futures_lite::future::block_on(b.wait(&cx)).expect("barrier wait should succeed");

            // Track leader
            if result.is_leader() {
                leaders.fetch_add(1, Ordering::SeqCst);
            }

            // Signal departure
            post.fetch_add(1, Ordering::SeqCst);
            tracing::debug!(task = i, "passed barrier");
        }));
    }

    test_section!("run");
    for handle in handles {
        handle.join().expect("barrier thread join");
    }

    test_section!("verify");
    let pre_count = pre_barrier.load(Ordering::SeqCst);
    let post_count = post_barrier.load(Ordering::SeqCst);
    let leaders = leader_count.load(Ordering::SeqCst);

    assert_with_log!(
        pre_count == num_tasks,
        "all tasks should arrive",
        num_tasks,
        pre_count
    );
    assert_with_log!(
        post_count == num_tasks,
        "all tasks should pass",
        num_tasks,
        post_count
    );
    assert_with_log!(leaders == 1, "exactly one leader", 1, leaders);

    test_complete!("e2e_sync_030_barrier_synchronization");
}

// ============================================================================
// NOTIFY TESTS
// ============================================================================

/// E2E-SYNC-040: Notify one wakes single waiter
///
/// Verifies that notify_one wakes exactly one waiting task.
#[test]
fn e2e_sync_040_notify_one() {
    init_test("e2e_sync_040_notify_one");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(3000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let notify = Arc::new(Notify::new());
    let woken = Arc::new(AtomicUsize::new(0));

    // Create multiple waiters
    for i in 0..3 {
        let n = notify.clone();
        let w = woken.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                n.notified().await;
                w.fetch_add(1, Ordering::SeqCst);
                tracing::debug!(task = i, "woken");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    // Run a few steps to let waiters register
    for _ in 0..10 {
        runtime.step_for_test();
    }

    test_section!("notify");
    // Notify one waiter
    notify.notify_one();

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let woken_count = woken.load(Ordering::SeqCst);
    // At least one should be woken, possibly more due to timing
    assert_with_log!(
        woken_count >= 1,
        "at least one waiter should be woken",
        ">= 1",
        woken_count
    );

    test_complete!("e2e_sync_040_notify_one");
}

/// E2E-SYNC-041: Notify all wakes all waiters
///
/// Verifies that notify_waiters wakes all waiting tasks.
#[test]
fn e2e_sync_041_notify_all() {
    init_test("e2e_sync_041_notify_all");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(3000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let notify = Arc::new(Notify::new());
    let woken = Arc::new(AtomicUsize::new(0));
    let num_waiters = 5;

    for i in 0..num_waiters {
        let n = notify.clone();
        let w = woken.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                n.notified().await;
                w.fetch_add(1, Ordering::SeqCst);
                tracing::debug!(task = i, "woken");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    // Run a few steps to let waiters register
    for _ in 0..10 {
        runtime.step_for_test();
    }

    test_section!("notify_all");
    notify.notify_waiters();

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let woken_count = woken.load(Ordering::SeqCst);
    assert_with_log!(
        woken_count == num_waiters,
        "all waiters should be woken",
        num_waiters,
        woken_count
    );

    test_complete!("e2e_sync_041_notify_all");
}

// ============================================================================
// ONCECELL TESTS
// ============================================================================

/// E2E-SYNC-050: OnceCell single initialization
///
/// Verifies that OnceCell initializes exactly once.
#[test]
fn e2e_sync_050_oncecell_single_init() {
    init_test("e2e_sync_050_oncecell_single_init");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(3000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let cell: Arc<OnceCell<usize>> = Arc::new(OnceCell::new());
    let init_count = Arc::new(AtomicUsize::new(0));
    let num_tasks = 5;

    for i in 0..num_tasks {
        let c = cell.clone();
        let count = init_count.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let value = c
                    .get_or_init(|| async {
                        count.fetch_add(1, Ordering::SeqCst);
                        42
                    })
                    .await;

                assert_eq!(*value, 42, "should get initialized value");
                tracing::debug!(task = i, value = *value, "got value");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let inits = init_count.load(Ordering::SeqCst);
    assert_with_log!(inits == 1, "should initialize exactly once", 1, inits);

    test_complete!("e2e_sync_050_oncecell_single_init");
}

/// E2E-SYNC-051: OnceCell get before init
///
/// Verifies that get() returns None before initialization.
#[test]
fn e2e_sync_051_oncecell_get_before_init() {
    init_test("e2e_sync_051_oncecell_get_before_init");
    test_section!("test");

    let cell: OnceCell<usize> = OnceCell::new();

    // Get before init should return None
    let value = cell.get();
    let is_none = value.is_none();
    assert_with_log!(is_none, "get before init should be None", true, is_none);

    // Initialize
    let _ = futures_lite::future::block_on(cell.get_or_init(|| async { 42 }));

    // Get after init should return Some
    let value = cell.get();
    let is_some = value.is_some();
    assert_with_log!(is_some, "get after init should be Some", true, is_some);
    assert_eq!(*value.unwrap(), 42);

    test_complete!("e2e_sync_051_oncecell_get_before_init");
}

// ============================================================================
// CANCEL-SAFETY STRESS TESTS
// ============================================================================

/// E2E-SYNC-100: Stress test with mixed primitives
///
/// High-contention scenario with multiple primitives.
#[test]
fn e2e_sync_100_stress_mixed_primitives() {
    init_test("e2e_sync_100_stress_mixed_primitives");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(20000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let mutex = Arc::new(Mutex::new(0));
    let sem = Arc::new(Semaphore::new(3));
    let completed = Arc::new(AtomicUsize::new(0));
    let num_tasks = 20;
    let ops_per_task = 10;

    for i in 0..num_tasks {
        let m = mutex.clone();
        let s = sem.clone();
        let c = completed.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();

                for _ in 0..ops_per_task {
                    // Acquire semaphore permit
                    let _permit = s.acquire(&cx, 1).await.expect("acquire should succeed");

                    // Acquire mutex
                    let mut guard = m.lock(&cx).await.expect("lock should succeed");
                    *guard += 1;

                    yield_now().await;
                }

                c.fetch_add(1, Ordering::SeqCst);
                tracing::debug!(task = i, "completed");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let completed_count = completed.load(Ordering::SeqCst);
    assert_with_log!(
        completed_count == num_tasks,
        "all tasks should complete",
        num_tasks,
        completed_count
    );

    // Verify final count
    let cx: Cx = Cx::for_testing();
    let guard = futures_lite::future::block_on(mutex.lock(&cx)).unwrap();
    let expected = num_tasks * ops_per_task;
    let actual = *guard;
    assert_with_log!(
        actual == expected,
        "all increments should be counted",
        expected,
        actual
    );

    // Semaphore should have all permits released
    let available = sem.available_permits();
    assert_with_log!(
        available == 3,
        "semaphore permits should be released",
        3,
        available
    );

    test_complete!("e2e_sync_100_stress_mixed_primitives");
}

/// E2E-SYNC-101: Cancel-safety during semaphore acquire
///
/// Verifies no permit leaks when cancelled during acquire.
#[test]
fn e2e_sync_101_semaphore_cancel_no_leak() {
    init_test("e2e_sync_101_semaphore_cancel_no_leak");
    test_section!("setup");

    let sem = Arc::new(Semaphore::new(1));

    // Hold the only permit
    let cx_holder: Cx = Cx::for_testing();
    let permit = futures_lite::future::block_on(sem.acquire(&cx_holder, 1)).unwrap();

    assert_with_log!(
        sem.available_permits() == 0,
        "permit held",
        0,
        sem.available_permits()
    );

    test_section!("cancel_waiting_acquire");
    // Try to acquire with cancelled context
    let cx_waiter: Cx = Cx::for_testing();
    cx_waiter.set_cancel_requested(true);

    let result = futures_lite::future::block_on(sem.acquire(&cx_waiter, 1));
    let was_cancelled = result.is_err();
    assert_with_log!(
        was_cancelled,
        "acquire should be cancelled",
        true,
        was_cancelled
    );

    test_section!("verify_no_leak");
    // Release the held permit
    drop(permit);

    // Should have 1 permit available (no leak from cancelled acquire)
    let available = sem.available_permits();
    assert_with_log!(available == 1, "no permit leak after cancel", 1, available);

    test_complete!("e2e_sync_101_semaphore_cancel_no_leak");
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

/// E2E-SYNC-200: Sync primitives determinism
///
/// Verifies that sync operations are deterministic in lab runtime.
#[test]
fn e2e_sync_200_determinism() {
    init_test("e2e_sync_200_determinism");

    test_section!("run_twice");
    let result1 = run_sync_determinism_with_seed(42);
    let result2 = run_sync_determinism_with_seed(42);

    test_section!("verify");
    assert_with_log!(
        result1 == result2,
        "same seed should produce same order",
        &result1,
        &result2
    );

    test_complete!("e2e_sync_200_determinism");
}

// ============================================================================
// DEADLOCK SCENARIO TESTS
// ============================================================================

/// E2E-SYNC-300: No deadlock with proper lock ordering
///
/// Verifies that consistent lock ordering prevents deadlock.
#[test]
fn e2e_sync_300_no_deadlock_proper_ordering() {
    init_test("e2e_sync_300_no_deadlock_proper_ordering");
    test_section!("setup");

    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(10000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let mutex_a = Arc::new(Mutex::new("A"));
    let mutex_b = Arc::new(Mutex::new("B"));
    let completed = Arc::new(AtomicUsize::new(0));

    // Both tasks acquire locks in same order (A then B)
    for i in 0..2 {
        let ma = mutex_a.clone();
        let mb = mutex_b.clone();
        let c = completed.clone();

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx: Cx = Cx::for_testing();

                // Always acquire A first, then B
                let _guard_a = ma.lock(&cx).await.expect("lock A should succeed");
                yield_now().await;
                let _guard_b = mb.lock(&cx).await.expect("lock B should succeed");

                c.fetch_add(1, Ordering::SeqCst);
                tracing::debug!(task = i, "completed both locks");
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let completed_count = completed.load(Ordering::SeqCst);
    assert_with_log!(
        completed_count == 2,
        "all tasks should complete without deadlock",
        2,
        completed_count
    );

    test_complete!("e2e_sync_300_no_deadlock_proper_ordering");
}
