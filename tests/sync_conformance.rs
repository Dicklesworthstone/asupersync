#![allow(warnings)]
#![allow(clippy::all)]
//! Sync Primitives Test Suite
//!
//! Conformance tests for synchronization primitives as specified in
//! the Asupersync design document.
//!
//! Test Coverage:
//! - SYNC-001: Mutex Basic Lock/Unlock
//! - SYNC-002: Mutex Contention Correctness
//! - SYNC-003: RwLock Reader/Writer Priority
//! - SYNC-004: Barrier Synchronization
//! - SYNC-005: Semaphore Permit Limiting
//! - SYNC-006: OnceCell Initialization
//! - SYNC-007: Notify (Condvar-style) Notification

// Allow significant_drop_tightening in tests - the scoped blocks are for clarity
#![allow(clippy::significant_drop_tightening)]

use asupersync::Cx;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec as AsupersyncCodec};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::intrusive_heap::IntrusivePriorityHeap;
use asupersync::sync::{Barrier, LockError, Mutex, Notify, OnceCell, RwLock, Semaphore};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::{Arena, ArenaIndex};
use std::collections::BinaryHeap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
#[macro_use]
mod common;

use common::*;
use futures_lite::future::block_on;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// SYNC-001: Mutex Basic Lock/Unlock
///
/// Verifies that a mutex can be locked and unlocked, and that
/// the protected data can be read and written through the guard.
#[test]
fn sync_001_mutex_basic_lock_unlock() {
    init_test("sync_001_mutex_basic_lock_unlock");
    let cx: Cx = Cx::for_testing();
    let mutex = Mutex::new(42);

    // Lock the mutex
    {
        let guard = block_on(mutex.lock(&cx)).expect("lock should succeed");
        assert_with_log!(*guard == 42, "should read initial value", 42, *guard);
    }

    // Lock should be released after guard is dropped
    let unlocked = !mutex.is_locked();
    assert_with_log!(
        unlocked,
        "mutex should be unlocked after guard drop",
        true,
        unlocked
    );

    // Lock again and modify
    {
        let mut guard = block_on(mutex.lock(&cx)).expect("second lock should succeed");
        *guard = 100;
        assert_with_log!(*guard == 100, "should read modified value", 100, *guard);
    }

    // Verify the modification persisted
    {
        let guard = block_on(mutex.lock(&cx)).expect("third lock should succeed");
        assert_with_log!(*guard == 100, "modification should persist", 100, *guard);
    }
    test_complete!("sync_001_mutex_basic_lock_unlock");
}

/// SYNC-001b: Mutex try_lock
///
/// Verifies that try_lock returns Locked when the mutex is already held.
#[test]
fn sync_001b_mutex_try_lock() {
    init_test("sync_001b_mutex_try_lock");
    let mutex = Mutex::new(42);

    // try_lock should succeed when unlocked
    {
        let guard = mutex
            .try_lock()
            .expect("try_lock should succeed when unlocked");
        assert_with_log!(*guard == 42, "try_lock should read value", 42, *guard);

        // try_lock should fail while guard is held
        let locked_err = mutex.try_lock().is_err();
        assert_with_log!(
            locked_err,
            "try_lock should fail while locked",
            true,
            locked_err
        );
    }

    // try_lock should succeed again after guard dropped
    let unlocked_ok = mutex.try_lock().is_ok();
    assert_with_log!(
        unlocked_ok,
        "try_lock should succeed after unlock",
        true,
        unlocked_ok
    );
    test_complete!("sync_001b_mutex_try_lock");
}

/// SYNC-002: Mutex Contention Correctness
///
/// Verifies that multiple threads contending for a mutex maintain
/// data integrity - no lost updates, no torn reads.
#[test]
fn sync_002_mutex_contention_correctness() {
    init_test("sync_002_mutex_contention_correctness");

    let mutex = Arc::new(Mutex::new(0i64));
    let iterations = 1000;
    let num_threads = 4;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let mutex = Arc::clone(&mutex);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                for _ in 0..iterations {
                    let mut guard = block_on(mutex.lock(&cx)).expect("lock should succeed");
                    *guard += 1;
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should complete");
    }

    let cx: Cx = Cx::for_testing();
    let final_value = *block_on(mutex.lock(&cx)).expect("final lock should succeed");
    let expected = i64::from(num_threads * iterations);
    assert_with_log!(
        final_value == expected,
        "all increments should be counted",
        expected,
        final_value
    );
    test_complete!("sync_002_mutex_contention_correctness");
}

/// SYNC-002b: Mutex Cancellation During Lock
///
/// Verifies that cancellation while waiting for a lock is handled correctly.
#[test]
fn sync_002b_mutex_cancellation() {
    init_test("sync_002b_mutex_cancellation");

    let mutex = Arc::new(Mutex::new(0));
    let cx_main: Cx = Cx::for_testing();

    // Hold the lock
    let _guard = block_on(mutex.lock(&cx_main)).expect("lock should succeed");

    // Spawn a thread that will try to lock with a cancelled context
    let mutex_clone = Arc::clone(&mutex);
    let handle = thread::spawn(move || {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        // Return whether the lock was cancelled (don't return the guard)
        matches!(block_on(mutex_clone.lock(&cx)), Err(LockError::Cancelled))
    });

    // The spawned thread should get a Cancelled error
    let was_cancelled = handle.join().expect("thread should complete");
    assert_with_log!(
        was_cancelled,
        "lock should fail with Cancelled when context is cancelled",
        true,
        was_cancelled
    );
    test_complete!("sync_002b_mutex_cancellation");
}

/// SYNC-003: RwLock Reader/Writer Priority
///
/// Verifies that:
/// - Multiple readers can hold the lock simultaneously
/// - Writers have exclusive access
/// - Read/write guards provide correct access to data
#[test]
fn sync_003_rwlock_reader_writer_priority() {
    init_test("sync_003_rwlock_reader_writer_priority");
    let cx: Cx = Cx::for_testing();
    let rwlock = RwLock::new(42);

    // Multiple readers can hold the lock simultaneously (same thread)
    {
        let r1 = block_on(rwlock.read(&cx)).expect("first read should succeed");
        let r2 = block_on(rwlock.read(&cx)).expect("second concurrent read should succeed");
        assert_with_log!(*r1 == 42, "reader 1 should see initial value", 42, *r1);
        assert_with_log!(*r2 == 42, "reader 2 should see initial value", 42, *r2);

        // try_write should fail while readers are held
        let try_w = rwlock.try_write().is_err();
        assert_with_log!(
            try_w,
            "try_write should fail while readers held",
            true,
            try_w
        );
    }

    // Writer has exclusive access
    {
        let mut w = block_on(rwlock.write(&cx)).expect("write should succeed");
        *w = 100;

        // try_read should fail while writer is held
        let try_r = rwlock.try_read().is_err();
        assert_with_log!(try_r, "try_read should fail while writer held", true, try_r);

        // try_write should also fail
        let try_w = rwlock.try_write().is_err();
        assert_with_log!(
            try_w,
            "try_write should fail while writer held",
            true,
            try_w
        );
    }

    // Verify write persisted after guard drop
    {
        let r = block_on(rwlock.read(&cx)).expect("read after write should succeed");
        assert_with_log!(*r == 100, "should see written value", 100, *r);
    }

    // Concurrent readers across threads
    let rwlock = Arc::new(RwLock::new(0i64));
    let num_readers: usize = 4;
    let active_readers = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_readers)
        .map(|_| {
            let rwlock = Arc::clone(&rwlock);
            let active_readers = Arc::clone(&active_readers);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                let _guard = block_on(rwlock.read(&cx)).expect("read should succeed");
                active_readers.fetch_add(1, Ordering::SeqCst);
                // Spin until all readers have acquired the lock
                while active_readers.load(Ordering::SeqCst) < num_readers {
                    thread::yield_now();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("reader thread should complete");
    }

    let final_count = active_readers.load(Ordering::SeqCst);
    assert_with_log!(
        final_count == num_readers,
        "all readers should acquire concurrently",
        num_readers,
        final_count
    );

    // Writer contention correctness across threads
    let rwlock = Arc::new(RwLock::new(0i64));
    let iterations = 500;
    let num_threads = 4;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let rwlock = Arc::clone(&rwlock);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                for _ in 0..iterations {
                    let mut guard = block_on(rwlock.write(&cx)).expect("write should succeed");
                    *guard += 1;
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("writer thread should complete");
    }

    let final_val = *block_on(rwlock.read(&cx)).expect("final read should succeed");
    let expected = i64::from(num_threads) * i64::from(iterations);
    assert_with_log!(
        final_val == expected,
        "all writer increments should be counted",
        expected,
        final_val
    );

    test_complete!("sync_003_rwlock_reader_writer_priority");
}

/// SYNC-004: Barrier Synchronization
///
/// Verifies that:
/// - All threads wait until the barrier count is reached
/// - Threads proceed together after barrier release
/// - Exactly one leader is elected per barrier round
#[test]
fn sync_004_barrier_synchronization() {
    init_test("sync_004_barrier_synchronization");

    let num_threads: usize = 4;
    let barrier = Arc::new(Barrier::new(num_threads));
    let arrived = Arc::new(AtomicUsize::new(0));
    let after_barrier = Arc::new(AtomicUsize::new(0));
    let leader_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let arrived = Arc::clone(&arrived);
            let after_barrier = Arc::clone(&after_barrier);
            let leader_count = Arc::clone(&leader_count);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                arrived.fetch_add(1, Ordering::SeqCst);
                let result = block_on(barrier.wait(&cx)).expect("barrier wait should succeed");
                if result.is_leader() {
                    leader_count.fetch_add(1, Ordering::SeqCst);
                }
                after_barrier.fetch_add(1, Ordering::SeqCst);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should complete");
    }

    let total_arrived = arrived.load(Ordering::SeqCst);
    assert_with_log!(
        total_arrived == num_threads,
        "all threads should have arrived",
        num_threads,
        total_arrived
    );

    let total_after = after_barrier.load(Ordering::SeqCst);
    assert_with_log!(
        total_after == num_threads,
        "all threads should proceed past barrier",
        num_threads,
        total_after
    );

    let leaders = leader_count.load(Ordering::SeqCst);
    assert_with_log!(
        leaders == 1,
        "exactly one leader should be elected",
        1,
        leaders
    );

    // Verify barrier is reusable (second round)
    let barrier = Arc::new(Barrier::new(num_threads));
    let round2_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let round2_count = Arc::clone(&round2_count);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                block_on(barrier.wait(&cx)).expect("round 2 wait should succeed");
                round2_count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("round 2 thread should complete");
    }

    let round2 = round2_count.load(Ordering::SeqCst);
    assert_with_log!(
        round2 == num_threads,
        "barrier should be reusable for round 2",
        num_threads,
        round2
    );

    test_complete!("sync_004_barrier_synchronization");
}

/// SYNC-005: Semaphore Permit Limiting
///
/// Verifies that a semaphore correctly limits concurrent access
/// to the specified number of permits.
#[test]
fn sync_005_semaphore_permit_limiting() {
    init_test("sync_005_semaphore_permit_limiting");
    let cx: Cx = Cx::for_testing();
    let sem = Semaphore::new(3);

    assert_with_log!(
        sem.available_permits() == 3,
        "available permits should start at 3",
        3,
        sem.available_permits()
    );
    assert_with_log!(
        sem.max_permits() == 3,
        "max permits should be 3",
        3,
        sem.max_permits()
    );

    // Acquire one permit
    let permit1 = block_on(sem.acquire(&cx, 1)).expect("first acquire should succeed");
    assert_with_log!(
        sem.available_permits() == 2,
        "available permits should be 2 after first acquire",
        2,
        sem.available_permits()
    );

    // Acquire two more permits
    let permit2 = block_on(sem.acquire(&cx, 2)).expect("second acquire should succeed");
    assert_with_log!(
        sem.available_permits() == 0,
        "available permits should be 0 after second acquire",
        0,
        sem.available_permits()
    );

    // try_acquire should fail when no permits available
    let try_err = sem.try_acquire(1).is_err();
    assert_with_log!(
        try_err,
        "try_acquire should fail with no permits",
        true,
        try_err
    );

    // Drop one permit
    drop(permit1);
    assert_with_log!(
        sem.available_permits() == 1,
        "available permits should be 1 after dropping one permit",
        1,
        sem.available_permits()
    );

    // Now try_acquire should succeed for 1
    let permit3 = sem
        .try_acquire(1)
        .expect("try_acquire should succeed after release");
    assert_with_log!(
        sem.available_permits() == 0,
        "available permits should be 0 after try_acquire",
        0,
        sem.available_permits()
    );

    // Drop remaining permits
    drop(permit2);
    drop(permit3);
    assert_with_log!(
        sem.available_permits() == 3,
        "available permits should be restored to 3",
        3,
        sem.available_permits()
    );
    test_complete!("sync_005_semaphore_permit_limiting");
}

/// SYNC-005b: Semaphore Concurrent Access
///
/// Verifies that semaphore correctly limits concurrent workers.
#[test]
fn sync_005b_semaphore_concurrent_access() {
    init_test("sync_005b_semaphore_concurrent_access");

    let sem = Arc::new(Semaphore::new(3));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));
    let num_workers = 10;

    let handles: Vec<_> = (0..num_workers)
        .map(|_| {
            let sem = Arc::clone(&sem);
            let max_concurrent = Arc::clone(&max_concurrent);
            let current = Arc::clone(&current);
            thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                let _permit = block_on(sem.acquire(&cx, 1)).expect("acquire should succeed");

                // Track concurrent access
                let prev = current.fetch_add(1, Ordering::SeqCst);
                max_concurrent.fetch_max(prev + 1, Ordering::SeqCst);

                // Simulate work
                thread::yield_now();

                current.fetch_sub(1, Ordering::SeqCst);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should complete");
    }

    let observed_max = max_concurrent.load(Ordering::SeqCst);
    assert_with_log!(
        observed_max <= 3,
        "max concurrent should not exceed semaphore limit",
        "<= 3",
        observed_max
    );
    test_complete!("sync_005b_semaphore_concurrent_access");
}

/// SYNC-006: OnceCell Initialization
///
/// Verifies that:
/// - get() before initialization returns None
/// - Value is initialized exactly once via set()
/// - Duplicate set() returns Err with the rejected value
/// - get_or_init_blocking initializes lazily and returns existing value
/// - Concurrent initialization runs the init function exactly once
#[test]
fn sync_006_oncecell_initialization() {
    init_test("sync_006_oncecell_initialization");

    // get() before initialization returns None
    let cell: OnceCell<i32> = OnceCell::new();
    let before = cell.get().is_none();
    assert_with_log!(before, "get should return None before init", true, before);
    assert_with_log!(
        !cell.is_initialized(),
        "should not be initialized",
        false,
        cell.is_initialized()
    );

    // set() initializes the cell
    let set_ok = cell.set(42).is_ok();
    assert_with_log!(set_ok, "first set should succeed", true, set_ok);

    // get() returns the value
    let val = cell.get().copied();
    assert_with_log!(
        val == Some(42),
        "get should return set value",
        42,
        val.unwrap_or(0)
    );
    assert_with_log!(
        cell.is_initialized(),
        "should be initialized after set",
        true,
        cell.is_initialized()
    );

    // Duplicate set fails and returns the rejected value
    let dup = cell.set(99);
    let dup_err = dup.is_err();
    assert_with_log!(dup_err, "second set should fail", true, dup_err);

    // Original value unchanged
    let val = cell.get().copied();
    assert_with_log!(
        val == Some(42),
        "value unchanged after failed set",
        42,
        val.unwrap_or(0)
    );

    // get_or_init_blocking: initializes on first call
    let cell2: OnceCell<i32> = OnceCell::new();
    let v = cell2.get_or_init_blocking(|| 77);
    assert_with_log!(*v == 77, "get_or_init_blocking should init", 77, *v);

    // get_or_init_blocking: returns existing on second call
    let v2 = cell2.get_or_init_blocking(|| 999);
    assert_with_log!(*v2 == 77, "get_or_init_blocking returns existing", 77, *v2);

    // Concurrent initialization: init function runs exactly once
    let cell3 = Arc::new(OnceCell::new());
    let init_count = Arc::new(AtomicUsize::new(0));
    let num_threads = 8;

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let cell = Arc::clone(&cell3);
            let init_count = Arc::clone(&init_count);
            thread::spawn(move || {
                let val = cell.get_or_init_blocking(|| {
                    init_count.fetch_add(1, Ordering::SeqCst);
                    i
                });
                *val
            })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().expect("thread should complete"));
    }

    // All threads see the same value
    let first = results[0];
    let all_same = results.iter().all(|&v| v == first);
    assert_with_log!(
        all_same,
        "all threads should see same value",
        true,
        all_same
    );

    // Init function ran exactly once
    let inits = init_count.load(Ordering::SeqCst);
    assert_with_log!(inits == 1, "init should run exactly once", 1, inits);

    test_complete!("sync_006_oncecell_initialization");
}

/// SYNC-007: Notify (Condvar-style) Notification
///
/// Verifies that:
/// - notify_one wakes exactly one waiter
/// - notify_waiters wakes all waiters
/// - waiter_count tracks registered waiters
#[test]
fn sync_007_notify_notification() {
    init_test("sync_007_notify_notification");

    // Initial state: no waiters
    let notify = Notify::new();
    assert_with_log!(
        notify.waiter_count() == 0,
        "should start with no waiters",
        0,
        notify.waiter_count()
    );

    // notify_one: wakes exactly one waiter
    {
        let notify = Arc::new(Notify::new());
        let woke = Arc::new(AtomicBool::new(false));
        let woke_clone = Arc::clone(&woke);
        let notify_clone = Arc::clone(&notify);

        let handle = thread::spawn(move || {
            block_on(notify_clone.notified());
            woke_clone.store(true, Ordering::SeqCst);
        });

        // Wait for waiter to register
        while notify.waiter_count() == 0 {
            thread::yield_now();
        }

        notify.notify_one();
        handle.join().expect("notify_one thread should complete");

        let was_woken = woke.load(Ordering::SeqCst);
        assert_with_log!(
            was_woken,
            "notify_one should wake the waiter",
            true,
            was_woken
        );
    }

    // notify_waiters: wakes all waiters
    {
        let notify = Arc::new(Notify::new());
        let num_waiters: usize = 4;
        let woke_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..num_waiters)
            .map(|_| {
                let notify = Arc::clone(&notify);
                let woke_count = Arc::clone(&woke_count);
                thread::spawn(move || {
                    block_on(notify.notified());
                    woke_count.fetch_add(1, Ordering::SeqCst);
                })
            })
            .collect();

        // Wait for all waiters to register
        while notify.waiter_count() < num_waiters {
            thread::yield_now();
        }

        notify.notify_waiters();

        for handle in handles {
            handle
                .join()
                .expect("notify_waiters thread should complete");
        }

        let total_woken = woke_count.load(Ordering::SeqCst);
        assert_with_log!(
            total_woken == num_waiters,
            "notify_waiters should wake all",
            num_waiters,
            total_woken
        );
    }

    // notify_one with multiple waiters: wakes exactly one
    {
        let notify = Arc::new(Notify::new());
        let num_waiters: usize = 3;
        let woke_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..num_waiters)
            .map(|_| {
                let notify = Arc::clone(&notify);
                let woke_count = Arc::clone(&woke_count);
                thread::spawn(move || {
                    block_on(notify.notified());
                    woke_count.fetch_add(1, Ordering::SeqCst);
                })
            })
            .collect();

        // Wait for all waiters to register
        while notify.waiter_count() < num_waiters {
            thread::yield_now();
        }

        // Notify one at a time
        for i in 0..num_waiters {
            notify.notify_one();
            // Wait for one waiter to wake
            while woke_count.load(Ordering::SeqCst) < i + 1 {
                thread::yield_now();
            }
        }

        for handle in handles {
            handle
                .join()
                .expect("sequential notify thread should complete");
        }

        let total_woken = woke_count.load(Ordering::SeqCst);
        assert_with_log!(
            total_woken == num_waiters,
            "sequential notify_one should wake all",
            num_waiters,
            total_woken
        );
    }

    test_complete!("sync_007_notify_notification");
}

/// SYNC-005c: Semaphore Fairness Ordering Conformance vs tokio::sync::Semaphore
///
/// Verifies that asupersync::sync::Semaphore and tokio::sync::Semaphore produce
/// identical fairness ordering when given:
/// - Same N permits
/// - Same K acquirers in same order
/// - Same permit request sizes
///
/// This is a differential conformance test ensuring FIFO fairness compatibility.
#[test]
fn sync_005c_semaphore_fairness_conformance() {
    init_test("sync_005c_semaphore_fairness_conformance");

    // Test case: 3 permits, 5 acquirers (2 oversubscribed)
    let permit_count = 3;
    let acquirer_requests = vec![(0, 1), (1, 1), (2, 1), (3, 1), (4, 1)];

    // Run asupersync test
    let asupersync_results = run_asupersync_semaphore_test(permit_count, &acquirer_requests);

    // Run tokio test
    let tokio_results = run_tokio_semaphore_test(permit_count, &acquirer_requests);

    // Compare fairness ordering
    assert_with_log!(
        asupersync_results.len() == tokio_results.len(),
        "result count should match",
        tokio_results.len(),
        asupersync_results.len()
    );

    // Verify grant ordering matches (FIFO fairness)
    for (i, (asup, tokio)) in asupersync_results
        .iter()
        .zip(tokio_results.iter())
        .enumerate()
    {
        assert_with_log!(
            asup.0 == tokio.0,
            format!("fairness ordering should match at position {}", i),
            tokio.0,
            asup.0
        );
    }

    // Test oversubscribed scenario (more requests than permits)
    let permit_count = 2;
    let acquirer_requests = vec![(0, 1), (1, 2), (2, 1)]; // 4 permits requested, 2 available

    let asupersync_results = run_asupersync_semaphore_test(permit_count, &acquirer_requests);
    let tokio_results = run_tokio_semaphore_test(permit_count, &acquirer_requests);

    // First two acquirers should get permits in FIFO order
    assert_with_log!(
        asupersync_results.len() >= 2,
        "should have at least 2 grants in oversubscribed test",
        ">= 2",
        asupersync_results.len()
    );

    for (i, (asup, tokio)) in asupersync_results
        .iter()
        .zip(tokio_results.iter())
        .enumerate()
        .take(2)
    {
        assert_with_log!(
            asup.0 == tokio.0,
            format!("oversubscribed fairness should match at position {}", i),
            tokio.0,
            asup.0
        );
    }

    test_complete!("sync_005c_semaphore_fairness_conformance");
}

/// Run asupersync semaphore test and return (acquirer_id, grant_order) pairs.
fn run_asupersync_semaphore_test(
    permit_count: usize,
    requests: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    use futures_lite::future::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    let sem = Arc::new(Semaphore::new(permit_count));
    let grant_counter = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let handles: Vec<_> = requests
        .iter()
        .map(|&(acquirer_id, permit_count)| {
            let sem = sem.clone();
            let grant_counter = grant_counter.clone();
            let results = results.clone();

            thread::spawn(move || {
                let cx = Cx::for_testing();

                // Small delay to ensure deterministic ordering
                thread::sleep(std::time::Duration::from_millis(acquirer_id as u64 * 10));

                if let Ok(_permit) = block_on(sem.acquire(&cx, permit_count)) {
                    let grant_order = grant_counter.fetch_add(1, Ordering::SeqCst);
                    results.lock().unwrap().push((acquirer_id, grant_order));

                    // Hold permit briefly to ensure ordering is observable
                    thread::sleep(std::time::Duration::from_millis(50));
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let mut results = results.lock().unwrap().clone();
    results.sort_by_key(|&(_, grant_order)| grant_order);
    results
}

/// Run tokio semaphore test and return (acquirer_id, grant_order) pairs.
fn run_tokio_semaphore_test(
    permit_count: usize,
    requests: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    // Use basic tokio runtime for this test
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let sem = Arc::new(tokio::sync::Semaphore::new(permit_count));
        let grant_counter = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let mut handles = Vec::new();

        for &(acquirer_id, permit_count) in requests {
            let sem = sem.clone();
            let grant_counter = grant_counter.clone();
            let results = results.clone();

            let handle = tokio::spawn(async move {
                // Small delay to ensure deterministic ordering
                tokio::time::sleep(std::time::Duration::from_millis(acquirer_id as u64 * 10)).await;

                if let Ok(_permit) = sem.acquire_many(permit_count as u32).await {
                    let grant_order = grant_counter.fetch_add(1, Ordering::SeqCst);
                    results.lock().await.push((acquirer_id, grant_order));

                    // Hold permit briefly to ensure ordering is observable
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let mut results = results.lock().await.clone();
        results.sort_by_key(|&(_, grant_order)| grant_order);
        results
    })
}

/// CODEC-001: LengthDelimitedCodec Frame Boundary Conformance
///
/// Verifies that our LengthDelimitedCodec produces byte-identical frame
/// boundaries compared to tokio_util::codec::LengthDelimitedCodec when
/// given the same byte sequence and framing configuration.
#[test]
fn codec_001_length_delimited_frame_boundary_conformance() {
    init_test("codec_001_length_delimited_frame_boundary_conformance");

    // Test case 1: Basic frames with default configuration
    let test_data = create_basic_test_frames();
    test_codec_differential(&test_data, "default");

    // Test case 2: Custom configuration - 2-byte little-endian length
    let test_data = create_2byte_little_endian_frames();
    test_codec_differential(&test_data, "2byte_little_endian");

    // Test case 3: Multiple frames in single buffer
    let test_data = create_multiple_frames();
    test_codec_differential(&test_data, "multiple_frames");

    test_complete!("codec_001_length_delimited_frame_boundary_conformance");
}

/// Test our codec vs tokio's codec for differential conformance
fn test_codec_differential(test_data: &[u8], config_name: &str) {
    use tokio_util::codec::{Decoder as TokioDecoder, LengthDelimitedCodec as TokioCodec};

    // Create codecs with same configuration
    let mut asupersync_codec = AsupersyncCodec::new();
    let mut tokio_codec = TokioCodec::new();

    // For 2-byte little-endian test case
    if config_name == "2byte_little_endian" {
        asupersync_codec = AsupersyncCodec::builder()
            .length_field_length(2)
            .little_endian()
            .new_codec();
        tokio_codec = TokioCodec::builder()
            .length_field_length(2)
            .little_endian()
            .new_codec();
    }

    // Decode all frames with both codecs
    let asupersync_frames = decode_all_frames_asupersync(&mut asupersync_codec, test_data.to_vec());
    let tokio_frames = decode_all_frames_tokio(&mut tokio_codec, test_data.to_vec());

    // Compare frame count
    assert_with_log!(
        asupersync_frames.len() == tokio_frames.len(),
        format!("[{}] frame count should match", config_name),
        tokio_frames.len(),
        asupersync_frames.len()
    );

    // Compare each frame byte-for-byte
    for (i, (asup_result, tokio_result)) in asupersync_frames
        .iter()
        .zip(tokio_frames.iter())
        .enumerate()
    {
        match (asup_result, tokio_result) {
            (Ok(asup_frame), Ok(tokio_frame)) => {
                let asup_bytes = asup_frame.clone().freeze();
                assert_with_log!(
                    asup_bytes == *tokio_frame,
                    format!("[{}] frame {} bytes should match", config_name, i),
                    format!("{:?}", tokio_frame),
                    format!("{:?}", asup_bytes)
                );
            }
            (Err(asup_err), Err(tokio_err)) => {
                // Both should error with same error kind
                assert_with_log!(
                    asup_err.kind() == tokio_err.kind(),
                    format!("[{}] frame {} error kinds should match", config_name, i),
                    format!("{:?}", tokio_err.kind()),
                    format!("{:?}", asup_err.kind())
                );
            }
            (Ok(_), Err(tokio_err)) => {
                panic!(
                    "[{}] frame {}: asupersync succeeded but tokio failed with {:?}",
                    config_name, i, tokio_err
                );
            }
            (Err(asup_err), Ok(_)) => {
                panic!(
                    "[{}] frame {}: tokio succeeded but asupersync failed with {:?}",
                    config_name, i, asup_err
                );
            }
        }
    }
}

/// Decode all frames using asupersync codec
fn decode_all_frames_asupersync(
    codec: &mut AsupersyncCodec,
    data: Vec<u8>,
) -> Vec<Result<BytesMut, io::Error>> {
    let mut frames = Vec::new();
    let mut buf = BytesMut::from(&data[..]);

    while !buf.is_empty() {
        let initial_len = buf.len();

        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                frames.push(Ok(frame));
            }
            Ok(None) => {
                // Need more data, but we don't have any more
                break;
            }
            Err(e) => {
                frames.push(Err(e));
                break;
            }
        }

        // Prevent infinite loop
        if buf.len() == initial_len {
            break;
        }
    }

    frames
}

/// Decode all frames using tokio codec
fn decode_all_frames_tokio(
    codec: &mut tokio_util::codec::LengthDelimitedCodec,
    data: Vec<u8>,
) -> Vec<Result<Bytes, io::Error>> {
    use tokio_util::codec::Decoder as TokioDecoder;

    let mut frames = Vec::new();
    // Use tokio's BytesMut for tokio codec
    let mut buf = tokio_util::bytes::BytesMut::from(&data[..]);

    while !buf.is_empty() {
        let initial_len = buf.len();

        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                // Convert from tokio's Bytes to asupersync's Bytes
                let asupersync_bytes = Bytes::copy_from_slice(&frame);
                frames.push(Ok(asupersync_bytes));
            }
            Ok(None) => {
                // Need more data, but we don't have any more
                break;
            }
            Err(e) => {
                frames.push(Err(e));
                break;
            }
        }

        // Prevent infinite loop
        if buf.len() == initial_len {
            break;
        }
    }

    frames
}

/// Create basic test frames (default 4-byte big-endian length)
fn create_basic_test_frames() -> Vec<u8> {
    let mut buf = Vec::new();

    // Frame 1: "hello" (5 bytes)
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(b"hello");

    // Frame 2: "world" (5 bytes)
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(b"world");

    // Frame 3: empty frame
    buf.extend_from_slice(&0u32.to_be_bytes());

    buf
}

/// Create test frames with 2-byte little-endian length
fn create_2byte_little_endian_frames() -> Vec<u8> {
    let mut buf = Vec::new();

    // Frame 1: "hi" (2 bytes)
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(b"hi");

    // Frame 2: "ok" (2 bytes)
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(b"ok");

    buf
}

/// Create multiple frames in single buffer
fn create_multiple_frames() -> Vec<u8> {
    let mut buf = Vec::new();

    // Create 5 small frames
    for i in 0..5 {
        let data = format!("frame{}", i);
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data.as_bytes());
    }

    buf
}

/// HEAP-001: IntrusivePriorityHeap vs BinaryHeap Pop Order Conformance
///
/// Verifies that our IntrusivePriorityHeap produces identical popping order
/// compared to std::collections::BinaryHeap when given the same insert/pop
/// sequence.
#[test]
fn heap_001_intrusive_heap_vs_binary_heap_conformance() {
    init_test("heap_001_intrusive_heap_vs_binary_heap_conformance");

    // Test case 1: Simple priority sequence
    let test_sequence = vec![
        HeapOperation::Insert(10),
        HeapOperation::Insert(5),
        HeapOperation::Insert(15),
        HeapOperation::Insert(3),
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Insert(12),
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
    ];
    test_heap_conformance(&test_sequence, "simple_priority");

    // Test case 2: Reverse order inserts
    let test_sequence = vec![
        HeapOperation::Insert(1),
        HeapOperation::Insert(2),
        HeapOperation::Insert(3),
        HeapOperation::Insert(4),
        HeapOperation::Insert(5),
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
    ];
    test_heap_conformance(&test_sequence, "reverse_order");

    // Test case 3: Mixed operations
    let test_sequence = vec![
        HeapOperation::Insert(8),
        HeapOperation::Pop,
        HeapOperation::Insert(4),
        HeapOperation::Insert(12),
        HeapOperation::Insert(6),
        HeapOperation::Pop,
        HeapOperation::Insert(2),
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
    ];
    test_heap_conformance(&test_sequence, "mixed_operations");

    // Test case 4: Duplicate priorities
    let test_sequence = vec![
        HeapOperation::Insert(7),
        HeapOperation::Insert(7),
        HeapOperation::Insert(7),
        HeapOperation::Insert(3),
        HeapOperation::Insert(11),
        HeapOperation::Insert(7),
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
        HeapOperation::Pop,
    ];
    test_heap_conformance(&test_sequence, "duplicate_priorities");

    test_complete!("heap_001_intrusive_heap_vs_binary_heap_conformance");
}

#[derive(Debug, Clone)]
enum HeapOperation {
    Insert(u8), // Priority value
    Pop,
}

/// Test heap conformance between intrusive heap and std BinaryHeap
fn test_heap_conformance(operations: &[HeapOperation], test_name: &str) {
    // Set up intrusive heap
    let mut arena = setup_heap_arena();
    let mut intrusive_heap = IntrusivePriorityHeap::new();

    // Set up standard library heap (max heap like intrusive heap)
    let mut std_heap = BinaryHeap::new();

    let mut task_counter = 0u32;

    // Execute operations on both heaps
    let mut intrusive_results = Vec::new();
    let mut std_results = Vec::new();

    for operation in operations {
        match operation {
            HeapOperation::Insert(priority) => {
                let task_id = TaskId::from_arena(ArenaIndex::new(task_counter, 0));

                // Ensure arena has enough capacity
                while arena.len() <= task_counter as usize {
                    let new_task_id = TaskId::from_arena(ArenaIndex::new(arena.len() as u32, 0));
                    let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));
                    let record = TaskRecord::new(new_task_id, region_id, Budget::INFINITE);
                    arena.insert(record);
                }

                // Insert into both heaps
                intrusive_heap.push(task_id, *priority, &mut arena);
                std_heap.push(*priority);

                task_counter += 1;
            }
            HeapOperation::Pop => {
                // Pop from intrusive heap
                let intrusive_result = intrusive_heap.pop(&mut arena);
                let intrusive_priority = intrusive_result.and_then(|task_id| {
                    arena
                        .get(task_id.arena_index())
                        .map(|record| record.sched_priority)
                });

                // Pop from std heap
                let std_priority = std_heap.pop();

                intrusive_results.push(intrusive_priority);
                std_results.push(std_priority);
            }
        }
    }

    // Compare results
    assert_with_log!(
        intrusive_results.len() == std_results.len(),
        format!("[{}] result count should match", test_name),
        std_results.len(),
        intrusive_results.len()
    );

    for (i, (intrusive_opt, std_opt)) in
        intrusive_results.iter().zip(std_results.iter()).enumerate()
    {
        match (intrusive_opt, std_opt) {
            (Some(intrusive_priority), Some(std_priority)) => {
                assert_with_log!(
                    intrusive_priority == std_priority,
                    format!("[{}] priority should match at pop {}", test_name, i),
                    std_priority,
                    intrusive_priority
                );
            }
            (None, None) => {
                // Both heaps are empty - this is correct
            }
            (intrusive_opt, std_opt) => {
                panic!(
                    "[{}] pop {} mismatch: intrusive={:?}, std={:?}",
                    test_name, i, intrusive_opt, std_opt
                );
            }
        }
    }
}

/// Set up arena for heap testing
fn setup_heap_arena() -> Arena<TaskRecord> {
    Arena::new()
}
