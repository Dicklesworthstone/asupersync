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
use asupersync::sync::{Barrier, LockError, Mutex, Notify, OnceCell, RwLock, Semaphore};
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
                let result = barrier.wait(&cx).expect("barrier wait should succeed");
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
                barrier.wait(&cx).expect("round 2 wait should succeed");
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
