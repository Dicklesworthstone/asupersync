//! Sync Primitives Test Suite
//!
//! Conformance tests for synchronization primitives as specified in
//! the Asupersync design document.
//!
//! Test Coverage:
//! - SYNC-001: Mutex Basic Lock/Unlock
//! - SYNC-002: Mutex Contention Correctness
//! - SYNC-003: RwLock Reader/Writer Priority (TODO: awaits RwLock)
//! - SYNC-004: Barrier Synchronization (TODO: awaits Barrier)
//! - SYNC-005: Semaphore Permit Limiting
//! - SYNC-006: OnceCell Initialization (TODO: awaits OnceCell)
//! - SYNC-007: Condvar Notification (TODO: awaits Condvar)

// Allow significant_drop_tightening in tests - the scoped blocks are for clarity
#![allow(clippy::significant_drop_tightening)]

use asupersync::sync::{Mutex, Semaphore};
use asupersync::Cx;
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
    let cx = Cx::for_testing();
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
    use std::sync::Arc;
    use std::thread;

    let mutex = Arc::new(Mutex::new(0i64));
    let iterations = 1000;
    let num_threads = 4;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let mutex = Arc::clone(&mutex);
            thread::spawn(move || {
                let cx = Cx::for_testing();
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

    let cx = Cx::for_testing();
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
    use asupersync::sync::LockError;
    use std::sync::Arc;
    use std::thread;

    let mutex = Arc::new(Mutex::new(0));
    let cx_main = Cx::for_testing();

    // Hold the lock
    let _guard = block_on(mutex.lock(&cx_main)).expect("lock should succeed");

    // Spawn a thread that will try to lock with a cancelled context
    let mutex_clone = Arc::clone(&mutex);
    let handle = thread::spawn(move || {
        let cx = Cx::for_testing();
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
/// TODO: Implement when RwLock is available.
/// This test will verify:
/// - Multiple readers can hold the lock simultaneously
/// - Writers have exclusive access
/// - Writer starvation is prevented
#[test]
#[ignore = "RwLock not yet implemented"]
fn sync_003_rwlock_reader_writer_priority() {
    init_test("sync_003_rwlock_reader_writer_priority");
    // Placeholder for RwLock tests
    test_complete!("sync_003_rwlock_reader_writer_priority");
}

/// SYNC-004: Barrier Synchronization
///
/// TODO: Implement when Barrier is available.
/// This test will verify:
/// - All threads wait until the barrier count is reached
/// - Threads proceed together after barrier release
#[test]
#[ignore = "Barrier not yet implemented"]
fn sync_004_barrier_synchronization() {
    init_test("sync_004_barrier_synchronization");
    // Placeholder for Barrier tests
    test_complete!("sync_004_barrier_synchronization");
}

/// SYNC-005: Semaphore Permit Limiting
///
/// Verifies that a semaphore correctly limits concurrent access
/// to the specified number of permits.
#[test]
fn sync_005_semaphore_permit_limiting() {
    init_test("sync_005_semaphore_permit_limiting");
    let cx = Cx::for_testing();
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

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
                let cx = Cx::for_testing();
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
/// TODO: Implement when OnceCell is available.
/// This test will verify:
/// - Value is initialized exactly once
/// - Concurrent initialization attempts block and return same value
/// - get() before initialization returns None
#[test]
#[ignore = "OnceCell not yet implemented"]
fn sync_006_oncecell_initialization() {
    init_test("sync_006_oncecell_initialization");
    // Placeholder for OnceCell tests
    test_complete!("sync_006_oncecell_initialization");
}

/// SYNC-007: Condvar Notification
///
/// TODO: Implement when Condvar is available.
/// This test will verify:
/// - notify_one wakes one waiter
/// - notify_all wakes all waiters
/// - Spurious wakeups are handled correctly
#[test]
#[ignore = "Condvar not yet implemented"]
fn sync_007_condvar_notification() {
    init_test("sync_007_condvar_notification");
    // Placeholder for Condvar tests
    test_complete!("sync_007_condvar_notification");
}
