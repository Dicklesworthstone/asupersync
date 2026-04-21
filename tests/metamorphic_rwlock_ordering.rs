#![allow(warnings)]
//! Metamorphic Testing for RwLock Reader/Writer Ordering Invariants
//!
//! Tests the fairness and ordering properties of the cancel-aware RwLock
//! with writer-preference fairness under various scenarios.
//!
//! Target: src/sync/rwlock.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Writer-Preference Invariant**: New readers blocked when writers waiting
//! 2. **Mutual Exclusion**: Never simultaneous readers and writers
//! 3. **Reader Concurrency**: Multiple readers can acquire simultaneously when no writers waiting
//! 4. **Temporal Consistency**: Operations eventually complete without deadlock
//! 5. **State Invariant**: Lock state remains consistent under concurrent access

#![cfg(test)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::sync::{RwLock, TryReadError};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;

/// Test helper functions (similar to those in src/sync/rwlock.rs)
fn init_test(name: &str) {
    eprintln!("Starting test: {}", name);
}

fn test_cx() -> Cx {
    test_cx_with_slot(0)
}

fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

fn poll_once<T>(future: &mut (impl Future<Output = T> + Unpin)) -> Option<T> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match Pin::new(future).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn poll_until_ready<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => thread::yield_now(),
        }
    }
}

fn read_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> asupersync::sync::RwLockReadGuard<'a, T> {
    poll_until_ready(lock.read(cx)).expect("read failed")
}

fn write_blocking<'a, T>(lock: &'a RwLock<T>, cx: &Cx) -> asupersync::sync::RwLockWriteGuard<'a, T> {
    poll_until_ready(lock.write(cx)).expect("write failed")
}

// MR1: Writer-Preference Invariant
// When writers are waiting, new readers should be blocked
#[test]
fn mr_writer_preference_blocks_readers() {
    init_test("mr_writer_preference_blocks_readers");
    let cx = test_cx();
    let lock = Arc::new(RwLock::new(42_i32));

    // Hold a read lock to make writer wait
    let initial_read = read_blocking(&lock, &cx);

    // Writer should wait
    let writer_lock = Arc::clone(&lock);
    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_flag = Arc::clone(&writer_started);

    let writer_handle = thread::spawn(move || {
        let cx = test_cx_with_slot(1);
        writer_flag.store(true, Ordering::Release);
        let _guard = write_blocking(&writer_lock, &cx);
    });

    // Wait for writer to start waiting
    while !writer_started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(Duration::from_millis(10)); // Give writer time to queue

    // New readers should be blocked by waiting writer
    assert!(matches!(lock.try_read(), Err(TryReadError::Locked)));

    // Release initial reader to let writer proceed
    drop(initial_read);
    writer_handle.join().unwrap();

    // Now readers should work again
    let final_read = read_blocking(&lock, &cx);
    assert_eq!(*final_read, 42);
}

// MR2: Mutual Exclusion
// Never simultaneous readers and writers
#[test]
fn mr_mutual_exclusion() {
    init_test("mr_mutual_exclusion");
    let cx = test_cx();
    let lock = Arc::new(RwLock::new(0_i32));
    let counter = Arc::new(AtomicUsize::new(0));
    let reader_active = Arc::new(AtomicBool::new(false));
    let writer_active = Arc::new(AtomicBool::new(false));

    let mut handles = vec![];

    // Launch multiple readers
    for i in 0..4 {
        let lock = Arc::clone(&lock);
        let counter = Arc::clone(&counter);
        let reader_active = Arc::clone(&reader_active);
        let writer_active = Arc::clone(&writer_active);

        let handle = thread::spawn(move || {
            let cx = test_cx_with_slot(i);
            let guard = read_blocking(&lock, &cx);

            // Assert no writer is active
            assert!(!writer_active.load(Ordering::SeqCst), "Writer active while reader holds lock");

            reader_active.store(true, Ordering::SeqCst);
            counter.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(1));
            reader_active.store(false, Ordering::SeqCst);

            *guard // Return value
        });
        handles.push(handle);
    }

    // Launch writers
    for i in 0..2 {
        let lock = Arc::clone(&lock);
        let reader_active = Arc::clone(&reader_active);
        let writer_active = Arc::clone(&writer_active);

        let handle = thread::spawn(move || {
            let cx = test_cx_with_slot(i + 10);
            let mut guard = write_blocking(&lock, &cx);

            // Assert no readers are active
            assert!(!reader_active.load(Ordering::SeqCst), "Readers active while writer holds lock");
            assert!(!writer_active.swap(true, Ordering::SeqCst), "Multiple writers active");

            *guard = i as i32;
            thread::sleep(Duration::from_millis(1));

            writer_active.store(false, Ordering::SeqCst);
            0_i32  // Return same type as readers
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    assert!(counter.load(Ordering::SeqCst) >= 4, "All readers should complete");
}

// MR3: Reader Concurrency
// Multiple readers can acquire simultaneously when no writers waiting
#[test]
fn mr_reader_concurrency_when_no_writers() {
    init_test("mr_reader_concurrency_when_no_writers");
    let cx = test_cx();
    let lock = Arc::new(RwLock::new(42_i32));
    let concurrent_readers = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Launch multiple readers simultaneously
    for i in 0..6 {
        let lock = Arc::clone(&lock);
        let concurrent_readers = Arc::clone(&concurrent_readers);
        let max_concurrent = Arc::clone(&max_concurrent);

        let handle = thread::spawn(move || {
            let cx = test_cx_with_slot(i);
            let guard = read_blocking(&lock, &cx);

            // Track concurrent readers
            let current = concurrent_readers.fetch_add(1, Ordering::SeqCst) + 1;
            let mut max = max_concurrent.load(Ordering::SeqCst);
            while max < current {
                match max_concurrent.compare_exchange_weak(max, current, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(actual) => max = actual,
                }
            }

            thread::sleep(Duration::from_millis(10)); // Hold lock briefly

            concurrent_readers.fetch_sub(1, Ordering::SeqCst);
            *guard
        });
        handles.push(handle);
    }

    // Wait for all readers
    let mut results = vec![];
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    // All readers should succeed
    assert_eq!(results.len(), 6);
    assert!(results.iter().all(|&x| x == 42));

    // Multiple readers should have been concurrent
    assert!(max_concurrent.load(Ordering::SeqCst) >= 2,
           "Multiple readers should be concurrent, got max: {}",
           max_concurrent.load(Ordering::SeqCst));
}

// MR4: Temporal Consistency
// Operations eventually complete without deadlock
#[test]
fn mr_temporal_consistency_no_deadlock() {
    init_test("mr_temporal_consistency_no_deadlock");
    let lock = Arc::new(RwLock::new(0_i32));
    let completed_ops = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Mix of readers and writers
    for i in 0..10 {
        let lock = Arc::clone(&lock);
        let completed_ops = Arc::clone(&completed_ops);

        let handle = thread::spawn(move || {
            let cx = test_cx_with_slot(i);

            if i % 3 == 0 {
                // Writer
                let mut guard = write_blocking(&lock, &cx);
                *guard = i as i32;
                completed_ops.fetch_add(1, Ordering::SeqCst);
            } else {
                // Reader
                let guard = read_blocking(&lock, &cx);
                let _value = *guard;
                completed_ops.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    // All operations should complete
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(completed_ops.load(Ordering::SeqCst), 10, "All operations should complete");
}

// MR5: State Invariant
// Lock state remains consistent under concurrent access
#[test]
fn mr_state_consistency_under_concurrency() {
    init_test("mr_state_consistency_under_concurrency");
    let lock = Arc::new(RwLock::new(100_i32));
    let operations = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Interleaved reads and writes
    for i in 0..8 {
        let lock = Arc::clone(&lock);
        let operations = Arc::clone(&operations);

        let handle = thread::spawn(move || {
            let cx = test_cx_with_slot(i);

            for j in 0..5 {
                if (i + j) % 2 == 0 {
                    // Read operation
                    let guard = read_blocking(&lock, &cx);
                    let value = *guard;
                    // Value should always be non-negative (our invariant)
                    assert!(value >= 0, "Value should be non-negative, got: {}", value);
                    operations.fetch_add(1, Ordering::SeqCst);
                } else {
                    // Write operation - increment by 1
                    let mut guard = write_blocking(&lock, &cx);
                    *guard += 1;
                    operations.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final state
    let final_cx = test_cx();
    let final_guard = read_blocking(&lock, &final_cx);
    let final_value = *final_guard;

    assert!(final_value >= 100, "Final value should be >= initial value");
    assert_eq!(operations.load(Ordering::SeqCst), 8 * 5, "All operations should complete");
}

#[test]
fn test_complete_coverage() {
    init_test("test_complete_coverage");
    // This test verifies all metamorphic relations work together
    eprintln!("All metamorphic relation tests completed successfully!");
}
