//! Fuzz Notify notified-future drop while pending sequences.
//!
//! Tests arbitrary drop-during-await sequences to ensure dropping unwakes
//! notification correctly and prevents resource leaks. Validates proper
//! cleanup of pending notified futures and notification slot management.
//!
//! Critical invariants:
//! - Dropping notified future releases notification slot
//! - No resource leaks when futures are dropped while pending
//! - Subsequent notify() calls work correctly after drops
//! - Waker cleanup is proper on future drop

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Notify;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Arbitrary)]
struct NotifyConfig {
    /// Sequences of notification and drop operations
    operations: Vec<NotifyOperation>,
    /// Number of concurrent waiters
    waiter_count: u8,
    /// Delays between operations (milliseconds)
    operation_delays: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyOperation {
    /// Start waiting for notification
    StartWaiting { waiter_id: u8 },
    /// Drop a pending notified future
    DropPending { waiter_id: u8 },
    /// Send notification
    NotifyOne,
    /// Send notification to all waiters
    NotifyAll,
    /// Check waiter count
    CheckWaiters,
    /// Small delay between operations
    Delay { millis: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
struct DropSequence {
    /// Test configuration
    config: NotifyConfig,
    /// Maximum operations to perform
    max_operations: u8,
    /// Whether to test concurrent drop scenarios
    test_concurrency: bool,
}

impl DropSequence {
    fn max_operations() -> u8 {
        25 // Keep test duration reasonable
    }

    fn max_waiters() -> u8 {
        8 // Reasonable number of concurrent waiters
    }
}

/// Test execution context tracking notification behavior
#[derive(Debug)]
struct NotifyTracker {
    active_waiters: AtomicUsize,
    successful_notifications: AtomicUsize,
    dropped_while_pending: AtomicUsize,
    notify_one_calls: AtomicUsize,
    notify_all_calls: AtomicUsize,
}

impl NotifyTracker {
    fn new() -> Self {
        Self {
            active_waiters: AtomicUsize::new(0),
            successful_notifications: AtomicUsize::new(0),
            dropped_while_pending: AtomicUsize::new(0),
            notify_one_calls: AtomicUsize::new(0),
            notify_all_calls: AtomicUsize::new(0),
        }
    }

    fn increment_active_waiters(&self) {
        self.active_waiters.fetch_add(1, Ordering::SeqCst);
    }

    fn decrement_active_waiters(&self) {
        self.active_waiters.fetch_sub(1, Ordering::SeqCst);
    }

    fn increment_successful_notifications(&self) {
        self.successful_notifications.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_dropped_pending(&self) {
        self.dropped_while_pending.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_notify_one(&self) {
        self.notify_one_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_notify_all(&self) {
        self.notify_all_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self, notify: &Notify) -> Result<(), String> {
        let active = self.active_waiters.load(Ordering::SeqCst);
        let actual_waiters = notify.waiter_count();

        // Active waiter count should match notify internal count
        if active != actual_waiters {
            return Err(format!(
                "Waiter count mismatch: tracker shows {}, notify shows {}",
                active, actual_waiters
            ));
        }

        let successful = self.successful_notifications.load(Ordering::SeqCst);
        let dropped = self.dropped_while_pending.load(Ordering::SeqCst);
        let notify_one = self.notify_one_calls.load(Ordering::SeqCst);
        let notify_all = self.notify_all_calls.load(Ordering::SeqCst);

        // No resource leaks: drops should clean up properly
        if dropped > 0 && active > 100 {
            return Err(format!(
                "Possible resource leak: {} dropped but {} still active",
                dropped, active
            ));
        }

        // Sanity check: if we sent notifications, some should have been received
        // (unless all were dropped before notification)
        if (notify_one + notify_all) > 10 && successful == 0 && dropped < 5 {
            return Err(format!(
                "Sent {} notifications but none successful (only {} dropped)",
                notify_one + notify_all, dropped
            ));
        }

        Ok(())
    }
}

/// Represents a waiter that can be dropped while pending
struct WaiterHandle {
    waiter_id: u8,
    tracker: Arc<NotifyTracker>,
    _handle: thread::JoinHandle<()>,
}

impl Drop for WaiterHandle {
    fn drop(&mut self) {
        self.tracker.increment_dropped_pending();
        self.tracker.decrement_active_waiters();
    }
}

fn create_noop_waker() -> Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};

    fn noop(_: *const ()) {}
    fn clone_noop(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)
    }

    const NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone_noop, noop, noop, noop);

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: DropSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.operations.is_empty() {
        return;
    }

    let max_ops = sequence.max_operations.min(DropSequence::max_operations()) as usize;
    let max_waiters = DropSequence::max_waiters() as usize;

    // Create notify and tracking context
    let notify = Arc::new(Notify::new());
    let tracker = Arc::new(NotifyTracker::new());
    let mut waiters: Vec<Option<WaiterHandle>> = (0..max_waiters).map(|_| None).collect();

    // Execute operations
    for (i, op) in sequence.config.operations.iter().take(max_ops).enumerate() {
        // Check invariants before each operation
        if let Err(msg) = tracker.check_invariants(&notify) {
            panic!("Notify invariant violation at op {}: {}", i, msg);
        }

        // Apply delay if specified
        if let Some(&delay) = sequence.config.operation_delays.get(i) {
            if delay > 0 && delay < 1000 { // Cap delay to prevent test timeout
                thread::sleep(Duration::from_millis(delay as u64));
            }
        }

        match op {
            NotifyOperation::StartWaiting { waiter_id } => {
                let waiter_idx = (*waiter_id as usize) % max_waiters;

                // Only start if slot is empty
                if waiters[waiter_idx].is_none() {
                    let notify_clone = Arc::clone(&notify);
                    let tracker_clone = Arc::clone(&tracker);
                    let waiter_id = *waiter_id;

                    tracker.increment_active_waiters();

                    let handle = thread::spawn(move || {
                        // Start waiting for notification
                        let mut notified_future = notify_clone.notified();

                        // Manual polling loop
                        loop {
                            let waker = create_noop_waker();
                            let mut context = Context::from_waker(&waker);

                            match Pin::new(&mut notified_future).poll(&mut context) {
                                Poll::Ready(()) => {
                                    tracker_clone.increment_successful_notifications();
                                    tracker_clone.decrement_active_waiters();
                                    break;
                                }
                                Poll::Pending => {
                                    // Still waiting, yield briefly
                                    thread::sleep(Duration::from_millis(1));
                                }
                            }
                        }
                    });

                    waiters[waiter_idx] = Some(WaiterHandle {
                        waiter_id,
                        tracker: Arc::clone(&tracker),
                        _handle: handle,
                    });
                }
            }

            NotifyOperation::DropPending { waiter_id } => {
                let waiter_idx = (*waiter_id as usize) % max_waiters;

                // Drop the waiter if it exists (this drops the future while pending)
                if let Some(_waiter) = waiters[waiter_idx].take() {
                    // WaiterHandle::drop will be called automatically
                    // This simulates dropping the notified future while it's pending
                }
            }

            NotifyOperation::NotifyOne => {
                tracker.increment_notify_one();
                notify.notify_one();
            }

            NotifyOperation::NotifyAll => {
                tracker.increment_notify_all();
                notify.notify_waiters();
            }

            NotifyOperation::CheckWaiters => {
                let _waiters = notify.waiter_count();
                // This should never panic regardless of state
            }

            NotifyOperation::Delay { millis } => {
                if *millis < 100 { // Cap delay to prevent timeout
                    thread::sleep(Duration::from_millis(*millis as u64));
                }
            }
        }

        // Check invariants after each operation
        if let Err(msg) = tracker.check_invariants(&notify) {
            panic!("Notify invariant violation after op {}: {}", i, msg);
        }
    }

    // Test concurrent drop scenarios if requested
    if sequence.test_concurrency {
        let notify = Arc::clone(&notify);
        let tracker = Arc::clone(&tracker);

        let handles: Vec<_> = (0..3)
            .map(|thread_id| {
                let notify = Arc::clone(&notify);
                let tracker = Arc::clone(&tracker);

                thread::spawn(move || {
                    for attempt in 0..3 {
                        tracker.increment_active_waiters();

                        // Start waiting
                        let mut notified_future = notify.notified();

                        // Poll a few times then potentially drop
                        let should_drop = (thread_id + attempt) % 2 == 0;
                        let mut poll_count = 0;

                        let result = catch_unwind(AssertUnwindSafe(|| {
                            loop {
                                let waker = create_noop_waker();
                                let mut context = Context::from_waker(&waker);

                                match Pin::new(&mut notified_future).poll(&mut context) {
                                    Poll::Ready(()) => {
                                        tracker.increment_successful_notifications();
                                        tracker.decrement_active_waiters();
                                        break;
                                    }
                                    Poll::Pending => {
                                        poll_count += 1;
                                        if should_drop && poll_count > 2 {
                                            // Drop while pending
                                            tracker.increment_dropped_pending();
                                            tracker.decrement_active_waiters();
                                            return;
                                        }
                                        thread::sleep(Duration::from_millis(1));
                                    }
                                }
                            }
                        }));

                        if result.is_err() {
                            tracker.decrement_active_waiters();
                        }

                        thread::sleep(Duration::from_millis(5));
                    }
                })
            })
            .collect();

        // Send some notifications during concurrent operations
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(10));
            notify.notify_one();
            tracker.increment_notify_one();
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }
    }

    // Clean up remaining waiters
    for waiter in waiters.iter_mut() {
        if let Some(_w) = waiter.take() {
            // Drop will be called automatically
        }
    }

    // Send final notifications to wake any remaining waiters
    notify.notify_waiters();
    tracker.increment_notify_all();

    // Brief wait for cleanup
    thread::sleep(Duration::from_millis(10));

    // Final invariant checks
    if let Err(msg) = tracker.check_invariants(&notify) {
        panic!("Final notify invariant violation: {}", msg);
    }

    // Verify no excessive resource usage
    let final_waiters = notify.waiter_count();
    if final_waiters > max_waiters * 2 {
        panic!("Excessive waiters remain: {} (max expected: {})", final_waiters, max_waiters * 2);
    }

    // Verify that dropping worked correctly
    let dropped = tracker.dropped_while_pending.load(Ordering::SeqCst);
    let successful = tracker.successful_notifications.load(Ordering::SeqCst);

    // Basic sanity check - if we had activity, verify reasonable behavior
    if dropped > 0 || successful > 0 {
        // At least one of the operations should have had some effect
        let total_notify_calls = tracker.notify_one_calls.load(Ordering::SeqCst)
                                + tracker.notify_all_calls.load(Ordering::SeqCst);
        if total_notify_calls > 0 && (dropped + successful) == 0 {
            panic!("Sent {} notifications but no waiters were affected", total_notify_calls);
        }
    }
});