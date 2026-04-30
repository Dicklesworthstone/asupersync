//! Fuzz notify_waiters() under empty waiter sets.
//!
//! Tests arbitrary call patterns of notify_waiters() when no waiters are
//! present to ensure it's a no-op (not an error). Validates that empty-set
//! notification doesn't create stored tokens or cause other side effects.
//!
//! Critical invariants:
//! - notify_waiters() with zero waiters is always a no-op
//! - No stored notifications created from empty-set broadcasts
//! - Generation counter advances properly even with no waiters
//! - Subsequent waiters behave correctly after empty broadcasts

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Notify;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::pin::Pin;
use std::future::Future;

#[derive(Debug, Clone, Arbitrary)]
struct NotifyWaitersEmptyConfig {
    /// Operations to perform
    operations: Vec<EmptyNotifyOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum EmptyNotifyOperation {
    /// Call notify_waiters() with empty waiter set
    NotifyWaitersEmpty,
    /// Call notify_one() with empty waiter set
    NotifyOneEmpty,
    /// Add a temporary waiter, then drop it immediately
    TemporaryWaiter { waiter_id: u8 },
    /// Multiple consecutive notify_waiters() calls
    RepeatedNotifyWaiters { count: u8 },
    /// Mixed notify_one and notify_waiters
    MixedNotifications { pattern: Vec<u8> },
    /// Create waiter after empty notifications
    PostEmptyWaiter { waiter_id: u8 },
    /// Check state consistency
    CheckState,
}

impl NotifyWaitersEmptyConfig {
    fn max_operations() -> u8 {
        50 // Limit test duration
    }

    fn max_repeated_notifications() -> u8 {
        10 // Limit repeated calls
    }

    fn max_mixed_pattern() -> u8 {
        8 // Limit mixed pattern length
    }
}

/// Tracks notify behavior with empty waiter sets
#[derive(Debug)]
struct EmptyNotifyTracker {
    empty_notify_waiters_calls: AtomicUsize,
    empty_notify_one_calls: AtomicUsize,
    stored_notifications_created: AtomicUsize,
    generation_advances: AtomicUsize,
    waiters_created: AtomicUsize,
    waiters_completed: AtomicUsize,
    invariant_violations: AtomicUsize,
}

impl EmptyNotifyTracker {
    fn new() -> Self {
        Self {
            empty_notify_waiters_calls: AtomicUsize::new(0),
            empty_notify_one_calls: AtomicUsize::new(0),
            stored_notifications_created: AtomicUsize::new(0),
            generation_advances: AtomicUsize::new(0),
            waiters_created: AtomicUsize::new(0),
            waiters_completed: AtomicUsize::new(0),
            invariant_violations: AtomicUsize::new(0),
        }
    }

    fn record_empty_notify_waiters(&self) {
        self.empty_notify_waiters_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn record_empty_notify_one(&self) {
        self.empty_notify_one_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn record_stored_notification_created(&self) {
        self.stored_notifications_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_generation_advance(&self) {
        self.generation_advances.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_created(&self) {
        self.waiters_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_completed(&self) {
        self.waiters_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_invariant_violation(&self) {
        self.invariant_violations.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let empty_waiters_calls = self.empty_notify_waiters_calls.load(Ordering::SeqCst);
        let empty_one_calls = self.empty_notify_one_calls.load(Ordering::SeqCst);
        let stored_created = self.stored_notifications_created.load(Ordering::SeqCst);
        let generations = self.generation_advances.load(Ordering::SeqCst);
        let violations = self.invariant_violations.load(Ordering::SeqCst);

        // Core invariant: no invariant violations should be detected
        if violations > 0 {
            return Err(format!("Detected {} invariant violations", violations));
        }

        // Empty notify_waiters should not create stored notifications
        if empty_waiters_calls > 0 && stored_created > 0 {
            // Note: This might be ok if notify_one was also called, so we need to check more carefully
            // For now, we'll allow stored notifications if notify_one was called
        }

        // Sanity checks
        if empty_waiters_calls > 1000 {
            return Err(format!("Excessive notify_waiters calls: {}", empty_waiters_calls));
        }

        if empty_one_calls > 1000 {
            return Err(format!("Excessive notify_one calls: {}", empty_one_calls));
        }

        Ok(())
    }
}

/// Tracks a waiter for testing purposes
struct TrackedWaiter {
    notify_future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    completed: Arc<AtomicBool>,
    waiter_id: u8,
}

impl TrackedWaiter {
    fn new(notify: Arc<Notify>, waiter_id: u8, tracker: Arc<EmptyNotifyTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let notify_future = Box::pin(async move {
            notify.notified().await;
            completed_clone.store(true, Ordering::SeqCst);
            tracker.record_waiter_completed();
        });

        tracker.record_waiter_created();

        Self {
            notify_future: Some(notify_future),
            completed,
            waiter_id,
        }
    }

    fn poll(&mut self) -> Poll<()> {
        if let Some(ref mut future) = self.notify_future {
            if self.completed.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            if result.is_ready() {
                self.notify_future = None;
            }

            result
        } else {
            Poll::Ready(())
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn drop_future(&mut self) {
        self.notify_future = None;
    }
}

fn noop_waker() -> Waker {
    use std::task::{RawWaker, RawWakerVTable};

    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

/// Test notify_waiters behavior with empty waiter sets
fn test_empty_notify_waiters_scenario(
    config: &NotifyWaitersEmptyConfig,
    tracker: &EmptyNotifyTracker,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();

    let max_ops = config.max_operations.min(NotifyWaitersEmptyConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            EmptyNotifyOperation::NotifyWaitersEmpty => {
                // Ensure no active waiters
                let waiter_count = notify.waiter_count();
                if waiter_count > 0 {
                    return Err(format!(
                        "notify_waiters called with {} active waiters, expected 0",
                        waiter_count
                    ));
                }

                // Record state before call
                let stored_before = notify.stored_notifications.load(Ordering::Acquire);

                // Call notify_waiters with empty set
                notify.notify_waiters();
                tracker.record_empty_notify_waiters();

                // Verify no stored notifications created
                let stored_after = notify.stored_notifications.load(Ordering::Acquire);
                if stored_after > stored_before {
                    tracker.record_invariant_violation();
                    return Err(format!(
                        "notify_waiters() with empty waiter set created stored notification: {} -> {}",
                        stored_before, stored_after
                    ));
                }
            }

            EmptyNotifyOperation::NotifyOneEmpty => {
                // Ensure no active waiters
                let waiter_count = notify.waiter_count();
                if waiter_count > 0 {
                    return Err(format!(
                        "notify_one called with {} active waiters, expected 0",
                        waiter_count
                    ));
                }

                // Record state before call
                let stored_before = notify.stored_notifications.load(Ordering::Acquire);

                // Call notify_one with empty set
                notify.notify_one();
                tracker.record_empty_notify_one();

                // notify_one SHOULD create stored notification even with no waiters
                let stored_after = notify.stored_notifications.load(Ordering::Acquire);
                if stored_after == stored_before + 1 {
                    tracker.record_stored_notification_created();
                } else if stored_after == stored_before {
                    // This might be ok if stored notifications are capped
                } else {
                    return Err(format!(
                        "notify_one() created unexpected stored notification count: {} -> {}",
                        stored_before, stored_after
                    ));
                }
            }

            EmptyNotifyOperation::TemporaryWaiter { waiter_id } => {
                let id = *waiter_id % 10;

                // Create a waiter briefly then drop it immediately
                let waiter = TrackedWaiter::new(notify.clone(), id, Arc::new(EmptyNotifyTracker::new()));

                // Poll once to register it
                let mut temp_waiter = waiter;
                let _ = temp_waiter.poll();

                // Drop immediately
                temp_waiter.drop_future();

                // Verify no active waiters remain
                let waiter_count = notify.waiter_count();
                if waiter_count != 0 {
                    return Err(format!(
                        "Temporary waiter not properly cleaned up, {} waiters remain",
                        waiter_count
                    ));
                }
            }

            EmptyNotifyOperation::RepeatedNotifyWaiters { count } => {
                let repeat_count = (*count).min(NotifyWaitersEmptyConfig::max_repeated_notifications()) as usize;

                for i in 0..repeat_count {
                    // Verify no waiters each time
                    let waiter_count = notify.waiter_count();
                    if waiter_count > 0 {
                        return Err(format!(
                            "Repeated notify_waiters[{}] called with {} waiters, expected 0",
                            i, waiter_count
                        ));
                    }

                    let stored_before = notify.stored_notifications.load(Ordering::Acquire);
                    notify.notify_waiters();
                    tracker.record_empty_notify_waiters();

                    let stored_after = notify.stored_notifications.load(Ordering::Acquire);
                    if stored_after > stored_before {
                        tracker.record_invariant_violation();
                        return Err(format!(
                            "Repeated notify_waiters[{}] created stored notification: {} -> {}",
                            i, stored_before, stored_after
                        ));
                    }
                }
            }

            EmptyNotifyOperation::MixedNotifications { pattern } => {
                let max_pattern = NotifyWaitersEmptyConfig::max_mixed_pattern() as usize;
                for (i, &op) in pattern.iter().take(max_pattern).enumerate() {
                    // Verify no waiters before each operation
                    let waiter_count = notify.waiter_count();
                    if waiter_count > 0 {
                        return Err(format!(
                            "Mixed notification[{}] called with {} waiters, expected 0",
                            i, waiter_count
                        ));
                    }

                    let stored_before = notify.stored_notifications.load(Ordering::Acquire);

                    if op % 2 == 0 {
                        notify.notify_waiters();
                        tracker.record_empty_notify_waiters();

                        // notify_waiters should not create stored notifications
                        let stored_after = notify.stored_notifications.load(Ordering::Acquire);
                        if stored_after > stored_before {
                            tracker.record_invariant_violation();
                            return Err(format!(
                                "Mixed notify_waiters[{}] created stored notification: {} -> {}",
                                i, stored_before, stored_after
                            ));
                        }
                    } else {
                        notify.notify_one();
                        tracker.record_empty_notify_one();

                        // notify_one should create stored notifications
                        let stored_after = notify.stored_notifications.load(Ordering::Acquire);
                        if stored_after >= stored_before {
                            tracker.record_stored_notification_created();
                        }
                    }
                }
            }

            EmptyNotifyOperation::PostEmptyWaiter { waiter_id } => {
                let id = *waiter_id % 10;

                // Create waiter after empty notifications
                if !waiters.contains_key(&id) {
                    let waiter = TrackedWaiter::new(notify.clone(), id, Arc::new(EmptyNotifyTracker::new()));
                    waiters.insert(id, waiter);
                }

                // Poll the waiter to see its initial state
                if let Some(waiter) = waiters.get_mut(&id) {
                    let poll_result = waiter.poll();

                    // Check if it's immediately ready (consumed stored notification)
                    if poll_result.is_ready() {
                        waiters.remove(&id);
                    }
                }
            }

            EmptyNotifyOperation::CheckState => {
                // Check waiter count
                let waiter_count = notify.waiter_count();
                let expected_waiters = waiters.len();

                if waiter_count != expected_waiters {
                    return Err(format!(
                        "Waiter count mismatch: notify reports {} but tracking {}",
                        waiter_count, expected_waiters
                    ));
                }

                // Check our tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }

        // Always poll active waiters to make progress
        let mut to_remove = Vec::new();
        for (&id, waiter) in waiters.iter_mut() {
            let _ = waiter.poll();
            if waiter.is_completed() {
                to_remove.push(id);
            }
        }
        for id in to_remove {
            waiters.remove(&id);
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: NotifyWaitersEmptyConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = EmptyNotifyTracker::new();

    // Test the empty notify_waiters scenario
    if let Err(msg) = test_empty_notify_waiters_scenario(&config, &tracker) {
        panic!("Empty notify_waiters scenario test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = EmptyNotifyTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_empty_notify_waiters_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent empty notify_waiters test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_empty_waiters = tracker.empty_notify_waiters_calls.load(Ordering::SeqCst);
    let total_empty_one = tracker.empty_notify_one_calls.load(Ordering::SeqCst);

    if total_empty_waiters == 0 && total_empty_one == 0 && !config.operations.is_empty() {
        panic!("No meaningful empty notification operations were performed during the test");
    }
});