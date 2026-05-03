//! Fuzz notify_one() under multiple-waiter race conditions.
//!
//! Tests arbitrary M waiters + N notify_one calls to ensure exactly min(M,N)
//! waiters are notified in FIFO order. Validates notification accounting,
//! stored notification handling, and proper waiter queue management.
//!
//! Critical invariants:
//! - Exactly min(M, N) waiters notified (no over/under notification)
//! - FIFO order: first waiter registered gets notified first
//! - No lost notifications or spurious wakeups
//! - Proper stored notification consumption when no waiters exist

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::notify::Notify;
use futures::task::{Context, noop_waker};
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::Poll;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct NotifyConfig {
    /// Number of waiter threads to spawn (1-8)
    waiter_count: u8,
    /// Number of notify_one calls to make (1-20)
    notify_count: u8,
    /// Delay patterns for waiters (microseconds)
    waiter_delays: Vec<u16>,
    /// Delay patterns for notifiers (microseconds)
    notify_delays: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
struct NotifySequence {
    /// Test configuration
    config: NotifyConfig,
    /// Whether to mix notify_one with stored notifications
    use_stored_notifications: bool,
    /// Whether to add post-notification waiters
    add_late_waiters: bool,
}

impl NotifySequence {
    fn max_waiters() -> u8 {
        8 // Reasonable upper bound for thread testing
    }

    fn max_notifies() -> u8 {
        20 // Keep test duration reasonable
    }
}

/// Result tracking for waiter threads
#[derive(Debug, Clone)]
struct WaiterResult {
    waiter_id: usize,
    registered_at: std::time::Instant,
    notified_at: Option<std::time::Instant>,
    notification_order: Option<usize>, // Order in which this waiter was notified
}

/// Test execution context tracking notification state
#[derive(Debug)]
struct NotifyTracker {
    total_waiters: usize,
    total_notifies: usize,
    expected_notified: usize,          // min(waiters, notifies)
    notification_counter: AtomicUsize, // Tracks order of notifications
}

impl NotifyTracker {
    fn new(waiters: usize, notifies: usize) -> Self {
        Self {
            total_waiters: waiters,
            total_notifies: notifies,
            expected_notified: waiters.min(notifies),
            notification_counter: AtomicUsize::new(0),
        }
    }

    fn record_notification(&self) -> usize {
        self.notification_counter.fetch_add(1, Ordering::SeqCst)
    }

    fn check_invariants(&self, results: &[WaiterResult]) -> Result<(), String> {
        // Count how many waiters were actually notified
        let notified_count = results.iter().filter(|r| r.notified_at.is_some()).count();

        // Core invariant: exactly min(M, N) waiters notified
        if notified_count != self.expected_notified {
            return Err(format!(
                "WRONG NOTIFICATION COUNT: expected {} (min({}, {})), got {}",
                self.expected_notified, self.total_waiters, self.total_notifies, notified_count
            ));
        }

        // FIFO order check: notification order should match registration order
        let mut notified_waiters: Vec<_> =
            results.iter().filter(|r| r.notified_at.is_some()).collect();

        // Sort by registration order (waiter_id serves as registration order proxy)
        notified_waiters.sort_by_key(|r| r.waiter_id);

        // Check that notification_order is sequential from 0
        for (i, waiter) in notified_waiters.iter().enumerate() {
            if let Some(notification_order) = waiter.notification_order {
                if notification_order != i {
                    return Err(format!(
                        "FIFO VIOLATION: waiter {} (registered {}) got notification order {}, expected {}",
                        waiter.waiter_id, i, notification_order, i
                    ));
                }
            }
        }

        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: NotifySequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.waiter_count == 0
        || sequence.config.notify_count == 0
        || sequence.config.waiter_count > NotifySequence::max_waiters()
        || sequence.config.notify_count > NotifySequence::max_notifies()
    {
        return;
    }

    let waiter_count = sequence.config.waiter_count as usize;
    let notify_count = sequence.config.notify_count as usize;

    // Create shared notify and synchronization primitives
    let notify = Arc::new(Notify::new());
    let start_barrier = Arc::new(Barrier::new(waiter_count + 1)); // +1 for main thread
    let tracker = Arc::new(NotifyTracker::new(waiter_count, notify_count));
    let results = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let test_complete = Arc::new(AtomicBool::new(false));

    // Spawn waiter threads
    let waiter_handles: Vec<_> = (0..waiter_count)
        .map(|waiter_id| {
            let notify = Arc::clone(&notify);
            let start_barrier = Arc::clone(&start_barrier);
            let tracker = Arc::clone(&tracker);
            let results = Arc::clone(&results);
            let test_complete = Arc::clone(&test_complete);
            let initial_delay = sequence
                .config
                .waiter_delays
                .get(waiter_id)
                .copied()
                .unwrap_or(0);

            thread::spawn(move || {
                // Wait for all threads to be ready
                start_barrier.wait();

                // Apply initial waiter delay for staggered registration
                if initial_delay > 0 {
                    thread::sleep(Duration::from_micros(initial_delay as u64));
                }

                let registered_at = std::time::Instant::now();
                let mut waiter_result = WaiterResult {
                    waiter_id,
                    registered_at,
                    notified_at: None,
                    notification_order: None,
                };

                // Create notified future and poll it synchronously
                let mut notified_future = notify.notified();
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                // Poll until notified or test completes
                loop {
                    match Pin::new(&mut notified_future).poll(&mut context) {
                        Poll::Ready(()) => {
                            // Notification received
                            let notified_at = std::time::Instant::now();
                            let notification_order = tracker.record_notification();

                            waiter_result.notified_at = Some(notified_at);
                            waiter_result.notification_order = Some(notification_order);
                            break;
                        }
                        Poll::Pending => {
                            // Check if test is complete (prevents hanging on insufficient notifies)
                            if test_complete.load(Ordering::Acquire) {
                                break;
                            }
                            // Small yield to avoid busy spinning
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                }

                results.lock().push(waiter_result);
            })
        })
        .collect();

    // Wait for all waiter threads to start
    start_barrier.wait();

    // Small delay to allow waiters to register
    thread::sleep(Duration::from_millis(10));

    // Perform notify_one calls
    for i in 0..notify_count {
        let delay = sequence.config.notify_delays.get(i).copied().unwrap_or(0);

        if delay > 0 {
            thread::sleep(Duration::from_micros(delay as u64));
        }

        notify.notify_one();
    }

    // Test stored notifications if requested
    if sequence.use_stored_notifications && waiter_count < notify_count {
        // Additional notify_one calls that should create stored notifications
        let extra_notifies = (notify_count - waiter_count).min(5);
        for _ in 0..extra_notifies {
            notify.notify_one();
        }

        // Add late waiters if requested to test stored notification consumption
        if sequence.add_late_waiters {
            let late_waiter_notify = Arc::clone(&notify);
            let late_result = Arc::clone(&results);
            let late_tracker = Arc::clone(&tracker);

            let late_handle = thread::spawn(move || {
                thread::sleep(Duration::from_millis(20)); // Ensure it's late

                let mut notified_future = late_waiter_notify.notified();
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                match Pin::new(&mut notified_future).poll(&mut context) {
                    Poll::Ready(()) => {
                        // Should get a stored notification
                        let notification_order = late_tracker.record_notification();
                        late_result.lock().push(WaiterResult {
                            waiter_id: waiter_count, // Special ID for late waiter
                            registered_at: std::time::Instant::now(),
                            notified_at: Some(std::time::Instant::now()),
                            notification_order: Some(notification_order),
                        });
                    }
                    Poll::Pending => {
                        // Should not be pending if stored notifications exist
                        panic!("Late waiter should have received stored notification immediately");
                    }
                }
            });

            late_handle.join().unwrap();
        }
    }

    // Small grace period for notifications to propagate
    thread::sleep(Duration::from_millis(50));

    // Mark test complete to unblock any remaining waiters
    test_complete.store(true, Ordering::Release);

    // Wait for all waiter threads to complete
    for handle in waiter_handles {
        handle.join().expect("Waiter thread should complete");
    }

    // Collect and validate results
    let final_results = results.lock().clone();

    // Check core invariants
    if let Err(msg) = tracker.check_invariants(&final_results) {
        panic!("Notification invariant violation: {}", msg);
    }

    // Additional sanity checks
    let actually_notified = final_results
        .iter()
        .filter(|r| r.notified_at.is_some())
        .count();

    // Ensure we got exactly the expected number of notifications
    assert_eq!(
        actually_notified, tracker.expected_notified,
        "Final notification count mismatch: expected {}, got {} notifications",
        tracker.expected_notified, actually_notified
    );

    // Check notification order sequence (should be 0, 1, 2, ...)
    let mut notification_orders: Vec<usize> = final_results
        .iter()
        .filter_map(|r| r.notification_order)
        .collect();
    notification_orders.sort();

    let expected_orders: Vec<usize> = (0..tracker.expected_notified).collect();
    assert_eq!(
        notification_orders, expected_orders,
        "Notification order sequence invalid: expected {:?}, got {:?}",
        expected_orders, notification_orders
    );

    // Verify no duplicate notification orders
    let unique_orders: std::collections::HashSet<_> = notification_orders.iter().collect();
    assert_eq!(
        unique_orders.len(),
        notification_orders.len(),
        "Duplicate notification orders detected: {:?}",
        notification_orders
    );
});
